//! Clock-only progress after a relay joins a running session. A peer clock proves
//! a baseline; actual received turns must fill every gap above it. These counts
//! are not evidence that this relay received the complete game history.

use std::collections::{BTreeSet, HashMap};

use rally_point_proto::ids::SlotId;

const AHEAD_CAP: usize = 4096;

#[derive(Default)]
pub(in crate::consensus) struct ClockProgress {
    baseline: Option<u64>,
    slots: HashMap<SlotId, SlotProgress>,
}

#[derive(Default)]
struct SlotProgress {
    count: u64,
    ahead: BTreeSet<u64>,
    overflow_reported: bool,
}

impl SlotProgress {
    fn absorb(&mut self) {
        while self.ahead.remove(&self.count) {
            let Some(next) = self.count.checked_add(1) else {
                break;
            };
            self.count = next;
        }
    }

    fn seed(&mut self, count: u64) {
        self.count = self.count.max(count);
        while self.ahead.first().is_some_and(|seq| *seq < self.count) {
            self.ahead.pop_first();
        }
        self.absorb();
    }
}

impl ClockProgress {
    /// Records an actually received turn. In-order arrivals advance without
    /// allocating after the slot exists; out-of-order arrivals wait for gaps.
    /// Returns true only when this slot first exceeds the ahead cap, so callers
    /// can diagnose lost recovery history once without logging every later turn.
    pub(in crate::consensus) fn note(&mut self, slot: SlotId, seq: u64) -> bool {
        let state = self.slots.entry(slot).or_insert_with(|| SlotProgress {
            count: self.baseline.unwrap_or(0),
            ..Default::default()
        });
        if seq < state.count {
            return false;
        }
        if seq == state.count {
            state.count = state.count.saturating_add(1);
            state.absorb();
            return false;
        }
        state.ahead.insert(seq);
        if state.ahead.len() > AHEAD_CAP {
            if self.baseline.is_some() {
                // Keep the turns nearest the next gap. Dropping a distant turn
                // cannot close that gap or certify receipt of anything absent.
                state.ahead.pop_last();
            } else {
                // Before a peer supplies the baseline, retain the recent suffix
                // most likely to overlap it, without inventing a prefix.
                state.ahead.pop_first();
            }
            let first_overflow = !state.overflow_reported;
            state.overflow_reported = true;
            return first_overflow;
        }
        false
    }

    /// Adopts a count confirmed by an accepted peer clock. This is deliberately
    /// not called with client cursors or a received turn's sequence number.
    /// Existing suffixes survive; slots first seen later inherit the same floor.
    pub(in crate::consensus) fn seed(&mut self, count: u64) {
        let baseline = self.baseline.unwrap_or(0).max(count);
        self.baseline = Some(baseline);
        for state in self.slots.values_mut() {
            state.seed(baseline);
        }
    }

    /// Next needed sequence for clock progression, including the trusted floor.
    pub(in crate::consensus) fn count(&self, slot: SlotId) -> u64 {
        self.slots
            .get(&slot)
            .map_or(self.baseline.unwrap_or(0), |state| state.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gap_above_the_baseline_waits_for_the_actual_missing_turn() {
        let mut progress = ClockProgress::default();
        progress.seed(101);
        progress.note(SlotId(0), 102);
        assert_eq!(progress.count(SlotId(0)), 101);
        progress.note(SlotId(0), 101);
        assert_eq!(progress.count(SlotId(0)), 103);
        progress.note(SlotId(0), 102);
        assert_eq!(progress.count(SlotId(0)), 103);
    }

    #[test]
    fn reversed_suffix_survives_whether_the_clock_arrives_before_or_after_it() {
        for seed_first in [false, true] {
            let mut progress = ClockProgress::default();
            if seed_first {
                progress.seed(100);
            }
            for seq in (101..120).rev() {
                progress.note(SlotId(0), seq);
            }
            progress.seed(100);
            assert_eq!(progress.count(SlotId(0)), 100);
            progress.note(SlotId(0), 100);
            assert_eq!(progress.count(SlotId(0)), 120);
        }
    }

    #[test]
    fn repeated_and_stale_baselines_preserve_progress_and_apply_to_later_slots() {
        let mut progress = ClockProgress::default();
        progress.seed(50);
        progress.note(SlotId(0), 50);
        progress.seed(50);
        progress.seed(20);
        assert_eq!(progress.count(SlotId(0)), 51);
        assert_eq!(progress.count(SlotId(1)), 50);
        progress.note(SlotId(1), 51);
        assert_eq!(progress.count(SlotId(1)), 50);
        progress.seed(51);
        assert_eq!(progress.count(SlotId(1)), 52);
        assert_eq!(progress.count(SlotId(2)), 51);
    }

    #[test]
    fn overflow_before_a_baseline_retains_the_recent_suffix_without_progress() {
        let mut progress = ClockProgress::default();
        for seq in 1..=AHEAD_CAP as u64 + 10 {
            assert_eq!(progress.note(SlotId(0), seq), seq == AHEAD_CAP as u64 + 1);
        }
        assert_eq!(progress.count(SlotId(0)), 0);
        assert_eq!(progress.slots[&SlotId(0)].ahead.len(), AHEAD_CAP);
        progress.seed(1);
        assert_eq!(progress.count(SlotId(0)), 1);
        progress.seed(11);
        assert_eq!(progress.count(SlotId(0)), AHEAD_CAP as u64 + 11);
    }

    #[test]
    fn overflow_after_a_baseline_retains_the_nearest_pending_turns_without_skipping() {
        let mut progress = ClockProgress::default();
        progress.seed(100);
        for (index, seq) in (101..=AHEAD_CAP as u64 + 110).rev().enumerate() {
            assert_eq!(progress.note(SlotId(0), seq), index == AHEAD_CAP);
        }
        assert_eq!(progress.count(SlotId(0)), 100);
        assert_eq!(progress.slots[&SlotId(0)].ahead.len(), AHEAD_CAP);
        progress.note(SlotId(0), 100);
        assert_eq!(progress.count(SlotId(0)), AHEAD_CAP as u64 + 101);
        progress.note(SlotId(0), AHEAD_CAP as u64 + 102);
        assert_eq!(progress.count(SlotId(0)), AHEAD_CAP as u64 + 101);
    }

    #[test]
    fn overflow_diagnostics_are_per_slot_and_do_not_reset_after_a_seed() {
        let mut progress = ClockProgress::default();
        for slot in [SlotId(0), SlotId(1)] {
            for seq in 1..=AHEAD_CAP as u64 + 1 {
                assert_eq!(progress.note(slot, seq), seq == AHEAD_CAP as u64 + 1);
            }
            assert_eq!(progress.count(slot), 0);
        }
        let baseline = AHEAD_CAP as u64 + 2;
        progress.seed(baseline);
        for slot in [SlotId(0), SlotId(1)] {
            for seq in baseline + 1..=baseline + AHEAD_CAP as u64 + 1 {
                assert!(!progress.note(slot, seq));
            }
            assert_eq!(progress.count(slot), baseline);
            assert_eq!(progress.slots[&slot].ahead.len(), AHEAD_CAP);
        }
    }

    #[test]
    fn in_order_progress_needs_no_seed_and_slots_are_independent() {
        let mut progress = ClockProgress::default();
        for seq in 0..20 {
            progress.note(SlotId(0), seq);
        }
        assert_eq!(progress.count(SlotId(0)), 20);
        assert_eq!(progress.count(SlotId(1)), 0);
        assert!(progress.slots[&SlotId(0)].ahead.is_empty());
        progress.seed(10);
        assert_eq!(progress.count(SlotId(0)), 20);
        assert_eq!(progress.count(SlotId(1)), 10);
    }

    #[test]
    fn sequence_and_count_limits_saturate_without_wrapping() {
        let mut progress = ClockProgress::default();
        progress.note(SlotId(0), u64::MAX);
        progress.seed(u64::MAX - 1);
        assert_eq!(progress.count(SlotId(0)), u64::MAX - 1);
        progress.note(SlotId(0), u64::MAX - 1);
        assert_eq!(progress.count(SlotId(0)), u64::MAX);
        progress.note(SlotId(0), u64::MAX);
        progress.seed(u64::MAX);
        progress.note(SlotId(1), u64::MAX);
        assert_eq!(progress.count(SlotId(0)), u64::MAX);
        assert_eq!(progress.count(SlotId(1)), u64::MAX);
        assert!(progress.slots[&SlotId(0)].ahead.is_empty());
    }
}
