//! Tags the checksum already staged in a native outgoing turn with its generation.
//!
//! The native sync recorder advances once per executed network step, whereas the
//! outgoing flush can run zero times (a shrinking pipe) or several times (a growing
//! pipe). A flush sends the assembled turn before staging the current sync slot
//! for the following flush. Tracking those two boundaries keeps generations tied
//! to checksums rather than to the send frame or transport sequence.

use rally_point_proto::commands::command_length;

const RING_SIZE: u64 = 16;
const SYNC_COMMAND: u8 = 0x37;
const SYNC_COMMAND_LEN: usize = 7;
/// Rejected by the relay's first-generation and bounded-advance checks. Keeping a
/// failed enhanced stream explicitly tagged prevents a fallback to ring guessing.
const INVALID_GENERATION: u64 = u64::MAX;

/// Per-game checksum generation state, driven only on the native game thread.
///
/// Observe only while native checksum generation is active. Pre-game pipe fills
/// precede native sync initialization and must not anchor this tracker.
/// Call [`Self::record_sync_slot`] around every active native sync-slot recording and
/// [`Self::stamp_turn`] at every native outgoing send, before its buffer is cleared
/// and seeded with the current slot. Native command bytes remain unchanged.
#[derive(Debug, Default)]
pub struct SyncGenerationTracker {
    native_generation: Option<u64>,
    staged_generation: Option<u64>,
    failed: bool,
}

impl SyncGenerationTracker {
    /// Observes one invocation of the native recorder using its ring index before
    /// and after the call. The initial native ring anchors generation zero's cycle;
    /// every subsequent invocation must advance exactly one position, including wrap.
    pub fn record_sync_slot(&mut self, before: u8, after: u8) {
        let Some(previous) = self.observe_native_ring(before) else {
            return;
        };
        if u64::from(after) != (u64::from(before) + 1) % RING_SIZE {
            self.failed = true;
            return;
        }
        match previous
            .checked_add(1)
            .filter(|&value| value != INVALID_GENERATION)
        {
            Some(generation) => self.native_generation = Some(generation),
            None => self.failed = true,
        }
    }

    /// Returns metadata for the first native `0x37` in the outgoing command buffer.
    /// `native_ring` is read at the send boundary, before the native flush seeds
    /// the next buffer. Turns without a checksum return `None`, but still stage
    /// the current generation for that next buffer.
    ///
    /// An inconsistent native observation is latched. Checksum turns then carry
    /// an invalid explicit generation so relays exclude this origin's coverage
    /// without interfering with gameplay or silently selecting legacy ordering.
    pub fn stamp_turn(&mut self, commands: &[u8], native_ring: u8) -> Option<u64> {
        let current = self.observe_native_ring(native_ring);
        let staged = self.staged_generation.or(current);
        self.staged_generation = current;
        let mut remaining = commands;
        while !remaining.is_empty() {
            let Some(length) =
                command_length(remaining).filter(|&length| length > 0 && length <= remaining.len())
            else {
                self.failed = true;
                return Some(INVALID_GENERATION);
            };
            if remaining[0] == SYNC_COMMAND && length == SYNC_COMMAND_LEN {
                let ring = u64::from(remaining[1] >> 4);
                if self.failed || staged.is_none_or(|generation| generation % RING_SIZE != ring) {
                    self.failed = true;
                    return Some(INVALID_GENERATION);
                }
                return staged;
            }
            remaining = &remaining[length..];
        }
        None
    }

    fn observe_native_ring(&mut self, ring: u8) -> Option<u64> {
        if self.failed {
            return None;
        }
        let ring = u64::from(ring);
        if ring >= RING_SIZE {
            self.failed = true;
            return None;
        }
        let generation = *self.native_generation.get_or_insert(ring);
        if generation % RING_SIZE != ring {
            self.failed = true;
            return None;
        }
        Some(generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(generation: u64) -> [u8; 7] {
        let ring = (generation % RING_SIZE) as u8;
        [SYNC_COMMAND, (ring << 4) | (1 + ring % 2), 0, 0, 0, 0, 0]
    }

    #[test]
    fn staged_checksum_keeps_its_generation_after_the_native_ring_advances() {
        let mut tracker = SyncGenerationTracker::default();
        tracker.record_sync_slot(0, 1);
        assert_eq!(tracker.stamp_turn(&checksum(1), 1), Some(1));
        tracker.record_sync_slot(1, 2);
        assert_eq!(tracker.stamp_turn(&checksum(1), 2), Some(1));
        tracker.record_sync_slot(2, 3);
        assert_eq!(tracker.stamp_turn(&checksum(2), 3), Some(2));
    }

    #[test]
    fn shrink_skips_generations_without_relabeling_the_buffer_already_staged() {
        for skipped in 1..=13 {
            let mut tracker = SyncGenerationTracker::default();
            assert_eq!(tracker.stamp_turn(&checksum(14), 14), Some(14));
            let mut generation = 14;
            for _ in 0..=skipped {
                tracker.record_sync_slot((generation % 16) as u8, ((generation + 1) % 16) as u8);
                generation += 1;
            }
            // The old outgoing buffer survives all suppressed flushes.
            assert_eq!(
                tracker.stamp_turn(&checksum(14), (generation % 16) as u8),
                Some(14)
            );
            tracker.record_sync_slot((generation % 16) as u8, ((generation + 1) % 16) as u8);
            assert_eq!(
                tracker.stamp_turn(&checksum(generation), ((generation + 1) % 16) as u8),
                Some(generation)
            );
        }
    }

    #[test]
    fn growth_flushes_repeat_the_current_generation_without_advancing_it() {
        let mut tracker = SyncGenerationTracker::default();
        tracker.stamp_turn(&checksum(1), 1);
        tracker.record_sync_slot(1, 2);
        assert_eq!(tracker.stamp_turn(&checksum(1), 2), Some(1));
        for _ in 0..14 {
            assert_eq!(tracker.stamp_turn(&checksum(2), 2), Some(2));
        }
        tracker.record_sync_slot(2, 3);
        assert_eq!(tracker.stamp_turn(&checksum(2), 3), Some(2));
    }

    #[test]
    fn repeated_resizes_preserve_native_generation_across_many_ring_wraps() {
        let mut tracker = SyncGenerationTracker::default();
        let mut native = 1_u64;
        let mut staged = 1_u64;
        let mut depth = 5_u32;
        let mut outstanding = 0_u32;
        let mut generations = Vec::new();
        // Native pre-loop pipe fill: several sends share one recorded checksum.
        for _ in 0..depth {
            generations.push(tracker.stamp_turn(&checksum(staged), 1).unwrap());
            outstanding += 1;
        }
        for step in 0..300 {
            depth = match step {
                20 => 6,
                60 => 5,
                100 => 1,
                150 => 14,
                180 => 1,
                220 => 6,
                240 => 5,
                _ => depth,
            };
            outstanding -= 1;
            for _ in 0..depth.saturating_sub(outstanding) {
                let generation = tracker
                    .stamp_turn(&checksum(staged), (native % 16) as u8)
                    .unwrap();
                assert_eq!(generation, staged);
                generations.push(generation);
                staged = native;
                outstanding += 1;
            }
            tracker.record_sync_slot((native % 16) as u8, ((native + 1) % 16) as u8);
            native += 1;
        }
        // The property is the in-loop equality above. What follows only checks
        // that the resize script above actually reached the shapes it was
        // written to reach -- a growth repeat, a one-turn shrink, the deepest
        // safe shrink -- so a future edit to the script cannot quietly stop
        // exercising them.
        let advances: Vec<_> = generations
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .collect();
        assert!(
            advances.contains(&0),
            "growth duplicates the current sample"
        );
        assert!(advances.contains(&2), "one-turn shrink omits one sample");
        assert!(
            advances.contains(&14),
            "the deepest safe shrink remains bounded"
        );
        assert!(advances.iter().all(|&advance| advance <= 14));
        assert!(generations.last().unwrap() > &256);
        assert!(!tracker.failed);
    }

    #[test]
    fn turns_without_sync_still_follow_native_buffer_staging() {
        let mut tracker = SyncGenerationTracker::default();
        assert_eq!(tracker.stamp_turn(&[0x05], 1), None);
        tracker.record_sync_slot(1, 2);
        assert_eq!(tracker.stamp_turn(&checksum(1), 2), Some(1));
    }

    #[test]
    fn only_the_first_checksum_in_a_turn_is_tagged() {
        // A turn carrying two sync commands names one generation: the first
        // checksum's. Reading the later one instead would label the turn with a
        // buffer the game never staged for it.
        let mut tracker = SyncGenerationTracker::default();
        let mut commands = vec![0x05];
        commands.extend(checksum(1));
        commands.extend(checksum(8));
        assert_eq!(tracker.stamp_turn(&commands, 1), Some(1));
    }

    #[test]
    fn invalid_observations_latch_explicit_failure() {
        for (before, after) in [(1, 3), (1, 1), (16, 1), (1, 16)] {
            let mut tracker = SyncGenerationTracker::default();
            tracker.record_sync_slot(before, after);
            assert_eq!(
                tracker.stamp_turn(&checksum(1), 1),
                Some(INVALID_GENERATION)
            );
            assert_eq!(
                tracker.stamp_turn(&checksum(2), 2),
                Some(INVALID_GENERATION)
            );
        }
        let mut tracker = SyncGenerationTracker::default();
        assert_eq!(
            tracker.stamp_turn(&checksum(2), 1),
            Some(INVALID_GENERATION)
        );
        assert_eq!(
            tracker.stamp_turn(&checksum(1), 1),
            Some(INVALID_GENERATION)
        );
    }

    #[test]
    fn counter_overflow_and_truncated_commands_cannot_fall_back_to_legacy() {
        let mut tracker = SyncGenerationTracker {
            native_generation: Some(u64::MAX - 1),
            ..Default::default()
        };
        tracker.record_sync_slot(14, 15);
        assert_eq!(
            tracker.stamp_turn(&checksum(15), 15),
            Some(INVALID_GENERATION)
        );
        let mut tracker = SyncGenerationTracker::default();
        assert_eq!(
            tracker.stamp_turn(&[SYNC_COMMAND, 0x12], 1),
            Some(INVALID_GENERATION)
        );
    }
}
