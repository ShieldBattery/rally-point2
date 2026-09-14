//! Bounded ordering of checksum metadata, independent of gameplay forwarding.

use super::*;

/// Exclusive distance ahead of a slot's next missing turn retained for comparison.
pub(in crate::consensus) const SYNC_TURN_WINDOW: u64 = rally_point_transport::RECEIVE_WINDOW;

#[derive(Debug, Clone, Copy)]
pub(in crate::consensus) struct SyncCommand {
    pub ring: u8,
    pub kind: u8,
    pub value: SyncValue,
}

/// Every turn occupies a sequence position, including turns without a checksum.
/// `ordinal` is assigned only when the complete prefix has unwrapped the sync ring.
#[derive(Debug, Clone, Copy)]
pub(in crate::consensus) struct SyncTurn {
    pub frame: Option<u32>,
    pub ordinal: Option<u64>,
    pub command: Option<SyncCommand>,
}

/// Captured before discarding a slot's pending metadata. Sequence gaps describe
/// missing observation history, not proof that the sender's simulation diverged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::consensus) struct SyncOrderingFailure {
    pub reason: &'static str,
    pub seq: u64,
    /// First missing sequence; on a ring failure, the sequence being consumed.
    pub next: u64,
    pub previous_ordinal: Option<u64>,
    pub ring: Option<u8>,
}

#[derive(Debug, Default)]
pub(in crate::consensus) struct SyncTurns {
    slots: HashMap<SlotId, SlotTurns>,
}

#[derive(Debug, Default)]
struct SlotTurns {
    next: u64,
    pending: BTreeMap<u64, SyncTurn>,
    ordinal: Option<u64>,
    failure: Option<SyncOrderingFailure>,
}

impl SyncTurns {
    /// Only sequence zero supplies an implicit anchor. Failure is permanent for
    /// this origin on this relay; other origins retain their independent history.
    pub fn push(
        &mut self,
        slot: SlotId,
        seq: u64,
        turn: SyncTurn,
    ) -> Result<Option<SyncTurn>, SyncOrderingFailure> {
        let state = self.slots.entry(slot).or_default();
        if state.failure.is_some() || seq < state.next {
            return Ok(None);
        }
        if seq == state.next {
            return state.consume(seq, turn).map(Some);
        }
        // A verdict can interrupt draining with a contiguous tail still queued.
        // Those turns are present, so the receive window starts at the first
        // actual hole, not the next report awaiting comparison.
        if seq - state.next >= SYNC_TURN_WINDOW
            && seq.saturating_sub(state.first_missing()) >= SYNC_TURN_WINDOW
        {
            return Err(state.fail("sequence_gap", seq, turn));
        }
        if state.pending.len() >= SYNC_TURN_WINDOW as usize && !state.pending.contains_key(&seq) {
            return Err(state.fail("metadata_capacity", seq, turn));
        }
        state.pending.entry(seq).or_insert(turn);
        Ok(None)
    }

    pub fn pop_ready(&mut self, slot: SlotId) -> Result<Option<SyncTurn>, SyncOrderingFailure> {
        let Some(state) = self.slots.get_mut(&slot) else {
            return Ok(None);
        };
        let Some(turn) = state.pending.remove(&state.next) else {
            return Ok(None);
        };
        state.consume(state.next, turn).map(Some)
    }

    pub fn failure(&self, slot: SlotId) -> Option<SyncOrderingFailure> {
        self.slots.get(&slot).and_then(|state| state.failure)
    }

    pub fn unavailable(&self, slot: SlotId) -> bool {
        self.failure(slot).is_some()
    }

    pub fn ordered(&self, slot: SlotId) -> bool {
        self.slots
            .get(&slot)
            .is_some_and(|s| s.failure.is_none() && s.ordinal.is_some() && s.pending.is_empty())
    }

    pub fn slots(&self) -> impl Iterator<Item = SlotId> + '_ {
        self.slots.keys().copied()
    }

    #[cfg(test)]
    pub(in crate::consensus) fn next_for_test(&self, slot: SlotId) -> u64 {
        self.slots.get(&slot).map_or(0, |s| s.next)
    }
}

impl SlotTurns {
    fn first_missing(&self) -> u64 {
        let mut next = self.next;
        while self.pending.contains_key(&next) {
            let Some(following) = next.checked_add(1) else {
                break;
            };
            next = following;
        }
        next
    }

    fn fail(&mut self, reason: &'static str, seq: u64, turn: SyncTurn) -> SyncOrderingFailure {
        let failure = SyncOrderingFailure {
            reason,
            seq,
            next: self.first_missing(),
            previous_ordinal: self.ordinal,
            ring: turn.command.map(|command| command.ring),
        };
        self.pending.clear();
        self.failure = Some(failure);
        failure
    }

    fn consume(&mut self, seq: u64, mut turn: SyncTurn) -> Result<SyncTurn, SyncOrderingFailure> {
        let Some(next) = self.next.checked_add(1) else {
            return Err(self.fail("sequence_overflow", seq, turn));
        };
        if let Some(command) = turn.command {
            let ring = u64::from(command.ring);
            // Repeated startup checksums retain their ordinal. A jump cannot
            // establish how many whole ring cycles were omitted, even when the
            // transport prefix is complete. Never guess an epoch from proximity.
            let ordinal = match self.ordinal {
                None => ring,
                Some(last) if last % SYNC_RING_MODULUS == ring => last,
                Some(last) if (last % SYNC_RING_MODULUS + 1) % SYNC_RING_MODULUS == ring => {
                    let Some(ordinal) = last.checked_add(1) else {
                        return Err(self.fail("ordinal_overflow", seq, turn));
                    };
                    ordinal
                }
                Some(_) => return Err(self.fail("ring_discontinuity", seq, turn)),
            };
            self.ordinal = Some(ordinal);
            turn.ordinal = Some(ordinal);
        }
        self.next = next;
        Ok(turn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn turn(ring: Option<u8>) -> SyncTurn {
        SyncTurn {
            frame: None,
            ordinal: None,
            command: ring.map(|ring| SyncCommand {
                ring,
                kind: 1,
                value: [0, 0],
            }),
        }
    }

    #[test]
    fn the_last_sequence_in_the_window_can_recover_without_guessing_a_prefix() {
        let mut turns = SyncTurns::default();
        assert!(
            turns
                .push(SlotId(0), SYNC_TURN_WINDOW - 1, turn(None))
                .unwrap()
                .is_none()
        );
        for seq in 0..SYNC_TURN_WINDOW - 1 {
            assert!(turns.push(SlotId(0), seq, turn(None)).unwrap().is_some());
        }
        assert!(turns.pop_ready(SlotId(0)).unwrap().is_some());
        assert!(turns.slots[&SlotId(0)].pending.is_empty());
        assert_eq!(turns.slots[&SlotId(0)].next, SYNC_TURN_WINDOW);
    }

    #[test]
    fn an_unrecoverable_gap_clears_only_its_origin_and_preserves_failure_context() {
        let mut turns = SyncTurns::default();
        turns.push(SlotId(1), 1, turn(Some(1))).unwrap();
        for seq in 1..SYNC_TURN_WINDOW {
            assert!(turns.push(SlotId(0), seq, turn(None)).unwrap().is_none());
        }
        let failure = turns
            .push(SlotId(0), SYNC_TURN_WINDOW, turn(Some(3)))
            .unwrap_err();
        assert_eq!(
            failure,
            SyncOrderingFailure {
                reason: "sequence_gap",
                seq: SYNC_TURN_WINDOW,
                next: 0,
                previous_ordinal: None,
                ring: Some(3),
            }
        );
        assert!(turns.slots[&SlotId(0)].pending.is_empty());
        assert!(turns.unavailable(SlotId(0)));
        assert!(turns.push(SlotId(0), 0, turn(None)).unwrap().is_none());
        assert!(turns.push(SlotId(1), 0, turn(Some(0))).unwrap().is_some());
        assert_eq!(
            turns.pop_ready(SlotId(1)).unwrap().unwrap().ordinal,
            Some(1)
        );
        assert!(!turns.unavailable(SlotId(1)));
    }

    #[test]
    fn repeated_sequences_never_reenter_ordered_comparison() {
        let mut turns = SyncTurns::default();
        turns.push(SlotId(0), 1, turn(None)).unwrap();
        turns.push(SlotId(0), 1, turn(None)).unwrap();
        assert_eq!(turns.slots[&SlotId(0)].pending.len(), 1);
        turns.push(SlotId(0), 0, turn(None)).unwrap();
        assert!(turns.pop_ready(SlotId(0)).unwrap().is_some());
        assert!(turns.push(SlotId(0), 1, turn(None)).unwrap().is_none());
    }

    #[test]
    fn ring_discontinuities_preserve_the_prior_ordinal_and_missing_sequence() {
        for ring in [3, 8, 9, 0] {
            let mut turns = SyncTurns::default();
            turns.push(SlotId(0), 0, turn(Some(1))).unwrap();
            turns.push(SlotId(0), 2, turn(Some(ring))).unwrap();
            turns.push(SlotId(0), 1, turn(Some(1))).unwrap();
            let failure = turns.pop_ready(SlotId(0)).unwrap_err();
            assert_eq!(failure.reason, "ring_discontinuity");
            assert_eq!(failure.seq, 2);
            assert_eq!(failure.next, 2);
            assert_eq!(failure.previous_ordinal, Some(1));
            assert_eq!(failure.ring, Some(ring));
        }
    }

    #[test]
    fn a_ready_tail_is_not_a_missing_prefix_after_comparison_pauses() {
        let mut turns = SyncTurns::default();
        for seq in 1..SYNC_TURN_WINDOW {
            turns.push(SlotId(0), seq, turn(None)).unwrap();
        }
        // Sequence zero produces a verdict before the caller drains the ready
        // tail. Sequence 4097 then arrives before the actual missing 4096.
        turns.push(SlotId(0), 0, turn(None)).unwrap();
        assert!(
            turns
                .push(SlotId(0), SYNC_TURN_WINDOW + 1, turn(None))
                .unwrap()
                .is_none()
        );
        assert!(!turns.unavailable(SlotId(0)));
        for _ in 1..SYNC_TURN_WINDOW {
            assert!(turns.pop_ready(SlotId(0)).unwrap().is_some());
        }
        assert!(turns.pop_ready(SlotId(0)).unwrap().is_none());
        turns.push(SlotId(0), SYNC_TURN_WINDOW, turn(None)).unwrap();
        assert!(turns.pop_ready(SlotId(0)).unwrap().is_some());
        assert!(turns.slots[&SlotId(0)].pending.is_empty());
    }

    #[test]
    fn metadata_capacity_backstop_clears_only_the_full_origin() {
        let mut turns = SyncTurns::default();
        // Construct a full ready tail without the caller draining it. This
        // exercises the storage bound independently of receive-window admission.
        turns.slots.insert(
            SlotId(0),
            SlotTurns {
                next: 1,
                pending: (1..=SYNC_TURN_WINDOW)
                    .map(|seq| (seq, turn(None)))
                    .collect(),
                ..Default::default()
            },
        );
        turns.push(SlotId(1), 1, turn(None)).unwrap();
        assert!(
            turns
                .push(SlotId(0), SYNC_TURN_WINDOW, turn(None))
                .unwrap()
                .is_none(),
            "a duplicate does not grow a full queue"
        );
        let failure = turns
            .push(SlotId(0), SYNC_TURN_WINDOW + 2, turn(None))
            .unwrap_err();
        assert_eq!(failure.reason, "metadata_capacity");
        assert_eq!(failure.next, SYNC_TURN_WINDOW + 1);
        assert!(turns.slots[&SlotId(0)].pending.is_empty());
        assert!(turns.unavailable(SlotId(0)));
        assert!(!turns.unavailable(SlotId(1)));
        assert_eq!(turns.slots[&SlotId(1)].pending.len(), 1);
    }

    #[test]
    fn arithmetic_overflow_is_a_per_origin_failure() {
        for (next, ordinal, reason) in [
            (u64::MAX, Some(0), "sequence_overflow"),
            (10, Some(u64::MAX), "ordinal_overflow"),
        ] {
            let mut turns = SyncTurns::default();
            turns.slots.insert(
                SlotId(0),
                SlotTurns {
                    next,
                    ordinal,
                    ..Default::default()
                },
            );
            assert_eq!(
                turns
                    .push(SlotId(0), next, turn(Some(0)))
                    .unwrap_err()
                    .reason,
                reason
            );
            assert!(turns.unavailable(SlotId(0)));
            assert!(turns.push(SlotId(1), 0, turn(Some(0))).unwrap().is_some());
        }
    }
}
