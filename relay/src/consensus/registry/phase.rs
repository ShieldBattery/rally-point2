//! Send-phase entry points: feeding one client-edge arrival to the controller,
//! reading back a slot's commanded delay for a connect-time re-push, and
//! releasing a command's fence on the client's acknowledgement.

use super::*;

impl DecisionMakers {
    /// Folds one client-edge arrival into `key`'s send-phase controller and runs a
    /// control iteration if one is due, returning the slots whose commanded delay
    /// changed — for the caller to fan out as `PhaseDirective`s (see
    /// [`DecisionMaker::ingest_arrival_phase`]). Empty on almost every call: the
    /// controller evaluates on its own sparse schedule, before the session starts
    /// nothing is recorded, and when no maker exists there is nothing to do.
    /// `received_at` is the instant the caller pulled the packet off the socket —
    /// stamped there, not here, so validation, fan-out, and this self's own
    /// lock contention never leak into the measured arrival phase.
    #[must_use]
    pub fn ingest_arrival_phase(
        &self,
        key: &SessionKey,
        slot: SlotId,
        seq: u64,
        received_at: Instant,
    ) -> Vec<(SlotId, u32)> {
        match self.lock().get_mut(key) {
            Some(maker) => maker.ingest_arrival_phase(slot, seq, received_at),
            None => Vec::new(),
        }
    }

    /// The send-phase delay `key`'s controller last commanded for `slot`, for the
    /// direct re-push a slot gets on (re)connecting after corrections were issued.
    /// `None` when none was ever issued, or when no maker exists.
    pub fn commanded_phase_delay(&self, key: &SessionKey, slot: SlotId) -> Option<u32> {
        self.lock().get(key)?.commanded_phase_delay(slot)
    }

    /// Releases `slot`'s send-phase command fence on the client's acknowledgement
    /// that it adopted `delay_us` (see [`DecisionMaker::note_phase_applied`]). A
    /// no-op when the echo is stale or no maker exists.
    pub fn note_phase_applied(&self, key: &SessionKey, slot: SlotId, delay_us: u32) {
        let now = Instant::now();
        if let Some(maker) = self.lock().get_mut(key) {
            maker.note_phase_applied(slot, delay_us, now);
        }
    }
}
