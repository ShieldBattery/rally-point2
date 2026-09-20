//! The send-phase controller's seam on the maker: folding one client-edge
//! arrival in, reading back what a slot was last commanded, and releasing a
//! command's fence when the client acknowledges it.

use super::*;

impl DecisionMaker {
    /// Folds one client-edge arrival into the send-phase controller and runs a
    /// control iteration if one is due, returning the slots whose commanded
    /// delay changed (usually none — the controller self-gates on its own
    /// schedule). Arrivals before the session starts are ignored: pre-start
    /// traffic flows at setup cadence, not the turn cadence a phase lives in.
    ///
    /// The caller must feed only this relay's own client-edge receipts, and
    /// only packets that first-delivered exactly one turn — a mesh-forwarded
    /// copy times another relay's hop, and a catch-up burst times the
    /// recovery, neither the sender's phase (see
    /// [`PhaseController::note_arrival`](crate::consensus::phase::PhaseController::note_arrival)).
    #[must_use]
    pub fn ingest_arrival_phase(
        &mut self,
        slot: SlotId,
        seq: u64,
        now: Instant,
    ) -> Vec<(SlotId, u32)> {
        if !self.started {
            return Vec::new();
        }
        self.phase.note_arrival(slot, seq, now);
        let corrections = self.phase.evaluate(now);
        if !corrections.is_empty() {
            tracing::info!(
                tenant = self.key.tenant.as_ref(),
                session = self.key.session.0,
                corrections = corrections.len(),
                span_us = self.phase.last_span_us(),
                issued_total = self.phase.corrections_issued(),
                "issuing send-phase corrections",
            );
        }
        corrections
    }

    /// The send-phase delay `slot` was last commanded, if corrections were
    /// ever issued for it — the value to re-push when it (re)connects.
    pub fn commanded_phase_delay(&self, slot: SlotId) -> Option<u32> {
        self.phase.commanded(slot)
    }

    /// Releases `slot`'s send-phase command fence on its acknowledgement (see
    /// [`PhaseController::note_applied`](crate::consensus::phase::PhaseController::note_applied)).
    pub fn note_phase_applied(&mut self, slot: SlotId, delay_us: u32, now: Instant) {
        self.phase.note_applied(slot, delay_us, now);
    }
}
