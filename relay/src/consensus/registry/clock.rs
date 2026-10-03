//! A rollback session's clock and lead reports: measuring home slots' arrivals, the authority's
//! clock changes, another relay adopting them, and the re-sends a (re)connect or a join gets.

use super::*;

impl DecisionMakers {
    /// Measures `slot`'s turn with seq `seq` against `key`'s session clock and returns the slot's
    /// lead report when one is due (see [`DecisionMaker::note_lead_arrival`]). `received_at` is the
    /// instant the caller pulled the packet off the socket, stamped there so validation and this
    /// registry's own lock never leak into the measured arrival. `None` on almost every call, and
    /// always outside a rollback session.
    #[must_use]
    pub fn note_lead_arrival(
        &self,
        key: &SessionKey,
        slot: SlotId,
        seq: u64,
        received_at: Instant,
    ) -> Option<LeadReport> {
        self.lock()
            .get_mut(key)?
            .note_lead_arrival(slot, seq, received_at)
    }

    /// `slot`'s current lead report in `key`'s session, for the re-send a slot gets when it
    /// (re)connects.
    pub fn lead_report(&self, key: &SessionKey, slot: SlotId) -> Option<LeadReport> {
        self.lock().get(key)?.lead_report(slot)
    }

    /// `key`'s session clock as the authority sends it to a relay that joins after the anchor.
    /// `None` on any other relay, before the anchor, and outside a rollback session.
    pub fn session_clock_frame(&self, key: &SessionKey) -> Option<SessionClockFrame> {
        self.lock().get(key)?.session_clock_frame(Instant::now())
    }

    /// Adopts the authority's session clock for `key` from a frame that arrived at `received_at`
    /// over a mesh link with a round trip of `mesh_rtt_us`, returning the lead reports to push
    /// down this relay's home slots when the clock's stopped time grew (see
    /// [`DecisionMaker::adopt_session_clock`]).
    #[must_use]
    pub fn adopt_session_clock(
        &self,
        key: &SessionKey,
        frame: &SessionClockFrame,
        received_at: Instant,
        mesh_rtt_us: u32,
    ) -> Vec<(SlotId, LeadReport)> {
        let reports = match self.lock().get_mut(key) {
            Some(maker) => maker.adopt_session_clock(frame, received_at, mesh_rtt_us),
            None => return Vec::new(),
        };
        if !reports.is_empty() {
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                pause_us = frame.pause_us,
                "session clock stopped longer on the authority; re-sending lead reports",
            );
        }
        reports
    }

    /// Logs a change the authority made to `key`'s session clock.
    pub(in crate::consensus) fn log_clock_update(key: &SessionKey, update: &ClockUpdate) {
        if update.reports.is_empty() && update.frame.pause_us == 0 {
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                anchor_step = update.frame.anchor_step,
                "anchored the session clock",
            );
        } else {
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                pause_us = update.frame.pause_us,
                "session clock stopped while the session waited on turns",
            );
        }
    }
}
