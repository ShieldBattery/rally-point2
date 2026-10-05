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

    /// This relay's home slots' lead figures in `key`'s session since the previous call, and the
    /// clock's stopped time, for the flight recorder's sample row (see
    /// [`DecisionMaker::take_lead_samples`]). `None` outside a rollback session, or with no maker
    /// here.
    pub fn take_lead_samples(&self, key: &SessionKey) -> Option<LeadSamples> {
        self.lock().get_mut(key)?.take_lead_samples()
    }

    /// The shared count `key`'s session stamps as `turns_complete` on every packet to this relay's
    /// own clients (see [`DecisionMaker::turns_complete_handle`]), or `None` before the session
    /// has a decision-maker here.
    pub fn turns_complete_handle(
        &self,
        key: &SessionKey,
    ) -> Option<std::sync::Arc<std::sync::atomic::AtomicU64>> {
        Some(self.lock().get(key)?.turns_complete_handle())
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
    /// [`DecisionMaker::adopt_session_clock`]). Records the adoption's anchoring and any growth
    /// of the stopped time in the flight recording.
    #[must_use]
    pub fn adopt_session_clock(
        &self,
        key: &SessionKey,
        frame: &SessionClockFrame,
        received_at: Instant,
        mesh_rtt_us: u32,
    ) -> Vec<(SlotId, LeadReport)> {
        let (reports, events) = match self.lock().get_mut(key) {
            Some(maker) => {
                let mark = maker.clock_mark();
                let reports = maker.adopt_session_clock(frame, received_at, mesh_rtt_us);
                (reports, maker.clock_events(mark, true))
            }
            None => return Vec::new(),
        };
        for event in events.into_iter().flatten() {
            self.record_event(key, event);
        }
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
