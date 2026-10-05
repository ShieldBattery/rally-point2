//! A rollback session's clock on the maker: anchoring and stopping it on the authority, adopting
//! the authority's elsewhere, and measuring this relay's home slots against it.

use super::*;

use rally_point_proto::rollback::LOCKSTEP_START_STEPS;

/// What moving the authority's session clock on calls for: a frame to send every other relay
/// when the clock changed in a way they should hear of at once, and reports to push down this
/// relay's own home slots.
#[derive(Debug, Clone, PartialEq)]
pub struct ClockUpdate {
    /// The clock as the other relays adopt it, when it was just anchored or a stop just ended.
    pub frame: Option<SessionClockFrame>,
    /// Every measured home slot's report when a stop just ended, carrying the clock's new stopped
    /// time; otherwise the reports due from turns whose deadlines just became final.
    pub reports: Vec<(SlotId, LeadReport)>,
}

/// The session clock as it stood before a change, for telling afterwards which flight events the
/// change earns (see [`DecisionMaker::clock_events`]).
#[derive(Debug, Clone, Copy)]
pub(in crate::consensus) struct ClockMark {
    anchored: bool,
    pause: Duration,
}

/// A duration in whole microseconds, saturating.
fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

impl DecisionMaker {
    /// Measures `slot`'s turn with seq `seq`, which first arrived on this relay's client edge at
    /// `received_at`, and returns the slot's lead report when one is due. A turn whose deadline
    /// isn't final yet is measured once the clock moves far enough on: on the authority as more
    /// turns become confirmable, elsewhere as its frames arrive
    /// ([`adopt_session_clock`](Self::adopt_session_clock)). Nothing outside a rollback session,
    /// before the clock is anchored, or for a turn of the lockstep start.
    ///
    /// The caller must feed only this relay's own home slots' client-edge arrivals: a mesh copy
    /// times another relay's hop, not the player's.
    #[must_use]
    pub fn note_lead_arrival(
        &mut self,
        slot: SlotId,
        seq: u64,
        received_at: Instant,
    ) -> Option<LeadReport> {
        if !self.rollback_enabled {
            return None;
        }
        self.lead.note(slot, seq, received_at, &self.clock)
    }

    /// This relay's home slots' lead figures since the previous call, and the clock's stopped time,
    /// for the flight recorder's sample row. Each slot starts its next interval. `None` outside a
    /// rollback session.
    pub fn take_lead_samples(&mut self) -> Option<LeadSamples> {
        if !self.rollback_enabled {
            return None;
        }
        Some(LeadSamples {
            clock_pause_us: self.clock.is_anchored().then(|| micros(self.clock.pause())),
            slots: self.lead.take_samples(),
        })
    }

    /// The session clock as it stands, to compare against after a change (see
    /// [`clock_events`](Self::clock_events)).
    pub(in crate::consensus) fn clock_mark(&self) -> ClockMark {
        ClockMark {
            anchored: self.clock.is_anchored(),
            pause: self.clock.pause(),
        }
    }

    /// The flight events the session clock's change since `mark` earns: its anchoring (`adopted`
    /// when the anchor came from the authority's clock), and a growth of its stopped time. Stops
    /// are recorded at most [`MAX_CLOCK_STOP_EVENTS`] times per session, so a session that keeps
    /// stopping cannot spend its event ring on them.
    pub(in crate::consensus) fn clock_events(
        &mut self,
        mark: ClockMark,
        adopted: bool,
    ) -> [Option<FlightEvent>; 2] {
        let anchored = self
            .clock
            .anchor_step()
            .filter(|_| !mark.anchored)
            .map(|anchor_step| FlightEvent::SessionClockAnchored {
                anchor_step,
                adopted,
            });
        let stopped =
            if self.clock.pause() > mark.pause && self.clock_stop_events < MAX_CLOCK_STOP_EVENTS {
                self.clock_stop_events += 1;
                Some(FlightEvent::SessionClockStopped {
                    pause_us: micros(self.clock.pause()),
                })
            } else {
                None
            };
        [anchored, stopped]
    }

    /// `slot`'s current lead report, for the re-send a slot gets when it (re)connects.
    pub fn lead_report(&self, slot: SlotId) -> Option<LeadReport> {
        self.lead.report(slot, self.clock.pause())
    }

    /// The session clock as the authority sends it: to a relay that joins after the anchor, after
    /// an authority change, and on the heartbeat that keeps every relay's copy of the limit
    /// current. `None` on any other relay, or before the anchor.
    pub fn session_clock_frame(&self, now: Instant) -> Option<SessionClockFrame> {
        if !self.rollback_enabled || !self.is_authority() {
            return None;
        }
        self.clock.to_frame(now)
    }

    /// Adopts the authority's session clock from a frame that arrived at `received_at` over a mesh
    /// link with a round trip of `mesh_rtt_us`, measuring the turns waiting for deadlines the frame
    /// made final. Returns the reports to push down this relay's home slots: every measured slot's
    /// when the clock's stopped time grew, so each client moves its schedule by the stop at once,
    /// and otherwise those the newly measured turns made due. The authority ignores the frame: its
    /// own clock is the original (a frame from a former authority can still be in flight after a
    /// promotion).
    #[must_use]
    pub fn adopt_session_clock(
        &mut self,
        frame: &SessionClockFrame,
        received_at: Instant,
        mesh_rtt_us: u32,
    ) -> Vec<(SlotId, LeadReport)> {
        if !self.rollback_enabled || self.is_authority() {
            return Vec::new();
        }
        let pause_before = self.clock.pause();
        if !self.clock.adopt(frame, received_at, mesh_rtt_us) {
            return Vec::new();
        }
        let stopped = self.clock.pause() > pause_before;
        self.lead.settle(&self.clock, stopped)
    }

    /// Moves the authority's clock on as the newest turn it can confirm for every player advances
    /// from count `before` to count `after` at `now`: anchors it once the lockstep start is
    /// confirmable, and afterwards moves its limit on, keeping the stop if it had stood still at
    /// the old one, and measures the turns waiting for deadlines that are now final. Returns what
    /// that calls for, if anything.
    pub(in crate::consensus) fn advance_clock(
        &mut self,
        before: u64,
        after: u64,
        now: Instant,
    ) -> Option<ClockUpdate> {
        if after <= before || !self.is_authority() {
            return None;
        }
        if !self.clock.is_anchored() {
            if after < LOCKSTEP_START_STEPS {
                return None;
            }
            // The turn that completed the count arrived just now, so it is the one due now. Every
            // client waited for every turn up to here, so this is when the slowest player's start
            // arrived, and nobody is asked to be earlier than the session has shown it can be.
            self.clock.anchor(after - 1, now);
            return Some(ClockUpdate {
                frame: self.clock.to_frame(now),
                reports: Vec::new(),
            });
        }
        // `before` turns of every player were confirmable and `after` are, so the newest went
        // from seq `before - 1` to seq `after - 1`.
        let stopped = self
            .clock
            .note_confirmable(before.checked_sub(1), after - 1, now);
        let reports = self.lead.settle(&self.clock, stopped);
        if !stopped && reports.is_empty() {
            return None;
        }
        Some(ClockUpdate {
            frame: if stopped {
                self.clock.to_frame(now)
            } else {
                None
            },
            reports,
        })
    }
}
