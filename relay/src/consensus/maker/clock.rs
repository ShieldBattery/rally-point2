//! A rollback session's clock on the maker: anchoring and stopping it on the authority, adopting
//! the authority's elsewhere, and measuring this relay's home slots against it.

use super::*;

use rally_point_proto::rollback::LOCKSTEP_START_STEPS;

/// A change to the session clock the authority made, for its caller to send to every other relay
/// and to push the carried reports down this relay's own home slots.
#[derive(Debug, Clone, PartialEq)]
pub struct ClockUpdate {
    /// The clock as the other relays adopt it.
    pub frame: SessionClockFrame,
    /// A report for every home slot measured here, carrying the clock's new stopped time and no
    /// lateness, since each slot's window starts over (none when the clock was only just
    /// anchored).
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
    /// `received_at`, and returns the slot's lead report when one is due. Nothing outside a
    /// rollback session, before the clock is anchored, or for a turn of the lockstep start.
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
        let lateness_us = self.clock.lateness_us(seq, received_at)?;
        self.lead.note(slot, seq, lateness_us, self.clock.pause())
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

    /// The session clock as the authority sends it to a relay that joins after the anchor. `None`
    /// on any other relay, or before the anchor.
    pub fn session_clock_frame(&self, now: Instant) -> Option<SessionClockFrame> {
        if !self.rollback_enabled || !self.is_authority() {
            return None;
        }
        self.clock.to_frame(now)
    }

    /// Adopts the authority's session clock from a frame that arrived at `received_at` over a mesh
    /// link with a round trip of `mesh_rtt_us`, returning the reports to push down this relay's
    /// home slots when the clock's stopped time grew (each slot's window starting over, since a
    /// turn that arrived before the frame was measured against the clock from before the stop).
    /// The authority ignores the frame: its own
    /// clock is the original (a frame from a former authority can still be in flight after a
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
        if !self.clock.adopt(frame, received_at, mesh_rtt_us) || self.clock.pause() == pause_before
        {
            return Vec::new();
        }
        self.lead.restart(self.clock.pause())
    }

    /// Moves the authority's clock on as the newest turn it can confirm for every player advances
    /// from count `before` to count `after` at `now`: anchors it once the lockstep start is
    /// confirmable, and afterwards stops it for any time it ran too far past what was confirmable.
    /// Returns the change for the other relays and this relay's home slots, if there was one.
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
                frame: self.clock.to_frame(now)?,
                reports: Vec::new(),
            });
        }
        // `before` turns of every player were confirmable, so the newest was seq `before - 1`.
        if before == 0 || !self.clock.note_confirmable_advance(before - 1, now) {
            return None;
        }
        Some(ClockUpdate {
            frame: self.clock.to_frame(now)?,
            reports: self.lead.restart(self.clock.pause()),
        })
    }
}
