//! A rollback session's clock on the maker: anchoring and stopping it on the authority, merging
//! every other relay's copy into this one, and measuring this relay's home slots against it.

use super::*;

use rally_point_proto::rollback::LOCKSTEP_START_STEPS;

/// What moving the authority's session clock on calls for: a frame to send every other relay
/// when the clock changed in a way they should hear of at once, and reports to push down this
/// relay's own home slots.
#[derive(Debug, Clone, PartialEq)]
pub struct ClockUpdate {
    /// The clock for every other relay to merge at once, when it was just anchored or a stop
    /// just ended.
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

/// The furthest count of confirmable turns at which an authority that saw the lockstep start
/// completed still anchors the clock: a slow player's turns can complete the start several steps
/// at once, but a count further on than two lockstep starts' worth is a relay that is only now
/// hearing of a session long under way.
const LATEST_ANCHORING_COUNT: u64 = 2 * LOCKSTEP_START_STEPS;

/// A duration in whole microseconds, saturating.
fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

impl DecisionMaker {
    /// Measures `slot`'s turn with seq `seq`, which first arrived on this relay's client edge at
    /// `received_at`, and returns the slot's lead report when one is due. A turn whose deadline
    /// isn't final yet is measured once the clock moves far enough on: on the authority as more
    /// turns become confirmable, elsewhere as copies of the clock arrive
    /// ([`merge_session_clock`](Self::merge_session_clock)). Nothing outside a rollback session,
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
    /// when the anchor came from another relay's copy), and a growth of its stopped time. Stops
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

    /// This relay's copy of the session clock as it goes to the other relays, which merge it: on
    /// the heartbeat, to a relay that joins after the anchor, and after an authority change. Every
    /// relay sends its copy, so a stop isn't lost while any relay knows of it. `None` before the
    /// anchor, and outside a rollback session.
    pub fn session_clock_frame(&self, now: Instant) -> Option<SessionClockFrame> {
        if !self.rollback_enabled {
            return None;
        }
        self.clock.to_frame(now)
    }

    /// Merges another relay's copy of the session clock, which arrived at `received_at` over a
    /// mesh link with a round trip of `mesh_rtt_us` (the later deadline of the two for each step,
    /// except one this relay already holds as final), measuring the turns waiting for deadlines it
    /// made final. Returns the reports to push down this relay's
    /// home slots: every measured slot's when the clock's stopped time grew, so each client moves
    /// its schedule by the stop at once, and otherwise those the newly measured turns made due.
    /// The authority merges too: a copy can know of a stop that a former authority made and that
    /// never reached this relay.
    #[must_use]
    pub fn merge_session_clock(
        &mut self,
        frame: &SessionClockFrame,
        received_at: Instant,
        mesh_rtt_us: u32,
    ) -> Vec<(SlotId, LeadReport)> {
        if !self.rollback_enabled {
            return Vec::new();
        }
        let pause_before = self.clock.pause();
        if !self.clock.merge(frame, received_at, mesh_rtt_us) {
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
            // Only an authority that saw the lockstep start completed anchors the clock from its
            // own view. One that missed it (promoted, or joined, later) waits for another relay's
            // copy instead: the clock may have stopped since, and an anchor of its own would
            // carry that stopped time no copy's stops could line up with.
            if before >= LOCKSTEP_START_STEPS
                || !(LOCKSTEP_START_STEPS..=LATEST_ANCHORING_COUNT).contains(&after)
            {
                return None;
            }
            // The turn that completed the lockstep start arrived just now, so it is the one due
            // now. Every client waited for every turn up to here, so this is when the slowest
            // player's start arrived, and nobody is asked to be earlier than the session has shown
            // it can be.
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
