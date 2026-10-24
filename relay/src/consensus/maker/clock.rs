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

/// How long an authority that didn't start the session waits, without the clock and without any
/// relay's copy of it, before it anchors the clock itself: four of the quarter-second heartbeats
/// every relay sends its copy on, so only a session where no reachable relay has the clock is
/// anchored twice.
pub const CLOCK_ANCHOR_QUIET: Duration = Duration::from_secs(1);

/// A duration in whole microseconds, saturating.
fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

impl DecisionMaker {
    /// Enables clock recovery only when this maker is created for an already running
    /// session. A surviving maker retains its complete-prefix clock progression.
    pub(in crate::consensus) fn recover_clock(&mut self) {
        if self.rollback_enabled {
            self.clock_progress = Some(ClockProgress::default());
        }
    }

    /// Folds one actually forwarded turn into the session's progress. Only a proven
    /// complete prefix advances silence and state-hash bookkeeping. Clock recovery
    /// separately follows a contiguous suffix above a peer-confirmed baseline.
    pub fn note_forwarded_turn(
        &mut self,
        slot: SlotId,
        seq: u64,
        forwarded: Option<u64>,
        now: Instant,
    ) -> Option<ClockUpdate> {
        let update = forwarded.and_then(|count| {
            self.note_forward_advance(slot, now);
            self.note_forwarded_turns(slot, count, now)
        });
        if !self.expected_slots.contains(&slot) {
            return update;
        }
        let Some(progress) = &mut self.clock_progress else {
            return update;
        };
        if progress.note(slot, seq) {
            tracing::warn!(
                tenant = self.key.tenant.as_ref(),
                session = self.key.session.0,
                slot = slot.0,
                seq,
                next_needed = progress.count(slot),
                "clock recovery pending-turn limit exceeded; timing progress may stall",
            );
        }
        let (before, after) = self.recovered_clock_progress();
        self.advance_clock(before, after, now)
    }

    /// Consumes the minimum clock count of the remaining players. Keeping the previous
    /// minimum also accounts for departures without skipping a stop at the old limit.
    fn recovered_clock_progress(&mut self) -> (u64, u64) {
        let before = self.clock_confirmed;
        let after = self
            .clock_progress
            .as_ref()
            .and_then(|progress| {
                self.expected_slots
                    .iter()
                    .filter(|slot| {
                        !self.observers.contains(slot) && !self.departures.contains_key(slot)
                    })
                    .map(|&slot| progress.count(slot))
                    .min()
            })
            .unwrap_or(before)
            .max(before);
        self.clock_confirmed = after;
        (before, after)
    }

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
        let changed = self.clock.merge(frame, received_at, mesh_rtt_us);
        if self.clock.anchor_step() != Some(frame.anchor_step) {
            return Vec::new();
        }
        self.lead.anchor_rehomes(frame.final_through);
        if let Some(progress) = &mut self.clock_progress {
            // A clock limit includes slack beyond the turns the former authority
            // confirmed. Only that confirmed prefix can seed the suffix, never the
            // slack itself or a client's resume cursor. Use the received frame so a
            // copy of our own clock cannot manufacture progress on each heartbeat.
            if let Some(count) = frame
                .final_through
                .checked_sub(STALL_SLACK_STEPS)
                .and_then(|seq| seq.checked_add(1))
            {
                progress.seed(count);
                let (before, after) = self.recovered_clock_progress();
                if after > before && self.is_authority() {
                    // A replay may precede its clock copy. Consume that retained suffix
                    // now; the regular heartbeat distributes any stop this records.
                    self.clock
                        .note_confirmable(before.checked_sub(1), after - 1, received_at);
                }
            }
        } else if !changed {
            return Vec::new();
        }
        let stopped = self.clock.pause() > pause_before;
        self.lead.settle(&self.clock, stopped)
    }

    /// Whether this relay, the authority with no clock yet, anchors it from its own view at `now`.
    ///
    /// The clock has one anchor, and its copies' stopped times only line up against that one. The
    /// authority that started the session (and has been the authority since) can be sure no other
    /// relay anchored it, so it anchors once the lockstep start is confirmable. Any other
    /// authority (promoted, or a relay that took the session over) may be missing a turn of the
    /// lockstep start that the relay that started the session had long ago, and an anchor of its
    /// own would carry whatever stopped time the clock has had since. So it waits for another
    /// relay's copy, which brings the anchor, and anchors itself only once it has gone
    /// [`CLOCK_ANCHOR_QUIET`] without one: then no reachable relay has the clock, so no stop
    /// exists yet either.
    fn may_anchor_clock(&mut self, now: Instant) -> bool {
        if self.started_session_as_authority {
            return true;
        }
        let since = *self.unanchored_authority_since.get_or_insert(now);
        now.saturating_duration_since(since) >= CLOCK_ANCHOR_QUIET
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
            if after < LOCKSTEP_START_STEPS || !self.may_anchor_clock(now) {
                return None;
            }
            // The newest confirmable turn arrived just now, so it is the one due now. Every client
            // waited for every turn of the lockstep start, so on the authority that started the
            // session this is when the slowest player's start arrived, and nobody is asked to be
            // earlier than the session has shown it can be.
            self.clock.anchor(after - 1, now);
            if let Some(final_through) = self.clock.final_through() {
                self.lead.anchor_rehomes(final_through);
            }
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
