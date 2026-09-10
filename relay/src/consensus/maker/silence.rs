//! The silence watch's per-session half: tracking when each slot's forwarded
//! prefix last advanced, naming the one slot holding its session up, and the
//! load state the heartbeat restates.

use super::*;

/// The slot the silence watch found holding up its session: the one whose turns
/// stopped reaching this relay's local clients before anyone else's did.
/// Produced by [`DecisionMaker::silent_slot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SilentSlot {
    pub slot: SlotId,
    /// How long ago the slot stopped: since its gap-free forwarded prefix last
    /// advanced, or — for a slot that has never advanced one — since the session
    /// started.
    pub silent_for: Duration,
    /// How much earlier this slot stopped than the next-earliest slot the
    /// session still requires — the whole margin the verdict rests on. In a real
    /// stall it is about the survivors' buffer depth: the turns they could still
    /// consume after the culprit's last one.
    pub lead: Duration,
}

/// When a slot stopped: the last time its gap-free forwarded prefix genuinely
/// advanced, or `session_started_at` for a slot that has never advanced one.
///
/// A slot that has forwarded nothing since the session began stopped at the
/// beginning, by definition, and that is the earliest stop time there is. The
/// fallback is deliberately the relay's own start latch rather than anything the
/// slot reports: a client that forwards no turns at all and delays saying its
/// game loop is running would otherwise carry a stop time later than the players
/// who did seed and then stalled waiting for it, and the watch would close one of
/// them instead.
pub(in crate::consensus) fn stopped_at(
    state: Option<&SlotState>,
    session_started_at: Instant,
) -> Instant {
    state
        .and_then(|state| state.last_forward_advance_at)
        .unwrap_or(session_started_at)
}

impl DecisionMaker {
    /// Records that `slot`'s gap-free prefix of forwarded turns advanced — that
    /// turns this relay had never delivered before went out to its local clients
    /// in order, closing no gap by fiat (see `mesh::Forwarded::prefix_advanced`,
    /// which decides what counts). This is the silence watch's only progress
    /// evidence, so `now` is the slot's stop clock being pushed forward.
    ///
    /// A slot with no live state here is not tracked: it left, or this relay has
    /// no link measurements for it yet, and either way the watch does not judge
    /// it.
    pub fn note_forward_advance(&mut self, slot: SlotId, now: Instant) {
        if let Some(state) = self.slots.get_mut(&slot) {
            state.last_forward_advance_at = Some(now);
        }
    }

    /// The slot whose turns stopped reaching this relay's local clients before
    /// any other slot's did — the one holding lockstep up, and whose link this
    /// relay should therefore close. A live QUIC link says nothing about whether
    /// the game behind it is still stepping: keepalives keep flowing from a hung
    /// game thread or a suspended process, and every other player is stalled
    /// behind it with no way out. Reported so the caller can close the link,
    /// after which the ordinary link-death path (departure record, drop hold,
    /// survivors' countdown) resolves the slot like any other lost client.
    ///
    /// **The verdict rests on complete knowledge of the session.** Naming a
    /// culprit is a claim about *every* participant lockstep still waits on, so
    /// each of them must resolve to a stop time this relay can vouch for. A
    /// participant it cannot account for is not a non-blocker — it is a hole in
    /// the evidence, and a hole names nobody. Everything below is that principle
    /// applied; none of it is an exception to it.
    ///
    /// Blame rests on one measurement and deliberately only one: the time each
    /// slot's gap-free forwarded prefix last genuinely advanced (see
    /// [`note_forward_advance`](Self::note_forward_advance)), falling back to the
    /// session's own start instant for a slot that has never advanced one. Every
    /// other per-slot quantity is the client's own choice — how many turns it
    /// sent, what frame they stamp, how far ahead their seqs run — so any of them
    /// can be padded by exactly the client this watch exists to catch. The
    /// forwarded prefix cannot be: it moves only when the turns below it actually
    /// arrived and went out, in order.
    ///
    /// That is what makes the *ordering* of stop times trustworthy. A client that
    /// withholds one turn while streaming higher seqs stops its own prefix dead at
    /// the gap however much it keeps sending, while its opponents go on consuming
    /// the turns it already sent until their buffers starve — so the honest slots'
    /// prefixes stop strictly later, and the earliest stopper is the slot the rest
    /// are waiting on. Flooding far-ahead seqs to force the forward gate to jump
    /// its prefix over a gap buys nothing either: a jumped prefix is excluded from
    /// counting as progress at the source, and freezes that slot's clock from then
    /// on.
    ///
    /// **The participants are the session descriptor's expected roster** — every
    /// slot the coordinator said this game is played by — not whichever slots this
    /// relay happens to hold state for. A roster slot with neither live state nor
    /// a departure record here has no stop time at all, and no verdict is
    /// available while one exists: two clients replaying into a session whose
    /// third player has yet to connect are stalled by that third player, and
    /// letting an absent participant contribute nothing would blame whichever of
    /// them stopped first. A session whose descriptor carried no roster (a
    /// standalone relay, a dev-injected descriptor) leaves the union of live and
    /// departed slots as the only participant set there is.
    ///
    /// **A participant that has not reported its game loop running has no clock
    /// either.** Lobby commands ride their own path and never reach the forward
    /// gate, but a client's pre-loop seed payloads — the initial-buffer turns it
    /// flushes right before its loop begins — do, so a slot can advance its
    /// forwarded prefix before it has simulated a single frame, while the players
    /// who finished loading sit waiting for its first simulated turn. Such
    /// advances measure traffic, not simulation progress, and the two are
    /// indistinguishable from here. So a
    /// slot with no start report is unknown and blocks, exactly like an
    /// unregistered roster slot; without that, the loaded players stalled behind a
    /// loader would be the earliest stoppers and one of them would be named. Only
    /// a slot's home receives that report, so the home shares it across the mesh
    /// (`SlotStarted`) and every relay serving the session answers from the same
    /// set.
    ///
    /// **A resumed session stands the watch down entirely.** On a fresh relay the
    /// forward gate bases every slot's prefix at seq 0, while a re-homed client's
    /// retained history legitimately begins above it — its retention cap discarded
    /// the low seqs long ago. At the gate those two are indistinguishable: an
    /// honest client whose coverage starts high looks exactly like one withholding
    /// its first turns, and its prefix never advances at all, so its clock sits at
    /// the session start forever. Forward-prefix clocks are therefore not evidence
    /// on a resumed session, and evidence that is not evidence names nobody.
    ///
    /// TODO(rp2-silence-rehome): restore eviction on resumed sessions by basing
    /// each origin's gate prefix, on a resumed session, at the lowest seq any
    /// *other* local client's resume cursor still needs from that origin — a
    /// client-claimed value taken only in the direction that asks for *more*
    /// replay, never less, so no client can shrink what it owes. With the gate
    /// anchored where the survivors actually resume, an honest re-homed client's
    /// prefix advances again and its clock means what it means anywhere else.
    ///
    /// **A decided leave stays a participant until the survivors have recovered
    /// from it.** A slot whose leave was decided is retired from the comparison
    /// only once every live participant's stop time is later than the instant this
    /// relay decided (or observed) that leave — never merely because the decision
    /// exists. The survivors' stalled clocks are explained by the departed slot
    /// right up until each of them demonstrably resumed after the directive was
    /// delivered and applied, and deciding a leave is not the same as the
    /// survivors recovering from one; retiring the slot at the decision would hand
    /// the blame straight to the players it stalled, who by then are all sitting
    /// past the window. The degenerate case is accepted deliberately: a survivor
    /// that genuinely hangs at the very moment another slot leaves keeps the
    /// departed slot in the comparison indefinitely and so is never named, which
    /// is the safe direction — the ordinary drop machinery still owns it.
    /// Retirement is one-way, so a clock that later moves backwards cannot put a
    /// long-gone slot back into the comparison.
    ///
    /// A participant is a *candidate* — a slot that may be named — when, on top of
    /// resolving to a stop time like everyone else:
    ///
    /// — this relay strictly homes it: only the home owns the slot's link and may
    ///   close it, and a peer relay's view of another home's slot is second-hand;
    /// — its connection is up, and it has neither a departure nor a decided leave —
    ///   anything else is already on its way out;
    /// — it has reported its game loop running. A loader can never be named. The
    ///   general rule reaches this first — an unreported slot is unknown, so no
    ///   verdict exists to name it in — and stating it here as well is what makes
    ///   "a loader is not a culprit" true of the candidate rule on its own terms,
    ///   rather than a coincidence of the order the checks run in;
    /// — it has not already been evicted for silence
    ///   ([`mark_silence_evicted`](Self::mark_silence_evicted)), so a slot whose
    ///   link is already closing is not re-reported every tick;
    /// — the whole session has been quiet for at least `window`: no participant's
    ///   prefix has advanced within it. Any advance is an unblocking event the
    ///   survivors may still be answering — a late turn from the slot everyone
    ///   waited on reaches them, they step, and their own turns follow a network
    ///   round-trip later — and in that gap the survivors' clocks are older than
    ///   the slot that just moved, so judging then would name a survivor for the
    ///   stall it is in the middle of leaving. A slot that genuinely hung after
    ///   an advance is named once the session has sat still for a window again.
    ///   This also means the candidate itself stopped at least `window` ago;
    /// — its link has been up at least `window`;
    /// — and it stopped *strictly* before every other participant. Ties evict
    ///   nobody: a session that stopped all at once has no victim to name, and a
    ///   slot with no other participant left to be earlier than is holding nobody
    ///   up.
    ///
    /// Only one slot can be strictly earliest, so only one is ever named.
    pub fn silent_slot(&mut self, now: Instant, window: Duration) -> Option<SilentSlot> {
        // The relay's own start latch, which is also the stop time of every slot
        // that has forwarded nothing since. Absent means nothing has begun.
        let session_started_at = self.started_at?;
        if self.resumed {
            if !self.resume_stand_down_logged {
                self.resume_stand_down_logged = true;
                tracing::debug!(
                    tenant = self.key.tenant.as_ref(),
                    session = self.key.session.0,
                    "silence watch stands down: a re-homed client's retained history can start \
                     above this relay's forward gate, so no slot's forwarded prefix is evidence",
                );
            }
            return None;
        }

        // The roster the coordinator named, or — for a descriptor that carried
        // none — everything this relay has ever held state for.
        let mut participants: Vec<SlotId> = if self.expected_slots.is_empty() {
            self.slots
                .keys()
                .chain(self.departures.keys())
                .copied()
                .collect::<HashSet<SlotId>>()
                .into_iter()
                .collect()
        } else {
            self.expected_slots.iter().copied().collect()
        };
        participants.retain(|slot| !self.recovered_leaves.contains(slot));
        participants.sort_unstable_by_key(|slot| slot.0);

        // Retire every decided leave the live participants have visibly moved
        // past. Their own stop times are the proof: a survivor that forwarded
        // something after the leave was decided has received and applied it.
        let live_stops: Vec<Instant> = participants
            .iter()
            .filter_map(|slot| self.slots.get(slot))
            .map(|state| stopped_at(Some(state), session_started_at))
            .collect();
        let recovered: Vec<SlotId> = participants
            .iter()
            .copied()
            .filter(|slot| {
                self.decided_leave_at
                    .get(slot)
                    .is_some_and(|decided| live_stops.iter().all(|stop| stop > decided))
            })
            .collect();
        for slot in recovered {
            self.recovered_leaves.insert(slot);
        }
        participants.retain(|slot| !self.recovered_leaves.contains(slot));

        // Complete knowledge or no verdict.
        let mut required: Vec<(SlotId, Instant)> = Vec::with_capacity(participants.len());
        for slot in participants {
            // A slot whose loop is not yet running can still advance its prefix
            // — its pre-loop seed payloads pass the forward gate — for reasons
            // that say nothing about its simulation. Its clock is not a stop
            // time until its game loop is known to be running.
            if !self.has_started(slot) {
                return None;
            }
            let stopped = match (self.slots.get(&slot), self.departures.get(&slot)) {
                (Some(state), _) => stopped_at(Some(state), session_started_at),
                // A departed slot's own state went with its departure record.
                (None, Some(departure)) => {
                    stopped_at(departure.slot_state.as_ref(), session_started_at)
                }
                // A participant this relay has never held state for has no stop
                // time to compare, and guessing one at either extreme would be
                // inventing evidence.
                (None, None) => return None,
            };
            required.push((slot, stopped));
        }

        // The session as a whole must have sat still for the window. A prefix
        // that advanced more recently than that is an unblocking event the other
        // participants may still be answering — the turn has to reach them and
        // their next step has to make it back — and until it has, their clocks
        // trail the slot that just moved through no fault of their own.
        let latest_advance = required.iter().map(|&(_, stopped)| stopped).max()?;
        if now.saturating_duration_since(latest_advance) < window {
            return None;
        }

        for &(slot, stopped_at) in &required {
            if !self.strictly_homes(slot)
                || !self.connection_is_up(slot)
                || !self.has_started(slot)
                || self.departures.contains_key(&slot)
                || self.decided_leaves.contains_key(&slot)
                || self.silence_evicted.contains(&slot)
            {
                continue;
            }
            // Implied by the session-wide quiet above (this slot stopped no later
            // than the latest advance), kept as the reported measure.
            let silent_for = now.saturating_duration_since(stopped_at);
            // A link that just came up is owed the whole window before it may be
            // closed: it has had no chance to forward anything yet. The grace is
            // time and nothing else — the slot's stop time stays where its
            // forwarding actually stopped — because a redial that moved the stop
            // time forward would make the slot that hung the freshest in the
            // session, and hand the blame to the players it stalled, who really
            // did stop earlier and would then be the earliest stoppers left. A
            // healthy replacement needs no more than the grace: its first
            // forwarded turn moves its clock by itself.
            let connection_up_at = self
                .slots
                .get(&slot)
                .and_then(|state| state.connection_up_at);
            if connection_up_at.is_some_and(|up| now.saturating_duration_since(up) < window) {
                continue;
            }
            // The margin over the next-earliest stopper. It stays absent when
            // any other participant stopped no later than this one — a tie, or
            // an earlier stop, is no verdict — and when there is no other
            // participant to be earlier than at all.
            let mut lead: Option<Duration> = None;
            for &(other, other_stopped_at) in &required {
                if other == slot {
                    continue;
                }
                let Some(gap) = other_stopped_at
                    .checked_duration_since(stopped_at)
                    .filter(|gap| !gap.is_zero())
                else {
                    lead = None;
                    break;
                };
                lead = Some(lead.map_or(gap, |lead| lead.min(gap)));
            }
            if let Some(lead) = lead {
                return Some(SilentSlot {
                    slot,
                    silent_for,
                    lead,
                });
            }
        }
        None
    }

    /// Marks `slot` as evicted for silence, so it is neither re-reported by
    /// [`silent_slot`](Self::silent_slot) nor readmitted if it re-dials (see
    /// the `silence_evicted` field). Idempotent.
    pub fn mark_silence_evicted(&mut self, slot: SlotId) {
        self.silence_evicted.insert(slot);
    }

    /// Records the wall-clock instant this relay learned the session started, for
    /// the heartbeat to restate — its own coverage latch on the authority, the
    /// adoption of the authority's directive on a peer. First write wins: the
    /// latch is a one-shot, and a later authority's own latch must not move an
    /// instant already reported.
    pub fn note_started_at_ms(&mut self, started_at_ms: u64) {
        self.started_at_ms.get_or_insert(started_at_ms);
    }

    /// This session's retained load state, as every heartbeat carries it.
    pub fn load_state(&self) -> RetainedLoadState {
        RetainedLoadState {
            ever_connected: sorted_slots(&self.connected_slots),
            started: sorted_slots(&self.started_slots),
            started_at_ms: self.started_at_ms,
        }
    }
}
