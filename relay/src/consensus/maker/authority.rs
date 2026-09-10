//! Frame observation and the authority verdict: folding each validated turn's
//! claimed frame into the session coordinate, and taking or losing the
//! decision-making role when the injected verdict changes.

use super::*;

impl DecisionMaker {
    /// Records a `game_frame_count` observed on one of `slot`'s validated
    /// turns. Monotonic per slot -- an older frame arriving out of order
    /// doesn't move the observation backward.
    ///
    /// A departed slot is ignored: its final turns can still be in flight across
    /// the mesh when the departure lands, and re-creating its entry here would
    /// resurrect the frozen frame that pins the session coordinate. The
    /// departure record already captured the home relay's complete view of the
    /// slot's last frame (every turn was observed at its home before the link
    /// ended), so a late copy carries nothing new.
    pub fn observe_frame(&mut self, slot: SlotId, frame: GameFrameCount) {
        if self.departures.contains_key(&slot) {
            return;
        }
        let state = self.slots.entry(slot).or_default();
        if state.frame.is_none_or(|current| frame > current) {
            state.frame = Some(frame);
        }
    }

    /// The seq-aware sibling of [`observe_frame`](Self::observe_frame): records the
    /// same monotone per-slot frame **and** appends `(seq, frame)` to the slot's
    /// bounded `frame_history`, so a leave decided
    /// later can clamp its apply frame to a survivor-reachable ceiling (see
    /// `reachable_frame`). **Every production
    /// frame-observation on the leave path must go through this**, not the
    /// seq-less `observe_frame`, or the clamp has no history to work from and a
    /// slot's inflated `game_frame_count` could schedule a leave past a
    /// survivor-reachable frame. `observe_frame` is retained only for tests that
    /// don't exercise the leave-frame clamp.
    ///
    /// A departed slot is ignored, exactly as in `observe_frame`.
    ///
    /// Returns the slot's prior high-water mark when this stamp is **below** it
    /// at a **higher** seq than any framed turn seen before — a tripwire, not a
    /// correction. A client stamps its executable-turn index, which only
    /// advances once its game loop is stepping, so an honest counter can never
    /// produce that ordering: it means the counter restarted underneath the
    /// stamps (a turn stamped before the loop began, when the index still held
    /// its lobby-era value, or a hostile stamp). The observation is deliberately
    /// left uncorrected — the slot's frame stays at the high-water mark and the
    /// history keeps the earlier entries — because lowering a slot's frame on
    /// its own say-so is the inflation lever in reverse; the point is to make
    /// the condition visible, since a frame-scheduled leave derived from that
    /// mark can land past the frame survivors stall at. Reported once per slot.
    /// Out-of-order arrival (a lower seq after a higher one) never trips it.
    pub fn observe_turn_frame(
        &mut self,
        slot: SlotId,
        seq: u64,
        frame: GameFrameCount,
    ) -> Option<FrameRegression> {
        if self.departures.contains_key(&slot) {
            return None;
        }
        // Only the window back to `frontier − buffer_max` is ever consulted; keep
        // a little more than the buffer depth so the fastest survivor's history
        // still reaches the threshold turn even under a bit of reordering.
        let cap = (self.bounds.max as usize).saturating_add(4).max(8);
        let state = self.slots.entry(slot).or_default();
        let regression = match (state.newest_framed_seq, state.frame) {
            (Some(newest), Some(prior))
                if seq > newest && frame < prior && !state.frame_regression_reported =>
            {
                state.frame_regression_reported = true;
                Some(FrameRegression {
                    prior_frame: prior.0,
                })
            }
            _ => None,
        };
        if state.newest_framed_seq.is_none_or(|newest| seq > newest) {
            state.newest_framed_seq = Some(seq);
        }
        if state.frame.is_none_or(|current| frame > current) {
            state.frame = Some(frame);
        }
        state.frame_history.push_back((seq, frame.0));
        while state.frame_history.len() > cap {
            state.frame_history.pop_front();
        }
        regression
    }

    /// The reachability ceiling for a leave's apply frame: the highest game frame
    /// **every surviving slot has provably executed**, or `None` when no survivor
    /// has framed history yet (lobby / the game's very first turns). Computed by
    /// the departing slot's home relay and carried in the `SlotDeparted` record so
    /// every relay clamps to the identical value (see [`decide_leave`] and the
    /// `reachable_frame` field on [`Departure`]).
    ///
    /// A turn stamped at transport seq `s` is provably executed once the session
    /// advanced `buffer_max` turns past `s`. So with `frontier_turn` the leading
    /// seq across survivors and `threshold = frontier_turn − buffer_max`
    /// (saturating, so the game's first turns yield the earliest framed floor
    /// rather than nothing), each survivor's proven-executed frame is the highest
    /// it stamped at seq ≤ `threshold`; the ceiling is the **minimum** across
    /// survivors, so all of them can reach it. Counting is in **turns**, never
    /// frames, so no frames-per-turn assumption enters. Excludes the departing
    /// slot (its own claim must not raise its leave's ceiling) and any slot with
    /// no framed history (it constrains nothing and will catch up).
    pub(in crate::consensus) fn reachable_frame(&self, departing: SlotId) -> Option<u32> {
        let buffer_max = u64::from(self.bounds.max);
        let frontier_turn = self
            .slots
            .iter()
            .filter(|(slot, _)| **slot != departing)
            .filter_map(|(_, s)| s.frame_history.back().map(|(seq, _)| *seq))
            .max()?;
        let threshold = frontier_turn.saturating_sub(buffer_max);
        let mut ceiling: Option<u32> = None;
        for (slot, s) in &self.slots {
            if *slot == departing || s.frame_history.is_empty() {
                continue;
            }
            // Highest frame proven executed (stamped at/before the threshold
            // turn). A survivor that only started framing after the threshold has
            // no proven frame yet; fall back to its earliest recorded frame — a
            // low, still-reachable bound — rather than abandoning the clamp
            // (which would reopen the inflation stall in the game's first turns).
            let executed = s
                .frame_history
                .iter()
                .filter(|(seq, _)| *seq <= threshold)
                .map(|(_, frame)| *frame)
                .max()
                .or_else(|| s.frame_history.front().map(|(_, frame)| *frame))?;
            ceiling = Some(ceiling.map_or(executed, |c| c.min(executed)));
        }
        ceiling
    }

    /// Records a directive this relay forwarded on behalf of the session's
    /// authority. Keeps `decision_seq` at least that high, so if this relay is
    /// later promoted to authority its first decision numbers *above* everything
    /// clients have already seen -- clients keep only the highest seq, and a
    /// restarted numbering would be silently ignored.
    ///
    /// Also adopts the directive's buffer as this relay's tracked buffer, so a
    /// peer relay follows the session's committed depth rather than sitting at its
    /// creation-time minimum. This is what lets a promoted authority baseline its
    /// control law -- and its promotion re-broadcast (see [`set_authority`]) --
    /// against the true current buffer instead of forcing an abrupt resize toward
    /// a stale minimum. Adopted immediately (before the directive's apply frame),
    /// exactly as the authority sets its own buffer the moment it decides; by the
    /// time a promotion consults it, the apply frame has long passed.
    ///
    /// Only ever called on a non-authority relay (the authority forwards its own
    /// directives through [`active_directive`](Self::active_directive), not here),
    /// and only a newer directive updates the buffer -- an out-of-order stale
    /// copy is ignored by the same `seq` gate that guards the numbering. Newer
    /// means a strictly higher `decision_seq`, or an equal one from a strictly
    /// higher `authority_relay_id`: two relays in a staggered-handoff window can
    /// each stamp the same seq (each counts from where it started), and this is
    /// the client's own tie-break verbatim (`Option<u64>` ordering: `None` never
    /// displaces `Some`, redundant copies of one decision never displace each
    /// other), so relay and client always land on the same winner instead of
    /// each latching whichever copy arrived first.
    pub fn observe_directive(&mut self, directive: &BufferDirective) {
        let newer = match directive.decision_seq.cmp(&self.decision_seq) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => directive.authority_relay_id > self.decision_seq_tiebreak,
            std::cmp::Ordering::Less => false,
        };
        if newer {
            self.decision_seq = directive.decision_seq;
            self.decision_seq_tiebreak = directive.authority_relay_id;
            self.buffer = BufferSize(directive.buffer_turns);
        }
    }

    /// Whether this relay is the decision-making authority for this session.
    pub fn is_authority(&self) -> bool {
        self.authority == Authority::SelfRelay
    }

    /// Reconciles this maker with a re-pushed session descriptor: adopts the
    /// coordinator's current bounds and the freshly computed authority verdict.
    /// The relay set serving a session changes as players join and leave, and
    /// with it who the lowest-id (deciding) relay is -- a maker frozen at its
    /// creation-time verdict could leave a session with two authorities or
    /// none. Condition history and frame observations are kept (they describe
    /// the links, not the descriptor); the committed buffer is kept too, since
    /// it reflects what was last broadcast, and future decisions clamp to the
    /// new bounds. A relay losing authority drops any directive it was still
    /// broadcasting -- only the authority stamps.
    ///
    /// `held_slots` is this relay's set of undecided drop holds, exactly as
    /// [`set_authority`](Self::set_authority) takes it -- a descriptor-driven
    /// promotion races a reconnection on this relay exactly the way a
    /// presence-driven one does (a client can be mid-reconnect when the
    /// coordinator's descriptor happens to re-push and promote this relay), so
    /// it must skip a held slot's departure the same way. The caller (which
    /// owns the drop-hold registry) passes the current held set in.
    ///
    /// Returns the synced leaves a promotion (Peer -> SelfRelay) must (re)broadcast
    /// -- see [`set_authority`](Self::set_authority); empty otherwise. The second
    /// element names which of those are **freshly derived** by this call (a first
    /// insert into the directive cache, not a verbatim re-broadcast of one already
    /// cached) -- see [`set_authority`](Self::set_authority) for why the caller
    /// needs the distinction.
    #[must_use]
    pub fn sync(
        &mut self,
        bounds: BufferBounds,
        authority: Authority,
        held_slots: &HashSet<SlotId>,
    ) -> (Vec<LeaveDirective>, Vec<LeaveDirective>) {
        self.bounds = bounds;
        self.set_authority(authority, held_slots)
    }

    /// Applies a fresh authority verdict without touching the bounds, returning
    /// the synced leaves a *promotion* must (re)broadcast (empty on any other
    /// transition). This is the presence-driven half of authority tracking:
    /// between descriptor pushes, the verdict moves as relays' players come and
    /// go, while the bounds stay whatever the coordinator last set.
    ///
    /// A relay **losing** authority drops any buffer directive it was still
    /// broadcasting (only the authority stamps), but keeps `decision_seq`, its
    /// cached leaves, and its recorded departures -- those are exactly what a
    /// later re-promotion needs.
    ///
    /// A relay **gaining** authority (Peer -> SelfRelay) yields the leaves to
    /// re-broadcast: every cached directive is re-emitted *verbatim* (its apply
    /// frame must not be recomputed -- survivors that already applied it did so
    /// at that exact frame), and a departure with no cached directive is decided
    /// fresh (safe: a directive that never escaped the dead authority was never
    /// applied by anyone). The caller pushes each down local survivors and across
    /// the mesh; all are idempotent (clients and peer relays dedup by slot), so
    /// re-delivering a leave every survivor already applied costs a few redundant
    /// frames, bounded by the slot count -- while skipping one a stalled survivor
    /// never received would strand it forever.
    ///
    /// Returns `(all, fresh)`: `all` is every leave to (re)broadcast, `fresh` is
    /// the subset that is a **first insert** into the directive cache this call --
    /// a departure re-derived because no directive escaped the dead authority. A
    /// verbatim re-broadcast of an already-cached directive is not in `fresh`:
    /// whichever relay cached it first already reported it, so re-announcing it
    /// again on every promotion would double-count the departure. The registry-
    /// level free function uses `fresh` to fire exactly one departure notice per
    /// slot, by whichever path (`decide_leave`, `observe_leave`, or this one)
    /// first grows the cache.
    ///
    /// `held_slots` is the set of this relay's slots whose *drop is still held
    /// undecided* for the session — a departure recorded and announced, but whose
    /// synced leave has neither been decided (by an honored manual request) nor
    /// discarded by the slot's return. A promotion **must not** decide such a slot:
    /// a held drop is decided only by an honored `RequestDrop`, or released when the
    /// client re-registers, so a promotion re-deriving it here would broadcast a
    /// leave no one asked for — defeating reconnection when a total-presence blip
    /// flips authority away and back on one relay. The caller (which owns the
    /// drop-hold registry) passes the held set in; an undecided departure *not* in
    /// it (a clean leave that never got decided) still re-derives, so no departure
    /// is lost.
    #[must_use]
    pub fn set_authority(
        &mut self,
        authority: Authority,
        held_slots: &HashSet<SlotId>,
    ) -> (Vec<LeaveDirective>, Vec<LeaveDirective>) {
        if self.authority == authority {
            return (Vec::new(), Vec::new());
        }
        let promoting = self.authority == Authority::Peer && authority == Authority::SelfRelay;
        self.authority = authority;
        if authority == Authority::Peer {
            // Only the authority stamps buffer changes; a demoted relay stops.
            // Its cached leaves and recorded departures are deliberately kept --
            // they are what a later promotion re-broadcasts.
            self.pending_directive = None;
            self.pending_decision_inputs = None;
        }
        if promoting {
            // Start the desync comparator fresh. No per-ordinal checksum state
            // transfers across a handoff — a real desync diverges every interval,
            // so the first interval after promotion re-detects it, and carrying
            // the window across would be complexity for a one-interval blind spot.
            // Observer membership is descriptor-driven, so it is deliberately kept.
            self.sync = SyncTracker::default();
            // Re-affirm the buffer to every survivor: the promoted relay tracked
            // the last-broadcast buffer as a peer (see [`observe_directive`]), so
            // this re-broadcast carries the session's true current buffer, not a
            // stale minimum -- a no-op resize for a survivor already at that depth,
            // and a correction for one that missed the original directive.
            self.initial_directive_sent = false;
            // Trace the new authority's control inputs promptly rather than
            // waiting out the interval from the previous authority's cadence.
            self.last_trace_frame = None;
            // A promoted authority has no target history, so its shrink floor
            // would read zero and allow an instant shrink on the first
            // post-handoff sample. Seed the floor with the buffer it inherited;
            // real observations take over from there.
            if let Some(frame) = self.session_frame() {
                let span = self.law.target_floor_bucket_span();
                self.target_peaks.observe(frame.0, self.buffer.0, span);
            }
            self.drain_handoff_leaves(held_slots)
        } else {
            (Vec::new(), Vec::new())
        }
    }

    /// The synced leaves a freshly promoted authority must (re)broadcast so no
    /// leave is lost when authority moves off a relay that had decided (or should
    /// have decided) one. Every cached directive is re-emitted verbatim, and
    /// every recorded departure without a cached directive is decided fresh and
    /// cached. See [`set_authority`](Self::set_authority) for the `(all, fresh)`
    /// shape.
    ///
    /// Deliberately **unconditional** -- there is no "already applied everywhere,
    /// skip it" test, because the relay cannot make one. The frames it observes
    /// are survivors' *send stamps*, which lead their execution by the latency
    /// buffer's depth: the survivors-only session frame reaches the apply frame
    /// (`last_frame + 1`) essentially the moment the leave is decided, whether
    /// every survivor applied it or every survivor is still stalled waiting for
    /// it. A predicate that is true in both states cannot gate the one
    /// re-delivery that would unstall a survivor the original push missed, so
    /// the leave is always re-sent and every consumer dedups by slot instead.
    ///
    /// The fresh derivation runs through [`decide_leave`](Self::decide_leave)
    /// itself (not a hand-rolled duplicate of its logic) -- at this point
    /// `self.authority` is already `SelfRelay` (the caller set it just above) and
    /// the slot is confirmed not yet cached, so `decide_leave` always succeeds
    /// unless there is no frame basis yet (the same "hold" it already documents).
    /// Routing through it means a promotion-derived leave is indistinguishable
    /// from any other `decide_leave` call, including the first-insert bookkeeping
    /// the departure notifier keys on -- a promotion that derives a leave for a
    /// slot no relay ever cached before (the case a 2-relay topology hits when the
    /// only other relay is the one that just died) is exactly as much a "first
    /// insert" as the authoring relay's own `decide_leave` would have been, and
    /// must fire the same one notice.
    pub(in crate::consensus) fn drain_handoff_leaves(
        &mut self,
        held_slots: &HashSet<SlotId>,
    ) -> (Vec<LeaveDirective>, Vec<LeaveDirective>) {
        let mut leaves = Vec::new();
        let mut fresh = Vec::new();

        // Cached directives (authored or observed): re-broadcast verbatim. Never
        // "fresh" -- the cache already held these, so whichever relay first
        // cached them already reported the departure. A held slot is undecided by
        // construction, so it is never in this map.
        leaves.extend(self.decided_leaves.values().copied());

        // Departures with no cached directive: the previous authority never got
        // to author one (or died before it escaped), so decide fresh through
        // `decide_leave`. Collect first to avoid holding an immutable borrow
        // across the mutation.
        //
        // A slot whose drop is still held undecided is skipped entirely — not
        // decided here at all. A held drop is decided only by an honored manual
        // request, or released when the client returns. Deciding it here (which
        // would also mark it decided) would remove a slot no one asked to drop and
        // lose the reconnection window.
        let to_derive: Vec<(SlotId, u32)> = self
            .departures
            .iter()
            .filter(|(slot, _)| {
                !self.decided_leaves.contains_key(slot) && !held_slots.contains(*slot)
            })
            .map(|(slot, departure)| (*slot, departure.reason))
            .collect();
        for (slot, reason) in to_derive {
            if let Some(directive) = self.decide_leave(slot, reason) {
                leaves.push(directive);
                fresh.push(directive);
            }
            // `None` means no frame basis yet (a lobby-era departure) -- hold,
            // exactly as a direct `decide_leave` call would.
        }

        (leaves, fresh)
    }
}
