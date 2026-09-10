//! Deciding a synced leave: choosing the apply frame every survivor's client
//! applies the departure at, committing it, and the end-of-game result echo
//! that rides alongside it.

use super::*;

/// The base frame a synced leave schedules from: the departing slot's last
/// observed frame, falling back to the session's slowest frame **only** when the
/// slot never produced a framed turn, or `None` when neither exists (no framed
/// turn observed anywhere -- a lobby departure with no coordinate to schedule
/// against). The apply frame is one past this.
///
/// Deliberately *not* the max of the two. Survivors' stamped frames run ahead of
/// the departed slot's last frame before they stall (a client leads the slowest
/// slot by up to the buffer cushion), so a survivors-only session frame can
/// exceed the departed slot's last frame -- while each stalled survivor's
/// simulation is pinned at `last_frame + 1`, where it applies the leave the
/// moment one arrives. Folding the session frame in would schedule the leave
/// past that stall point: a frame the stalled survivors can never reach, a
/// permanent stall. Shared by [`DecisionMaker::decide_leave`] and the promotion
/// re-derivation so both reproduce the identical frame from the same departure
/// record.
pub(in crate::consensus) fn leave_base_frame(
    slot_last: Option<u32>,
    session: Option<u32>,
) -> Option<u32> {
    slot_last.or(session)
}

impl DecisionMaker {
    /// Decides a synced player-leave for `slot` and queues it for broadcast.
    /// Returns the queued [`LeaveDirective`] (for logging), or `None` when this
    /// relay is not the authority, a leave for the slot is already broadcasting,
    /// or there is no frame basis yet (no in-game turn observed for the session
    /// -- a lobby/pre-game drop, which the game handles natively, not here).
    ///
    /// `reason` is the native `pending_leave_reason` value every client will
    /// write (`0x40000006` dropped, else left). Call this on the authority --
    /// directly when a home client's link ends, or on a peer relay's
    /// `SlotDeparted` signal for a client the peer served.
    ///
    /// The directive's primary synchronization point is the record's
    /// home-authored `final_turn_count` (see `Departure::final_turn_count`):
    /// clients that understand it apply the leave after consuming exactly that
    /// many of the departed slot's turns — a relay-authored, client-verifiable
    /// coordinate every client reaches at the same simulated step, immune to
    /// anyone's frame stamps.
    ///
    /// The apply *frame* is the fallback for clients that predate the count.
    /// It is one past the departing slot's last observed frame — the step
    /// remaining clients would stall at waiting for a turn that will never
    /// come — **clamped down** to the home-authored reachability ceiling
    /// (`Departure`'s `reachable_frame`) so a slot that inflates its own
    /// `game_frame_count` before leaving cannot schedule the leave past a frame
    /// the survivors can reach (which would strand them). That clamp is why the
    /// frame is only a fallback: the ceiling trails the live frontier by up to
    /// the buffer depth, so a clamped frame can sit at a frame clients have
    /// already passed — and a client applies a passed frame on directive
    /// *arrival*, at whatever frame it happens to be simulating, not in
    /// lockstep with anyone. The session frame is the basis only when the slot
    /// never produced a framed turn; it is never folded in as a max (see
    /// `leave_base_frame` for why that would strand stalled survivors) and is
    /// not clamped (no `last_frame` to inflate). The count, the last frame,
    /// and the ceiling all come from the slot's departure record -- surviving
    /// `remove_slot` -- so every relay, including one promoted mid-handoff,
    /// derives the identical directive (clients dedup by slot and require that
    /// agreement).
    pub fn decide_leave(&mut self, slot: SlotId, reason: u32) -> Option<LeaveDirective> {
        // Record the departure regardless of the outcome below (even a hold), so
        // a later promotion can re-derive this slot's leave. This merges the
        // slot's own live frame into the record and retires the slot from
        // `slots`; the record is the single frame source from here on. Passing
        // `None` for the ceiling and the result preserves whatever the home
        // already authored.
        self.note_departure(slot, DepartureStamps::default(), reason, None);

        if self.authority != Authority::SelfRelay {
            return None;
        }
        self.commit_leave(slot, reason)
    }

    /// Decides `slot`'s leave **without** the authority gate, used only to close out
    /// a fully-abandoned session (see [`decide_abandoned_departures`]). With every
    /// slot session-wide disconnected, presence names no authority — the verdict is
    /// [`Authority::Peer`] on every relay — so an authority-gated decide would leave
    /// the departures undecided forever. There are no clients left to desync, so
    /// whichever relay's abandoned-session timer fires decides its own record; the
    /// same per-slot dedup (`commit_leave` / [`observe_leave`] / the coordinator's
    /// notice dedup) that makes an ordinary decide idempotent makes this safe even
    /// when several relays' timers fire at once. Records the departure first, like
    /// [`decide_leave`].
    pub fn force_decide_leave(&mut self, slot: SlotId, reason: u32) -> Option<LeaveDirective> {
        self.note_departure(slot, DepartureStamps::default(), reason, None);
        if let Some(directive) = self.commit_leave(slot, reason) {
            return Some(directive);
        }
        if self.decided_leaves.contains_key(&slot) {
            return None; // already decided or cached — the ordinary dedup
        }
        // No framed turn was ever observed (a pre-frame abandonment).
        // `commit_leave` holds in that state because live survivors schedule
        // the removal against the apply frame — but an abandoned session has no
        // survivors left to schedule, so the frame is cosmetic (exactly as on a
        // rehome's `seed_departed`), and leaving the departure undecided
        // forever would strand everything keyed on its decision: the slot's
        // drop hold, and the session-emptied close waiting on it.
        self.next_leave_seq += 1;
        // Same count gate as `commit_leave`: a clean leave on a never-rehomed
        // session, or a home-finalized drop, may carry the exact count; any
        // other dropped record's count (possibly authored by an older peer
        // over the mesh) and a resumed session's clean count are unsound and
        // must not ride a straggler reconnect's replayed directive.
        let record = self.departures.get(&slot);
        let finalized = reason == LEAVE_REASON_DROPPED
            && record.is_some_and(|d| d.finalized && d.final_turn_count.is_some());
        let directive = LeaveDirective {
            finalized,
            slot: u32::from(slot.0),
            reason,
            apply_at_frame: 0,
            leave_seq: self.next_leave_seq,
            final_turn_count: if reason == LEAVE_REASON_DROPPED {
                if finalized {
                    record.and_then(|d| d.final_turn_count)
                } else {
                    None
                }
            } else if self.resumed {
                None
            } else {
                record.and_then(|d| d.final_turn_count)
            },
        };
        self.decided_leaves.insert(slot, directive);
        self.note_leave_decided(slot);
        Some(directive)
    }

    /// Stamps the instant `slot`'s leave became decided on this relay — its own
    /// decision, or a peer authority's directive arriving. The silence watch
    /// measures the survivors' recovery from the leave against this instant (see
    /// [`silent_slot`](Self::silent_slot)), which is why every path that first
    /// caches a decided leave stamps it: the watch cares that the leave is
    /// decided, not who decided it. First stamp wins, so a re-announce cannot
    /// push the recovery bar forward and re-protect a slot the survivors already
    /// moved past.
    pub(in crate::consensus) fn note_leave_decided(&mut self, slot: SlotId) {
        self.decided_leave_at
            .entry(slot)
            .or_insert_with(Instant::now);
    }

    /// The decision-and-cache step shared by [`decide_leave`] (behind the authority
    /// gate) and [`force_decide_leave`] (a fully-abandoned session, no authority).
    /// Dedups by slot — a `None` return means the slot's leave was already decided
    /// or cached, or no framed turn has been observed to schedule against yet.
    pub(in crate::consensus) fn commit_leave(
        &mut self,
        slot: SlotId,
        reason: u32,
    ) -> Option<LeaveDirective> {
        if self.decided_leaves.contains_key(&slot) {
            return None; // already decided or cached this slot's leave
        }
        let record = self.departures.get(&slot);
        let slot_last = record.and_then(|d| d.last_frame).map(|f| f.0);
        let reachable = record.and_then(|d| d.reachable_frame);
        // The precise synchronization point, when the home authored one: clients
        // that understand it apply the leave after consuming exactly this many of
        // the departed slot's turns, and the frame below is only the fallback for
        // clients that predate the count.
        //
        // A count is sound only when its derivation and the slot's ingress cut
        // are the same step, so that nothing past it can ever reach a client.
        // Two origins have that: the clean-leave intent (the slot's home
        // serve task — its single ingress — derives the count and stops
        // forwarding in the same step, and a decided leave refuses
        // readmission), and home-side drop **finalization** (the home seals
        // the generation terminal — refusing admission and fencing its turn
        // ingress — and only then snapshots the count; see [`finalize_drop`]).
        // An UNFINALIZED dropped record has no cut: the slot can be
        // reconnecting (here or on another relay) while an honored drop
        // request or abandon expiry decides this leave, pushing turns past
        // the recorded count into the mesh — one survivor consumes such a
        // turn before the directive arrives, another applies the leave first,
        // and they diverge. So an unfinalized drop degrades to frame
        // scheduling. The `resumed` gate applies to clean-leave counts (a
        // rehome splits the forwarding history the intent's cut covered); a
        // finalized count is exempt — its soundness rests entirely on the
        // home's own gap-free cursor, and a home without cursor continuity
        // refuses to finalize at all (a home gained mid-session is refused
        // outright via `rehomed_homes`, and a collapsed or absent prefix
        // reads as no cursor).
        let finalized = reason == LEAVE_REASON_DROPPED
            && record.is_some_and(|d| d.finalized && d.final_turn_count.is_some());
        let final_turn_count = if reason == LEAVE_REASON_DROPPED {
            if finalized {
                record.and_then(|d| d.final_turn_count)
            } else {
                None
            }
        } else if self.resumed {
            None
        } else {
            record.and_then(|d| d.final_turn_count)
        };
        let session = self.session_frame().map(|f| f.0);
        // No framed turn observed anywhere yet (pre-game / lobby): nothing to
        // schedule against, so hold — a `None` short-circuits the decision.
        let base = leave_base_frame(slot_last, session)?;
        // Clamp only a framed departure's base, and only when the home supplied a
        // ceiling; the session-frame fallback has no client-inflatable basis.
        let base = match (slot_last, reachable) {
            (Some(_), Some(ceiling)) => base.min(ceiling),
            _ => base,
        };
        self.next_leave_seq += 1;
        let directive = LeaveDirective {
            finalized,
            slot: u32::from(slot.0),
            reason,
            apply_at_frame: base.saturating_add(1),
            leave_seq: self.next_leave_seq,
            final_turn_count,
        };
        self.decided_leaves.insert(slot, directive);
        self.note_leave_decided(slot);
        Some(directive)
    }

    /// The `(slot, reason)` of every recorded departure that has not yet had its
    /// leave decided. Read to close out a fully-abandoned session — each is
    /// force-decided (see [`force_decide_leave`]). A slot whose leave is already
    /// decided or cached is excluded, so a duplicate close is a no-op.
    pub(in crate::consensus) fn undecided_departures(&self) -> Vec<(SlotId, u32)> {
        self.departures
            .iter()
            .filter(|(slot, _)| !self.decided_leaves.contains_key(slot))
            .map(|(slot, departure)| (*slot, departure.reason))
            .collect()
    }

    /// Whether any recorded departure still has no decided leave — the "at least one
    /// undecided departure" half of the abandoned-session condition.
    pub fn has_undecided_departure(&self) -> bool {
        self.departures
            .keys()
            .any(|slot| !self.decided_leaves.contains_key(slot))
    }

    /// Whether any departure still promises a reconnect on this relay: recorded,
    /// not yet decided, of a slot this relay homes
    /// (`admits_slot`), and named in `held` — the caller's
    /// current set of pending drop holds. All three conditions mirror the
    /// re-register admission gate (`server.rs`): only a departed-but-held slot
    /// is admitted back, only on its home relay, and a decided leave refuses it
    /// terminally. So the session-emptied close waits on exactly these — a
    /// peer-homed slot's hold (kept for authority-handoff robustness) and an
    /// undecided departure whose hold is gone (a clean leave releases it) defer
    /// nothing. With an empty homed set (unenforced — dev/legacy descriptors),
    /// every slot counts, matching `admits_slot`'s permissive default: a relay
    /// that would admit any slot's reconnect must also wait on it.
    pub fn has_reconnectable_departure(&self, held: &HashSet<SlotId>) -> bool {
        self.departures.keys().any(|slot| {
            !self.decided_leaves.contains_key(slot)
                && self.admits_slot(*slot)
                && held.contains(slot)
        })
    }

    /// Claims the one session-closed report for this session: `true` exactly once
    /// until [`reopen_close_report`](Self::reopen_close_report) clears the latch.
    /// See the `close_reported` field.
    pub fn claim_close_report(&mut self) -> bool {
        !std::mem::replace(&mut self.close_reported, true)
    }

    /// Clears the session-closed latch because this relay is serving the session
    /// again — its next emptying is a new fact the coordinator must hear. See the
    /// `close_reported` field.
    pub fn reopen_close_report(&mut self) {
        self.close_reported = false;
    }

    /// Records a slot departure without deciding a leave for it, and retires the
    /// slot's live state (see `note_departure`). Every relay calls this when it
    /// learns a slot left (its own home client, or a peer's `SlotDeparted`), so a
    /// later authority promotion can re-derive the leave even on a relay that was
    /// never the authority. `last_frame` is the departing slot's last observed
    /// frame at its home relay (`None` if it never produced a framed turn); it is
    /// max-merged with this relay's own observation of the slot, so whichever
    /// view is fuller wins. `reachable` is the home-authored apply-frame ceiling
    /// (single-sourced, first non-`None` kept). `result` is the departing slot's
    /// home-authored end-of-game result echo (single-sourced, first non-`None`
    /// kept). The reason keeps the first observation.
    pub fn record_departure(&mut self, slot: SlotId, stamps: DepartureStamps, reason: u32) {
        self.note_departure(slot, stamps, reason, None);
        // A departed slot's frozen cursors and newest-seq must not hold the
        // worst-lag view (and its buffer cushion) up forever.
        self.delivery.forget_slot(slot);
    }

    /// Epoch-fenced counterpart to [`record_departure`](Self::record_departure).
    /// A departure from an older connection is a no-op. A present epoch may
    /// establish a previously-unfenced slot directly in Down(E), because a
    /// reliable departure can legitimately be the first generation-bearing
    /// frame observed. An absent epoch is accepted only in legacy mode.
    #[must_use]
    pub fn record_departure_for_epoch(
        &mut self,
        slot: SlotId,
        stamps: DepartureStamps,
        reason: u32,
        connection_epoch: Option<u64>,
    ) -> bool {
        if !self.mark_connection_down(slot, connection_epoch) {
            return false;
        }
        self.note_departure(slot, stamps, reason, connection_epoch);
        self.delivery.forget_slot(slot);
        true
    }

    /// Seeds a coordinator-known departure as **already decided** on a rehome (see
    /// the free [`sync_maker`]). Records the departure — retiring the slot from
    /// the comparator, coverage, and live set — then caches a decided leave for it
    /// so a promotion re-broadcasts it verbatim rather than re-deriving it (which
    /// would fire a redundant notice) or re-waiting on it. Idempotent: a slot
    /// already decided is left as is.
    ///
    /// `final_turn_count` is the count the original directive carried, retained
    /// by the coordinator across the rehome, and it is **not** cosmetic: a
    /// survivor that never received the original directive (its link was down
    /// when the leave was decided, and it reconnected onto this fresh relay)
    /// picks the leave up from this seeded copy via `leave_reconcile`, and must
    /// apply it at the same consumption count every other survivor did. The
    /// apply *frame* is only a fallback for a count-less seed — it is scheduled
    /// one past the current session frame (or 0 before any framed turn), which
    /// a survivor that already applied the leave dedups away by slot.
    ///
    /// A **dropped** seed's count is accepted only with the finalization
    /// proof, and only in a session whose descriptor enables finalized drops
    /// (see `commit_leave`); otherwise it is discarded here regardless of
    /// what the carrier holds — the seed may have travelled through a
    /// coordinator or peer running code that predates the
    /// clean-leaves-or-finalized rule, so the invariant is re-enforced at
    /// this ingress rather than trusted from the wire.
    ///
    /// Returns the seeded directive when this call newly decided the slot's
    /// leave — the copy the caller must fan to already-connected local
    /// survivors, who otherwise perform their one leave reconciliation at
    /// registration and would never hear of a departure seeded afterward.
    /// `None` for a slot already decided (nothing new to deliver).
    pub fn seed_departed(
        &mut self,
        slot: SlotId,
        kind: DepartureKind,
        final_turn_count: Option<u64>,
        finalized: bool,
    ) -> Option<LeaveDirective> {
        let finalized =
            matches!(kind, DepartureKind::Dropped) && finalized && self.finalized_drops_enabled;
        let final_turn_count = match kind {
            DepartureKind::Dropped if !finalized => None,
            _ => final_turn_count,
        };
        let reason = match kind {
            DepartureKind::Dropped => LEAVE_REASON_DROPPED,
            DepartureKind::Left => LEAVE_REASON_LEFT,
        };
        self.note_departure(
            slot,
            DepartureStamps {
                final_turn_count,
                finalized,
                ..DepartureStamps::default()
            },
            reason,
            None,
        );
        if self.decided_leaves.contains_key(&slot) {
            return None;
        }
        self.next_leave_seq += 1;
        let base = self.session_frame().map(|f| f.0).unwrap_or(0);
        let directive = LeaveDirective {
            finalized: finalized && final_turn_count.is_some(),
            slot: u32::from(slot.0),
            reason,
            apply_at_frame: base.saturating_add(1),
            leave_seq: self.next_leave_seq,
            final_turn_count,
        };
        self.decided_leaves.insert(slot, directive);
        self.note_leave_decided(slot);
        Some(directive)
    }

    /// Records the end-of-game result `slot` reported, returning whether this was
    /// the **first** report from the slot. A repeat returns `false` and keeps the
    /// first `echo`, so the caller fires at most one result notice per slot
    /// (anti-flooding, the same first-writer-wins posture as
    /// [`observe_leave`](Self::observe_leave)). The full `echo` is retained so the
    /// slot's departure record and `SlotDeparted` frame can embed it when the slot
    /// leaves. The report does not retire the slot's live state — a result is not
    /// a departure — so the caller's frame stamps still read the slot's framed
    /// history.
    ///
    /// An empty or over-cap payload is rejected here regardless of what the
    /// caller already checked — this map is the sole owner of the retained-result
    /// invariant, so the check lives where the state lives rather than trusting
    /// every call site to have done it. Also returns `false`, so a rejected
    /// report fires no notice and is indistinguishable to the caller from a
    /// duplicate: either way, nothing new was recorded.
    #[must_use]
    pub fn record_result(&mut self, slot: SlotId, echo: ResultEcho) -> bool {
        if !result_payload_is_valid(&echo.payload) {
            tracing::warn!(
                tenant = self.key.tenant.as_ref(),
                session = self.key.session.0,
                slot = slot.0,
                len = echo.payload.len(),
                cap = MAX_GAME_RESULT_PAYLOAD_LEN,
                "rejecting invalid end-of-game result payload",
            );
            return false;
        }
        use std::collections::hash_map::Entry;
        match self.results.entry(slot) {
            Entry::Occupied(_) => false,
            Entry::Vacant(vacant) => {
                vacant.insert(echo);
                true
            }
        }
    }

    /// The result `slot` reported for this session, if any — read on the slot's
    /// home relay when the slot departs, to seed the departure record and the
    /// `SlotDeparted` frame with the retained result.
    pub fn result_for(&self, slot: SlotId) -> Option<&ResultEcho> {
        self.results.get(&slot)
    }
}
