//! Departure records: what this relay retains about a slot that left, how an
//! authority-authored leave observed off the mesh folds in, and how a promoted
//! relay re-derives the set it must re-broadcast.

use super::*;

/// One recorded departure as re-announced to a freshly (re)joined mesh link:
/// the slot, its home-authored stamps, the native leave reason, and the
/// authoring connection generation. See `DecisionMaker::leave_reconcile`.
pub type RecordedDeparture = (SlotId, DepartureStamps, u32, Option<u64>);

/// The home-authored half of a departure record: everything the departing
/// slot's home relay stamps at the departure — its last observed frame, the
/// survivor-reachability ceiling, any retained end-of-game result, and the
/// final turn count — and every other relay folds in verbatim (first
/// non-`None` wins per field), so authority-handoff re-derivation lands on
/// identical values everywhere. `last_frame` is additionally max-merged with
/// the folding relay's own observation of the slot (see
/// [`DecisionMaker::record_departure`]); the other fields are single-sourced.
#[derive(Debug, Clone, Default)]
pub struct DepartureStamps {
    /// The departing slot's last observed frame at its home relay (`None` if it
    /// never produced a framed turn).
    pub last_frame: Option<GameFrameCount>,
    /// The home-authored survivor-reachability ceiling for the leave's apply
    /// frame (see `DecisionMaker::reachable_frame`).
    pub reachable_frame: Option<u32>,
    /// The end-of-game result the slot reported before departing, if any.
    pub result: Option<ResultEcho>,
    /// The slot's gap-free forwarded turn count at the departure — the exact
    /// number of its turns any client can ever consume (see
    /// `Departure::final_turn_count`).
    pub final_turn_count: Option<u64>,
    /// Whether `final_turn_count` on a DROPPED departure was derived through
    /// home-side finalization (see [`finalize_drop`]) — the proof every count
    /// ingress requires before accepting a dropped count.
    pub finalized: bool,
}

/// One observed slot departure, kept for authority-handoff re-derivation. Holds
/// exactly what deriving the leave's apply frame needs: the departing slot's
/// last observed frame (`None` if it never produced a framed turn -- a lobby
/// departure with no frame basis) and the native leave reason to author. The
/// frame is the max-merge of every observation of this departure (the home
/// relay's carried value, this relay's own view, any re-announce), so the
/// fullest view wins; the reason keeps the first observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::consensus) struct Departure {
    pub(in crate::consensus) last_frame: Option<GameFrameCount>,
    /// The slot's complete game-progress state at departure. A reconnect
    /// restores this state and resets only physical-link measurements, keeping
    /// both the last frame and bounded seq/frame reachability history continuous
    /// across connections. Duplicate departure observations never replace an
    /// already-captured state.
    pub(in crate::consensus) slot_state: Option<SlotState>,
    /// The home-authored reachability ceiling for the leave's apply frame — the
    /// highest frame every survivor had provably executed when the home relay saw
    /// the departure (see [`DecisionMaker::reachable_frame`]). Single-sourced
    /// (only the home computes it, from `reachable_frame`) and carried in the
    /// `SlotDeparted` frame, so [`decide_leave`](DecisionMaker::decide_leave) and
    /// the handoff re-derivation clamp to the identical value on every relay.
    /// `None` when the home had no survivor framed history yet (no clamp).
    pub(in crate::consensus) reachable_frame: Option<u32>,
    pub(in crate::consensus) reason: u32,
    /// The end-of-game result this slot reported before departing, if any.
    /// Home-authored: only the departing slot's home relay retains the report
    /// and seeds this; other relays receive it in the `SlotDeparted` frame. Folded
    /// first-non-`None`-wins, exactly like `reachable_frame` — a result can never
    /// be recorded after a slot's departure (reports ride only the live link,
    /// which the departure closes), so once seeded it is final. Carried into the
    /// [`DepartureNotice`] so a departure webhook is atomic terminal truth.
    pub(in crate::consensus) result: Option<ResultEcho>,
    /// The number of this slot's turns in its home relay's gap-free forwarded
    /// prefix at the departure — the exact count of the slot's turns any client
    /// can ever consume (the home forwards nothing past it), and therefore the
    /// count every client consumes before applying the leave
    /// (`LeaveDirective::final_turn_count`). Home-authored from the
    /// session-level forward gate (see `crate::mesh::forwarded_count` — state
    /// that survives connection replacement and that no client claim can
    /// advance), carried in the `SlotDeparted` frame, and folded
    /// first-non-`None`-wins exactly like `reachable_frame`, so the authority —
    /// including one promoted mid-handoff — stamps the identical count. `None`
    /// when authored by a sender that predates the field, or by a home with no
    /// gap-free knowledge to answer from.
    pub(in crate::consensus) final_turn_count: Option<u64>,
    /// Whether `final_turn_count` on a DROPPED departure carries the
    /// finalization proof: the home marked the slot's generation terminal
    /// (refusing future admission and fencing its turn ingress) and only then
    /// snapshotted the count, so nothing past it can ever enter the mesh.
    /// Sticky across merges — once proven, proven. Without it a dropped
    /// record's count is never emitted (see `commit_leave`).
    pub(in crate::consensus) finalized: bool,
    /// Physical connection generation that authored this departure. Stored on
    /// the record itself so Join-time reconciliation cannot accidentally stamp
    /// it with a newer generation from mutable live-link state.
    pub(in crate::consensus) connection_epoch: Option<u64>,
}

impl DecisionMaker {
    /// Caches a synced leave this relay observed authored by the session's
    /// authority (a peer relay's `LeaveDirective` off the mesh), so a later
    /// promotion re-broadcasts it verbatim. First writer wins; a conflicting
    /// duplicate for the same slot (a different apply frame or reason) is logged
    /// -- that would mean two relays decided the same slot's leave differently, an
    /// authority bug. Keeps `next_leave_seq` at least the observed seq so a
    /// promoted relay's own numbering never collides with what clients hold.
    ///
    /// Returns whether this was a **first insert** for the slot — the moment the
    /// directive cache gains the slot — so the caller fires exactly one departure
    /// notice per (session, slot) on this relay (a redundant copy, a second mesh
    /// path, or a reconcile-on-join re-send all return `false`).
    #[must_use]
    pub fn observe_leave(&mut self, leave: &LeaveDirective) -> bool {
        use std::collections::hash_map::Entry;
        // The cache must never hold an unproven dropped count, no matter
        // which path delivered the directive — normalize here, where the
        // state lives, in addition to the wire ingress (see
        // [`normalize_observed_leave`]). Normalizing before the substance
        // comparison below also keeps two relays convergent when only one of
        // them saw the legacy count.
        let leave = &normalize_observed_leave(leave, self.finalized_drops_enabled);
        let Ok(slot) = u8::try_from(leave.slot).map(SlotId) else {
            // A slot id past `u8` range can't name any real slot; a silent
            // truncation would alias it onto a valid one. Drop it (defensive —
            // the wire values are validated upstream, so this shouldn't occur).
            tracing::warn!(
                tenant = self.key.tenant.as_ref(),
                session = self.key.session.0,
                slot = leave.slot,
                "leave directive names a slot id out of range; ignoring",
            );
            return false;
        };
        let inserted = match self.decided_leaves.entry(slot) {
            Entry::Occupied(existing) => {
                let cached = *existing.get();
                if cached != *leave {
                    // `leave_seq` is assigned locally by whichever relay decides
                    // (`next_leave_seq += 1`), so two relays independently
                    // force-deciding the same fully-abandoned slot (see
                    // `force_decide_leave`) can agree completely on the decision
                    // itself — `reason`, `apply_at_frame`, and
                    // `final_turn_count` — while disagreeing on this
                    // purely-local numbering. That is not a conflict, just two
                    // relays labeling the identical decision differently, so it
                    // is logged at debug. A disagreement on the decision's
                    // substance is the real authority-bug signal and still
                    // warns — the count especially, since clients schedule the
                    // leave's application by it, so a count disagreement means
                    // two relays would have survivors remove the slot at
                    // different simulation steps.
                    if cached.reason == leave.reason
                        && cached.apply_at_frame == leave.apply_at_frame
                        && cached.final_turn_count == leave.final_turn_count
                    {
                        tracing::debug!(
                            tenant = self.key.tenant.as_ref(),
                            session = self.key.session.0,
                            slot = leave.slot,
                            cached_leave_seq = cached.leave_seq,
                            observed_leave_seq = leave.leave_seq,
                            "same synced leave decided independently with a different leave_seq; keeping the first",
                        );
                    } else {
                        tracing::warn!(
                            tenant = self.key.tenant.as_ref(),
                            session = self.key.session.0,
                            slot = leave.slot,
                            cached_apply = cached.apply_at_frame,
                            observed_apply = leave.apply_at_frame,
                            cached_count = ?cached.final_turn_count,
                            observed_count = ?leave.final_turn_count,
                            "conflicting synced leave for a slot already cached; keeping the first",
                        );
                    }
                }
                false
            }
            Entry::Vacant(vacant) => {
                vacant.insert(*leave);
                true
            }
        };
        if leave.leave_seq > self.next_leave_seq {
            self.next_leave_seq = leave.leave_seq;
        }
        if inserted {
            self.note_leave_decided(slot);
            // A final leave is terminal even when it outruns the corresponding
            // SlotDeparted on another peer link. Retire the live slot now and
            // leave a departure tombstone so frames/conditions cannot recreate
            // it. The decided-leave guard rejects every later true generation.
            if let Some(ConnectionState::Up(epoch)) = self.connection_states.get(&slot).copied() {
                self.connection_states
                    .insert(slot, ConnectionState::Down(epoch));
            }
            let retained_result = self.results.get(&slot).cloned();
            self.note_departure(
                slot,
                DepartureStamps {
                    result: retained_result,
                    final_turn_count: leave.final_turn_count,
                    ..DepartureStamps::default()
                },
                leave.reason,
                None,
            );
            self.delivery.forget_slot(slot);
        }
        inserted
    }

    /// This slot's last observed game frame, or `None` before its first framed
    /// turn — or after its departure was recorded, which retires the slot's live
    /// state (the frame lives on in the departure record). Read at a departure
    /// trigger, before recording, to fill a `SlotDeparted`'s `last_frame`.
    pub fn slot_frame(&self, slot: SlotId) -> Option<GameFrameCount> {
        self.slots.get(&slot).and_then(|s| s.frame)
    }

    #[cfg(test)]
    pub(crate) fn has_slot_state(&self, slot: SlotId) -> bool {
        self.slots.contains_key(&slot)
    }

    /// Whether a departure has been recorded for `slot` — its link ended (a drop or
    /// a clean leave), which retired it from the live slot set. Distinguishes a slot
    /// the game has moved on from (or is holding a drop over) from one that never
    /// departed, so a re-register can tell a resumable reconnect from a decided one.
    pub fn has_departure(&self, slot: SlotId) -> bool {
        self.departures.contains_key(&slot)
    }

    /// Discards `slot`'s departure record because the client returned while its drop
    /// was still held — the slot is live again, not gone. Returns whether a record
    /// was actually cleared. Called at the re-register that releases the slot's drop
    /// hold: the return is the held drop's resolution to *not* leave, so the record
    /// it was holding over must go, or a later authority promotion would re-derive
    /// the leave from a departure that no longer describes reality (a re-registered
    /// slot's hold is already released, so the promotion's held-slot skip cannot
    /// protect it — clearing the record is what does).
    ///
    /// The departure's suspended slot state is restored, preserving game-frame
    /// and bounded seq/frame reachability history across the reconnect while
    /// resetting RTT/loss/mesh measurements — and the link's age — that belong to
    /// the old physical link. Presence is re-asserted by the register's own
    /// `note_slot_present`.
    ///
    /// A no-op — returns `false`, the departure record untouched — when the slot's
    /// leave is **already decided**. Ordinarily a re-register only reaches an
    /// undecided departure (its hold is what the caller checked to get here), so
    /// there is nothing to conflict with; but the fully-abandoned-session path can
    /// force-decide a slot without a hold ever being released first (its hold
    /// survives until this relay's own local roster next empties — see
    /// [`crate::session::drop_hold::DropHolds::end_session`]), so a reconnect racing a
    /// force-decide on this exact slot could otherwise land here. This check is
    /// what keeps that race safe under the registry's single-mutex serialization:
    /// [`crate::consensus::decide_abandoned_departures`] holds the same lock for
    /// its entire read-then-decide sequence, so this call either runs entirely
    /// before it (nothing decided yet — clears normally) or entirely after (the
    /// leave is already cached — a no-op that leaves the decided state, and the
    /// broadcast it already produced, standing rather than silently erasing it).
    pub fn reinstate_slot(&mut self, slot: SlotId) -> bool {
        if self.decided_leaves.contains_key(&slot) {
            return false;
        }
        let Some(departure) = self.departures.remove(&slot) else {
            return false;
        };
        let mut state = departure.slot_state.unwrap_or_default();
        if let Some(last_frame) = departure.last_frame
            && state.frame.is_none_or(|frame| last_frame > frame)
        {
            state.frame = Some(last_frame);
        }
        state.reset_link_conditions();
        // The restored progress history belongs to the link that died. The
        // resumed slot is owed the whole silence window on its new link before
        // the watch may close it, which is what this records — the stop time the
        // history carries stays exactly where its forwarding stopped.
        state.connection_up_at = Some(Instant::now());
        self.slots.insert(slot, state);
        true
    }

    /// The slots whose leave this relay has already decided or cached for this
    /// session (the keys of `decided_leaves`). Read at a session-emptied teardown
    /// so the drop-hold sweep can tell a hold that already reflects a decided leave
    /// (safe to discard) from one that still gates an undecided drop (must survive
    /// — see [`crate::session::drop_hold::DropHolds::end_session`]).
    pub(in crate::consensus) fn decided_slots(&self) -> HashSet<SlotId> {
        self.decided_leaves.keys().copied().collect()
    }

    /// This relay's known leave state for re-announcing to a freshly (re)joined
    /// mesh link: every recorded departure (slot, last frame, reachable ceiling,
    /// embedded result, reason) and every cached leave, unconditionally. A redialed
    /// link starts knowing nothing, so resending these lets it reconverge — all
    /// idempotent (dedup by slot on receipt). Nothing is filtered as "already
    /// applied everywhere": the relay cannot tell that state apart from "everyone
    /// still stalled waiting" (see [`drain_handoff_leaves`](Self::drain_handoff_leaves)),
    /// and the cost of a redundant re-announce is a few deduped frames, bounded by
    /// the slot count.
    pub(in crate::consensus) fn leave_reconcile(
        &self,
    ) -> (Vec<RecordedDeparture>, Vec<LeaveDirective>) {
        let departures = self
            .departures
            .iter()
            .map(|(slot, departure)| {
                (
                    *slot,
                    DepartureStamps {
                        last_frame: departure.last_frame,
                        reachable_frame: departure.reachable_frame,
                        result: departure.result.clone(),
                        final_turn_count: departure.final_turn_count,
                        finalized: departure.finalized,
                    },
                    departure.reason,
                    departure.connection_epoch,
                )
            })
            .collect();
        let directives = self.decided_leaves.values().copied().collect();
        (departures, directives)
    }

    /// Records a departure and retires the slot's live state. The shared step
    /// behind [`record_departure`](Self::record_departure) and
    /// [`decide_leave`](Self::decide_leave).
    ///
    /// The record's `last_frame` is the **max-merge** of every observation: the
    /// caller-provided frame (a `SlotDeparted`'s carried frame, or `None`), the
    /// slot's own frame in `slots`, and any prior record — so whichever of the
    /// home relay's carried value and this relay's own view is fuller wins, and a
    /// re-announce can only raise it. The `reason` keeps the first observation
    /// (a departure has one reason; a duplicate signal doesn't rewrite it).
    ///
    /// `reachable` is the home-authored apply-frame ceiling (see
    /// [`Departure::reachable_frame`]). It is **single-sourced** — only the
    /// departing slot's home computes it, and it is carried verbatim — so this
    /// keeps the first non-`None` value seen and never recomputes or merges it
    /// (a later `decide_leave`/re-announce passing `None` must not clobber it).
    ///
    /// `result` is the departing slot's home-authored end-of-game result echo,
    /// single-sourced and kept the same first-non-`None`-wins way as `reachable`
    /// (the home seeds it from the report it retained; a peer receives it in the
    /// `SlotDeparted` frame). A result can never arrive after a slot's departure,
    /// so once seeded it never changes. An invalid `result` — empty or over-cap —
    /// is dropped before it can be folded in: the home relay's own report already
    /// went through [`record_result`](Self::record_result)'s check, but a peer's
    /// `SlotDeparted` fold-in reaches this map without passing through that
    /// method, so the check is repeated here to hold the same bound regardless of
    /// path.
    ///
    /// Removing the slot from `slots` here — on *every* relay, not just the
    /// slot's home — is what lets `session_frame()` follow the survivors: a
    /// departed slot's frozen frame left in place would pin the minimum for the
    /// rest of the game, freezing the buffer machinery's dwell clock and keeping
    /// a pending buffer directive from ever retiring. The
    /// `observe_frame`/`ingest` guards keep late in-flight traffic from
    /// resurrecting the entry.
    pub(in crate::consensus) fn note_departure(
        &mut self,
        slot: SlotId,
        stamps: DepartureStamps,
        reason: u32,
        connection_epoch: Option<u64>,
    ) {
        let DepartureStamps {
            last_frame,
            reachable_frame: reachable,
            result,
            final_turn_count,
            finalized,
        } = stamps;
        use std::collections::hash_map::Entry;
        let result = result.filter(|echo| {
            let valid = result_payload_is_valid(&echo.payload);
            if !valid {
                tracing::warn!(
                    tenant = self.key.tenant.as_ref(),
                    session = self.key.session.0,
                    slot = slot.0,
                    len = echo.payload.len(),
                    cap = MAX_GAME_RESULT_PAYLOAD_LEN,
                    "rejecting invalid end-of-game result payload folded in from a peer relay",
                );
            }
            valid
        });
        let mut slot_state = self.slots.remove(&slot);
        let own_frame = slot_state.as_ref().and_then(|state| state.frame);
        let merged = match (last_frame, own_frame) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        if let (Some(state), Some(frame)) = (&mut slot_state, merged)
            && state.frame.is_none_or(|current| frame > current)
        {
            state.frame = Some(frame);
        }
        match self.departures.entry(slot) {
            Entry::Occupied(mut existing) => {
                let record = existing.get_mut();
                record.last_frame = match (record.last_frame, merged) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
                // Preserve the first captured full state. A duplicate may fill
                // an initially absent state, but never replaces frame history
                // already suspended by the first observation.
                if record.slot_state.is_none() {
                    record.slot_state = slot_state;
                }
                if let (Some(state), Some(frame)) = (&mut record.slot_state, record.last_frame)
                    && state.frame.is_none_or(|current| frame > current)
                {
                    state.frame = Some(frame);
                }
                // First non-`None` wins — single-sourced from the home.
                record.reachable_frame = record.reachable_frame.or(reachable);
                record.result = record.result.take().or(result);
                record.final_turn_count = record.final_turn_count.or(final_turn_count);
                record.finalized |= finalized;
                record.connection_epoch = record.connection_epoch.or(connection_epoch);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(Departure {
                    last_frame: merged,
                    slot_state,
                    reachable_frame: reachable,
                    result,
                    reason,
                    final_turn_count,
                    finalized,
                    connection_epoch,
                });
            }
        }
        // A departed slot stops being required by the desync comparator: drop it
        // from the compare set so ordinals it would never report can still
        // complete on the survivors. Harmless on a non-authority relay (the
        // comparator is empty there) and idempotent for a slot never seen.
        self.sync.remove_member(slot);
        // Drop it from the live-slot set too: a slot that left is no longer
        // present. A start decision already made stays made (the `started` latch
        // is untouched); this only keeps a not-yet-started session from counting a
        // departed slot toward coverage.
        self.live_slots.remove(&slot);
    }

    /// Removes a slot's condition history (the client disconnected). Called
    /// when a home client leaves so its stale stats don't outlive its
    /// connection -- mirroring `unpublish_conditions`. A slot whose departure was
    /// already announced is already gone (recording a departure retires the
    /// slot), so this is a harmless no-op there; it still covers cleanup paths
    /// that are not departures. The slot's departure record (and any cached
    /// leave) is kept -- those outlive the connection so a promotion can still
    /// re-derive the leave.
    pub fn remove_slot(&mut self, slot: SlotId) {
        self.slots.remove(&slot);
        self.delivery.forget_slot(slot);
        // The phase estimate describes the torn-down connection; the commanded
        // delay survives inside the controller for the reconnect re-push.
        self.phase.remove_slot(slot);
    }

    /// Removes live per-slot state only when teardown belongs to the active
    /// connection generation. The epoch tombstone itself is retained so late
    /// datagrams and a second stale teardown stay fenced afterward.
    #[must_use]
    pub fn remove_slot_for_epoch(&mut self, slot: SlotId, epoch: Option<u64>) -> bool {
        if !self.connection_epoch_matches(slot, epoch) {
            return false;
        }
        self.remove_slot(slot);
        true
    }
}
