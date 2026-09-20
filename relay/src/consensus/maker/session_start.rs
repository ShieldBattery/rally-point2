//! Session start: the presence coverage that latches a session started, the
//! per-slot connected/started reports the heartbeat restates, the session shape
//! a descriptor supplies, and the initial buffer depth the latch sizes from it.

use super::*;

impl DecisionMaker {
    /// Latches whether this session runs the home-side drop-finalization
    /// handshake, from the descriptor that created the maker.
    ///
    /// Immutable for the session's lifetime, which is why this is only ever
    /// called at creation: every count-acceptance rule keys on the flag, so a
    /// session must never change its mind mid-game.
    pub fn latch_finalized_drops(&mut self, enabled: bool) {
        self.finalized_drops_enabled = enabled;
    }

    /// Checks a later descriptor push's `finalized_drops` against the latched
    /// value, warning when they disagree. The create-time value stands — see
    /// [`latch_finalized_drops`](Self::latch_finalized_drops).
    pub fn reconcile_finalized_drops(&self, pushed: bool) {
        if self.finalized_drops_enabled != pushed {
            tracing::warn!(
                tenant = self.key.tenant.as_ref(),
                session = self.key.session.0,
                latched = self.finalized_drops_enabled,
                pushed,
                "descriptor re-push disagrees on finalized_drops; keeping the latched value",
            );
        }
    }

    /// Records that `slot`'s link activated on this relay, into the ever-connected
    /// set the heartbeat restates. Idempotent: a reconnect re-inserts a slot the
    /// set already holds, and nothing ever removes one.
    pub fn note_slot_connected(&mut self, slot: SlotId) {
        self.connected_slots.insert(slot);
    }

    /// Records that `slot` reported its game loop running, into the ever-started
    /// set the heartbeat restates. Idempotent for the same reason as
    /// [`note_slot_connected`](Self::note_slot_connected).
    ///
    /// Only a slot's own home receives this report, and the silence watch on
    /// every relay needs it (see [`silent_slot`](Self::silent_slot)), so the home
    /// also shares it across the mesh; the peer side lands in
    /// [`note_peer_slot_started`](Self::note_peer_slot_started) instead, keeping
    /// this set first-hand.
    ///
    /// The report deliberately supplies no timestamp to the watch: the moment a
    /// client says it began is the client's to choose, and a slot that delays
    /// saying so must not thereby look like it stopped later than the players
    /// already waiting on it.
    pub fn note_slot_started(&mut self, slot: SlotId) {
        self.started_slots.insert(slot);
    }

    /// Records a peer relay's report that one of ITS home slots' game loops is
    /// running (a mesh `SlotStarted`). Idempotent, and harmless for a slot this
    /// relay homes: the two sets are only ever read as a union, so a crossed
    /// report changes no answer. Deliberately does not touch `started_slots`,
    /// which is what this relay restates to the coordinator — the home already
    /// reported this slot, and a second relay reporting it would attribute the
    /// same load twice.
    pub fn note_peer_slot_started(&mut self, slot: SlotId) {
        self.peer_started_slots.insert(slot);
    }

    /// Whether `slot`'s game loop is known to be running, from this relay's own
    /// home client or a peer's shared report. The question every relay-side
    /// judgement asks; which relay heard it first matters only to the coordinator
    /// reporting, never here.
    pub(in crate::consensus) fn has_started(&self, slot: SlotId) -> bool {
        self.started_slots.contains(&slot) || self.peer_started_slots.contains(&slot)
    }

    /// The slots this relay's own home clients have reported started, for the
    /// home to (re)share with a mesh peer that just joined. First-hand only: a
    /// relay never relays another relay's report, so a peer set converges from
    /// each home directly and no report can loop the mesh.
    pub fn started_home_slots(&self) -> Vec<SlotId> {
        sorted_slots(&self.started_slots)
    }

    /// Records that `slot` is present — registered on some relay serving the
    /// session (this relay's own roster, or a peer's `SlotPresent`) — and returns
    /// whether the session-start directive should now be emitted session-wide.
    ///
    /// The live-slot set accumulates on every relay so a mid-startup promotion can
    /// evaluate coverage, but only the **authority** returns `true`, and only
    /// once: when the expected set is non-empty and the accumulated live slots
    /// cover it, this latches `started` and returns `true`. A slot arriving on a
    /// non-authority relay, before coverage, or after the latch is set returns
    /// `false`.
    #[must_use]
    pub fn note_slot_present(&mut self, slot: SlotId) -> bool {
        // Presence and final-leave frames can arrive over different peer links.
        // A delayed present must not resurrect a terminal slot or satisfy start
        // coverage after its departure/leave already linearized here.
        if self.departures.contains_key(&slot) || self.decided_leaves.contains_key(&slot) {
            return false;
        }
        self.live_slots.insert(slot);
        self.maybe_start()
    }

    /// Re-evaluates the start condition without a new presence report — the
    /// authority-churn path. A relay just promoted to `SelfRelay` may already hold
    /// a covering live-slot set (accumulated while it was a peer), so it fires the
    /// directive the previous authority never got to. Same one-shot latch as
    /// [`note_slot_present`](Self::note_slot_present); returns `false` on a
    /// non-authority relay, before coverage, or once already started.
    #[must_use]
    pub fn reevaluate_start(&mut self) -> bool {
        self.maybe_start()
    }

    /// Latches the session started without firing — used when a peer relay's
    /// `SessionStart` arrives, so this relay's own late-registering local slots
    /// still get a re-push even though it never made the decision itself. A relay
    /// that receives the directive fans it to its current local slots separately;
    /// this only records that the session has begun.
    pub fn mark_started(&mut self) {
        self.latch_started();
    }

    /// The one place the session-started latch is set, so the start instant the
    /// region-label release gate measures from can never be missed by a path that
    /// only remembers the boolean. Every way a session starts funnels through
    /// here: the authority's own coverage latch, a peer relay adopting the
    /// authority's directive off the mesh, and a relay resuming an already-running
    /// session from a rehome descriptor.
    ///
    /// The instant is recorded only on the first latch. A start directive can be
    /// delivered more than once (an authority handoff re-firing it, a late slot's
    /// re-push), and re-stamping the clock on each would let a session that keeps
    /// re-announcing its start defer the region-label release without bound.
    pub(in crate::consensus) fn latch_started(&mut self) {
        self.started = true;
        self.started_at.get_or_insert_with(Instant::now);
    }

    /// Whether the session-start directive has already been emitted — the guard a
    /// relay checks to re-push it to a slot that registers after start.
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// The slot count the session is currently shaped for, for sizing
    /// per-session state whose need scales with turn production (every live
    /// slot produces turns at the same nominal cadence — see the forwarded-turn
    /// replay ring). The larger of the accumulated live-slot view and the
    /// descriptor's expected set: live covers slots a descriptor never named
    /// (an unenforced dev session), expected covers a freshly resumed relay
    /// whose live view hasn't re-accumulated yet — either alone can transiently
    /// under-count, and under-counting under-retains. `0` when both are empty:
    /// the shape is genuinely unknown, and the caller must assume the largest
    /// game rather than a small one.
    pub fn session_slot_count(&self) -> usize {
        self.live_slots.len().max(self.expected_slots.len())
    }

    /// The one-shot start decision: fires (latching `started`, returning `true`)
    /// exactly when this relay is the authority, the expected set is non-empty,
    /// and the accumulated live slots cover it. Every other case returns `false`
    /// and changes nothing.
    ///
    /// The coverage latch is also where the authority sizes the session's initial
    /// latency-buffer depth — exactly once, from the conditions accumulated during
    /// the pre-start window (see [`compute_initial_depth`](Self::compute_initial_depth)).
    /// It adopts the depth as its current `buffer` (so the one-shot first-frame
    /// re-affirm in [`decide`](Self::decide) broadcasts the stamped depth rather
    /// than clobbering it back to the minimum) and stores it for every
    /// `SessionStart` it stamps.
    pub(in crate::consensus) fn maybe_start(&mut self) -> bool {
        if self.started || self.authority != Authority::SelfRelay || self.expected_slots.is_empty()
        {
            return false;
        }
        if self.expected_slots.is_subset(&self.live_slots) {
            self.latch_started();
            let depth = self.compute_initial_depth();
            self.buffer = BufferSize(depth);
            self.initial_buffer_turns = Some(depth);
            return true;
        }
        false
    }

    /// Moves this session's recorded start instant `by` further into the past, so
    /// a test can drive the region-label gate's elapsed-time condition without
    /// sleeping out a real delay. A no-op on a session that has not started —
    /// there is no clock to move, and the gate stays shut either way.
    #[cfg(test)]
    pub(in crate::consensus) fn backdate_session_start(&mut self, by: Duration) {
        self.started_at = self.started_at.and_then(|at| at.checked_sub(by));
    }

    /// Records the descriptor-derived inputs to the initial-depth computation:
    /// the tenant's `latency_hint_ms` estimate and whether the session is
    /// `single_relay` (no mesh peers). Descriptor-driven like
    /// [`set_expected_slots`](Self::set_expected_slots): set on create and on
    /// every re-sync, so a rehome-rebuilt descriptor keeps them current (harmless
    /// on a resumed relay, which never sizes a depth). Idempotent on a repeat.
    pub fn set_session_shape(&mut self, latency_hint_ms: Option<u32>, single_relay: bool) {
        self.latency_hint_ms = latency_hint_ms;
        self.single_relay = single_relay;
    }

    /// The computed initial latency-buffer depth this relay stamps onto the
    /// `SessionStart` directive — `Some` once the authority sized it at the
    /// coverage latch (or a peer adopted the authority's value), `None`
    /// otherwise. Read for every fan-out and late re-push.
    pub fn initial_buffer_turns(&self) -> Option<u32> {
        self.initial_buffer_turns
    }

    /// Adopts the authority's `SessionStart` on a peer relay: latches the session
    /// started (so this relay's own late-registering local slots still get a
    /// re-push) and, when the directive carried a depth, adopts it as this relay's
    /// current buffer and stores it for this relay's own re-pushes — so a later
    /// promotion reasons from the right base and this relay stamps the same depth.
    /// A depth-less directive (an authority that predates the field, or a resumed
    /// re-home re-push into a running game) leaves the buffer untouched: a stale
    /// initial depth must never resize a live game. The depth is clamped
    /// defensively (bounds plus the game-sync-safe ceiling), though the
    /// authority already clamped it before stamping.
    ///
    /// Also stamps this relay's own wall clock as the session's start instant, so
    /// every relay that knows the session started can restate one on its
    /// heartbeat. The coordinator keeps the first instant it is told, so the
    /// authority's own (earlier) stamp wins wherever it arrives; this slightly
    /// later stand-in is what a tenant gets when the authority's notice was lost
    /// and the authority died before a beat could restate it.
    pub fn adopt_session_start(&mut self, initial_buffer_turns: Option<u32>) {
        self.latch_started();
        self.note_started_at_ms(unix_millis());
        if let Some(depth) = initial_buffer_turns {
            let clamped = self.game_safe_clamp(depth);
            self.buffer = BufferSize(clamped);
            self.initial_buffer_turns = Some(clamped);
        }
    }

    /// Clamps a buffer depth into this session's policy bounds, then caps it at
    /// [`GAME_SYNC_SAFE_BUFFER_MAX`] regardless of what those bounds allow. The
    /// coordinator validates its tenant registry against the same ceiling, but
    /// bounds also reach the relay straight off the wire — a descriptor from an
    /// older or misconfigured coordinator deserializes with no validation — and
    /// a depth past the ceiling deterministically mass-drops the game's players
    /// (the game's own sync validation, not the relay, is what breaks). Every
    /// depth the relay emits (the computed seed, an adopted seed, and each
    /// buffer directive) funnels through this, so no configuration can make the
    /// relay issue a game-breaking depth.
    pub(in crate::consensus) fn game_safe_clamp(&self, depth: u32) -> u32 {
        self.bounds.clamp(depth).min(GAME_SYNC_SAFE_BUFFER_MAX)
    }

    /// Sizes the session's initial latency-buffer depth at the coverage latch,
    /// from the pre-start conditions the authority has accumulated. The result is
    /// clamped to [`BufferBounds`].
    ///
    /// `observed` is the control law's [`target`](Self::target) over those
    /// conditions (the pairwise path of the two highest effective-RTT slots plus a
    /// loss-risk term); `hint_turns` converts the descriptor's one-way
    /// `latency_hint_ms` into turns. The session is **fully observed** only when it
    /// is single-relay *and* every expected, still-present slot has an RTT
    /// sample — a multi-relay session's per-slot conditions never cross the mesh
    /// before the game starts, and a local slot may not have measured yet. A fully
    /// observed session uses `observed` alone (the hint is a fallback for what the
    /// window couldn't see, not a floor over reality). Otherwise it takes
    /// `max(observed, hint)` and adds a one-turn hop cushion for a multi-relay
    /// session (mirroring the in-game per-hop delivery cushion: pairwise max is two
    /// hops, so +1). With neither observed nor hint, it falls back to `bounds.min`.
    pub(in crate::consensus) fn compute_initial_depth(&self) -> u32 {
        let observed = self.target();
        let hint_turns = self.latency_hint_turns();

        let depth = if self.single_relay && self.all_expected_slots_have_rtt() {
            // Fully observed: the pre-start window saw every expected slot's link,
            // so the observed target is the truth; the hint is deliberately ignored
            // (a stale estimate must not distort a fully-observed session). With
            // every slot sampled, `observed` is `Some`, but fall back defensively.
            observed.unwrap_or(self.bounds.min)
        } else if observed.is_none() && hint_turns.is_none() {
            // Nothing to size from — the pre-start window saw no RTT and no hint was
            // supplied. Today's behavior: start at the tenant minimum.
            self.bounds.min
        } else {
            let base = observed.unwrap_or(0).max(hint_turns.unwrap_or(0));
            // One turn of hop cushion when the session spans more than one relay.
            let cushion = u32::from(!self.single_relay);
            base.saturating_add(cushion)
        };

        self.game_safe_clamp(depth)
    }

    /// The descriptor's one-way `latency_hint_ms` converted to whole turns:
    /// `ceil(ms * 1000 / turn_duration_us)`. The hint is the same one-way
    /// pairwise-path quantity as the control law's path term, so the ms→turns
    /// conversion lives here, in one place. `None` when no hint was supplied (or,
    /// defensively, when the turn duration is zero).
    pub(in crate::consensus) fn latency_hint_turns(&self) -> Option<u32> {
        let turn_us = u64::from(self.law.turn_duration_us);
        if turn_us == 0 {
            return None;
        }
        self.latency_hint_ms.map(|ms| {
            let us = u64::from(ms).saturating_mul(1000);
            // Whole turns, rounded up: a fractional turn of latency still needs a
            // full turn of cushion. Bounded by `bounds.clamp` at the call site.
            us.div_ceil(turn_us).min(u64::from(u32::MAX)) as u32
        })
    }

    /// Whether every expected, still-present slot has at least one RTT sample —
    /// the "fully observed" precondition. A departed slot is not still-present, so
    /// it is exempt (at the latch, coverage means no expected slot has departed, so
    /// this is defensive). A slot with no tracked conditions, or one QUIC has not
    /// measured yet (RTT `0`), is not sampled, so the session is not fully observed
    /// and the hint fallback applies.
    pub(in crate::consensus) fn all_expected_slots_have_rtt(&self) -> bool {
        self.expected_slots.iter().all(|slot| {
            self.departures.contains_key(slot) || self.slots.get(slot).is_some_and(|s| s.rtt() > 0)
        })
    }
}
