//! Session start and session shape: the roster the coordinator descriptor
//! sets, the presence coverage that latches the session started, the initial
//! buffer depth start sizes, and the region-label and arrival-phase state that
//! hangs off the same start instant.

use super::*;

impl DecisionMaker {
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

    /// Replaces the session's observer slots (from the coordinator descriptor)
    /// on a re-push, dropping any newly-observer slot from the desync compare
    /// set — an observer must never be a required reporter. The first descriptor
    /// seeds the observer set at maker creation instead (see
    /// [`DecisionMaker::new`]); this re-applies it when a later descriptor
    /// carries a changed set, so the observer set follows the descriptor rather
    /// than accumulating.
    pub fn set_observers(&mut self, observers: HashSet<SlotId>) {
        for slot in &observers {
            self.sync.remove_member(*slot);
        }
        self.observers = observers;
    }

    /// Replaces the session's expected-slot set from the coordinator descriptor —
    /// the slots that must connect before the session may start. Descriptor-driven
    /// like [`set_observers`](Self::set_observers): the first descriptor seeds it,
    /// a later one carrying a changed set replaces it. Never clears the `started`
    /// latch: a session that already started stays started even if a re-push
    /// reshaped the expected set.
    pub fn set_expected_slots(&mut self, expected: HashSet<SlotId>) {
        self.expected_slots = expected;
    }

    /// Replaces the session's homed-slot set from the coordinator descriptor —
    /// the slots the coordinator assigned to THIS relay. Descriptor-driven like
    /// [`set_expected_slots`](Self::set_expected_slots): the first descriptor
    /// seeds it, a later one (e.g. a rehome) replaces it wholesale, so a slot
    /// moved off this relay stops being admissible here and one moved onto it
    /// starts being admissible, with no accumulation across descriptors.
    pub fn set_homed_slots(&mut self, homed: HashSet<SlotId>) {
        self.homed_slots = homed;
    }

    /// Replaces the session's relay → region labels from the coordinator
    /// descriptor, returning the map to (re)send when the release gate is already
    /// open and the new map differs from what clients were last told — a re-home
    /// names a different relay, and a client still holding the old map would
    /// label a member by a relay that no longer serves it.
    ///
    /// Returns `None` while the gate is shut, so a descriptor push can never be
    /// the thing that leaks a label early: the labels are recorded and go nowhere
    /// until [`maybe_release_region_labels`](Self::maybe_release_region_labels)
    /// opens the gate. Descriptor-driven like
    /// [`set_expected_slots`](Self::set_expected_slots) — a later push replaces
    /// the map wholesale rather than accumulating.
    #[must_use]
    pub fn set_region_labels(&mut self, labels: Vec<RegionLabel>) -> Option<Vec<RegionLabel>> {
        if self.region_labels == labels {
            return None;
        }
        self.region_labels = labels;
        self.released_region_labels()
    }

    /// Opens the region-label release gate once `delay` has elapsed since this
    /// relay latched the session started, returning the map to fan out on the one
    /// call that opens it.
    ///
    /// `Some` comes back on that single transition only, and only when there is
    /// actually a map to send; every later call returns `None`, so a caller on the
    /// turn path fans the labels out exactly once. A session that never starts, or
    /// that ends inside the delay, never opens its gate and never sends labels —
    /// the intended outcome, not a failure.
    ///
    /// Reads nothing but this relay's own clock and its own start latch. In
    /// particular it does **not** read the turns being delivered: a turn's
    /// `game_frame_count` is a client-asserted claim, and a relay delivers turns
    /// that originated at other relays, so keying on one would let a single client
    /// open the gate across every relay serving the session. `delay` is a caller
    /// parameter rather than a direct read of [`REGION_LABEL_RELEASE_DELAY`] so a
    /// relay can be built with a shortened one for testing without a second
    /// gate-evaluating path existing at all.
    #[must_use]
    pub fn maybe_release_region_labels(&mut self, delay: Duration) -> Option<Vec<RegionLabel>> {
        if self.region_labels_released {
            return None;
        }
        if self.started_at?.elapsed() < delay {
            return None;
        }
        self.region_labels_released = true;
        self.released_region_labels()
    }

    /// Moves this session's recorded start instant `by` further into the past, so
    /// a test can drive the region-label gate's elapsed-time condition without
    /// sleeping out a real delay. A no-op on a session that has not started —
    /// there is no clock to move, and the gate stays shut either way.
    #[cfg(test)]
    pub(in crate::consensus) fn backdate_session_start(&mut self, by: Duration) {
        self.started_at = self.started_at.and_then(|at| at.checked_sub(by));
    }

    /// The session's relay → region labels when the release gate is open and
    /// there are labels to send, else `None`. Read for the direct push a slot
    /// gets when it connects after the gate has already opened, so a late or
    /// reconnecting client is not left without them.
    pub fn released_region_labels(&self) -> Option<Vec<RegionLabel>> {
        (self.region_labels_released && !self.region_labels.is_empty())
            .then(|| self.region_labels.clone())
    }

    /// Folds one client-edge arrival into the send-phase controller and runs a
    /// control iteration if one is due, returning the slots whose commanded
    /// delay changed (usually none — the controller self-gates on its own
    /// schedule). Arrivals before the session starts are ignored: pre-start
    /// traffic flows at setup cadence, not the turn cadence a phase lives in.
    ///
    /// The caller must feed only this relay's own client-edge receipts, and
    /// only packets that first-delivered exactly one turn — a mesh-forwarded
    /// copy times another relay's hop, and a catch-up burst times the
    /// recovery, neither the sender's phase (see
    /// [`PhaseController::note_arrival`](crate::consensus::phase::PhaseController::note_arrival)).
    #[must_use]
    pub fn ingest_arrival_phase(
        &mut self,
        slot: SlotId,
        seq: u64,
        now: Instant,
    ) -> Vec<(SlotId, u32)> {
        if !self.started {
            return Vec::new();
        }
        self.phase.note_arrival(slot, seq, now);
        let corrections = self.phase.evaluate(now);
        if !corrections.is_empty() {
            tracing::info!(
                tenant = self.key.tenant.as_ref(),
                session = self.key.session.0,
                corrections = corrections.len(),
                span_us = self.phase.last_span_us(),
                issued_total = self.phase.corrections_issued(),
                "issuing send-phase corrections",
            );
        }
        corrections
    }

    /// The send-phase delay `slot` was last commanded, if corrections were
    /// ever issued for it — the value to re-push when it (re)connects.
    pub fn commanded_phase_delay(&self, slot: SlotId) -> Option<u32> {
        self.phase.commanded(slot)
    }

    /// Releases `slot`'s send-phase command fence on its acknowledgement (see
    /// [`PhaseController::note_applied`](crate::consensus::phase::PhaseController::note_applied)).
    pub fn note_phase_applied(&mut self, slot: SlotId, delay_us: u32, now: Instant) {
        self.phase.note_applied(slot, delay_us, now);
    }

    /// Records this relay's own id, stamped onto every `BufferDirective` this
    /// maker queues from here on (see `queue_directive`).
    /// Idempotent — the caller's own id never changes for a running relay
    /// process, so calling this again on every descriptor push is harmless.
    pub fn set_own_relay_id(&mut self, id: RelayId) {
        self.own_relay_id = Some(id);
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
        self.note_started_at_ms(now_ms());
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

    /// Whether `slot` is admissible on this relay: the homed set is empty
    /// (unenforced — see the field's doc) or contains `slot`. Read by
    /// [`slot_homed`] at client admission.
    pub(in crate::consensus) fn admits_slot(&self, slot: SlotId) -> bool {
        self.homed_slots.is_empty() || self.homed_slots.contains(&slot)
    }

    /// Whether the descriptor strictly homes `slot` here — see the free
    /// [`slot_strictly_homed`] for why this, unlike `admits_slot`, never
    /// fails open on an empty set.
    pub(in crate::consensus) fn strictly_homes(&self, slot: SlotId) -> bool {
        self.homed_slots.contains(&slot)
    }

    /// Whether `slot` currently has a live (Up) connection generation.
    pub(in crate::consensus) fn connection_is_up(&self, slot: SlotId) -> bool {
        matches!(
            self.connection_states.get(&slot),
            Some(ConnectionState::Up(_))
        )
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
