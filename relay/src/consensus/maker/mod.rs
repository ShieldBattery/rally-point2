//! The per-session [`DecisionMaker`]: the state every concern below folds
//! into, plus its constructor and the plain accessors.
//!
//! The behavior is split across sibling files by concern -- frame observation
//! and authority handoff, connection epochs, the buffer control law, synced
//! leaves and departures, session start and shape, the silence watch, and the
//! desync hook -- each contributing its own `impl DecisionMaker` block.

use super::*;

mod authority;
mod buffer;
mod connection;
mod departure;
mod leave;
mod silence;
mod start;
mod sync;

pub use departure::{DepartureStamps, RecordedDeparture};
pub use silence::SilentSlot;

pub(in crate::consensus) use departure::Departure;

/// The latency-buffer decision-maker for one session.
///
/// Owns the per-slot condition history (RTT ring buffer for jitter, cumulative
/// counter differencing for loss, mesh-hop RTT for cross-relay paths, the
/// newest validated frame), the current buffer size, the session frame the
/// last decision was made at (for min-dwell on lowers), and the directive
/// currently being broadcast.
///
/// One instance per session. Fed frame observations off validated turns via
/// [`observe_frame`](Self::observe_frame) and conditions by `run_slot_link`
/// (home-client conditions, via [`ingest_local`](Self::ingest_local)) and
/// `run_mesh_link` (peer-relay conditions, via
/// [`ingest_remote`](Self::ingest_remote)) -- but it decides only when
/// `Authority::SelfRelay`.
pub struct DecisionMaker {
    pub(in crate::consensus) key: SessionKey,
    pub(in crate::consensus) bounds: BufferBounds,
    pub(in crate::consensus) law: ControlLaw,
    pub(in crate::consensus) authority: Authority,

    /// The current buffer size, clamped to bounds. Starts at `bounds.min`.
    pub(in crate::consensus) buffer: BufferSize,
    /// The send-phase controller for this relay's own home slots: client-edge
    /// arrival phases in, per-slot delay corrections out (see [`crate::consensus::phase`]).
    /// A sibling of the buffer law, not an input to it — the law keeps sizing
    /// the buffer from pacing and loss exactly as before, while this aligns the
    /// phases that pacing is blind to. Fed only from this relay's client edge,
    /// so on every relay (authority or not) it covers exactly the slots whose
    /// wire arrivals this relay observes first-hand.
    pub(in crate::consensus) phase: crate::consensus::phase::PhaseController,
    /// Per-slot condition history and frame observations.
    pub(in crate::consensus) slots: HashMap<SlotId, SlotState>,
    /// The physical connection lifecycle for each epoch-aware slot. Epochs are
    /// opaque random equality tokens, not ordered counters. Keeping this map
    /// independently of `slots` makes a down generation a tombstone across
    /// departure/removal, so delayed datagrams and teardown from an older
    /// connection cannot recreate or erase the replacement's state.
    ///
    /// An absent entry is the rolling-upgrade legacy mode: wire messages with
    /// no epoch remain admissible until this relay observes a present epoch for
    /// the slot. Once fenced, absent messages cannot downgrade it back.
    pub(in crate::consensus) connection_states: HashMap<SlotId, ConnectionState>,
    /// Every superseded random epoch for each slot, retained until this session's
    /// decision-maker is destroyed. Epochs are equality-only tokens, so there is
    /// no safe age/order cutoff: evicting even the oldest token would let an
    /// arbitrarily delayed reliable `connected=true` resurrect that generation.
    /// The current Down(E) tombstone remains in `connection_states`; it moves here
    /// only when a distinct replacement becomes current.
    pub(in crate::consensus) retired_connection_epochs: HashMap<SlotId, HashSet<u64>>,
    /// The session frame at which the last decision was *made* (not applied).
    /// Used to gate lowers: a lower is suppressed until the session frame has
    /// advanced `min_dwell_turns` past it. Raises are never suppressed (you
    /// can't dwell through a stall).
    pub(in crate::consensus) last_decision_frame: Option<GameFrameCount>,
    /// Trailing peaks of the control law's target, spanning 4x
    /// [`ControlLaw::shrink_lookback_turns`] of session-frame progress. The
    /// base slice ([`TARGET_FLOOR_BASE_BUCKETS`]) is the shrink floor: a
    /// shrink never takes the buffer below the target's maximum over one
    /// lookback, because noisy conditions make the target *recur* at its
    /// high-water rather than sit on it, and a buffer lowered into that
    /// recurrence is immediately re-raised -- flapping on the shrink-dwell
    /// cadence. The full span serves edge probation (`edge_burned`): once a
    /// floor-level shrink has been disproven, the next one must clear the
    /// whole 4x window. Parking at the high-water (and shrinking only as
    /// peaks age out) keeps the buffer still through sustained noise while
    /// still coming down, boundedly, once conditions genuinely improve.
    pub(in crate::consensus) target_peaks: BucketedMax<TARGET_FLOOR_BUCKETS>,
    /// The most recent shrink decision: the buffer level it left and the
    /// session frame it fired at. A raise arriving within two lookbacks that
    /// returns to (or passes) the departed level *disproves* that shrink --
    /// the cushion it removed was still needed -- and burns the edge.
    pub(in crate::consensus) last_shrink: Option<ShrinkRecord>,
    /// Whether a floor-level ("edge") shrink has been disproven: the next
    /// edge shrink must then clear the full [`EDGE_PROBATION_BUCKETS`]
    /// peak-free window (~4x the lookback) instead of the base slice. One
    /// strike: on a noisy edge, the law gets to be wrong about dipping once
    /// per episode before it parks -- dips into a stuttery buffer are exactly
    /// the feel this law exists to avoid. Expires only after a long burn-free
    /// stretch: probation never gates shrinks landing *above* the floor, so
    /// keeping the burn through a genuine recovery costs nothing, while
    /// clearing it on one that merely looks genuine re-arms the edge for
    /// another dip.
    pub(in crate::consensus) edge_burned: bool,
    /// The session frame of the most recent burn, for the long-quiet reset.
    pub(in crate::consensus) last_burn_frame: Option<u32>,
    /// Orders this session's decisions on the wire. Incremented for every
    /// broadcast directive, so clients receiving copies out of order (or a
    /// superseded directive after its replacement) keep only the newest. Also
    /// advanced by [`observe_directive`](Self::observe_directive) to the
    /// highest seq seen on *forwarded* stamps: an authority's local turns carry
    /// each directive directly to every relay serving the session, so a relay promoted to authority
    /// continues the numbering instead of restarting below what clients
    /// already hold (which they would ignore).
    pub(in crate::consensus) decision_seq: u32,
    /// The `authority_relay_id` carried by the directive `decision_seq`
    /// currently reflects — this relay's own id when it authored the decision,
    /// the stamp's id when [`observe_directive`](Self::observe_directive)
    /// adopted a forwarded one. Each authority stamps its own `decision_seq`
    /// count from where IT started, so during a staggered handoff two relays
    /// can collide on the same seq with different buffers; clients break that
    /// tie by relay id (see `directive::DirectiveTracker` in the client
    /// crate), and this field lets `observe_directive` apply the identical
    /// rule — otherwise a relay would latch whichever equal-seq copy it saw
    /// first and could disagree with its clients about the session buffer
    /// until the next decision.
    pub(in crate::consensus) decision_seq_tiebreak: Option<u64>,
    /// The `decision_seq` of the last observed directive whose depth exceeded
    /// [`GAME_SYNC_SAFE_BUFFER_MAX`] and drew the over-ceiling tripwire, so
    /// the warn and flight event fire once per such decision rather than on
    /// every redundant stamped-turn copy. Only a peer authority running code
    /// that predates the ceiling can author one; this relay's own decisions
    /// are clamped at the source.
    pub(in crate::consensus) over_ceiling_warned_seq: Option<u32>,
    /// The buffer change currently being broadcast, if any. Set when a
    /// decision fires; handed out by
    /// [`active_directive`](Self::active_directive) for every forwarded turn,
    /// and retired once the session frame reaches its apply frame -- by then
    /// every slot has passed the frame, so the change is applied (or moot)
    /// everywhere. A non-authority relay never sets this (it makes no
    /// decisions), so it never stamps -- it only forwards the authority's
    /// already-stamped turns verbatim.
    pub(in crate::consensus) pending_directive: Option<BufferDirective>,
    /// The control-law derivation behind [`pending_directive`], for the flight
    /// recording only -- no decision reads it back. Unlike the directive, which
    /// keeps being stamped onto turns until the session passes its apply frame,
    /// this is consumed by the recording of the decision that produced it, so a
    /// later directive can never be recorded against a stale derivation.
    pub(in crate::consensus) pending_decision_inputs: Option<BufferDecisionInputs>,
    /// Whether this authority has broadcast the session's buffer at least once.
    /// The control law only emits a directive when the buffer *changes*, so a
    /// session that sits at its initial buffer never broadcasts one -- and a
    /// client that seeded a different buffer than the relay's initial state is
    /// then never corrected. This flag drives a single unconditional broadcast of
    /// the current buffer at the first framed turn (see [`decide`](Self::decide))
    /// to close that gap. Reset to `false` on promotion so a newly promoted
    /// authority re-affirms the buffer to every survivor, the same way a promotion
    /// re-broadcasts leaves.
    pub(in crate::consensus) initial_directive_sent: bool,
    /// End-to-end delivery tracking: which origins' turns have reached which
    /// destination clients, folded from the beacon cursors this relay taps
    /// locally and receives over the mesh. Feeds the control law's target a
    /// clamped additive cushion (see [`decide`](Self::decide)) and the flight
    /// recorder's per-session lag/hop fields; the law itself never reads it
    /// beyond that one additive term.
    pub(in crate::consensus) delivery: crate::consensus::delivery::DeliveryTracking,
    /// The session frame at which the control law's inputs were last traced, for
    /// the rate-limited diagnostic in [`decide`](Self::decide). `None` until the
    /// first trace. Only observability state; carries no decision meaning.
    pub(in crate::consensus) last_trace_frame: Option<u32>,
    /// The synced player-leaves this relay has authored (as authority) or
    /// observed (a peer relay's authority pushed it across the mesh), keyed by
    /// slot. A leave is a one-shot: it is pushed down each surviving client's
    /// reliable control stream (never stamped onto turns -- a drop stops the turn
    /// stream). This map dedups a slot so a duplicate signal doesn't re-decide or
    /// re-cache it, and -- crucially -- **survives a demotion**: it is exactly the
    /// set a later promotion re-broadcasts, so a leave the previous authority
    /// decided is not lost when authority moves. Bounded by the slot count (<=12),
    /// so keeping it costs nothing.
    pub(in crate::consensus) decided_leaves: HashMap<SlotId, LeaveDirective>,
    /// Every slot departure this relay has observed for the session -- its own
    /// home client's link ending, or a peer relay's `SlotDeparted` frame -- kept
    /// so a later promotion can re-derive a leave the previous authority never got
    /// to author. Also survives a demotion.
    ///
    /// Recording a departure *retires* the slot from `slots` (on every relay,
    /// not just the slot's home — see [`note_departure`](Self::note_departure)),
    /// so this record is the sole owner of the departed slot's last frame, and
    /// membership here doubles as the guard that keeps late in-flight traffic
    /// from resurrecting the slot's live state.
    pub(in crate::consensus) departures: HashMap<SlotId, Departure>,
    /// Next `leave_seq` to assign -- its own space, distinct from `decision_seq`
    /// (buffer and leave directives never supersede one another). Clients dedup
    /// leaves by slot, so this only has to be non-colliding per distinct leave.
    /// Kept above every observed `leave_seq` so a promoted relay's own numbering
    /// never collides with what clients already hold.
    pub(in crate::consensus) next_leave_seq: u32,
    /// Slots the coordinator flagged as observers (from the session descriptor).
    /// Excluded from the desync comparator — observers do not reliably emit sync
    /// commands, so requiring their checksums would stall the cross-check.
    /// Descriptor-driven, so it survives authority changes (unlike the comparator
    /// state, which resets on promotion).
    pub(in crate::consensus) observers: HashSet<SlotId>,
    /// The end-of-game result each slot reported, keyed by slot. First report per
    /// slot wins; a repeat is dropped without firing a second notice — the same
    /// anti-flooding posture as the one-sync-command-per-turn rule. The full
    /// result is retained (not just a marker) so this relay — the reporting slot's
    /// home — can embed it into the slot's departure record and `SlotDeparted`
    /// frame when the slot leaves. Bounded by the slot count (≤12) times the
    /// per-result cap. Not tied to the desync comparator, so it survives an
    /// authority change (a result is a per-slot one-shot the relay reports
    /// regardless of authority).
    pub(in crate::consensus) results: HashMap<SlotId, ResultEcho>,
    /// The per-session desync comparator. Only meaningful while this relay is the
    /// authority; reset wholesale on promotion (a real desync re-diverges every
    /// interval, so no state need transfer across a handoff).
    pub(in crate::consensus) sync: SyncTracker,
    /// The slots the coordinator expects to connect before the session may start
    /// (every player and observer, from the session descriptor). Empty disables
    /// the session-start directive — a session whose descriptor carried no
    /// expected set (a standalone relay, a coordinator that predates the field)
    /// never fires one. Descriptor-driven, so it survives authority changes
    /// (like `observers`).
    pub(in crate::consensus) expected_slots: HashSet<SlotId>,
    /// The slots the coordinator assigned to home on THIS relay (from the
    /// session descriptor). Empty means unenforced — a standalone relay, a
    /// dev-injected descriptor, or a coordinator that predates the field —
    /// exactly like `expected_slots` empty disables the start directive. Read
    /// by [`slot_homed`] at client admission, in `server.rs`, to refuse a
    /// token authorized for a slot this relay does not home: a token binds
    /// tenant/session/slot/key but not the relay, so without this check the
    /// same slot could register on two relays in a true multi-relay session.
    /// Descriptor-driven, so it survives authority changes (like
    /// `expected_slots`).
    pub(in crate::consensus) homed_slots: HashSet<SlotId>,
    /// The slots this relay has seen registered anywhere in the session: its own
    /// registered slots plus the ones peer relays reported via `SlotPresent`.
    /// Every relay accumulates it (not just the authority) so a relay promoted
    /// mid-startup can evaluate coverage against the fullest view. A slot's
    /// departure removes it here, but the `started` latch, once set, stays set.
    pub(in crate::consensus) live_slots: HashSet<SlotId>,
    /// Whether the session-start directive has been emitted for this session — a
    /// one-shot latch. Set when the authority first sees `live_slots` cover
    /// `expected_slots`, or when a peer relay's `SessionStart` arrives, so a set
    /// re-covering after churn never re-fires and a late-registering local slot
    /// still gets a re-push.
    pub(in crate::consensus) started: bool,
    /// Every slot whose link has activated on this relay for the session. Grows
    /// monotonically — a slot that connected and then dropped stays, because the
    /// question this answers is whether the player ever arrived, not who is here
    /// now (`live_slots` answers that). Retained so every heartbeat can restate
    /// the whole set: the matching notice is dropped once its send succeeds, so
    /// the beat is what survives a coordinator losing or forgetting one.
    pub(in crate::consensus) connected_slots: HashSet<SlotId>,
    /// Every slot whose game-loop report this relay accepted **from its own home
    /// client**. Grows monotonically and is restated on every heartbeat, for the
    /// same reasons as `connected_slots` — and stays home-only precisely so the
    /// heartbeat keeps meaning "the slots I myself watched start", with no relay
    /// restating another relay's slot to the coordinator. It is also the set the
    /// home shares over the mesh when a link (re)joins.
    pub(in crate::consensus) started_slots: HashSet<SlotId>,
    /// Slots a peer relay reported started over the mesh (`SlotStarted`), which
    /// only ever names slots that peer homes. Kept apart from `started_slots` so
    /// nothing this relay reports upward is second-hand; the two are read as a
    /// union wherever the question is simply whether a slot has left loading
    /// behind (see [`has_started`](Self::has_started)).
    pub(in crate::consensus) peer_started_slots: HashSet<SlotId>,
    /// Slots this relay closed for producing no turns while the session advanced
    /// past them (see [`silent_slot`](Self::silent_slot)). Kept so a
    /// re-dialing client whose simulation is dead is refused rather than
    /// readmitted: readmission would clear the survivors' drop hold and restart
    /// their countdown on every redial, which is the stall this eviction exists
    /// to end. Only the slot's home ever marks one, since only the home closed
    /// the link.
    pub(in crate::consensus) silence_evicted: HashSet<SlotId>,
    /// When each decided leave was decided here, on this relay's monotonic
    /// clock: the instant this relay authored the decision, or the instant a
    /// peer authority's directive for the slot arrived. The silence watch keeps
    /// a decided slot among the participants it compares until every live
    /// participant has forwarded something after this instant — the survivors'
    /// stalled clocks are explained by the slot that left until each of them
    /// demonstrably resumed past the leave (see [`silent_slot`](Self::silent_slot)).
    /// Bounded by the slot count (<=12).
    pub(in crate::consensus) decided_leave_at: HashMap<SlotId, Instant>,
    /// Decided leaves every live participant has demonstrably resumed past, so
    /// the silence watch no longer counts them among the session's participants.
    /// One-way: a slot enters when that recovery test passes and never leaves,
    /// so a stop time that later moves backwards (a reconnect seeding fresh
    /// state) cannot put a long-gone slot back into the comparison.
    pub(in crate::consensus) recovered_leaves: HashSet<SlotId>,
    /// Whether the silence watch has already recorded, for this session, that a
    /// resumed descriptor stands it down. The watch re-examines every session
    /// every couple of seconds and the reason it declines is a property of the
    /// session, so it is worth saying once and never again.
    pub(in crate::consensus) resume_stand_down_logged: bool,
    /// Relay wall-clock (unix epoch milliseconds) for the session's start,
    /// restated on every heartbeat: this relay's own coverage latch where the
    /// latch fires here, otherwise the moment it adopted the authority's
    /// directive off the mesh. `None` until the session starts here. First write
    /// wins, matching the latch itself.
    pub(in crate::consensus) started_at_ms: Option<u64>,
    /// One-shot latch: a resumed (rehome) descriptor has named this session.
    /// After a rehome no single relay's forward gate provably covers
    /// everything every survivor consumed — the replaced relay can have
    /// delivered turns toward one surviving relay that another (including the
    /// slot's fresh home) never carried — so a leave decided after this point
    /// must not stamp an exact `final_turn_count`; see
    /// [`commit_leave`](Self::commit_leave). Departures the coordinator seeded
    /// with a count are unaffected: those were decided before the rehome, by
    /// an origin that was sound at the time.
    pub(in crate::consensus) resumed: bool,
    /// Whether this session's descriptor enables home-side drop finalization
    /// (`SessionDescriptor::finalized_drops`). Latched at maker creation and
    /// immutable for the session's lifetime, exactly like the descriptor
    /// field it mirrors: every count-acceptance rule keys on it, so a session
    /// must never change its mind mid-game.
    pub(in crate::consensus) finalized_drops_enabled: bool,
    /// Slots whose drop is being (or has been) home-finalized here: admission
    /// is refused while a slot is in this set, which is what makes the
    /// finalization snapshot's ingress cut real. Populated only on the
    /// slot's home relay. An entry is removed again only when a finalization
    /// attempt fails to produce a count (so a later reconnect can still
    /// resume); a successful finalization's decided leave then refuses
    /// readmission on its own.
    pub(in crate::consensus) finalizing_drops: HashSet<SlotId>,
    /// Homed slots whose forward-gate cursor cannot be trusted as a total
    /// count of the slot's turns: every home this relay *gained* mid-session
    /// (a rehome moved the slot here), plus every home seeded by a resumed
    /// descriptor into a fresh maker. For such a slot this relay was not the
    /// single ingress for the slot's whole history, so even a non-`None`
    /// gap-free forwarded prefix (this relay may have been serving the
    /// session all along, just not homing the slot) can stop short of turns
    /// other relays' clients already consumed — sealing that prefix as the
    /// slot's final turn count would recreate the exact desync finalization
    /// exists to remove. Drop finalization refuses these slots outright; a
    /// home held continuously since the session's first descriptor is the
    /// only sound finalizer. Never removed for the session's lifetime.
    pub(in crate::consensus) rehomed_homes: HashSet<SlotId>,
    /// Whether this relay has already reported its own closure for the session
    /// (the `SessionClosed` notice the coordinator's all-relays-closed
    /// retirement counts). The session-emptied close can be evaluated from
    /// several places — the last local slot's link teardown, a held drop's
    /// decision arriving over the mesh, the abandoned-session force-decide —
    /// and whichever evaluation runs the close claims this latch, so the
    /// others (and any later re-evaluation) don't repeat it. Cleared when a
    /// slot link starts serving the session again: the relay is serving once
    /// more, so its next emptying must be reported anew.
    pub(in crate::consensus) close_reported: bool,
    /// This relay's own id, stamped onto every `BufferDirective` this maker
    /// queues as the deterministic tie-break for two directives that land on
    /// the same `decision_seq` (see [`queue_directive`](Self::queue_directive)
    /// and [`set_own_relay_id`](Self::set_own_relay_id)). `None` until set —
    /// `DecisionMaker::new` has no relay id to seed it with (`sync_maker`'s
    /// many callers, mostly tests that don't care about the tie-break, would
    /// all need updating otherwise); the one production caller
    /// (`MeshControl`) sets it once, right after creating or syncing the
    /// maker, from the id it already carries.
    pub(in crate::consensus) own_relay_id: Option<RelayId>,
    /// The tenant's worst-pairwise one-way path-latency estimate (milliseconds)
    /// for the session, from the descriptor — a fallback the initial-depth
    /// computation folds in for the pre-start window the relay's own link
    /// measurements cannot see. `None` when the descriptor carried none.
    /// Descriptor-driven (set via [`set_session_shape`](Self::set_session_shape)),
    /// so it survives authority changes like `expected_slots`.
    pub(in crate::consensus) latency_hint_ms: Option<u32>,
    /// Whether the session spans exactly one relay (no mesh peers). The
    /// initial-depth computation treats the pre-start conditions as *fully
    /// observed* only for a single-relay session — a multi-relay session's
    /// per-slot conditions never cross the mesh before the game starts — and adds
    /// a one-turn hop cushion for a multi-relay session. Defaults `true` (a
    /// standalone/dev maker with no descriptor is single-relay);
    /// descriptor-driven via [`set_session_shape`](Self::set_session_shape).
    pub(in crate::consensus) single_relay: bool,
    /// The computed initial latency-buffer depth this authority sized at the
    /// coverage latch (see [`maybe_start`](Self::maybe_start)), stored so every
    /// `SessionStart` this relay emits — the session-wide fan-out and each late
    /// re-push — stamps the same value. `None` until the latch fires, on a relay
    /// that never became the deciding authority, and on a resumed relay (which
    /// latches started without sizing a depth). A peer relay adopts the
    /// authority's value here via [`adopt_session_start`](Self::adopt_session_start).
    pub(in crate::consensus) initial_buffer_turns: Option<u32>,
    /// The session's relay → region labels, in the order the coordinator
    /// descriptor listed them. Every relay serving the session receives the whole
    /// session's map on its own descriptor, so nothing is exchanged across the
    /// mesh to build it. Empty for a session whose descriptor carried no labels
    /// (a standalone relay, a dev-injected descriptor, an untagged fleet), which
    /// simply means this relay has nothing to release. Descriptor-driven like
    /// `expected_slots`, so it follows a re-push rather than accumulating.
    pub(in crate::consensus) region_labels: Vec<RegionLabel>,
    /// Whether [`REGION_LABEL_RELEASE_DELAY`] has elapsed since `started_at` —
    /// the one-way latch that permits `region_labels` to leave this relay. Never
    /// cleared: the gameplay that had to elapse already has, so there is nothing
    /// left to conceal, and a slot connecting afterwards must still be told.
    pub(in crate::consensus) region_labels_released: bool,
    /// When this relay latched the session started, on its own monotonic clock.
    /// The region-label release gate measures from here, and so does
    /// [`silent_slot`](Self::silent_slot): it is the stop time of every slot that
    /// has forwarded nothing since the session began. Set exactly once, by
    /// [`latch_started`](Self::latch_started) — every path that starts a session
    /// funnels through it — so a re-delivered start directive (an authority
    /// handoff re-firing, a late slot's re-push) cannot push the clock forward,
    /// deferring the release indefinitely or making a slot that has forwarded
    /// nothing look like it stopped later than it did. `None` until the session
    /// starts, which holds both gates shut.
    pub(in crate::consensus) started_at: Option<Instant>,
}

impl DecisionMaker {
    /// Creates a new decision-maker for `key`, starting at the coordinator's
    /// minimum buffer. `authority` is the injected input: `SelfRelay` to run
    /// the decision core, `Peer` to forward conditions without deciding.
    /// `observers` is the descriptor's observer-slot set: a maker created by a
    /// descriptor starts with that set, so those slots are never required
    /// reporters in the desync comparator from the maker's first turn onward.
    pub fn new(
        key: SessionKey,
        bounds: BufferBounds,
        law: ControlLaw,
        authority: Authority,
        observers: HashSet<SlotId>,
    ) -> Self {
        Self {
            key,
            buffer: BufferSize(bounds.min),
            bounds,
            phase: crate::consensus::phase::PhaseController::new(law.turn_duration_us),
            law,
            authority,
            slots: HashMap::new(),
            connection_states: HashMap::new(),
            retired_connection_epochs: HashMap::new(),
            last_decision_frame: None,
            target_peaks: BucketedMax::default(),
            last_shrink: None,
            edge_burned: false,
            last_burn_frame: None,
            decision_seq: 0,
            decision_seq_tiebreak: None,
            over_ceiling_warned_seq: None,
            pending_directive: None,
            pending_decision_inputs: None,
            initial_directive_sent: false,
            delivery: crate::consensus::delivery::DeliveryTracking::default(),
            last_trace_frame: None,
            decided_leaves: HashMap::new(),
            departures: HashMap::new(),
            next_leave_seq: 0,
            observers,
            results: HashMap::new(),
            sync: SyncTracker::default(),
            expected_slots: HashSet::new(),
            homed_slots: HashSet::new(),
            live_slots: HashSet::new(),
            started: false,
            connected_slots: HashSet::new(),
            started_slots: HashSet::new(),
            peer_started_slots: HashSet::new(),
            silence_evicted: HashSet::new(),
            decided_leave_at: HashMap::new(),
            recovered_leaves: HashSet::new(),
            resume_stand_down_logged: false,
            started_at_ms: None,
            resumed: false,
            finalized_drops_enabled: false,
            finalizing_drops: HashSet::new(),
            rehomed_homes: HashSet::new(),
            close_reported: false,
            own_relay_id: None,
            latency_hint_ms: None,
            single_relay: true,
            initial_buffer_turns: None,
            region_labels: Vec::new(),
            region_labels_released: false,
            started_at: None,
        }
    }

    /// The session this decision-maker serves.
    pub fn key(&self) -> &SessionKey {
        &self.key
    }

    /// The session's end-to-end delivery fold, for the observation feeds (the
    /// beacon tap, the mesh `DeliveryCursors` handler) and the observability
    /// reads. Mutable access is deliberate: the fold is observation-only state
    /// the decision path reads but never writes.
    pub fn delivery_mut(&mut self) -> &mut crate::consensus::delivery::DeliveryTracking {
        &mut self.delivery
    }

    /// The session's end-to-end delivery view (worst pair lag in turns, max
    /// relay hops), for observability. `None` on either half until a pair has
    /// evidence on both ends.
    pub fn delivery_view(&self) -> (Option<u64>, Option<u32>) {
        (
            self.delivery.worst_lag_turns(),
            self.delivery.max_relay_hops(),
        )
    }

    /// The current buffer size.
    pub fn buffer(&self) -> BufferSize {
        self.buffer
    }

    /// The session's consensus coordinate: the *minimum* of the per-slot
    /// frames observed so far, i.e. the slowest participant's progress --
    /// which is what lockstep actually advances by. `None` until at least one
    /// slot has produced a framed turn (lobby). Taking the minimum is the
    /// poisoning defense: `game_frame_count` is client-asserted, so one slot's
    /// inflated claim moves only its own observation, never the coordinate.
    ///
    /// A departed slot is excluded: its departure retires it from `slots`, so
    /// the coordinate follows the *survivors* rather than staying pinned at the
    /// departed slot's frozen last frame for the rest of the game -- which would
    /// freeze the dwell clock and keep a pending buffer directive from ever
    /// retiring.
    pub fn session_frame(&self) -> Option<GameFrameCount> {
        self.slots.values().filter_map(|s| s.frame).min()
    }
}
