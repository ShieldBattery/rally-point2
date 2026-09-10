//! The registry the turn path actually holds: the locked per-session map of
//! decision-makers, the coordinator-bound notice channel and its builders, and
//! the retained per-session load state.
//!
//! Everything here adds locking, logging and notice plumbing around the pure
//! [`DecisionMaker`]; the free functions callers use live in `ops`.

use super::*;

/// The per-session decision-maker map behind [`DecisionMakers`]. A plain
/// (non-async) mutex mirrors `MeshLinks` and `routing::Sessions`: every critical
/// section is a short, await-free insert or lookup, so the lock is never held
/// across a turn's delivery.
pub(in crate::consensus) type MakerMap = HashMap<SessionKey, DecisionMaker>;

/// The tenant's correlation ids for one session, as a relay knows them from the
/// coordinator's [`SessionDescriptor`](rally_point_proto::control::SessionDescriptor).
/// Kept relay-side (not shared with the coordinator's own `session::SessionRefs`
/// type) so this crate has no dependency on the coordinator crate; the shapes
/// mirror each other because both describe the same wire fields.
#[derive(Debug, Clone, Default)]
pub(in crate::consensus) struct SessionExternalRefs {
    /// The tenant's own id for the session (ShieldBattery's `gameId`).
    pub(in crate::consensus) external_id: Option<String>,
    /// The tenant's own id for the player in each slot that carried one.
    pub(in crate::consensus) slots: HashMap<SlotId, String>,
}

/// A notice a relay sends up its coordinator control connection about a running
/// game: a slot connected, the session started, a client's game loop began, a
/// player departed, the game desynced, or a client reported its result.
/// All ride one channel (the leave sites, the sync comparator, the result and
/// game-loop ingresses, and the slot-activation and coverage-latch sites all
/// feed the same sender), so the reconnect buffering that guarantees a queued
/// notice survives a coordinator restart is written once, not per kind.
/// The coordinator client wraps each into the matching
/// [`RelayToCoordinator`](rally_point_proto::control::RelayToCoordinator) frame
/// when it forwards it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayNotice {
    /// A player permanently departed a running game (left vs. dropped).
    Departure(DepartureNotice),
    /// The game's sims diverged — a relay-observed desync.
    Desync(DesyncNotice),
    /// A client reported its end-of-game result, forwarded opaque.
    Result(ResultNotice),
    /// A slot's link activated on this relay — the client arrived (or came back).
    SlotConnected(SlotConnectedNotice),
    /// This relay's authority coverage latch fired: the session started.
    SessionStarted(SessionStartedNotice),
    /// A client reported that its game loop began running.
    SlotStarted(SlotStartedNotice),
    /// This relay tore down its last local state for a session. Fired after the
    /// session's departures have already gone up this same ordered channel, so
    /// the coordinator — which waits for every serving relay to report it — can
    /// treat a delivered close as proof no earlier notice is still in flight.
    SessionClosed {
        /// The tenant the session belongs to.
        tenant: TenantId,
        /// The session this relay closed.
        session: SessionId,
    },
}

/// A registry of per-session decision-makers, one per session this relay is
/// (or may become) the authority for. Shared across the slot-link and mesh-link
/// tasks that feed conditions in.
///
/// It also owns an optional **notice notifier** — the sender half of an
/// unbounded channel drained by the coordinator control connection. The leave
/// sites ([`decide_leave`], [`observe_leave`], and the promotion re-derivation
/// in [`set_authority`]/[`sync_maker`]) fire a [`DepartureNotice`] onto it the
/// moment a synced leave for a slot first enters this relay's cache, and the
/// desync comparator ([`observe_sync`]) fires a [`DesyncNotice`] when it confirms
/// a divergence — so the coordinator learns "player X left vs. was dropped" and
/// "this game desynced at ordinal N". The notifier is set once at startup when a
/// coordinator is configured and is simply absent when the relay runs standalone
/// (no coordinator to notify), where firing is a no-op.
///
/// It also holds each session's **correlation ids** (`SessionExternalRefs`),
/// populated from the coordinator's descriptor at apply time
/// ([`set_session_refs`](Self::set_session_refs)) so a departure notice can be
/// self-describing (carry its own `external_id`/`external_ref`) without the
/// coordinator's in-memory session-refs store surviving to notice time — a
/// coordinator restart wipes that store, but the descriptor a relay already
/// applied does not.
///
/// `Default` (empty maps, no notifier) is what `Arc::<DecisionMakers>::default`
/// builds where a registry is created without going through
/// [`new_decision_makers`] — the same empty state.
#[derive(Default)]
pub struct DecisionMakers {
    pub(in crate::consensus) makers: parking_lot::Mutex<MakerMap>,
    /// Set once at startup, drains into the coordinator control connection.
    /// Absent for a standalone relay. Unbounded so queueing a notice while the
    /// coordinator link is down never blocks the turn path — the drain end holds
    /// the channel across reconnects and flushes pending notices on redial.
    /// Carries the [`RelayNotice`] union so departures, desyncs, and results
    /// share one pipe.
    pub(in crate::consensus) notices: OnceLock<UnboundedSender<RelayNotice>>,
    /// Correlation ids per session, from the coordinator's descriptor. Absent
    /// for a session whose descriptor never carried them (a standalone relay,
    /// or a coordinator that predates the fields) — a departure notice for such
    /// a session simply carries no `external_id`/`external_ref`, and the
    /// coordinator falls back to its own store.
    pub(in crate::consensus) refs: parking_lot::Mutex<HashMap<SessionKey, SessionExternalRefs>>,
    /// The relay-wide flight recorder. Carried here — not as its own parameter
    /// through every task — because this `Arc` already reaches every wiring
    /// site: the slot-link tasks (via `MeshState`), the consensus decision
    /// paths in this module, `MeshControl`, and the binary. Always present
    /// (recording is cheap and bounded); the *sink* is what's optional.
    pub(in crate::consensus) flight: crate::observability::flight_recorder::FlightRecorder,
    /// How long this relay withholds a session's region labels after latching it
    /// started — [`REGION_LABEL_RELEASE_DELAY`] for a production relay. Held here
    /// rather than read directly at the gate so the whole relay can be built with
    /// a shortened delay (see [`new_decision_makers_with_region_delay`]) instead
    /// of the gate growing a second, test-only evaluation path.
    pub(in crate::consensus) region_release_delay: Duration,
}

impl DecisionMakers {
    /// Locks the per-session map. Kept method-shaped (rather than exposing the
    /// mutex directly) so every existing `registry.lock()` call site is
    /// unchanged by the registry gaining the departure notifier.
    pub fn lock(&self) -> parking_lot::MutexGuard<'_, MakerMap> {
        self.makers.lock()
    }

    /// The relay-wide flight recorder (see the field's doc for why it rides
    /// this registry).
    pub fn flight_recorder(&self) -> &crate::observability::flight_recorder::FlightRecorder {
        &self.flight
    }

    /// Installs the notice notifier — the sender half of the channel the
    /// coordinator control connection drains (departures and desyncs both). Set
    /// once at startup; a second call is ignored (the first sender wins), matching
    /// the "one coordinator link per relay" reality.
    pub fn set_notice_notifier(&self, sender: UnboundedSender<RelayNotice>) {
        let _ = self.notices.set(sender);
    }

    /// Fires a notice up the coordinator control connection, if a notifier is
    /// installed. A no-op on a standalone relay. The channel is unbounded, so this
    /// never blocks; a send error means the drain end is gone (no coordinator
    /// subscriber), which for a standalone relay is expected.
    pub(in crate::consensus) fn emit_notice(&self, notice: RelayNotice) {
        if let Some(sender) = self.notices.get() {
            let _ = sender.send(notice);
        }
    }

    /// Fires a departure notice (see [`emit_notice`](Self::emit_notice)).
    pub(in crate::consensus) fn notify_departure(&self, notice: DepartureNotice) {
        self.emit_notice(RelayNotice::Departure(notice));
    }

    /// Fires a desync notice (see [`emit_notice`](Self::emit_notice)).
    pub(in crate::consensus) fn notify_desync(&self, notice: DesyncNotice) {
        self.emit_notice(RelayNotice::Desync(notice));
    }

    /// Fires a result notice (see [`emit_notice`](Self::emit_notice)).
    pub(in crate::consensus) fn notify_result(&self, notice: ResultNotice) {
        self.emit_notice(RelayNotice::Result(notice));
    }

    /// Fires a slot-connected notice (see [`emit_notice`](Self::emit_notice)).
    pub(in crate::consensus) fn notify_slot_connected(&self, notice: SlotConnectedNotice) {
        self.emit_notice(RelayNotice::SlotConnected(notice));
    }

    /// Fires a session-started notice (see [`emit_notice`](Self::emit_notice)).
    pub(in crate::consensus) fn notify_session_started(&self, notice: SessionStartedNotice) {
        self.emit_notice(RelayNotice::SessionStarted(notice));
    }

    /// Fires a slot-started notice (see [`emit_notice`](Self::emit_notice)).
    pub(in crate::consensus) fn notify_slot_started(&self, notice: SlotStartedNotice) {
        self.emit_notice(RelayNotice::SlotStarted(notice));
    }

    /// Fires a session-closed notice (see [`emit_notice`](Self::emit_notice)).
    pub(in crate::consensus) fn notify_session_closed(&self, tenant: TenantId, session: SessionId) {
        self.emit_notice(RelayNotice::SessionClosed { tenant, session });
    }

    /// Records `key`'s correlation ids from a coordinator descriptor, replacing
    /// whatever was recorded before. Called on every descriptor apply (not just
    /// the first), so a changed descriptor's refs replace rather than
    /// accumulate alongside a stale copy.
    pub fn set_session_refs(
        &self,
        key: &SessionKey,
        external_id: Option<String>,
        slots: HashMap<SlotId, String>,
    ) {
        self.refs
            .lock()
            .insert(key.clone(), SessionExternalRefs { external_id, slots });
    }

    /// Forgets `key`'s correlation ids (the session ended). Idempotent; mirrors
    /// the maker's own removal so this map doesn't outlive the sessions it
    /// describes.
    pub(in crate::consensus) fn forget_session_refs(&self, key: &SessionKey) {
        self.refs.lock().remove(key);
    }

    /// `key`'s correlation ids, if a coordinator descriptor ever carried them.
    pub(in crate::consensus) fn session_refs(
        &self,
        key: &SessionKey,
    ) -> Option<SessionExternalRefs> {
        self.refs.lock().get(key).cloned()
    }

    /// How long this relay withholds a session's region labels after latching it
    /// started (see the field's doc).
    pub fn region_release_delay(&self) -> Duration {
        self.region_release_delay
    }

    /// The end-of-game result embedded in `slot`'s departure record for `key`, if
    /// the relay has a maker holding a departure that carried one. Read while
    /// building a [`DepartureNotice`] so the notice embeds the same result every
    /// relay folded into its record.
    pub(in crate::consensus) fn departure_result(
        &self,
        key: &SessionKey,
        slot: SlotId,
    ) -> Option<ResultEcho> {
        self.makers
            .lock()
            .get(key)
            .and_then(|maker| maker.departures.get(&slot).and_then(|d| d.result.clone()))
    }
}

/// Creates an empty decision-maker registry for a relay with no sessions yet,
/// and no notice notifier installed (a standalone relay, or before startup
/// wiring calls [`DecisionMakers::set_notice_notifier`]).
pub fn new_decision_makers() -> DecisionMakers {
    new_decision_makers_with_region_delay(REGION_LABEL_RELEASE_DELAY)
}

/// [`new_decision_makers`] with an explicit region-label release delay, so a test
/// can drive the release path without waiting out the production
/// [`REGION_LABEL_RELEASE_DELAY`]. Production builds the registry through
/// [`new_decision_makers`] with the real constant.
pub fn new_decision_makers_with_region_delay(region_release_delay: Duration) -> DecisionMakers {
    DecisionMakers {
        makers: parking_lot::Mutex::new(HashMap::new()),
        notices: OnceLock::new(),
        refs: parking_lot::Mutex::new(HashMap::new()),
        flight: crate::observability::flight_recorder::FlightRecorder::default(),
        region_release_delay,
    }
}

/// Builds the departure notice for a synced leave that just first entered this
/// relay's cache: classifies left-vs-dropped from the native `reason`, and
/// carries the raw reason and the deciding relay's `leave_seq` for the
/// coordinator's telemetry. The slot comes straight off the directive (the
/// relay-authoritative departing slot).
///
/// Also stamps the session's correlation ids, if this relay's descriptor ever
/// carried them ([`DecisionMakers::set_session_refs`]) — `None` for a
/// standalone relay, a coordinator that predates the fields, or a session this
/// relay never received a descriptor for. Stamping them here (rather than
/// leaving the coordinator to look them up) is what makes the notice
/// self-describing: the descriptor a relay already applied survives a
/// coordinator restart even though the coordinator's own in-memory copy does
/// not.
pub(in crate::consensus) fn departure_notice(
    registry: &DecisionMakers,
    key: &SessionKey,
    leave: &LeaveDirective,
) -> DepartureNotice {
    let slot = SlotId(leave.slot as u8);
    let refs = registry.session_refs(key);
    DepartureNotice {
        finalized: leave.finalized,
        tenant: key.tenant.clone(),
        session: key.session,
        slot,
        kind: if leave.reason == LEAVE_REASON_DROPPED {
            DepartureKind::Dropped
        } else {
            DepartureKind::Left
        },
        reason: leave.reason,
        leave_seq: leave.leave_seq,
        external_id: refs.as_ref().and_then(|r| r.external_id.clone()),
        external_ref: refs.as_ref().and_then(|r| r.slots.get(&slot).cloned()),
        // The result this slot reported before departing, folded into its
        // departure record (home-seeded, carried across the mesh). Embedding it
        // makes the departure webhook atomic terminal truth; `None` proves the
        // slot departed without ever reporting.
        result: registry.departure_result(key, slot),
        // The count clients schedule the leave's application by — carried so
        // the coordinator can seed it back through a rehome's `DepartedSlot`.
        final_turn_count: leave.final_turn_count,
    }
}

/// Builds the desync notice for a divergence the comparator just confirmed:
/// carries the sync ordinal + confirming frame, the majority/minority verdict,
/// and a wall-clock detection timestamp (unix epoch ms). Stamps the session's
/// `external_id` and each diverged slot's `external_ref` the same way (and from
/// the same store) as [`departure_notice`], so the notice is self-describing
/// across a coordinator restart. The timestamp is read here rather than in the
/// pure comparator, which holds no clock.
pub(in crate::consensus) fn desync_notice(
    registry: &DecisionMakers,
    key: &SessionKey,
    divergence: &SyncDivergence,
) -> DesyncNotice {
    let refs = registry.session_refs(key);
    let detected_at_ms = now_ms();
    DesyncNotice {
        tenant: key.tenant.clone(),
        session: key.session,
        sync_ordinal: divergence.sync_ordinal,
        game_frame: divergence.game_frame,
        detected_at_ms,
        no_majority: divergence.no_majority,
        diverged: divergence
            .diverged
            .iter()
            .map(|slot| DivergedSlot {
                slot: *slot,
                external_ref: refs.as_ref().and_then(|r| r.slots.get(slot).cloned()),
            })
            .collect(),
        external_id: refs.as_ref().and_then(|r| r.external_id.clone()),
    }
}

/// Builds the standalone result notice from the retained result `echo` a slot
/// reported: the opaque payload byte-for-byte, the wall-clock arrival stamp, and
/// the relay's view of where the report landed in the game timeline — all
/// captured into the echo by [`record_result`] when the report arrived, and the
/// same echo that will later ride the slot's departure. Stamps the session's
/// `external_id` and the slot's `external_ref` the same way (and from the same
/// store) as [`departure_notice`], so the notice is self-describing across a
/// coordinator restart.
pub(in crate::consensus) fn result_notice(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    echo: ResultEcho,
) -> ResultNotice {
    let refs = registry.session_refs(key);
    ResultNotice {
        tenant: key.tenant.clone(),
        session: key.session,
        slot,
        external_id: refs.as_ref().and_then(|r| r.external_id.clone()),
        external_ref: refs.as_ref().and_then(|r| r.slots.get(&slot).cloned()),
        payload: echo.payload,
        arrival_ms: echo.arrival_ms,
        session_frame: echo.session_frame,
        slot_frame: echo.slot_frame,
    }
}

/// Builds the slot-connected notice for a slot link that just activated: the
/// slot, whether the dial presented resume cursors, and a wall-clock stamp read
/// here. Stamps the session's `external_id` and the slot's `external_ref` the
/// same way (and from the same store) as [`departure_notice`], so the notice is
/// self-describing across a coordinator restart.
pub(in crate::consensus) fn slot_connected_notice(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    resumed: bool,
) -> SlotConnectedNotice {
    let refs = registry.session_refs(key);
    SlotConnectedNotice {
        tenant: key.tenant.clone(),
        session: key.session,
        slot,
        external_id: refs.as_ref().and_then(|r| r.external_id.clone()),
        external_ref: refs.as_ref().and_then(|r| r.slots.get(&slot).cloned()),
        resumed,
        connected_at_ms: now_ms(),
    }
}

/// Builds the session-started notice for the coverage latch that just fired,
/// carrying the depth the authority sized onto the directive and a wall-clock
/// stamp read here. Stamps the session's `external_id` the same way (and from the
/// same store) as [`departure_notice`].
pub(in crate::consensus) fn session_started_notice(
    registry: &DecisionMakers,
    key: &SessionKey,
    initial_buffer_turns: Option<u32>,
) -> SessionStartedNotice {
    let refs = registry.session_refs(key);
    SessionStartedNotice {
        tenant: key.tenant.clone(),
        session: key.session,
        external_id: refs.as_ref().and_then(|r| r.external_id.clone()),
        started_at_ms: now_ms(),
        initial_buffer_turns,
    }
}

/// Builds the slot-started notice for a client's game-loop report: the reporting
/// slot, a wall-clock arrival stamp, and the relay's view of where the report
/// landed in the game timeline (both frames normally absent — a game announcing
/// its loop has begun has usually not produced a framed turn). Stamps the
/// session's `external_id` and the slot's `external_ref` the same way (and from
/// the same store) as [`departure_notice`].
pub(in crate::consensus) fn slot_started_notice(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
) -> SlotStartedNotice {
    let refs = registry.session_refs(key);
    let (session_frame, slot_frame) = {
        let makers = registry.lock();
        match makers.get(key) {
            Some(maker) => (
                maker.session_frame().map(|f| f.0),
                maker.slot_frame(slot).map(|f| f.0),
            ),
            None => (None, None),
        }
    };
    SlotStartedNotice {
        tenant: key.tenant.clone(),
        session: key.session,
        slot,
        external_id: refs.as_ref().and_then(|r| r.external_id.clone()),
        external_ref: refs.as_ref().and_then(|r| r.slots.get(&slot).cloned()),
        arrival_ms: now_ms(),
        session_frame,
        slot_frame,
    }
}

/// One session's load state as this relay has retained it: the slots whose links
/// ever activated here, the slots that ever reported their game loop running,
/// and the instant this relay learned the session started. Both slot lists are
/// ascending, so a heartbeat's wire output is deterministic rather than following
/// a hash set's iteration order.
///
/// This is the durable half of the load-progress reporting: the matching notices
/// are dropped the moment their send succeeds, while every heartbeat restates
/// this in full, so a coordinator that lost a notice — or restarted — converges
/// on the truth within one beat.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetainedLoadState {
    /// Slots whose links ever activated on this relay, ascending.
    pub ever_connected: Vec<SlotId>,
    /// Slots that ever reported their game loop running here, ascending.
    pub started: Vec<SlotId>,
    /// Relay wall-clock (unix epoch milliseconds) for the session's start, as
    /// this relay knows it. `None` on a relay that has not seen the session
    /// start at all.
    pub started_at_ms: Option<u64>,
}

/// A slot set as an ascending vector, so what a heartbeat reports is
/// deterministic rather than hash-set ordered.
pub(in crate::consensus) fn sorted_slots(slots: &HashSet<SlotId>) -> Vec<SlotId> {
    let mut sorted: Vec<SlotId> = slots.iter().copied().collect();
    sorted.sort_unstable();
    sorted
}

/// Logs a buffer change the authority just decided — the observable that the
/// runtime decision-maker is live and what it chose, correlated by session.
pub(in crate::consensus) fn log_decision(key: &SessionKey, decision: Decision) {
    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        buffer = decision.buffer.0,
        apply_at_frame = decision.applied_frame.0,
        "latency-buffer decision",
    );
}

/// Logs a synced player-leave the authority just decided — the observable that a
/// coordinated leave is being broadcast, and which slot at which frame.
pub(in crate::consensus) fn log_leave(key: &SessionKey, leave: &LeaveDirective) {
    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        slot = leave.slot,
        reason = leave.reason,
        apply_at_frame = leave.apply_at_frame,
        leave_seq = leave.leave_seq,
        "synced player-leave decision",
    );
}

/// Logs a desync the comparator just confirmed — the observable that the relay
/// detected a divergence, at which sync ordinal/frame, and who diverged. A warn
/// because a desync is an abnormal, result-affecting event.
pub(in crate::consensus) fn log_desync(key: &SessionKey, divergence: &SyncDivergence) {
    let diverged: Vec<u8> = divergence.diverged.iter().map(|slot| slot.0).collect();
    tracing::warn!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        sync_ordinal = divergence.sync_ordinal,
        game_frame = divergence.game_frame,
        no_majority = divergence.no_majority,
        ?diverged,
        "relay-side desync detected",
    );
}
