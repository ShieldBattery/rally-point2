//! Authority injection and frame observation: reconciling a session's
//! decision-maker against a fresh descriptor, setting the authority verdict,
//! and folding each forwarded turn's frame and sync command in.

use super::*;

/// Everything a descriptor push (or a reconcile) tells a session's
/// decision-maker. Built with [`MakerSync::new`] plus struct-update syntax for
/// whatever else the caller has to say, or with
/// [`from_descriptor`](Self::from_descriptor) straight off a coordinator push.
#[derive(Debug, Clone)]
pub struct MakerSync<'a> {
    /// The latency-buffer bounds the maker clamps every decision to. They
    /// follow the descriptor rather than staying frozen at whatever the first
    /// push said.
    pub bounds: BufferBounds,
    /// Who decides the buffer for this session, as of this push. Re-injected
    /// on every push and every presence change: a frozen verdict could leave a
    /// session with two authorities or none.
    pub authority: Authority,
    /// The descriptor's observer-slot set, applied as part of maker
    /// creation/sync rather than through a separately-ordered call: a maker
    /// created by this sync starts with the set (so its observer slots are
    /// excluded from the desync comparator from the first turn — a
    /// single-relay session that only ever receives one push therefore never
    /// loses them), and an existing maker has its set replaced to follow a
    /// changed descriptor.
    pub observers: HashSet<SlotId>,
    /// The slots the session waits on before it may start. Seeded and replaced
    /// exactly like `observers`.
    pub expected_slots: HashSet<SlotId>,
    /// The slots this relay is home for. Seeded and replaced exactly like
    /// `observers` — see [`DecisionMaker::set_homed_slots`].
    pub homed_slots: HashSet<SlotId>,
    /// This relay's current set of undecided drop holds, read by the caller
    /// from the drop-hold registry (see [`DecisionMaker::sync`]). Only
    /// meaningful on the reconcile path: a fresh maker has nothing recorded
    /// yet to hold back.
    pub held_slots: HashSet<SlotId>,
    /// `Some` exactly when the descriptor is a rehome (resumed) one, carrying
    /// the coordinator-known departed slots to seed.
    pub resumed_departed: Option<&'a [DepartedSlot]>,
    /// The descriptor's immutable per-session flag enabling the home-side
    /// drop-finalization handshake. Latched at maker creation; a re-push that
    /// disagrees is ignored with a warning — every count-acceptance rule keys
    /// on the flag, so a session must never change its mind mid-game.
    pub finalized_drops: bool,
}

impl<'a> MakerSync<'a> {
    /// A sync carrying only what a maker cannot exist without: every slot set
    /// empty, nothing to seed, finalized drops off.
    pub fn new(bounds: BufferBounds, authority: Authority) -> Self {
        Self {
            bounds,
            authority,
            observers: HashSet::new(),
            expected_slots: HashSet::new(),
            homed_slots: HashSet::new(),
            held_slots: HashSet::new(),
            resumed_departed: None,
            finalized_drops: false,
        }
    }

    /// What a coordinator descriptor push says: every slot set read off
    /// `descriptor`, departed seeds present exactly when it is a resumed
    /// (re-home) descriptor, and `held_slots` the drop holds the caller read
    /// from the registry the descriptor cannot see.
    pub fn from_descriptor(
        descriptor: &'a SessionDescriptor,
        authority: Authority,
        held_slots: HashSet<SlotId>,
    ) -> Self {
        Self {
            bounds: descriptor.bounds,
            authority,
            observers: descriptor.observer_slots.iter().copied().collect(),
            expected_slots: descriptor.expected_slots.iter().copied().collect(),
            homed_slots: descriptor.homed_slots.iter().copied().collect(),
            held_slots,
            resumed_departed: descriptor
                .resumed
                .then_some(descriptor.departed_slots.as_slice()),
            finalized_drops: descriptor.finalized_drops,
        }
    }
}

/// Creates a decision-maker for `key`, or reconciles an existing one with the
/// bounds and authority verdict `sync` carries. Called on every descriptor
/// push: the relay set serving a session changes as players join and leave,
/// and the authority verdict (and bounds) must follow the descriptor.
/// Condition history survives a re-push (see [`DecisionMaker::sync`]).
///
/// A promotion can *freshly derive* a leave for a departure no relay ever
/// cached before (the directive never escaped the dead authority) -- that is
/// as much a first insert into this relay's cache as `decide_leave`/
/// `observe_leave` firing one, so it fires exactly one departure notice too;
/// a verbatim re-broadcast of an already-cached directive fires nothing (the
/// relay that cached it first already reported it).
///
/// A resumed sync's departed slots are seeded — and the maker's started and
/// resumed latches set — *inside* the registry lock that creates or reconciles
/// the maker, never as follow-up calls: the moment this function returns,
/// other tasks can reach the maker (a provisionally admitted client's
/// clean-leave intent, say), and a maker momentarily visible without its
/// resumed latch would stamp an exact final turn count that the rehomed
/// session's split forwarding history cannot support. Seeding runs before the
/// authority `sync`, so a promotion in the same push re-broadcasts the seeded
/// leaves like any other decided ones.
///
/// The returned batch is everything the caller must (re)broadcast: the
/// promotion re-broadcast, plus any directive newly decided by this push's
/// seeding — a client admitted before the descriptor did its one leave
/// reconciliation at registration and would otherwise never hear a seeded
/// departure, stalling forever on the departed slot's turns. Deduplicated by
/// slot (receivers dedup again regardless).
#[must_use]
pub fn sync_maker(
    registry: &DecisionMakers,
    key: &SessionKey,
    sync: MakerSync<'_>,
) -> Vec<LeaveDirective> {
    use std::collections::hash_map::Entry;
    let MakerSync {
        bounds,
        authority,
        observers,
        expected_slots,
        homed_slots,
        held_slots,
        resumed_departed,
        finalized_drops,
    } = sync;
    let seed = |maker: &mut DecisionMaker| -> Vec<LeaveDirective> {
        let Some(departed) = resumed_departed else {
            return Vec::new();
        };
        let seeded = departed
            .iter()
            .filter_map(|d| maker.seed_departed(d.slot, d.kind, d.final_turn_count, d.finalized))
            .collect();
        // Latch the session started, so a resumed relay never waits on the
        // full expected set (which still lists the departed slots that will
        // never dial) and never re-fires the session-start machinery
        // session-wide; and latch it resumed, so no leave it ever decides
        // carries an exact final turn count.
        maker.mark_started();
        maker.resumed = true;
        seeded
    };
    let (mut leaves, fresh, seeded) = {
        let mut makers = registry.lock();
        match makers.entry(key.clone()) {
            Entry::Occupied(mut existing) => {
                let maker = existing.get_mut();
                maker.set_observers(observers);
                maker.set_expected_slots(expected_slots);
                // Any home this push ADDS to an existing maker is a home
                // gained mid-session — this relay was not the slot's single
                // ingress for its whole history, so its forward-gate cursor
                // can never soundly seal the slot's final turn count (see
                // `rehomed_homes`). Recorded before the wholesale replace
                // below, which is what makes "added" observable at all.
                let gained: Vec<SlotId> = homed_slots
                    .difference(&maker.homed_slots)
                    .copied()
                    .collect();
                maker.rehomed_homes.extend(gained);
                maker.set_homed_slots(homed_slots);
                if maker.finalized_drops_enabled != finalized_drops {
                    // Immutable for the session's lifetime: the create-time
                    // value stands, since every count-acceptance decision
                    // already keyed on it.
                    tracing::warn!(
                        tenant = key.tenant.as_ref(),
                        session = key.session.0,
                        latched = maker.finalized_drops_enabled,
                        pushed = finalized_drops,
                        "descriptor re-push disagrees on finalized_drops; keeping the latched value",
                    );
                }
                let seeded = seed(maker);
                let (leaves, fresh) = maker.sync(bounds, authority, &held_slots);
                (leaves, fresh, seeded)
            }
            Entry::Vacant(vacant) => {
                let maker = vacant.insert(DecisionMaker::new(
                    key.clone(),
                    bounds,
                    ControlLaw::default(),
                    authority,
                    observers,
                ));
                // Seed the expected-slot and homed-slot sets as part of
                // creation — a maker created by this descriptor starts with
                // them, so a single-relay session (one push, before any
                // client dials) never loses them, exactly as the observer set
                // is seeded above. The finalized-drops flag latches the same
                // way, and only here (immutable thereafter).
                maker.set_expected_slots(expected_slots);
                maker.set_homed_slots(homed_slots);
                maker.finalized_drops_enabled = finalized_drops;
                // A maker created by a RESUMED descriptor is a relay pulled
                // into (or restarted into) a session that already has
                // history this relay's forward gate never carried — even if
                // a stale seen registry answers with a prefix, it is not the
                // slot's whole ingress history. Every home it starts with is
                // therefore cursor-broken for finalization purposes.
                if resumed_departed.is_some() {
                    maker.rehomed_homes = maker.homed_slots.clone();
                }
                let seeded = seed(maker);
                (Vec::new(), Vec::new(), seeded)
            }
        }
    };
    for leave in &fresh {
        record_leave_event(registry, key, leave);
        registry.notify_departure(departure_notice(registry, key, leave));
    }
    // A seeded departure fires no departure notice (the coordinator that
    // seeded it already knows), but must still reach local survivors and mesh
    // peers exactly like the promotion batch.
    for seeded_leave in seeded {
        if !leaves.iter().any(|l| l.slot == seeded_leave.slot) {
            leaves.push(seeded_leave);
        }
    }
    leaves
}

/// Applies a fresh authority verdict to a session's decision-maker, if the
/// relay has one, logging a change of authority and returning the synced leaves a
/// *promotion* must (re)broadcast (empty on any other transition, or when no
/// maker exists). The presence-driven handoff path: called when a relay's
/// live-player report flips some relay's liveness, between (and independent of)
/// descriptor pushes. A no-op when no maker exists — a maker is only ever created
/// by a descriptor, which carries the bounds a maker cannot exist without. The
/// caller pushes the returned leaves down local survivors and across the mesh.
///
/// A promotion that freshly derives a leave (no relay ever cached this
/// departure's directive before) fires exactly one departure notice for it,
/// same as `decide_leave`/`observe_leave`; a verbatim re-broadcast of an
/// already-cached directive fires nothing.
///
/// `held_slots` is the set of slots whose drop is still held undecided on this
/// relay — the caller reads it from the drop-hold registry the maker cannot see. A
/// promotion skips them, leaving each held drop to be decided only by an honored
/// manual request; see [`DecisionMaker::set_authority`]. This is what keeps a
/// single-relay presence flap (authority to `Peer` and back when the roster
/// momentarily empties) from deciding drops of slots that are reconnecting.
#[must_use]
pub fn set_authority(
    registry: &DecisionMakers,
    key: &SessionKey,
    authority: Authority,
    held_slots: &HashSet<SlotId>,
) -> Vec<LeaveDirective> {
    let (leaves, fresh) = {
        let mut guard = registry.lock();
        let Some(maker) = guard.get_mut(key) else {
            return Vec::new();
        };
        if maker.authority == authority {
            return Vec::new();
        }
        maker.set_authority(authority, held_slots)
    };
    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        authority = ?authority,
        rebroadcast_leaves = leaves.len(),
        "presence moved the session's buffer authority",
    );
    for leave in &fresh {
        record_leave_event(registry, key, leave);
        registry.notify_departure(departure_notice(registry, key, leave));
    }
    leaves
}

/// The last game frame observed on `slot`'s validated turns for the session, if
/// the relay has a maker. Read at a departure trigger — before the departure is
/// recorded, which retires the slot's live state — to fill a `SlotDeparted`'s
/// `last_frame`.
pub fn slot_frame(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
) -> Option<GameFrameCount> {
    registry
        .lock()
        .get(key)
        .and_then(|maker| maker.slot_frame(slot))
}

/// Whether this relay is the decision-making authority for `key` (see
/// [`DecisionMaker::is_authority`]). `false` when no maker exists for the session.
/// Read before honoring a manual drop request: only the authority may decide a
/// leave, so a non-authority (including one that received the request broadcast
/// over the mesh) ignores it and leaves the decision to whichever relay is
/// authority among the receivers.
pub fn is_authority(registry: &DecisionMakers, key: &SessionKey) -> bool {
    registry
        .lock()
        .get(key)
        .is_some_and(DecisionMaker::is_authority)
}

/// Records a `game_frame_count` observed on one of `slot`'s validated turns,
/// if the relay has a maker for the session. The per-slot observations are
/// what the session's consensus coordinate (the minimum across slots) is
/// computed from, so this is called for every framed turn a link forwards. A
/// no-op when no maker exists (no policy pushed yet).
pub fn observe_frame(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    frame: GameFrameCount,
) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.observe_frame(slot, frame);
    }
}

/// The seq-aware sibling of [`observe_frame`]: records the same per-slot frame
/// **and** the turn's transport seq into the slot's bounded frame history, so a
/// later leave can clamp its apply frame to a survivor-reachable ceiling (see
/// `DecisionMaker`'s `reachable_frame`). **Every production frame-observation on
/// the leave path calls this**, never the seq-less `observe_frame` (which is
/// test-only), so the clamp always has history to work from. A no-op when no
/// maker exists.
pub fn observe_turn_frame(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    seq: u64,
    frame: GameFrameCount,
    home: crate::consensus::delivery::DeliveryHome,
) {
    let regression = {
        let mut makers = registry.lock();
        let Some(maker) = makers.get_mut(key) else {
            return;
        };
        let regression = maker.observe_turn_frame(slot, seq, frame);
        // The same validated turn is the origin-side half of end-to-end
        // delivery tracking: the newest seq this relay has seen from `slot`,
        // and — because turns are never re-forwarded relay-to-relay — the
        // source it arrived by is the slot's home relay, which is what hop
        // inference keys on.
        maker.delivery_mut().observe_origin(slot, seq, home);
        regression
    };
    // Reported outside the maker lock: the recorder takes its own per-session
    // lock, and this fires at most once per slot, never on the steady-state
    // turn path.
    if let Some(FrameRegression { prior_frame }) = regression {
        tracing::warn!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            slot = slot.0,
            seq,
            frame = frame.0,
            prior_frame,
            "framed turn stamped below the slot's newest frame at a higher seq: the client's \
             executable-turn index restarted underneath its stamps (a turn stamped before its \
             game loop began, or a hostile stamp); the slot's recorded frame stays at the \
             high-water mark, so a frame-scheduled leave for it may be unreachable",
        );
        registry.flight_recorder().record(
            key,
            crate::observability::flight_recorder::FlightEvent::FrameStampRegressed {
                slot: slot.0,
                seq,
                frame: frame.0,
                prior_frame,
            },
        );
    }
}

/// What [`DecisionMaker::observe_turn_frame`] reports when a slot's stamp went
/// backwards at a higher seq: the high-water mark the stamp fell below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRegression {
    pub prior_frame: u32,
}

/// Folds one destination delivered-through cursor into `key`'s end-to-end
/// delivery tracking: `dest` claims `origin`'s turns reached it through
/// `delivered_seq`. `home` is where the claim arrived by — the local beacon tap
/// for a slot homed here, or the mesh link to the destination's home relay for
/// a `DeliveryCursors` frame. Monotonic per pair (a regressing cursor is
/// ignored). A no-op when no maker exists.
pub fn observe_delivery(
    registry: &DecisionMakers,
    key: &SessionKey,
    dest: SlotId,
    origin: SlotId,
    delivered_seq: u64,
    home: crate::consensus::delivery::DeliveryHome,
) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker
            .delivery_mut()
            .observe_delivery(dest, origin, delivered_seq, home);
    }
}

/// The session's end-to-end delivery view — `(worst pair lag in turns, max
/// relay hops)` — for the flight recorder's sample rows. `None` when no maker
/// exists; either half `None` until a pair has evidence on both ends.
pub fn session_e2e(registry: &DecisionMakers, key: &SessionKey) -> (Option<u64>, Option<u32>) {
    registry
        .lock()
        .get(key)
        .map(|maker| maker.delivery_view())
        .unwrap_or((None, None))
}

/// Feeds one forwarded turn's commands into the session's desync comparator, if
/// the relay has a maker, and fires a [`DesyncNotice`] up the coordinator
/// connection when a divergence is confirmed. Called at the same turn choke
/// points as [`observe_frame`], for every turn (client edge, mesh hop, oversize
/// divert). Every relay retains ordered checksum metadata so a promotion keeps
/// its native ring epochs; only the authority compares or emits a notice.
///
/// `seq` is the origin's full transport sequence. `game_frame` is the turn's
/// `game_frame_count`; `commands` its raw command
/// bytes (already validated at the ingress edge — this walk is the authority's
/// own independent parse, not a trust in a peer's).
pub fn observe_sync(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    seq: u64,
    game_frame: Option<u32>,
    commands: &[u8],
) {
    observe_sync_with_generation(registry, key, slot, seq, game_frame, commands, None);
}

/// The enhanced checksum-coverage variant of [`observe_sync`].
pub fn observe_sync_with_generation(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    seq: u64,
    game_frame: Option<u32>,
    commands: &[u8],
    sync_generation: Option<u64>,
) {
    let (divergence, ordering_failure) = {
        let mut makers = registry.lock();
        match makers.get_mut(key) {
            Some(maker) => {
                let was_unavailable = maker.sync_turns.unavailable(slot);
                let divergence = maker.observe_sync_with_generation(
                    slot,
                    seq,
                    game_frame,
                    commands,
                    sync_generation,
                );
                let failure = if was_unavailable {
                    None
                } else {
                    maker.sync_turns.failure(slot)
                };
                (divergence, failure)
            }
            None => (None, None),
        }
    };
    // The recorder has its own locks. Capture the transition under the maker
    // lock, then publish outside it; a latched origin produces only one event.
    if let Some(failure) = ordering_failure {
        registry.flight.record(
            key,
            crate::observability::flight_recorder::FlightEvent::SyncOrderingUnavailable {
                slot: slot.0,
                reason: failure.reason.to_owned(),
                seq: failure.seq,
                missing_next: failure.next,
                previous_ordinal: failure.previous_ordinal,
                ring: failure.ring,
            },
        );
    }
    if let Some(divergence) = divergence {
        log_desync(key, &divergence);
        registry.flight.record(
            key,
            crate::observability::flight_recorder::FlightEvent::DesyncDetected {
                sync_ordinal: divergence.sync_ordinal,
                diverged: divergence.diverged.iter().map(|slot| slot.0).collect(),
                no_majority: divergence.no_majority,
            },
        );
        registry.notify_desync(desync_notice(registry, key, &divergence));
    }
}
