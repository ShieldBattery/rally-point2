//! Session-start entry points: the slot connection and game-loop reports that
//! go up the coordinator connection, the presence coverage that latches a
//! session started, and the session shape and initial buffer depth that latch
//! sizes from.

use super::*;

/// Reports that `slot`'s link just activated on this relay: retains the slot in
/// the session's ever-connected set and fires one slot-connected notice up the
/// coordinator connection. `resumed` marks a dial that presented resume cursors
/// (a reconnect or a re-home re-dial) apart from a first connect.
///
/// Fired on every activation, not just the first: the coordinator keeps the
/// ever-connected set and dedups the tenant notification itself, and only the
/// relay can see a reconnect at all. The retained set is what every heartbeat
/// restates, so the fact survives a lost notice; the notice is only the fast
/// path. A session run without a decision-maker (no descriptor) retains nothing
/// and still reports, with a notice that simply carries no correlation ids.
pub fn record_slot_connected(
    registry: &DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    resumed: bool,
) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.note_slot_connected(slot);
    }
    registry.emit_notice(RelayNotice::SlotConnected(slot_connected_notice(
        registry, key, slot, resumed,
    )));
}

/// Forwards a **home** client's report that its game loop has started: retains
/// the slot in the session's first-hand ever-started set and fires one
/// slot-started notice up the coordinator connection. `slot` is the
/// authenticated connection's slot the frame arrived on, never a value from the
/// wire.
///
/// The one-report-per-slot rule lives at the relay's client edge (the link that
/// received the frame), so a repeat never reaches here; the retained set is a
/// union regardless, and — like [`record_slot_connected`] — a session with no
/// decision-maker retains nothing, reports anyway, and stamps no frame
/// coordinates.
///
/// The coordinator notice is the half that stays home-only: see
/// [`record_peer_slot_started`], which folds a peer relay's shared report into
/// the maker and stops there.
pub fn record_slot_started(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.note_slot_started(slot);
    }
    registry.emit_notice(RelayNotice::SlotStarted(slot_started_notice(
        registry, key, slot,
    )));
}

/// Folds a peer relay's `SlotStarted` into the session's maker: the slot's home
/// heard its client's report and shared it, so this relay knows the slot is past
/// loading and its silent-slot watch can weigh it (see
/// [`DecisionMaker::silent_slot`]). A session with no maker here has nothing to
/// record, and the frame is simply dropped.
///
/// Fires **no** coordinator notice, which is the whole reason this is separate
/// from [`record_slot_started`]: the home already reported the slot, and a
/// second relay reporting it would attribute one client's load twice.
pub fn record_peer_slot_started(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.note_peer_slot_started(slot);
    }
}

/// Whether `slot`'s game loop is known to be running for `key` — this relay's own
/// home client's report or a peer's shared one. `false` for a session with no
/// maker here, which knows nothing about any slot.
pub fn slot_has_started(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> bool {
    registry
        .lock()
        .get(key)
        .is_some_and(|maker| maker.has_started(slot))
}

/// The slots this relay's own home clients have reported started, for the mesh
/// reconcile to (re)share with a freshly joined peer. Empty when the relay has no
/// maker for the session (nothing to share).
pub fn started_home_slots(registry: &DecisionMakers, key: &SessionKey) -> Vec<SlotId> {
    registry
        .lock()
        .get(key)
        .map(|maker| maker.started_home_slots())
        .unwrap_or_default()
}

/// Records that `slot` is present for `key` — registered on some relay serving
/// the session — and returns whether the session-start directive should now be
/// emitted session-wide (fanned to every local slot and broadcast across the
/// mesh). Only the authority relay ever returns `true`, and only once the
/// accumulated live slots cover the descriptor's expected set (see
/// [`DecisionMaker::note_slot_present`]). A no-op returning `false` when no maker
/// exists (a session this relay does not serve, or one run without descriptors).
#[must_use]
pub fn note_slot_present(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) -> bool {
    // Capture the sized depth under the same lock the latch fires under, so the
    // flight-recorder event names exactly what this fan-out will stamp.
    let fired = {
        let mut makers = registry.lock();
        match makers.get_mut(key) {
            Some(maker) => maker
                .note_slot_present(slot)
                .then(|| maker.initial_buffer_turns()),
            None => None,
        }
    };
    note_start_latched(registry, key, fired);
    fired.is_some()
}

/// Re-evaluates `key`'s session-start condition after an authority change,
/// returning whether the directive should now fire — the authority-churn path
/// ([`DecisionMaker::reevaluate_start`]). A relay just promoted to authority may
/// already hold a covering live-slot set. A no-op returning `false` when no maker
/// exists.
#[must_use]
pub fn reevaluate_session_start(registry: &DecisionMakers, key: &SessionKey) -> bool {
    let fired = {
        let mut makers = registry.lock();
        match makers.get_mut(key) {
            Some(maker) => maker
                .reevaluate_start()
                .then(|| maker.initial_buffer_turns()),
            None => None,
        }
    };
    note_start_latched(registry, key, fired);
    fired.is_some()
}

/// Records that `key`'s coverage latch just fired on this relay, with the depth
/// the authority sized (`Some(depth)`) or none (`Some(None)`). `None` means the
/// latch did not fire and nothing is recorded.
///
/// Every coverage-fired path funnels through here — the presence ingest, the
/// mesh's presence receive, and the authority-churn re-evaluation all reach it
/// through [`note_slot_present`] or [`reevaluate_session_start`] — so it is the
/// one place the flight-recorder event is written and the one place the
/// session-started notice fires. Deliberately *not* reached from
/// [`adopt_session_start`](DecisionMaker::adopt_session_start) or
/// [`mark_started`](DecisionMaker::mark_started): a peer relay adopting the
/// authority's directive off the mesh made no decision to report, and reporting
/// there would give the coordinator one notice per serving relay instead of one
/// per session.
pub(in crate::consensus) fn note_start_latched(
    registry: &DecisionMakers,
    key: &SessionKey,
    fired: Option<Option<u32>>,
) {
    let Some(initial_buffer_turns) = fired else {
        return;
    };
    registry.record_event(
        key,
        FlightEvent::SessionStart {
            initial_buffer_turns,
        },
    );
    let notice = session_started_notice(registry, key, initial_buffer_turns);
    // Retain the same instant the notice carries, so every heartbeat restates it
    // and a lost notice costs nothing. A peer adopting the directive off the mesh
    // retains its own, later, adoption instant; the coordinator keeps the first
    // instant reported, so this authored one wins wherever it arrives.
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.note_started_at_ms(notice.started_at_ms);
    }
    registry.emit_notice(RelayNotice::SessionStarted(notice));
}

/// Whether `key`'s session-start directive has already been emitted — the guard
/// a relay checks to re-push it to a slot that registers after start. `false`
/// when no maker exists.
pub fn session_started(registry: &DecisionMakers, key: &SessionKey) -> bool {
    registry
        .lock()
        .get(key)
        .is_some_and(DecisionMaker::is_started)
}

/// The slot count `key`'s session is shaped for, or `None` when the session has
/// not started (or no maker exists). The started gate mirrors
/// [`session_started`] so a caller sizing started-session state gets the gate
/// and the shape in one registry lock; the count itself is
/// [`DecisionMaker::session_slot_count`], including its `0`-means-unknown
/// convention.
pub fn started_session_slot_count(registry: &DecisionMakers, key: &SessionKey) -> Option<usize> {
    let makers = registry.lock();
    let maker = makers.get(key)?;
    maker.is_started().then(|| maker.session_slot_count())
}

/// Latches `key`'s session started without firing — used when a peer relay's
/// `SessionStart` arrives over the mesh, so this relay's own late-registering
/// local slots still get a re-push. A no-op when no maker exists.
pub fn mark_session_started(registry: &DecisionMakers, key: &SessionKey) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.mark_started();
    }
}

/// Records the descriptor-derived initial-depth inputs (`latency_hint_ms` and
/// whether the session is `single_relay`) onto `key`'s maker (see
/// [`DecisionMaker::set_session_shape`]). A no-op when no maker exists.
pub fn set_session_shape(
    registry: &DecisionMakers,
    key: &SessionKey,
    latency_hint_ms: Option<u32>,
    single_relay: bool,
) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.set_session_shape(latency_hint_ms, single_relay);
    }
}

/// The computed initial latency-buffer depth `key`'s maker stamps onto every
/// `SessionStart` it emits — `Some` once the authority sized it (or a peer
/// adopted the authority's), `None` otherwise (including when no maker exists).
/// See [`DecisionMaker::initial_buffer_turns`].
pub fn session_initial_buffer_turns(registry: &DecisionMakers, key: &SessionKey) -> Option<u32> {
    registry
        .lock()
        .get(key)
        .and_then(DecisionMaker::initial_buffer_turns)
}

/// Adopts an authority's mesh `SessionStart` onto a peer relay's maker: latches
/// started and, when the directive carried a depth, adopts it as the buffer and
/// stores it for this relay's re-pushes (see
/// [`DecisionMaker::adopt_session_start`]). A no-op when no maker exists.
pub fn adopt_session_start(
    registry: &DecisionMakers,
    key: &SessionKey,
    initial_buffer_turns: Option<u32>,
) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.adopt_session_start(initial_buffer_turns);
    }
}
