//! Buffer-law entry points: feeding conditions in, handing the turn path the
//! directive to stamp, and folding a peer authority's directive in.

use super::*;

/// Feeds one home-client `conditions` sample into the session's decision-maker
/// if the relay has one, logging any decision it fires. Returns the
/// [`Decision`], if any — the broadcast the decision queues is emitted later by
/// [`active_directive`] at fan-out. A no-op returning `None` when no maker
/// exists for the session (no policy pushed yet), so a slot link can call it
/// unconditionally.
pub fn ingest_local_conditions(
    registry: &DecisionMakers,
    key: &SessionKey,
    conditions: &LinkConditions,
) -> Option<Decision> {
    ingest_conditions(registry, key, &conditions.slots, 0, true)
}

/// The allocation-free single-slot counterpart to [`ingest_local_conditions`].
/// Slot-link sampling produces exactly one [`SlotConditions`], so accepting it
/// directly avoids wrapping every sample in a temporary `Vec` while retaining
/// the identical state update, decision, logging, and flight-recording path.
pub fn ingest_local_condition(
    registry: &DecisionMakers,
    key: &SessionKey,
    conditions: &SlotConditions,
) -> Option<Decision> {
    ingest_conditions(registry, key, std::slice::from_ref(conditions), 0, true)
}

pub(in crate::consensus) fn ingest_conditions(
    registry: &DecisionMakers,
    key: &SessionKey,
    conditions: &[SlotConditions],
    mesh_rtt_us: u32,
    local: bool,
) -> Option<Decision> {
    let (decision, directive, inputs) = {
        let mut makers = registry.lock();
        let maker = makers.get_mut(key)?;
        if local {
            maker.activate_local_epochs(conditions);
        }
        let decision = maker.ingest_slots(conditions, mesh_rtt_us)?;
        // The queued broadcast carries the decision seq the Decision lacks;
        // read it under the same lock so the recorded event matches exactly
        // what clients will be stamped with. The derivation is *taken* -- it
        // belongs to this decision alone, and the next directive brings its
        // own (or none).
        (
            decision,
            maker.pending_directive,
            maker.pending_decision_inputs.take(),
        )
    };
    log_decision(key, decision);
    record_buffer_event(registry, key, directive, inputs);
    Some(decision)
}

/// Records a freshly queued buffer directive into the session's flight
/// recording — the buffer decision's observability shadow.
pub(in crate::consensus) fn record_buffer_event(
    registry: &DecisionMakers,
    key: &SessionKey,
    directive: Option<BufferDirective>,
    inputs: Option<BufferDecisionInputs>,
) {
    if let Some(directive) = directive {
        registry.flight.record(
            key,
            crate::observability::flight_recorder::FlightEvent::BufferDirective {
                buffer_turns: directive.buffer_turns,
                apply_frame: directive.apply_at_frame,
                decision_seq: directive.decision_seq,
                inputs,
            },
        );
    }
}

/// Feeds a peer relay's `conditions` sidecar (reached over a mesh hop of
/// `mesh_rtt_us`) into the session's decision-maker if the relay has one,
/// logging any decision it fires. Returns the [`Decision`], if any. A no-op
/// returning `None` when no maker exists for the session.
pub fn ingest_remote_conditions(
    registry: &DecisionMakers,
    key: &SessionKey,
    conditions: &LinkConditions,
    mesh_rtt_us: u32,
) -> Option<Decision> {
    ingest_conditions(registry, key, &conditions.slots, mesh_rtt_us, false)
}

/// The buffer directive to stamp onto a turn forwarded for this session, if
/// the relay is the authority and has a change it is still broadcasting.
/// Returns `None` — the common case — when no change is pending, the change
/// has been applied everywhere, or no maker exists for the session.
pub fn active_directive(registry: &DecisionMakers, key: &SessionKey) -> Option<BufferDirective> {
    registry.lock().get_mut(key)?.active_directive()
}

/// Records `id` as the session's own relay id on its maker, if one exists
/// (see [`DecisionMaker::set_own_relay_id`]). A no-op when the session has no
/// maker yet — nothing to stamp until one is created.
pub fn set_own_relay_id(registry: &DecisionMakers, key: &SessionKey, id: RelayId) {
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.set_own_relay_id(id);
    }
}

/// Records an authority-stamped directive this relay is forwarding, if the relay
/// has a maker for the session, so a later promotion to authority continues the
/// session's decision numbering and baselines against the committed buffer (see
/// [`DecisionMaker::observe_directive`]). A no-op when no maker exists.
///
/// A directive whose depth exceeds [`GAME_SYNC_SAFE_BUFFER_MAX`] trips a
/// once-per-decision warn and flight event on its way through. It is still
/// forwarded verbatim: only the authoring authority may change a session's
/// depth (rewriting it selectively here would hand different clients different
/// depths — itself a desync), and only an authority running code that predates
/// the ceiling can author one. The tripwire makes the exposure observable; the
/// operational rule that prevents it is draining every session enrolled with
/// pre-ceiling bounds before mixing relay versions in a fleet.
pub fn observe_directive(registry: &DecisionMakers, key: &SessionKey, directive: &BufferDirective) {
    let over_ceiling = {
        let mut makers = registry.lock();
        let Some(maker) = makers.get_mut(key) else {
            return;
        };
        maker.observe_directive(directive);
        let fresh_over_ceiling = directive.buffer_turns > GAME_SYNC_SAFE_BUFFER_MAX
            && maker.over_ceiling_warned_seq != Some(directive.decision_seq);
        if fresh_over_ceiling {
            maker.over_ceiling_warned_seq = Some(directive.decision_seq);
        }
        fresh_over_ceiling
    };
    if over_ceiling {
        tracing::warn!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            buffer_turns = directive.buffer_turns,
            ceiling = GAME_SYNC_SAFE_BUFFER_MAX,
            decision_seq = directive.decision_seq,
            "forwarding a peer authority's buffer directive above the game-sync-safe \
             ceiling; a depth past it deterministically mass-drops the session once \
             applied",
        );
        registry.flight.record(
            key,
            crate::observability::flight_recorder::FlightEvent::OverCeilingDirectiveForwarded {
                buffer_turns: directive.buffer_turns,
                decision_seq: directive.decision_seq,
            },
        );
    }
}
