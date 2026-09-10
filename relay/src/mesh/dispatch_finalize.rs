//! The drop-finalization handshake's two mesh control-frame arms, split out of
//! the main dispatch: the home relay sealing a dropped slot's exact turn count,
//! and the authority acting on the answer.

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{FinalizeDrop, FinalizeDropResult};

use crate::routing::{self, SessionKey};

use super::seen::forwarded_count;
use super::{
    FINALIZE_OUTCOME_FINALIZED, FINALIZE_OUTCOME_REJECTED_LIVE,
    FINALIZE_OUTCOME_REJECTED_NO_CURSOR, MeshState, fan_out_finalize_drop_result,
};

/// The authority's request that this slot's home finalize its drop, answered
/// with a broadcast result. A relay that does not strictly home the slot, or
/// whose session does not run the handshake at all, stays silent.
pub(super) fn dispatch_finalize_drop(request: FinalizeDrop, key: &SessionKey, mesh: &MeshState) {
    let session_id = key.session;
    let Ok(slot) = u8::try_from(request.slot).map(SlotId) else {
        tracing::warn!(
            session = session_id.0,
            slot = request.slot,
            "mesh FinalizeDrop names a slot id out of range; dropping",
        );
        return;
    };
    // The authority's request that this slot's home finalize its drop.
    // Only the relay whose descriptor STRICTLY homes the slot answers
    // (an open fallback would have every relay finalize with its own,
    // different cursor), and only in a session whose descriptor runs
    // the handshake at all. Everyone else stays silent — the request
    // was broadcast, so the one home is among the receivers.
    if !crate::consensus::finalized_drops_enabled(&mesh.decision_makers, key)
        || !crate::consensus::slot_strictly_homed(&mesh.decision_makers, key, slot)
    {
        return;
    }
    let outcome = crate::consensus::finalize_drop(
        &mesh.decision_makers,
        key,
        slot,
        request.connection_epoch,
        || forwarded_count(&mesh.seen, key, slot),
    );
    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = session_id.0,
        slot = slot.0,
        ?outcome,
        "home-side drop finalization evaluated",
    );
    if outcome == crate::consensus::FinalizeOutcome::RejectedNoCursor {
        // The fail-closed branch: the drop stays undecided (survivors
        // remain stalled and may retry), never a frame fallback. Make
        // it observable — a session stuck here is the signal for the
        // coordinated-abort follow-up.
        mesh.decision_makers.flight_recorder().record(
            key,
            crate::observability::flight_recorder::FlightEvent::DropFinalizeRejected {
                slot: slot.0,
                no_cursor: true,
            },
        );
    }
    fan_out_finalize_drop_result(&mesh.links, key, slot, request.connection_epoch, outcome);
}

/// The home's finalization outcome, acted on only by the session authority in a
/// handshake-enabled session, and only while it still describes the departure
/// this relay currently holds.
pub(super) fn dispatch_finalize_drop_result(
    result: FinalizeDropResult,
    sessions: &routing::Sessions,
    key: &SessionKey,
    mesh: &MeshState,
) {
    let session_id = key.session;
    let Ok(slot) = u8::try_from(result.slot).map(SlotId) else {
        tracing::warn!(
            session = session_id.0,
            slot = result.slot,
            "mesh FinalizeDropResult names a slot id out of range; dropping",
        );
        return;
    };
    // The home's answer. Only the session authority acts on it (the
    // broadcast reaches everyone; a non-authority has no decide to
    // make), and only in a handshake-enabled session.
    if !crate::consensus::is_authority(&mesh.decision_makers, key)
        || !crate::consensus::finalized_drops_enabled(&mesh.decision_makers, key)
    {
        return;
    }
    // Bind the answer to the departure this relay currently holds: a
    // result that survived a partition or a slow link can describe a
    // generation the slot has since moved past (it reconnected to a
    // new home and dropped again), and its count then stops short of
    // turns survivors already consumed. The echoed epoch must match
    // the current record's — a reconnect clears the record (epoch
    // reads `None`) and a re-drop records the newer generation, so
    // either drift rejects the stale answer here; the requester's
    // next honored drop request re-asks with the current epoch.
    if result.connection_epoch
        != crate::consensus::departure_epoch(&mesh.decision_makers, key, slot)
    {
        tracing::warn!(
            tenant = key.tenant.as_ref(),
            session = session_id.0,
            slot = slot.0,
            result_epoch = ?result.connection_epoch,
            "drop-finalization result names a stale connection generation; ignoring",
        );
        return;
    }
    match (result.outcome, result.final_turn_count) {
        (FINALIZE_OUTCOME_FINALIZED, Some(final_turn_count)) => {
            routing::complete_finalized_drop(
                &mesh.drop_holds,
                &mesh.decision_makers,
                sessions,
                &mesh.links,
                &mesh.seen,
                key,
                slot,
                final_turn_count,
            );
            // The decide may have been the last undecided departure
            // deferring this relay's session-emptied close.
            routing::maybe_close_emptied_session(sessions, mesh, key);
        }
        (FINALIZE_OUTCOME_REJECTED_LIVE, _) => {
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = session_id.0,
                slot = slot.0,
                "drop finalization rejected; the slot has a live generation",
            );
        }
        (FINALIZE_OUTCOME_REJECTED_NO_CURSOR, _) => {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = session_id.0,
                slot = slot.0,
                "drop finalization rejected with no gap-free cursor; the drop stays                          undecided",
            );
            mesh.decision_makers.flight_recorder().record(
                key,
                crate::observability::flight_recorder::FlightEvent::DropFinalizeRejected {
                    slot: slot.0,
                    no_cursor: true,
                },
            );
        }
        (outcome, count) => {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = session_id.0,
                slot = slot.0,
                outcome,
                ?count,
                "unrecognized drop-finalization outcome; ignoring",
            );
        }
    }
}
