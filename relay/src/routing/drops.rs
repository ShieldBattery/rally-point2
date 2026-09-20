//! Manual drop requests: the client-edge validation of a survivor's
//! `RequestDrop`, the authority-side honoring of one past the unlock floor, and
//! the completion of a home-finalized drop once the home has sealed its count.

use super::*;

use super::departure::decide_and_broadcast_leave;
use crate::consensus;
use crate::consensus::LEAVE_REASON_DROPPED;
use crate::observability::events::{
    DropRequestRefusalReason, DropRequestRejectionReason, FlightEvent,
};

fn elapsed_ms(elapsed: std::time::Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// Samples rejection diagnostics independently of admission. All reasons and
/// targets share the authenticated requester's budget, so cycling invalid
/// targets cannot flood logs or rapidly evict the flight recorder's history.
fn record_drop_rejection(
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    requester: SlotId,
    target: u32,
    reason: DropRequestRejectionReason,
) {
    if !mesh
        .session
        .drop_holds
        .admit_rejection_diagnostic(key, requester)
    {
        return;
    }
    mesh.session.decision_makers.flight_recorder().record(
        key,
        FlightEvent::DropRequestRejected {
            requester: requester.0,
            target,
            reason,
        },
    );
    let message = match reason {
        DropRequestRejectionReason::OutOfRange => {
            "ignoring drop request for a slot id out of range"
        }
        DropRequestRejectionReason::SelfTarget => {
            "ignoring drop request that names its own requester"
        }
        DropRequestRejectionReason::NotDisconnected => {
            "ignoring drop request for a slot that is not disconnected"
        }
        DropRequestRejectionReason::RateCapped => {
            "dropping drop request; requester exceeded its request rate cap"
        }
    };
    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        slot = requester.0,
        requester = requester.0,
        target,
        ?reason,
        "{message}",
    );
}

/// Validates and acts on a client's manual `RequestDrop` at the relay's client
/// edge. `requester` is the authenticated connection's slot (never a wire value);
/// `wire_target` is the slot the requester asked to drop.
///
/// Rejects without a client response or link close, because a mis-click must not
/// disconnect the survivor who made it. Rejection logs and flight events share
/// a separate diagnostic rate cap. Requests are rejected when the target is out
/// of range, names the requester, or is neither held nor departed, or when the
/// requester exceeds its rate cap. A valid request is honored locally (this relay
/// may be the authority; see [`honor_drop_request`]) and broadcast to every peer
/// so a peer-homed authority honors it too.
pub(super) fn handle_drop_request(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    requester: SlotId,
    wire_target: u32,
) {
    let drop_holds = &mesh.session.drop_holds;
    let decision_makers = &mesh.session.decision_makers;
    let mesh_links = &mesh.links;
    let Ok(target) = u8::try_from(wire_target).map(SlotId) else {
        record_drop_rejection(
            mesh,
            key,
            requester,
            wire_target,
            DropRequestRejectionReason::OutOfRange,
        );
        return;
    };
    if target == requester {
        record_drop_rejection(
            mesh,
            key,
            requester,
            wire_target,
            DropRequestRejectionReason::SelfTarget,
        );
        return;
    }
    // A cheap sanity check at the edge — the authoritative gate is at the
    // authority, which alone holds the unlock timer. A request for a slot this
    // relay sees as neither held nor departed is nonsense (a stale or hostile
    // client), so drop it before spending a mesh broadcast on it.
    if !drop_holds.is_pending(key, target) && !decision_makers.has_departure(key, target) {
        record_drop_rejection(
            mesh,
            key,
            requester,
            wire_target,
            DropRequestRejectionReason::NotDisconnected,
        );
        return;
    }
    // Rate-limit per requester so a double-click (or a hostile flood) cannot spray
    // the mesh with request broadcasts. Over-limit requests are dropped silently —
    // never a link close.
    if !drop_holds.admit_request(key, requester) {
        record_drop_rejection(
            mesh,
            key,
            requester,
            wire_target,
            DropRequestRejectionReason::RateCapped,
        );
        return;
    }
    decision_makers.flight_recorder().record(
        key,
        FlightEvent::DropRequested {
            requester: requester.0,
            target: target.0,
        },
    );
    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        requester = requester.0,
        target = target.0,
        "admitting manual drop request",
    );
    // Honor it here (this relay may be the authority) and broadcast to every peer
    // so a peer-homed authority honors it too. The broadcast carries the
    // relay-stamped requester for logging/attribution.
    honor_drop_request(sessions, mesh, key, target, u32::from(requester.0));
    crate::mesh::fan_out_request_drop(mesh_links, key, target, requester);
}

/// Honors a manual drop request against `target` if this relay is the session
/// authority and the target's drop has stood past the unlock floor. `requester` is
/// carried only for logging/attribution — the decision never keys on who asked.
///
/// Called both from the client edge (this relay's own local request) and from a
/// mesh `RequestDrop` frame (a peer's request). A non-authority does nothing: the
/// request was broadcast to every relay, so the one authority among the receivers
/// is the single relay that acts. On the authority, a hold past the floor is
/// claimed and, if the claim succeeds, the synced leave decided with the DROPPED
/// reason; the decide path also dedups, so a duplicate request after the decide
/// is a harmless no-op. A hold short of the floor, or no hold at all (the slot
/// reconnected or left cleanly), is ignored without a client response; an info log
/// and flight event retain the refusal reason and any observed hold duration.
///
/// `held_for`'s read and `release`'s claim below are two separate lock
/// acquisitions, not one atomic check-and-take — a concurrent reconnect's
/// `DropHolds::take_if_pending` (the client edge's `Admission`) can slip in between them and claim
/// the same hold first. That is exactly why the claim is checked: `release`
/// returning `false` means this call lost that race, and it must stand down
/// rather than decide anyway. Deciding unconditionally here would be a genuine
/// correctness bug, not just redundant work — `DecisionMakers::decide_leave` records
/// (or *re-records*) the departure before it checks anything, so calling it after
/// a reconnect's `reinstate_slot` already cleared the record would resurrect a
/// departure, and then commit a leave, against a slot that is live again.
pub(crate) fn honor_drop_request(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    target: SlotId,
    requester: u32,
) {
    let drop_holds = &mesh.session.drop_holds;
    let decision_makers = &mesh.session.decision_makers;
    let mesh_links = &mesh.links;
    let seen = &mesh.seen;
    if !decision_makers.is_authority(key) {
        // Not the authority — the authority is among the broadcast's receivers and
        // will act. Nothing to do, and the hold stays for a possible promotion.
        return;
    }
    match drop_holds.held_for(key, target) {
        Some(elapsed) if elapsed >= drop_holds.unlock() => {
            // In a handshake-enabled session, the drop is decided only
            // through home-side finalization: the home seals the slot's
            // generation (refusing admission and fencing its turn ingress)
            // and snapshots the gap-free count the leave then carries, so
            // every survivor applies it at the same consumed-turn step. The
            // hold is NOT released up front — a rejected finalization (a
            // live reconnect, or no sealable cursor) leaves the drop held
            // and undecided, never frame-scheduled.
            if decision_makers.finalized_drops_enabled(key) {
                if decision_makers.strictly_homes(key, target) {
                    let outcome = decision_makers.finalize_drop(
                        key,
                        target,
                        decision_makers.departure_epoch(key, target),
                        || crate::mesh::forwarded_count(seen, key, target),
                    );
                    tracing::info!(
                        tenant = key.tenant.as_ref(),
                        session = key.session.0,
                        target = target.0,
                        requester,
                        ?outcome,
                        "honoring manual drop request via local finalization",
                    );
                    if let consensus::FinalizeOutcome::Finalized { final_turn_count } = outcome {
                        complete_finalized_drop(sessions, mesh, key, target, final_turn_count);
                    } else if outcome == consensus::FinalizeOutcome::RejectedNoCursor {
                        decision_makers.flight_recorder().record(
                            key,
                            FlightEvent::DropFinalizeRejected {
                                slot: target.0,
                                no_cursor: true,
                            },
                        );
                    }
                } else {
                    // A peer homes the target: ask it to finalize. The decide
                    // happens when its FinalizeDropResult arrives; until then
                    // the drop stays held, and a re-honored request simply
                    // re-sends this idempotent ask.
                    tracing::info!(
                        tenant = key.tenant.as_ref(),
                        session = key.session.0,
                        target = target.0,
                        requester,
                        held_ms = elapsed.as_millis(),
                        "requesting home-side finalization for a manual drop",
                    );
                    crate::mesh::fan_out_finalize_drop(
                        mesh_links,
                        key,
                        target,
                        decision_makers.departure_epoch(key, target),
                    );
                }
                return;
            }
            if drop_holds.release(key, target) {
                decide_and_broadcast_leave(
                    decision_makers,
                    sessions,
                    mesh_links,
                    key,
                    target,
                    LEAVE_REASON_DROPPED,
                );
                tracing::info!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    target = target.0,
                    requester,
                    held_ms = elapsed.as_millis(),
                    "honoring manual drop request",
                );
            } else {
                // Lost the claim: a concurrent reconnect (or another relay's
                // honor of this same broadcast request) released the hold
                // first. The slot may already be live again, so standing down
                // -- not deciding anyway -- is what keeps this from
                // resurrecting a departure record for a connected player.
                decision_makers.flight_recorder().record(
                    key,
                    FlightEvent::DropRequestRefused {
                        requester,
                        target: target.0,
                        held_ms: Some(elapsed_ms(elapsed)),
                        reason: DropRequestRefusalReason::LostClaim,
                    },
                );
                tracing::info!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    target = target.0,
                    requester,
                    "drop request lost the claim race; the hold was already released",
                );
            }
        }
        Some(elapsed) => {
            decision_makers.flight_recorder().record(
                key,
                FlightEvent::DropRequestRefused {
                    requester,
                    target: target.0,
                    held_ms: Some(elapsed_ms(elapsed)),
                    reason: DropRequestRefusalReason::BelowFloor,
                },
            );
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                target = target.0,
                requester,
                held_ms = elapsed.as_millis(),
                floor_ms = drop_holds.unlock().as_millis(),
                "ignoring drop request; the target's drop has not stood past the unlock floor",
            );
        }
        None => {
            decision_makers.flight_recorder().record(
                key,
                FlightEvent::DropRequestRefused {
                    requester,
                    target: target.0,
                    held_ms: None,
                    reason: DropRequestRefusalReason::NoHold,
                },
            );
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                target = target.0,
                requester,
                "ignoring drop request; the target has no pending drop hold",
            );
        }
    }
}

/// Completes a home-finalized drop on the authority: stamps the sealed count
/// (with its proof) into the slot's departure record, releases the hold, and
/// decides + broadcasts the leave, which then carries the count (see
/// `commit_leave`). Shared by the local-home fast path
/// ([`honor_drop_request`]) and the mesh `FinalizeDropResult` arm. A lost
/// hold-claim race stands down exactly like the legacy honor path — the slot
/// may be live again on a relay whose rejection is still in flight.
pub(crate) fn complete_finalized_drop(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    target: SlotId,
    final_turn_count: u64,
) {
    let drop_holds = &mesh.session.drop_holds;
    let decision_makers = &mesh.session.decision_makers;
    let mesh_links = &mesh.links;
    let seen = &mesh.seen;
    // Local staleness proof, checked before anything is stamped: if this
    // relay's own gap-free forwarded prefix for the slot already extends
    // PAST the sealed count, turns beyond the count entered the mesh after
    // the seal the answer describes — the slot reconnected (on a new home)
    // and played on while this answer was in flight. The home is the slot's
    // single ingress, so past the seal no legitimate turn can ever exceed
    // the count; a longer prefix here is proof, not suspicion. The epoch
    // check at the mesh arm closes most of this; this closes the interleaving
    // where the reconnect's own connectivity update is still in flight while
    // its turns (datagrams, a different channel) have already arrived.
    if let Some(forwarded) = crate::mesh::forwarded_count(seen, key, target)
        && forwarded > final_turn_count
    {
        tracing::warn!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            target = target.0,
            final_turn_count,
            forwarded,
            "finalized count is stale; this relay already forwarded past it — refusing",
        );
        decision_makers.flight_recorder().record(
            key,
            FlightEvent::DropFinalizeStaleCount {
                slot: target.0,
                sealed_count: final_turn_count,
                forwarded,
            },
        );
        return;
    }
    // The decide below silently short-circuits without a framed scheduling
    // basis — and by then the hold would already be released, leaving the
    // departure with no committed leave, no hold for a retry to claim, and
    // (with the home's seal standing) no reconnect path either: a stranded
    // session. Check the basis FIRST and keep the hold when it is missing;
    // the home's answer is idempotent, so a later honored drop request
    // completes once a framed turn exists. Safe as a check-then-act because
    // frames only accumulate — schedulable never reverts to unschedulable.
    if !decision_makers.leave_schedulable(key, target) {
        tracing::warn!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            target = target.0,
            final_turn_count,
            "finalized drop has no framed scheduling basis yet; keeping the hold for a retry",
        );
        decision_makers.flight_recorder().record(
            key,
            FlightEvent::DropFinalizeRejected {
                slot: target.0,
                no_cursor: false,
            },
        );
        return;
    }
    decision_makers.record_departure(
        key,
        target,
        consensus::DepartureStamps {
            final_turn_count: Some(final_turn_count),
            finalized: true,
            ..consensus::DepartureStamps::default()
        },
        LEAVE_REASON_DROPPED,
    );
    if drop_holds.release(key, target) {
        decide_and_broadcast_leave(
            decision_makers,
            sessions,
            mesh_links,
            key,
            target,
            LEAVE_REASON_DROPPED,
        );
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            target = target.0,
            final_turn_count,
            "decided a home-finalized drop",
        );
    } else {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            target = target.0,
            "finalized drop lost the hold-claim race; standing down",
        );
    }
}
