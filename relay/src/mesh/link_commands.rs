//! The mesh-link driver's command and outbound-send `select!` arm bodies:
//! joining and leaving a session on the shared connection, writing an
//! outbound control frame, and sending one forwarded turn.

use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::Arc;

use rally_point_proto::ids::SessionId;
use rally_point_proto::messages::{MeshControlFrame, Payload};

use crate::routing;

use super::conditions::snapshot_conditions;
use super::forward::send_turn_over_link;
use super::join::{
    local_live_players, push_presence_updates, reconcile_leaves_on_join,
    reconcile_local_slots_on_join, reconcile_resume_cursors_on_join,
    reconcile_started_slots_on_join,
};
use super::link_arms::LinkDriver;
use super::link_run::{MeshCommand, defer_flush_after_send};
use super::links::{
    LeaseAwait, MESH_STREAM_WRITE_TIMEOUT, MeshLinkExit, SessionState, await_while_current,
};
use super::seen::resume_cursor_snapshot;
use super::{mesh_session_key, register_mesh_link};

impl LinkDriver {
    /// Writes one outbound control frame — a departure, a leave directive, a
    /// join-time reconcile re-send — on the shared reliable control stream.
    pub(super) async fn write_outbound_control(
        &mut self,
        outbound: Option<MeshControlFrame>,
    ) -> ControlFlow<MeshLinkExit> {
        let Self {
            control_send,
            lease,
            ..
        } = self;
        match outbound {
            Some(frame) => {
                // Deadline-bounded: a peer that keeps its connection
                // alive but stops reading this stream would otherwise
                // suspend the whole loop here indefinitely while the
                // unbounded forward channel keeps growing. See
                // `MESH_STREAM_WRITE_TIMEOUT`.
                match await_while_current(
                    lease,
                    tokio::time::timeout(
                        MESH_STREAM_WRITE_TIMEOUT,
                        rally_point_transport::mesh_control_stream::send_mesh_control_frame(
                            control_send,
                            &frame,
                        ),
                    ),
                )
                .await
                {
                    LeaseAwait::Superseded => return ControlFlow::Break(MeshLinkExit::Superseded),
                    LeaseAwait::Completed(Ok(Ok(()))) => {}
                    LeaseAwait::Completed(Ok(Err(error))) => {
                        tracing::info!(%error, "mesh control send failed; closing link");
                        return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
                    }
                    LeaseAwait::Completed(Err(_)) => {
                        tracing::warn!("mesh control send stalled; closing link");
                        return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
                    }
                }
                ControlFlow::Continue(())
            }
            None => ControlFlow::Break(MeshLinkExit::CommandChannelClosed),
        }
    }

    /// Sends one locally originated turn out this link for the session it names.
    pub(super) async fn send_forwarded_turn(
        &mut self,
        forwarded: Option<(SessionId, Payload)>,
    ) -> ControlFlow<MeshLinkExit> {
        let Self {
            link,
            control_send,
            joined,
            lease,
            conditions,
            ..
        } = self;
        match forwarded {
            Some((session_id, payload)) => {
                let Some(state) = joined.get(&session_id) else {
                    return ControlFlow::Continue(());
                };
                let key = state.key.clone();
                let outgoing = snapshot_conditions(conditions, &key);
                let carried_redundancy = match await_while_current(
                    lease,
                    send_turn_over_link(link, control_send, &key, payload, outgoing, "forward"),
                )
                .await
                {
                    LeaseAwait::Superseded => return ControlFlow::Break(MeshLinkExit::Superseded),
                    LeaseAwait::Completed(Some(carried)) => carried,
                    LeaseAwait::Completed(None) => {
                        return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
                    }
                };
                if let Some(state) = joined.get_mut(&session_id) {
                    defer_flush_after_send(
                        &mut state.flush_deadline,
                        carried_redundancy,
                        tokio::time::Instant::now(),
                    );
                }
                ControlFlow::Continue(())
            }
            None => ControlFlow::Break(MeshLinkExit::CommandChannelClosed),
        }
    }

    /// Handles one `MeshCommand`: open or close a session's transport state and
    /// registration on this link, or wind the driver down when the channel
    /// closes.
    pub(super) async fn handle_command(
        &mut self,
        command: Option<MeshCommand>,
        mut maintenance_sleep: Pin<&mut tokio::time::Sleep>,
    ) -> ControlFlow<MeshLinkExit> {
        let Self {
            link,
            joined,
            lease,
            presence_tx,
            presence_sent,
            peer_presence_seen,
            forward_tx,
            control_forward_tx,
            shutdown,
            seen_registries,
            mesh_links,
            conditions,
            decision_makers,
            maintenance,
            idle_since,
            sessions,
            ..
        } = self;
        match command {
            Some(MeshCommand::Join(key)) => {
                let joined_presence = lease.with_current(|| {
                    let session_id = key.session;
                    if let Some(existing) = joined.get(&session_id)
                        && existing.key.tenant != key.tenant
                    {
                        tracing::error!(
                            session = session_id.0,
                            existing_tenant = existing.key.tenant.as_ref(),
                            new_tenant = key.tenant.as_ref(),
                            "session id collision across tenants; refusing second tenant",
                        );
                        return None;
                    }
                    // Already joined (same tenant): a re-announce is harmless.
                    if joined.contains_key(&session_id) {
                        return None;
                    }
                    let first_session = joined.is_empty();
                    let live_players = local_live_players(sessions, &key);
                    link.open_session(mesh_session_key(&key));
                    // Anchor each slot's receive window at the seq this
                    // session actually still needs — its forwarded-to-locals
                    // cursor — rather than 0. A session joins a link
                    // mid-stream whenever the link redialed (or this relay
                    // joined a running session), so an unanchored window
                    // would open a full window's width behind the live
                    // stream. The peer's resume replay (asked for just
                    // below) starts from these same cursors, so the window
                    // and the replay agree on where the stream resumes.
                    // No-op on slots with no contiguous forwarded prefix;
                    // the window's own forward collapse covers those.
                    for (slot, next_needed) in resume_cursor_snapshot(seen_registries, &key) {
                        link.anchor_receive_window(mesh_session_key(&key), slot, next_needed);
                    }
                    let registration = register_mesh_link(
                        mesh_links,
                        key.clone(),
                        forward_tx.clone(),
                        control_forward_tx.clone(),
                        Arc::clone(shutdown),
                    );
                    // Replay every currently-active local slot after the
                    // link registration. This closes the race where a
                    // client's original announcement ran before the Join.
                    // The same snapshot carries active connection epochs.
                    reconcile_local_slots_on_join(conditions, control_forward_tx, &key);
                    // And the game-started reports its own home clients made,
                    // which reach no other relay on their own.
                    reconcile_started_slots_on_join(decision_makers, control_forward_tx, &key);
                    // Re-send this relay's known leave state for the session
                    // down the fresh registration, so a link that died and
                    // redialed (its `joined` empty again) reconverges. All of
                    // these are idempotent (dedup by slot everywhere).
                    reconcile_leaves_on_join(decision_makers, control_forward_tx, &key);
                    // Ask the peer, over the same fresh registration, to
                    // replay whatever this relay's forward-gate is still
                    // missing for the session — the resume-cursor mesh
                    // counterpart of the leave re-sync just above.
                    reconcile_resume_cursors_on_join(seen_registries, control_forward_tx, &key);
                    let joined_at = tokio::time::Instant::now();
                    joined.insert(
                        session_id,
                        SessionState {
                            key,
                            flush_deadline: joined_at + routing::FLUSH_INTERVAL,
                            _registration: registration,
                        },
                    );
                    if first_session {
                        maintenance.arm(joined_at);
                        maintenance_sleep
                            .as_mut()
                            .reset(maintenance.deadline().expect("armed maintenance timer"));
                    }
                    *idle_since = None;
                    peer_presence_seen.remove(&session_id);
                    Some((session_id, live_players))
                });
                let Some(joined_presence) = joined_presence else {
                    return ControlFlow::Break(MeshLinkExit::Superseded);
                };
                let Some((session_id, live_players)) = joined_presence else {
                    return ControlFlow::Continue(());
                };
                // Announce this session's presence right away rather
                // than waiting a flush tick: a fresh join (or a
                // rejoin on a redialed link, whose `presence_sent`
                // starts empty) is exactly when the peer knows
                // nothing yet. Deadline-bounded like every inline
                // stream write here — see `MESH_STREAM_WRITE_TIMEOUT`.
                match await_while_current(
                    lease,
                    tokio::time::timeout(
                        MESH_STREAM_WRITE_TIMEOUT,
                        push_presence_updates(
                            presence_tx,
                            presence_sent,
                            &[(session_id, live_players)],
                        ),
                    ),
                )
                .await
                {
                    LeaseAwait::Superseded => return ControlFlow::Break(MeshLinkExit::Superseded),
                    LeaseAwait::Completed(Ok(Ok(()))) => {}
                    LeaseAwait::Completed(Ok(Err(_)) | Err(_)) => {
                        tracing::info!("mesh presence push failed or stalled; closing link");
                        return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
                    }
                }
                ControlFlow::Continue(())
            }
            Some(MeshCommand::Leave(key)) => {
                let leave_current = lease.with_current(|| {
                    let session_id = key.session;
                    // Match the full SessionKey, not just the wire's bare
                    // session id. A colliding cross-tenant Join (same id,
                    // different tenant) was refused at Join time and never
                    // entered `joined`, so a later Leave carrying that
                    // refused key must not evict the tenant that
                    // legitimately holds the id — that would close the wrong
                    // tenant's session and cross-wire the two.
                    if joined
                        .get(&session_id)
                        .is_some_and(|state| state.key == key)
                    {
                        // Dropping the removed `SessionState` deregisters this
                        // session's mesh forward channel (its RAII guard).
                        joined.remove(&session_id);
                        link.close_session(mesh_session_key(&key));
                        presence_sent.remove(&session_id);
                        peer_presence_seen.remove(&session_id);
                        // Arm the idle timer when the last session leaves,
                        // so the driver tears the link down after
                        // `idle_timeout` of no further Joins.
                        if joined.is_empty() {
                            maintenance.disarm();
                            *idle_since = Some(tokio::time::Instant::now());
                        }
                    }
                });
                if leave_current.is_none() {
                    return ControlFlow::Break(MeshLinkExit::Superseded);
                }
                ControlFlow::Continue(())
            }
            // The command channel closed: the sender (the relay's
            // mesh-link manager, or the test) dropped it, signaling
            // the link should wind down.
            None => ControlFlow::Break(MeshLinkExit::CommandChannelClosed),
        }
    }
}
