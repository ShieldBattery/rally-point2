//! The mesh-link driver's loop state and the bodies of its longer `select!`
//! arms: the periodic maintenance pass, an inbound datagram, a peer control
//! frame, and a peer presence report.
//!
//! [`LinkDriver`] exists so those bodies can be written as ordinary methods
//! over the loop's locals; each returns [`ControlFlow::Break`] carrying the
//! [`MeshLinkExit`] the loop would have broken with, and
//! [`ControlFlow::Continue`] where it would have gone round again.

use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::Arc;

use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::MeshControlFrame;
use tokio::sync::Notify;

use crate::routing::{self};

use super::conditions::ConditionsRegistry;
use super::dispatch::dispatch_mesh_control;
use super::fan_out::{apply_ack_cursors, fold_oversize_into_link, reconcile_ack_cursors};
use super::forward::{resume_replay_for_frame, send_resume_replay};
use super::join::{
    local_live_players, push_presence_updates, reconcile_local_slots_on_join,
    reconcile_started_slots_on_join,
};
use super::link_run::{MeshMaintenanceTimer, defer_flush_after_send};
use super::links::{
    LeaseAwait, MESH_STREAM_WRITE_TIMEOUT, MeshControlTx, MeshForwardTx, MeshLinkExit,
    MeshLinkLease, MeshLinks, MeshRttCache, SessionState, await_while_current,
    mesh_window_exhausted,
};
use super::seen::SeenRegistries;
use super::{MeshState, broadcast_leaves, deliver_mesh_turn, mesh_session_key};

/// Everything one [`run_mesh_link`](super::link_run::run_mesh_link) loop
/// iteration touches, held together so each extracted `select!` arm body can
/// take it by `&mut` instead of a dozen separate parameters. The channel
/// receivers stay outside: each is polled by exactly one branch, and only the
/// value it yields reaches the arm body here.
pub(super) struct LinkDriver {
    /// The shared relay-pair transport, demultiplexed by session.
    pub(super) link: rally_point_transport::MeshLink,
    /// The outbound half of the bidirectional mesh control stream.
    pub(super) control_send: rally_point_transport::noq::SendStream,
    /// The outbound half of the peer presence stream.
    pub(super) presence_tx: rally_point_transport::noq::SendStream,
    /// The sender each joined session registers for outbound control frames.
    pub(super) control_forward_tx: MeshControlTx,
    /// The sender each joined session registers for outbound turns.
    pub(super) forward_tx: MeshForwardTx,
    /// This link's reset signal, notified when its shared forward queue fills.
    pub(super) shutdown: Arc<Notify>,
    /// The live-player count last pushed to the peer, per session.
    pub(super) presence_sent: HashMap<SessionId, u32>,
    /// Sessions whose peer has proved its own Join with a presence report.
    pub(super) peer_presence_seen: HashSet<SessionId>,
    /// The delivered-through cursor last pushed to the peer, per (session, slot).
    pub(super) ack_cursors_sent: HashMap<(SessionId, SlotId), u64>,
    /// Per-session driver state, keyed by the wire's bare session id.
    pub(super) joined: HashMap<SessionId, SessionState>,
    /// When the last session left; `None` while any is joined, and before the
    /// first Join.
    pub(super) idle_since: Option<tokio::time::Instant>,
    /// The link-wide maintenance cadence.
    pub(super) maintenance: MeshMaintenanceTimer,
    /// The lazily sampled relay-pair round-trip time.
    pub(super) mesh_rtt: MeshRttCache,
    /// This driver's process-local provenance lease.
    pub(super) lease: MeshLinkLease,
    /// The peer relay this link serves.
    pub(super) peer_id: RelayId,
    /// The relay's local client roster.
    pub(super) sessions: routing::Sessions,
    /// The whole mesh bundle, for the dispatch and delivery paths that take it.
    pub(super) mesh_for_dispatch: MeshState,
    /// The session-to-peer-link fan-out registry.
    pub(super) mesh_links: MeshLinks,
    /// The session-level forward-once gate.
    pub(super) seen_registries: SeenRegistries,
    /// This relay's own home-client link conditions.
    pub(super) conditions: ConditionsRegistry,
    /// The per-session latency-buffer decision-makers.
    pub(super) decision_makers: Arc<crate::consensus::DecisionMakers>,
    /// The per-session presence registry.
    pub(super) presence: Arc<crate::session::presence::PresenceRegistry>,
    /// The per-relay holds on dropped slots' synced-leave decisions.
    pub(super) drop_holds: crate::session::drop_hold::DropHolds,
}

impl LinkDriver {
    /// Runs the link-wide maintenance pass once its deadline has come: the
    /// per-session unacked-window check, fresh-free flush, presence
    /// reconciliation, and ack-cursor beacon, then rearms the schedule. A no-op
    /// while the schedule is disarmed or the deadline is not yet due.
    pub(super) async fn run_due_maintenance(
        &mut self,
        mut maintenance_sleep: Pin<&mut tokio::time::Sleep>,
    ) -> ControlFlow<MeshLinkExit> {
        let Self {
            link,
            control_send,
            presence_tx,
            presence_sent,
            ack_cursors_sent,
            joined,
            maintenance,
            lease,
            sessions,
            ..
        } = self;
        // Service due maintenance synchronously, before selecting on the data
        // paths. The select below is biased toward the hot branches, and a
        // saturated link keeps them continuously ready — so if maintenance
        // only ran as a (lower-priority) select branch, sustained traffic
        // could postpone it without bound. Maintenance carries work that must
        // not lose to throughput: the per-session fresh-free flushes (the only
        // packets a wide payload blocked at the refill's head of line can ride
        // — see the head-of-line gate in the transport's redundancy refill),
        // the ack-cursor beacon that keeps unacked windows bounded, the
        // window-cap check, and presence. Running the due check at the top of
        // every loop iteration bounds its delay by one event's servicing time,
        // independent of select polling order.
        if maintenance
            .deadline()
            .is_some_and(|deadline| deadline <= tokio::time::Instant::now())
        {
            let now = tokio::time::Instant::now();
            let mut failed = None;
            let mut window_exhausted = false;
            let mut presence_updates = Vec::new();
            let mut ack_cursor_frames = Vec::with_capacity(joined.len());

            // One link-wide pass handles every periodic responsibility.
            // Ordinary turn and control events can wake this select loop
            // thousands of times a second; none of them scans `joined`.
            for state in joined.values_mut() {
                let key = mesh_session_key(&state.key);
                let in_flight = link.payloads_in_flight(key.clone());
                // Checked every link-wide tick, independent of this
                // session's own flush deadline. See
                // `MESH_UNACKED_WINDOW_CAP` for why this reads per session,
                // not summed across the link.
                if mesh_window_exhausted(in_flight) {
                    window_exhausted = true;
                    break;
                }
                if state.flush_deadline <= now {
                    if in_flight > 0
                        && let Err(error) = link.send(key, None, None)
                    {
                        failed = Some(error);
                        break;
                    }
                    state.flush_deadline = now + routing::FLUSH_INTERVAL;
                }

                let live = local_live_players(sessions, &state.key);
                if presence_sent.get(&state.key.session) != Some(&live) {
                    presence_updates.push((state.key.session, live));
                }

                if let Some(frame) = reconcile_ack_cursors(link, ack_cursors_sent, state) {
                    ack_cursor_frames.push(frame);
                }
            }
            if window_exhausted {
                // The ack-cursor beacon (`reconcile_ack_cursors`, above)
                // could not keep this session's window bounded -- a
                // genuine forward gap, not lost reverse-path acks. Reset
                // the whole link like the full-forward-queue case: the
                // redial's Join/reconcile and resume-cursor exchange
                // recover every session on it, including this one.
                tracing::warn!("mesh unacked window exceeded cap; resetting link");
                return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
            }
            if let Some(error) = failed {
                tracing::info!(%error, "mesh flush failed; closing link");
                return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
            }
            // Reconcile presence on the same cadence: push each joined
            // session's live-player count when it differs from what the
            // peer last heard. Riding the tick (rather than hooking every
            // roster change into this task) keeps the roster paths free of
            // mesh plumbing; the ≤150ms of staleness is nothing against
            // the seconds-scale dwell of the buffer decisions presence
            // feeds. This reliable push is also why a relay whose players
            // have all left — and which therefore sends no datagrams at
            // all — still gets its "I'm out" to the peer.
            // Deadline-bounded like the control-stream writes: the
            // presence stream is written inline here too, so a peer that
            // stops reading it could suspend the whole loop. See
            // `MESH_STREAM_WRITE_TIMEOUT`.
            match await_while_current(
                lease,
                tokio::time::timeout(
                    MESH_STREAM_WRITE_TIMEOUT,
                    push_presence_updates(presence_tx, presence_sent, &presence_updates),
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
            // Every cursor frame is still independently length-prefixed and
            // decoded by the peer in this order; only the application write is
            // coalesced. Keeping this direct and link-local avoids routing up to
            // one frame per active session through our own control channel and
            // revisiting each through the select loop. Deadline-bound like all
            // other inline stream writes: a wedged peer resets the link rather
            // than suspending every joined session.
            match await_while_current(
                lease,
                tokio::time::timeout(
                    MESH_STREAM_WRITE_TIMEOUT,
                    rally_point_transport::mesh_control_stream::send_mesh_control_frames(
                        control_send,
                        &ack_cursor_frames,
                    ),
                ),
            )
            .await
            {
                LeaseAwait::Superseded => return ControlFlow::Break(MeshLinkExit::Superseded),
                LeaseAwait::Completed(Ok(Ok(()))) => {}
                LeaseAwait::Completed(Ok(Err(error))) => {
                    tracing::info!(%error, "mesh ack-cursor batch send failed; closing link");
                    return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
                }
                LeaseAwait::Completed(Err(_)) => {
                    tracing::warn!("mesh ack-cursor batch send stalled; closing link");
                    return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
                }
            }
            // Delay the next pass from completion rather than trying to
            // catch up missed ticks back-to-back after a slow stream write.
            maintenance.complete_tick(tokio::time::Instant::now());
            maintenance_sleep
                .as_mut()
                .reset(maintenance.deadline().expect("active maintenance timer"));
        }
        ControlFlow::Continue(())
    }

    /// Handles one inbound datagram, or the receive error that ended the link:
    /// resolve its session, fold the peer's conditions sidecar, and deliver
    /// each fresh payload to this relay's local clients.
    pub(super) fn handle_datagram(
        &mut self,
        received: Result<rally_point_transport::MeshReceived, rally_point_transport::MeshLinkError>,
    ) -> ControlFlow<MeshLinkExit> {
        let peer_id = self.peer_id;
        let Self {
            link,
            joined,
            mesh_rtt,
            lease,
            sessions,
            mesh_for_dispatch,
            decision_makers,
            ..
        } = self;
        match received {
            Ok(mesh_received) => {
                let _ = lease.with_current(|| {
                    let Some(state) = joined.get(&mesh_received.session) else {
                        tracing::warn!(
                            session = mesh_received.session.0,
                            "mesh datagram for unjoined session; dropping",
                        );
                        return;
                    };
                    let key = state.key.clone();
                    // Feed the peer relay's home-client conditions into this
                    // session's decision-maker. The mesh hop is a property of
                    // the relay-pair, sampled from this link's QUIC RTT, so a
                    // remote slot's effective path includes the trip across
                    // the backbone.
                    if let Some(peer_conditions) = &mesh_received.conditions {
                        tracing::trace!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            slots = peer_conditions.slots.len(),
                            "received peer-relay link conditions",
                        );
                        let mesh_rtt_us =
                            mesh_rtt.get_or_refresh(link.connection(), tokio::time::Instant::now());
                        // Any decision it fires is logged by the helper and
                        // broadcast later, at fan-out.
                        let _ = crate::consensus::ingest_remote_conditions(
                            decision_makers,
                            &key,
                            peer_conditions,
                            mesh_rtt_us,
                        );
                    }
                    for payload in mesh_received.delivery.fresh {
                        let slot = SlotId(payload.slot as u8);
                        // NOTE: no frame-observation or desync-comparator
                        // call here. Duplicate delivery can still occur
                        // across a link replacement, resume replay, or slot
                        // re-home, so consensus remains downstream of the
                        // session-level dedup in `deliver_mesh_turn`.
                        deliver_mesh_turn(
                            sessions,
                            mesh_for_dispatch,
                            &key,
                            slot,
                            payload,
                            peer_id,
                        );
                    }
                });
                ControlFlow::Continue(())
            }
            Err(rally_point_transport::MeshLinkError::UnknownSession(session)) => {
                tracing::warn!(
                    session = session.0,
                    "mesh packet for unknown session; ignoring",
                );
                ControlFlow::Continue(())
            }
            Err(error) => {
                tracing::info!(%error, "mesh link closed");
                ControlFlow::Break(MeshLinkExit::ConnectionFailed)
            }
        }
    }

    /// Handles one control frame from the peer relay: the link-local folds that
    /// need this driver's own transport state (ack cursors, a resume-cursor
    /// reply, the oversize-turn dedup fold), then the ordinary dispatch.
    pub(super) async fn handle_peer_control(
        &mut self,
        received: Option<MeshControlFrame>,
    ) -> ControlFlow<MeshLinkExit> {
        let peer_id = self.peer_id;
        let Self {
            link,
            control_send,
            joined,
            lease,
            conditions,
            sessions,
            mesh_for_dispatch,
            ..
        } = self;
        match received {
            Some(frame) => {
                if !lease.is_current() {
                    return ControlFlow::Continue(());
                }
                // A resume-cursor ask answers with turns THIS relay
                // originated, sent straight out this link — computed
                // and sent before the ordinary dispatch below, which
                // has no link to send a reply over (see
                // `resume_replay_for_frame`'s own doc).
                // A peer's push of its own link-level receive cursors:
                // force-retire this link's unacked window through them
                // before anything else touches the frame. Needs direct
                // link access `dispatch_mesh_control` doesn't have, so
                // it's handled here, like the resume-cursor reply below.
                apply_ack_cursors(link, &frame, joined);
                if let Some((key, payloads)) =
                    resume_replay_for_frame(&frame, joined, mesh_for_dispatch)
                {
                    let carried_redundancy = match await_while_current(
                        lease,
                        send_resume_replay(link, control_send, conditions, &key, payloads),
                    )
                    .await
                    {
                        LeaseAwait::Superseded => {
                            return ControlFlow::Break(MeshLinkExit::Superseded);
                        }
                        LeaseAwait::Completed(Some(carried)) => carried,
                        LeaseAwait::Completed(None) => {
                            return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
                        }
                    };
                    if let Some(state) = joined.get_mut(&key.session) {
                        defer_flush_after_send(
                            &mut state.flush_deadline,
                            carried_redundancy,
                            tokio::time::Instant::now(),
                        );
                    }
                }
                // An oversize turn's transport-dedup fold also needs
                // direct link access, so it too runs here. A copy the
                // link has already delivered stops before dispatch.
                let _ = lease.with_current(|| {
                    if fold_oversize_into_link(link, &frame, joined) {
                        dispatch_mesh_control(frame, peer_id, joined, sessions, mesh_for_dispatch);
                    }
                });
            }
            // The reader task ended: a one-sided stream reset, an
            // over-cap frame, a decode failure, or a clean EOF. This
            // stream is the only channel `SlotDeparted`,
            // `LeaveDirective`, an oversize-turn divert, and delivery
            // cursors ever arrive on from this peer, so losing it is a
            // link failure like any other here, not a degradation to
            // limp on through -- ending the driver lets the dial
            // supervisor (`dial_and_serve`) redial a fresh connection
            // and every stream comes up new. Harmless if the
            // connection was already dying for the same reason this
            // reader ended.
            None => {
                tracing::info!("mesh control stream reader ended; closing link");
                return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
            }
        }
        ControlFlow::Continue(())
    }

    /// Handles one presence report from the peer: record its live-player count
    /// and re-derive the session's buffer authority, and — on the first report
    /// for a session — replay the state that may have raced ahead of the peer's
    /// own Join, then answer the rendezvous.
    pub(super) async fn handle_presence_report(
        &mut self,
        received: Option<rally_point_proto::mesh::MeshPresence>,
    ) -> ControlFlow<MeshLinkExit> {
        let peer_id = self.peer_id;
        let Self {
            joined,
            lease,
            presence_tx,
            presence_sent,
            peer_presence_seen,
            control_forward_tx,
            conditions,
            decision_makers,
            presence,
            drop_holds,
            sessions,
            mesh_links,
            mesh_for_dispatch,
            ..
        } = self;
        match received {
            Some(report) => {
                let handshake_presence = lease.with_current(|| {
                    // Tenant-scope the bare wire session id through the
                    // joined map, like a datagram; a report for an
                    // unjoined session has no key to record under.
                    let state = joined.get(&report.session)?;
                    let key = state.key.clone();
                    let first_peer_presence = peer_presence_seen.insert(report.session);
                    if first_peer_presence {
                        reconcile_local_slots_on_join(conditions, control_forward_tx, &key);
                        reconcile_started_slots_on_join(decision_makers, control_forward_tx, &key);
                    }
                    if crate::session::presence::record_peer(
                        presence,
                        &key,
                        peer_id,
                        report.live_players,
                    ) {
                        // A promotion here (the peer's players all left, and
                        // this relay is next in the order) yields any synced
                        // leave the departed authority never delivered; push
                        // each to local survivors and across the mesh.
                        // Skip slots whose drop is still held on this relay: a
                        // promotion here must not decide a departure a
                        // reconnecting client could still return from, and a held
                        // drop is only ever decided by a manual request.
                        let held = drop_holds.pending_slots(&key);
                        let leaves = crate::session::presence::recompute(
                            presence,
                            decision_makers,
                            &key,
                            &held,
                        );
                        broadcast_leaves(sessions, mesh_links, &key, leaves);
                        // A promotion here may also make this relay the one to
                        // observe full slot presence: re-evaluate and fire the
                        // session-start directive if it now covers the expected
                        // set (idempotent for already-started sessions).
                        routing::maybe_start_session(sessions, decision_makers, mesh_links, &key);
                        // The peer's report may have emptied the session
                        // session-wide (the last live relay reporting zero),
                        // arming the abandoned-session timer — or refilled it,
                        // cancelling it.
                        routing::reconcile_abandon(sessions, mesh_for_dispatch, &key);
                    }
                    first_peer_presence
                        .then(|| (report.session, local_live_players(sessions, &key)))
                });
                let Some(handshake_presence) = handshake_presence else {
                    return ControlFlow::Break(MeshLinkExit::Superseded);
                };
                if let Some(update) = handshake_presence {
                    match await_while_current(
                        lease,
                        tokio::time::timeout(
                            MESH_STREAM_WRITE_TIMEOUT,
                            push_presence_updates(
                                presence_tx,
                                presence_sent,
                                std::slice::from_ref(&update),
                            ),
                        ),
                    )
                    .await
                    {
                        LeaseAwait::Superseded => {
                            return ControlFlow::Break(MeshLinkExit::Superseded);
                        }
                        LeaseAwait::Completed(Ok(Ok(()))) => {}
                        LeaseAwait::Completed(Ok(Err(_)) | Err(_)) => {
                            tracing::info!(
                                "mesh presence rendezvous reply failed or stalled; closing link"
                            );
                            return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
                        }
                    }
                }
                ControlFlow::Continue(())
            }
            // The reader task ended: the peer's presence stream reset
            // or closed while the connection lives on. Presence is the
            // authority-handoff signal — live-player counts drive
            // `record_peer`/`recompute` and with them who decides the
            // session's buffer and leaves — so a link that keeps
            // carrying turns while its presence view is frozen can
            // strand a session with no authority (or two) when the
            // peer's players leave. There is no read-side re-open (the
            // outbound reconcile is write-only), so treat it exactly
            // like the control-stream reader dying just above: end the
            // driver and let the dial supervisor bring up a fresh
            // connection with every stream new.
            None => {
                tracing::info!("mesh presence stream reader ended; closing link");
                ControlFlow::Break(MeshLinkExit::ConnectionFailed)
            }
        }
    }
}
