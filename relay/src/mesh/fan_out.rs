//! Fan-out to peer relays: the turn and control-frame deliveries that leave
//! this relay for every peer serving a session, plus the link-level cursor
//! folds that keep the shared connection's windows bounded.

use std::collections::HashMap;
use std::sync::Arc;

use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::{
    FinalizeDrop, FinalizeDropResult, GameChat, LeaveDirective, LobbyCommand, MeshControlFrame,
    Payload, PlayerSkin, mesh_control_frame,
};
use tokio::sync::{Notify, mpsc};

use crate::routing::{self, SessionKey};

use super::frames::*;
use super::links::{MeshControlTx, MeshForwardTx, SessionState};
use super::{MeshLinks, mesh_session_key};

/// Delivers a locally originated `payload` to every peer-relay mesh link serving
/// `key`, without ever blocking on a slow peer. Mirrors `routing::fan_out` but
/// for mesh links instead of local slots. Callers must enforce the ingress
/// boundary: a payload received from a mesh peer must never enter this function.
///
/// A full forward queue is *not* the same recoverable case a full local slot
/// queue is: a local client's own transport re-carries a dropped datagram from
/// its own unacked window, but this queue feeds the mesh link's `AckManager` —
/// a turn dropped here never enters it, so the link has nothing to re-carry on
/// its own. So, like `routing::fan_out`'s lagging peer, a full queue signals
/// the link to reset (see `MeshLinkTx`'s `shutdown` field) rather than silently
/// dropping the turn: the dial supervisor redials, the Join-time reconcile
/// re-syncs leave state, and each side's resume-cursor exchange on that fresh
/// link (see `reconcile_resume_cursors_on_join`) replays whatever the
/// peer's forward-gate is still missing from this relay's own
/// locally-originated turns — turning what would otherwise be a permanent
/// per-(slot, seq) gap into a recovered one. Never a per-packet retransmit:
/// the recovery is resume-from-cursor on the next Join, not acknowledgement
/// of this specific drop.
pub fn fan_out_to_mesh(links: &MeshLinks, key: &SessionKey, payload: Payload) {
    let targets: Vec<(MeshForwardTx, Arc<Notify>)> = {
        let roster = links.lock();
        match roster.get(key) {
            Some(mesh_txs) => mesh_txs
                .iter()
                .map(|tx| (tx.forward.clone(), Arc::clone(&tx.shutdown)))
                .collect(),
            None => Vec::new(),
        }
    };
    for (tx, shutdown) in targets {
        // Tag with the session id so the driver's merged receiver can demux.
        match tx.try_send((key.session, payload.clone())) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    "mesh forward queue full; resetting the congested link",
                );
                shutdown.notify_one();
            }
            // The driver already exited (a redial, if warranted, is already
            // in motion via whatever ended it); nothing more to signal.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

/// Delivers `frame` to every peer-relay mesh link serving `key` over each link's
/// reliable control stream. The control-channel twin of [`fan_out_to_mesh`], but
/// unbounded and drop-free: a control frame propagates a synced player-leave, so —
/// unlike a redundantly-re-carried turn — it must never be dropped. The frame's
/// `session` is stamped to `key` so every link on the pair reads it under the
/// right tenant-scoped session, exactly as its bare `MeshPacket` session resolves.
///
/// Senders are cloned under the lock and the lock dropped before delivery, as in
/// [`fan_out_to_mesh`]. The only send failure is a closed channel (the driver
/// exited); that is tolerated — the link is gone, and a redialed one re-syncs its
/// state via the Join-time reconcile.
pub(crate) fn fan_out_control(links: &MeshLinks, key: &SessionKey, mut frame: MeshControlFrame) {
    frame.session = key.session.0;
    let targets: Vec<MeshControlTx> = {
        let roster = links.lock();
        match roster.get(key) {
            Some(mesh_txs) => mesh_txs.iter().map(|tx| tx.control.clone()).collect(),
            None => Vec::new(),
        }
    };
    for tx in targets {
        let _ = tx.send(frame.clone());
    }
}

/// Ships one destination client's complete delivered-through cursor map to every
/// peer relay serving `key` — the home relay re-sharing the beacon cursors it
/// already reads, so the session's authority (wherever it is) can fold final
/// delivery. Declarative per frame (the complete map), throttled at the caller
/// by [`crate::consensus::delivery::CursorShare`]; the receiver folds it and never
/// re-broadcasts (the no-echo rule every mesh control kind follows).
pub(crate) fn fan_out_delivery_cursors(
    links: &MeshLinks,
    key: &SessionKey,
    dest: SlotId,
    cursors: &[(SlotId, u64)],
) {
    fan_out_control(
        links,
        key,
        MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::DeliveryCursors(
                rally_point_proto::messages::DeliveryCursors {
                    dest_slot: u32::from(dest.0),
                    cursors: cursors
                        .iter()
                        .map(
                            |&(origin, seq)| rally_point_proto::messages::DeliveryCursor {
                                origin_slot: u32::from(origin.0),
                                delivered_seq: seq,
                            },
                        )
                        .collect(),
                },
            )),
        },
    );
}

/// Applies a peer's `MeshAckCursors` push to this link's own transport: for
/// each named slot, force-retires this link's unacked window through the
/// peer-confirmed cursor -- the mesh-link counterpart of a client-edge
/// driver's `Link::retire_through` call off its beacon reader. A no-op for
/// any other frame kind, a zero session, or a slot id out of `SlotId` range
/// (defensive; wire values are validated upstream). A cursor for a session
/// this link hasn't opened is harmless: `MeshLink::retire_through` already
/// returns `0` for one, matching how every other control-frame kind here
/// tolerates a stale or unknown session.
///
/// Called from [`run_mesh_link`]'s own select branch, before the ordinary
/// [`dispatch_mesh_control`] -- like [`resume_replay_for_frame`], it needs
/// direct access to this link's transport state, which that function does
/// not have.
///
/// `joined` supplies the session's tenant (this relay always knows it for a
/// session it has joined), so the retire targets the same tenant-scoped
/// [`MeshSessionKey`] the datagram path opened. A frame naming a session this
/// relay hasn't joined (predating a Leave, or a stale peer echo) is harmless:
/// there is no key to build, so it falls through as a no-op exactly like an
/// unopened session already does.
pub(super) fn apply_ack_cursors(
    link: &mut rally_point_transport::MeshLink,
    frame: &MeshControlFrame,
    joined: &HashMap<SessionId, SessionState>,
) {
    if frame.session == 0 {
        return;
    }
    let Some(mesh_control_frame::Kind::MeshAckCursors(cursors)) = &frame.kind else {
        return;
    };
    let session = SessionId(frame.session);
    let Some(state) = joined.get(&session) else {
        return;
    };
    let key = mesh_session_key(&state.key);
    for cursor in &cursors.cursors {
        let Ok(slot) = u8::try_from(cursor.slot).map(SlotId) else {
            continue;
        };
        link.retire_through(key.clone(), slot, cursor.delivered_through);
    }
}

/// Folds an `OversizeTurn` frame's `(slot, seq)` into this link's per-session
/// receive dedup — the stream-delivered turn must advance the same
/// delivered-through prefix a datagram delivery would, or the seq holds a
/// permanent gap that stalls the ack-cursor push and pins the peer's unacked
/// window (mirroring the client edge's own `deliver_external` fold on its
/// oversize ingress). Returns whether the frame should still be dispatched:
/// `false` only for an oversize turn the link's dedup has already delivered
/// (dropping a redundant copy before it burns a session-level dedup pass);
/// every other frame kind, and every defensively-skipped case (zero/unjoined
/// session, out-of-range slot — the dispatch's own arms log and drop those),
/// passes through as `true`.
///
/// Called from [`run_mesh_link`]'s own select branch before
/// [`dispatch_mesh_control`], like [`apply_ack_cursors`]: it needs direct
/// access to this link's transport state, which the dispatch does not have.
/// A fold failure is logged and the turn still dispatched — delivering a turn
/// whose transport bookkeeping hiccuped merely leans on the session-level
/// dedup, while dropping it would strand a gap in every local client.
pub(super) fn fold_oversize_into_link(
    link: &mut rally_point_transport::MeshLink,
    frame: &MeshControlFrame,
    joined: &HashMap<SessionId, SessionState>,
) -> bool {
    let Some(mesh_control_frame::Kind::OversizeTurn(payload)) = &frame.kind else {
        return true;
    };
    if frame.session == 0 {
        return true;
    }
    let Some(state) = joined.get(&SessionId(frame.session)) else {
        return true;
    };
    let Ok(slot) = u8::try_from(payload.slot).map(SlotId) else {
        return true;
    };
    match link.deliver_external(mesh_session_key(&state.key), slot, payload.seq) {
        Ok(fresh) => {
            if !fresh {
                tracing::debug!(
                    tenant = state.key.tenant.as_ref(),
                    session = frame.session,
                    slot = slot.0,
                    seq = payload.seq,
                    "oversize mesh turn already delivered on this link; dropping",
                );
            }
            fresh
        }
        Err(error) => {
            tracing::warn!(
                %error,
                session = frame.session,
                slot = slot.0,
                seq = payload.seq,
                "folding oversize mesh turn into link dedup failed; delivering anyway",
            );
            true
        }
    }
}

/// Builds one joined session's mesh-link cursor frame when its
/// delivered-through state has advanced past what the peer last heard -- the
/// mesh-link counterpart of the client edge's ack-beacon push. The caller
/// invokes this inside the link-wide maintenance pass, alongside this session's
/// flush/window/presence checks, then writes every frame the pass produced as
/// one control-stream batch. Push-on-advance: a slot with nothing new since the
/// last push produces no frame, so a healthy link stays quiet.
pub(super) fn reconcile_ack_cursors(
    link: &rally_point_transport::MeshLink,
    ack_cursors_sent: &mut HashMap<(SessionId, SlotId), u64>,
    state: &SessionState,
) -> Option<MeshControlFrame> {
    let session_id = state.key.session;
    let advanced: Vec<(SlotId, u64)> = link
        .delivered_through_all(mesh_session_key(&state.key))
        .into_iter()
        .filter(|&(slot, cursor)| {
            !matches!(
                ack_cursors_sent.get(&(session_id, slot)),
                Some(&prev) if prev >= cursor
            )
        })
        .collect();
    if advanced.is_empty() {
        return None;
    }
    for &(slot, cursor) in &advanced {
        ack_cursors_sent.insert((session_id, slot), cursor);
    }
    Some(ack_cursors_frame(session_id, advanced))
}

/// Announces a departed slot to every peer relay serving `key`: the home relay
/// tells its peers one of its clients left, so the session's authority can author
/// the synced leave and every relay records the departure for handoff robustness.
pub(crate) fn fan_out_slot_departed(
    links: &MeshLinks,
    key: &SessionKey,
    slot: SlotId,
    stamps: &crate::consensus::DepartureStamps,
    reason: u32,
    connection_epoch: Option<u64>,
) {
    fan_out_control(
        links,
        key,
        slot_departed_frame(key.session, slot, stamps, reason, connection_epoch),
    );
}

/// Propagates a synced leave the authority decided to every peer relay serving
/// `key`, so each pushes it down its own local survivors. A relay that receives
/// this caches and locally fans it out but does not re-broadcast it — no echo.
pub(crate) fn fan_out_leave_directive(links: &MeshLinks, key: &SessionKey, leave: LeaveDirective) {
    fan_out_control(links, key, leave_directive_frame(key.session, leave));
}

/// Propagates a member's lobby command to every peer relay serving `key`, so each
/// fans it out to its own local members and appends it to its own replay log. The
/// origin relay stamps the authoring slot onto `command` before this call, so a
/// peer copy already carries the authoritative author. A relay that receives this
/// delivers it locally but does not re-broadcast it — no echo — mirroring the
/// oversize-turn divert.
pub(crate) fn fan_out_lobby_command(links: &MeshLinks, key: &SessionKey, command: LobbyCommand) {
    fan_out_control(links, key, lobby_command_frame(key.session, command));
}

/// Propagates one member's game-chat message to every peer relay serving `key`,
/// so each fans it out to its own local members. The origin relay stamps the
/// authoring slot onto `chat` before this call, so a peer copy already carries
/// the authoritative author. A relay that receives this delivers it locally but
/// does not re-broadcast it — no echo — mirroring [`fan_out_lobby_command`]
/// minus the replay-log side effect (chat keeps none).
pub(crate) fn fan_out_chat(links: &MeshLinks, key: &SessionKey, chat: GameChat) {
    fan_out_control(links, key, chat_frame(key.session, chat));
}

/// Propagates one member's cosmetic-skin blob to every peer relay serving `key`,
/// so each stores it and fans it out to its own local members. The origin relay
/// stamps the authoring slot onto `skin` before this call, so a peer copy already
/// carries the authoritative author. A relay that receives this stores and
/// locally fans it out but does not re-broadcast it — no echo — mirroring
/// [`fan_out_lobby_command`] (a peer stores it for its own late joiners, as with
/// the lobby log) rather than [`fan_out_chat`] (which keeps nothing).
pub(crate) fn fan_out_skin(links: &MeshLinks, key: &SessionKey, skin: PlayerSkin) {
    fan_out_control(links, key, skin_frame(key.session, skin));
}

/// Announces a freshly registered slot to every peer relay serving `key`, so
/// each accumulates it into the session's live-slot set and the authority can
/// decide when every expected slot has connected. A duplicate (a re-announce) is
/// idempotent — the accumulated set is a set.
pub(crate) fn fan_out_slot_present(links: &MeshLinks, key: &SessionKey, slot: SlotId) {
    fan_out_control(links, key, slot_present_frame(key.session, slot));
}

/// Shares one home client's game-started report with every peer relay serving
/// `key`. The report reaches only the slot's home, but every relay's silent-slot
/// watch has to know whether a slot is still loading, so the home tells them. A
/// receiving relay records it and nothing else — it does not re-broadcast (no
/// echo) and does not report the slot to its own coordinator connection, which
/// stays the home's job. A duplicate is idempotent — the accumulated set is a
/// set.
pub(crate) fn fan_out_slot_started(links: &MeshLinks, key: &SessionKey, slot: SlotId) {
    fan_out_control(links, key, slot_started_frame(key.session, slot));
}

/// Broadcasts the session-start directive the authority decided to every peer
/// relay serving `key`, so each fans it down its own local slots — carrying the
/// authority's computed initial buffer depth (`None` when it sized none) so each
/// peer adopts the same depth. A relay that receives this latches the session
/// started and fans it locally but does not re-broadcast it — the authority
/// already sent it to every relay — so there is no echo.
pub(crate) fn fan_out_session_start(
    links: &MeshLinks,
    key: &SessionKey,
    initial_buffer_turns: Option<u32>,
) {
    fan_out_control(
        links,
        key,
        session_start_frame(key.session, initial_buffer_turns),
    );
}

/// Broadcasts a slot-connectivity change to every peer relay serving `key`, so
/// each fans it down its own local slots. Sent the moment the origin relay's
/// home client's link dies (`connected` false) or (re)registers (`connected`
/// true). A relay that receives this delivers it to its local slots but does not
/// re-broadcast it — the origin already sent a copy to every peer, so re-flooding
/// would only echo (mirroring the chat/oversize-turn divert). Best-effort and
/// informational; it rides the reliable mesh control stream but carries no
/// delivery guarantee of its own.
pub(crate) fn fan_out_slot_connectivity(
    links: &MeshLinks,
    key: &SessionKey,
    slot: SlotId,
    connected: bool,
    connection_epoch: Option<u64>,
) {
    fan_out_control(
        links,
        key,
        slot_connectivity_frame(key.session, slot, connected, connection_epoch),
    );
}

/// Broadcasts a manual drop request to every peer relay serving `key`, so the
/// session's authority relay — which may be a peer, not this one — can honor it.
/// `requester` is the authenticated slot that authored the request, stamped here
/// for logging and abuse attribution; `target` is the disconnected slot it wants
/// dropped. A relay that receives this honors it only if it is the authority and
/// the target's drop is past the unlock floor, and does not re-broadcast it — the
/// origin already sent a copy to every peer, so re-flooding would only echo.
pub(crate) fn fan_out_request_drop(
    links: &MeshLinks,
    key: &SessionKey,
    target: SlotId,
    requester: SlotId,
) {
    fan_out_control(
        links,
        key,
        request_drop_frame(key.session, target, requester),
    );
}

/// Broadcasts the authority's request that a dropped slot's home finalize the
/// drop. Sent to every peer serving `key` — the one relay whose descriptor
/// strictly homes the slot self-selects and answers; the rest ignore it.
/// Idempotent by design: every honored drop request re-sends it until a
/// result decides the leave.
pub(crate) fn fan_out_finalize_drop(
    links: &MeshLinks,
    key: &SessionKey,
    target: SlotId,
    connection_epoch: Option<u64>,
) {
    fan_out_control(
        links,
        key,
        MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::FinalizeDrop(FinalizeDrop {
                slot: u32::from(target.0),
                connection_epoch,
            })),
        },
    );
}

/// Broadcasts the home's finalization outcome. Sent to every peer serving
/// `key` rather than plumbed back to one link — the authority (wherever it is,
/// including mid-handoff) self-selects on receipt; everyone else ignores it.
pub(crate) fn fan_out_finalize_drop_result(
    links: &MeshLinks,
    key: &SessionKey,
    target: SlotId,
    connection_epoch: Option<u64>,
    outcome: crate::consensus::FinalizeOutcome,
) {
    let (outcome, final_turn_count) = match outcome {
        crate::consensus::FinalizeOutcome::Finalized { final_turn_count } => {
            (FINALIZE_OUTCOME_FINALIZED, Some(final_turn_count))
        }
        crate::consensus::FinalizeOutcome::RejectedLive => (FINALIZE_OUTCOME_REJECTED_LIVE, None),
        crate::consensus::FinalizeOutcome::RejectedNoCursor => {
            (FINALIZE_OUTCOME_REJECTED_NO_CURSOR, None)
        }
    };
    fan_out_control(
        links,
        key,
        MeshControlFrame {
            session: key.session.0,
            kind: Some(mesh_control_frame::Kind::FinalizeDropResult(
                FinalizeDropResult {
                    slot: u32::from(target.0),
                    connection_epoch,
                    outcome,
                    final_turn_count,
                },
            )),
        },
    );
}

/// Broadcasts a batch of synced leaves — the ones a fresh authority promotion
/// must (re)deliver — to both local survivors ([`routing::fan_out_leave`]) and
/// every peer relay ([`fan_out_leave_directive`]). All are idempotent: clients
/// dedup by slot, and a peer relay caches by slot. A no-op on an empty batch (the
/// overwhelmingly common case — most authority changes carry no pending leave).
pub(crate) fn broadcast_leaves(
    sessions: &routing::Sessions,
    mesh_links: &MeshLinks,
    key: &SessionKey,
    leaves: Vec<LeaveDirective>,
) {
    for leave in leaves {
        // Every leave reaching this point was already accepted by this
        // relay's own consensus (`decide_leave`/`observe_leave`), which
        // validates the slot before caching it -- so this should always
        // succeed. Refusing gracefully rather than truncating keeps that
        // true by construction instead of by this call path's current
        // shape, so a future caller that skips consensus can't silently
        // alias a leave onto the wrong slot.
        let Ok(slot) = u8::try_from(leave.slot).map(SlotId) else {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = leave.slot,
                "synced leave broadcast names a slot id out of range; dropping",
            );
            continue;
        };
        routing::fan_out_leave(sessions, key, slot, leave);
        fan_out_leave_directive(mesh_links, key, leave);
    }
}
