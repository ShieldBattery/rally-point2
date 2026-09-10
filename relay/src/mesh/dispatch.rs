//! The receive half of the mesh control stream: resolving a peer frame's bare
//! session id to a tenant-scoped key and folding each frame kind into this
//! relay's own session state.

use std::collections::HashMap;

use rally_point_proto::control::ResultEcho;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::{MeshControlFrame, mesh_control_frame};

use crate::routing::{self, SessionKey};

use super::dispatch_finalize::{dispatch_finalize_drop, dispatch_finalize_drop_result};
use super::links::SessionState;
use super::{MeshState, deliver_mesh_turn, fan_out_session_start};

/// Handles one control frame received from the peer relay over the mesh control
/// stream. Resolves the frame's bare session id to a tenant-scoped key through
/// the same per-link `joined` state the datagram path uses (the collision guard
/// makes that mapping unambiguous), then:
///
/// - **`SlotDeparted`**: records the departure — max-merging the carried last
///   frame with this relay's own observation of the slot (the fuller view wins)
///   and retiring the slot's live state — and, if this relay is the authority,
///   decides the one synced leave, pushing it to local survivors and
///   broadcasting it to every peer (including the origin, harmlessly: it dedups
///   by slot, and may have its own survivors). A non-authority relay records but
///   decides nothing.
/// - **`LeaveDirective`**: caches it (dedup by slot) and fans it out to local
///   survivors. It is **not** re-broadcast across the mesh — the authority already
///   sent it to every relay — so there is no echo.
/// - **`OversizeTurn`**: a turn too large for the peer's datagram path, folded
///   back into the normal turn path exactly as a datagram delivery would be —
///   frame observation, the session-level duplicate gate, buffer-directive
///   stamping, and local fan-out — trusting it like any mesh-carried turn (validated at the origin's
///   client edge, never re-validated at a mesh hop). It too is not re-broadcast
///   to other mesh links: the origin diverted a copy to every link serving the
///   session itself.
/// - **`LobbyCommand`**: a lobby command a peer relay's member authored, already
///   slot-stamped by the origin. Delivered to this relay's local members and
///   appended to this relay's replay log — so a late-dialing local member still
///   gets it — but, like the oversize turn, not re-broadcast across the mesh:
///   the origin already sent a copy to every link serving the session.
/// - **`GameChat`**: a chat message a peer relay's member authored, already
///   slot-stamped by the origin. Delivered to this relay's local members — no
///   log to append to, chat is ephemeral — and, like the lobby command, not
///   re-broadcast across the mesh.
/// - **`PlayerSkin`**: a cosmetic-skin blob a peer relay's member authored,
///   already slot-stamped by the origin. Stored in this relay's latest-per-slot
///   map and fanned to its local members — so a late-dialing or reconnecting
///   local member still replays it on register (as the lobby command is appended
///   to this relay's log) — but, like the chat message, not re-broadcast across
///   the mesh: the origin already sent a copy to every link serving the session.
/// - **`RequestDrop`**: a manual drop request a peer relay's member authored,
///   already `requester`-stamped by the origin. Honored only if this relay is the
///   session authority and the target slot's drop has stood past the unlock floor;
///   a non-authority ignores it (the authority is among the broadcast's
///   receivers). Not re-broadcast across the mesh — no echo, like the arms above.
/// - **`MeshResumeCursors`**: the peer's per-origin-slot resume cursors.
///   Answered before this function ever runs — the reply is a replay of this
///   relay's own turns, sent directly over the link that received the ask, not
///   a session-state fold this dispatch performs. This arm exists only so the
///   match stays exhaustive.
///
/// Kept defensive like the datagram path: a zero session id is malformed and a
/// session this link has not joined has no key to act under; both are logged at
/// debug and skipped (a race with `Join`/`Leave` is possible and benign given the
/// Join-time reconcile).
///
/// Takes the whole `mesh` bundle rather than its individual registries so this
/// signature doesn't grow a new parameter every time a control-frame kind needs
/// another per-session registry (`seen`, `lobby`, `chat`, and `skins` all live
/// inside it already); `sessions` stays separate because it is not part of
/// `MeshState`.
pub(super) fn dispatch_mesh_control(
    frame: MeshControlFrame,
    peer_id: RelayId,
    joined: &HashMap<SessionId, SessionState>,
    sessions: &routing::Sessions,
    mesh: &MeshState,
) {
    if frame.session == 0 {
        tracing::debug!("mesh control frame with zero session id; dropping");
        return;
    }
    let session_id = SessionId(frame.session);
    let Some(state) = joined.get(&session_id) else {
        tracing::debug!(
            session = session_id.0,
            "mesh control frame for unjoined session; dropping",
        );
        return;
    };
    let key = state.key.clone();

    // The gate is the retirement fence AND the mutation barrier. The joined
    // map above lags retirement (end_session only queues this driver's Leave),
    // so a buffered frame still passes it — and the dispatch arms below mutate
    // per-session state (holds, the maker, close reports, flight events) that
    // a concurrent retirement sweeps. Running the whole dispatch inside the
    // gate's read side means a retirement either waits for this frame's
    // mutations (and then sweeps them) or has already marked the session, in
    // which case the frame is dropped here — a frame can no longer check one
    // piece of state and then mutate another across the sweep.
    let dispatched = mesh.gates.with_ingress(&key, || {
        dispatch_mesh_control_frame(frame, peer_id, &key, sessions, mesh)
    });
    if dispatched.is_none() {
        tracing::debug!(
            tenant = key.tenant.as_ref(),
            session = session_id.0,
            "mesh control frame for a retired session; dropping",
        );
    }
}

/// The dispatch arms of [`dispatch_mesh_control`], run inside the session's
/// ingress gate — see the gate acquisition there.
fn dispatch_mesh_control_frame(
    frame: MeshControlFrame,
    peer_id: RelayId,
    key: &SessionKey,
    sessions: &routing::Sessions,
    mesh: &MeshState,
) {
    let session_id = key.session;
    let key = key.clone();
    match frame.kind {
        Some(mesh_control_frame::Kind::SlotDeparted(departed)) => {
            let Ok(slot) = u8::try_from(departed.slot).map(SlotId) else {
                // A slot id past `u8` range names no real slot; a silent
                // truncation would alias it onto a valid one. Drop the frame
                // (defensive — wire values are validated upstream).
                tracing::warn!(
                    session = session_id.0,
                    slot = departed.slot,
                    "mesh SlotDeparted names a slot id out of range; dropping",
                );
                return;
            };
            // The departure record max-merges the carried last frame with this
            // relay's own observation of the slot, so the fuller view drives the
            // apply frame — and recording retires the slot's live state, letting
            // the session frame follow the survivors. A non-empty result payload
            // means the home relay embedded the slot's end-of-game result; fold it
            // into the record (first non-`None` wins) so this relay's own
            // departure notice can carry it too.
            let result = (!departed.result_payload.is_empty()).then(|| ResultEcho {
                payload: departed.result_payload.to_vec(),
                arrival_ms: departed.result_arrival_ms,
                session_frame: departed.result_session_frame,
                slot_frame: departed.result_slot_frame,
            });
            // A dropped count is accepted only with the finalization proof,
            // in a session whose descriptor runs the handshake; anything else
            // is discarded at this ingress rather than trusted from the wire
            // — the peer may be running code that predates the
            // clean-leaves-or-finalized rule, and a stale drop count that
            // survives into the record could ride a later decide or a
            // straggler reconnect's replayed directive.
            let finalized_accepted = departed.reason == crate::consensus::LEAVE_REASON_DROPPED
                && departed.finalized
                && crate::consensus::finalized_drops_enabled(&mesh.decision_makers, &key);
            let stamps = crate::consensus::DepartureStamps {
                last_frame: departed
                    .last_frame
                    .map(rally_point_proto::ids::GameFrameCount),
                reachable_frame: departed.reachable_frame,
                result,
                final_turn_count: (departed.reason != crate::consensus::LEAVE_REASON_DROPPED
                    || finalized_accepted)
                    .then_some(departed.final_turn_count)
                    .flatten(),
                finalized: finalized_accepted,
            };
            let outcome = if departed.reason == crate::consensus::LEAVE_REASON_DROPPED {
                mesh.drop_holds.record_and_maybe_hold(&key, slot, || {
                    let outcome = crate::consensus::record_departure_for_epoch_outcome(
                        &mesh.decision_makers,
                        &key,
                        slot,
                        stamps.clone(),
                        departed.reason,
                        departed.connection_epoch,
                    );
                    (
                        outcome,
                        outcome == crate::consensus::DepartureRecordOutcome::Pending,
                    )
                })
            } else if crate::consensus::record_departure_for_epoch(
                &mesh.decision_makers,
                &key,
                slot,
                stamps,
                departed.reason,
                departed.connection_epoch,
            ) {
                crate::consensus::DepartureRecordOutcome::Pending
            } else {
                crate::consensus::DepartureRecordOutcome::Rejected
            };
            if outcome != crate::consensus::DepartureRecordOutcome::Pending {
                return;
            }
            // Turn the departure into the one synced leave — marking a *drop* as an
            // undecided hold (decided later only by an honored `RequestDrop`, or
            // never) and deciding a *clean* leave at once (which also releases any
            // hold this slot's earlier drop marked, the clean-intent-during-hold
            // ordering). A drop decides nothing here; a clean leave is a no-op on a
            // non-authority (`decide_leave` returns `None` there) and for an
            // already-decided slot. The departure is recorded above regardless, so a
            // promotion can still re-derive it.
            routing::hold_or_decide_leave(
                &mesh.drop_holds,
                &mesh.decision_makers,
                sessions,
                &mesh.links,
                &key,
                slot,
                departed.reason,
            );
        }
        Some(mesh_control_frame::Kind::LeaveDirective(leave)) => {
            let Ok(slot) = u8::try_from(leave.slot).map(SlotId) else {
                // Out of `u8` range: `observe_leave` below would reject it the
                // same way internally, but check here first so this specific
                // case gets its own diagnostic rather than reading as an
                // ordinary rejected/redundant directive.
                tracing::warn!(
                    session = session_id.0,
                    slot = leave.slot,
                    "mesh LeaveDirective names a slot id out of range; dropping",
                );
                return;
            };
            // Sanitize before anything consumes the directive: a dropped
            // leave's count is stripped here (a legacy authority's copy can
            // outrun its matching SlotDeparted, so the departure-record
            // sanitizers never see it), and the same normalized copy is what
            // gets cached, recorded, and fanned to local clients below — the
            // cache and the clients must never disagree about the count.
            let leave = crate::consensus::normalize_observed_leave(
                &leave,
                crate::consensus::finalized_drops_enabled(&mesh.decision_makers, &key),
            );
            // A `false` here means this relay's own consensus state didn't
            // accept the directive as new: either an ordinary redundant copy
            // (already fanned out on its own first insert, so re-forwarding
            // is unnecessary) or -- the case that matters -- a genuine
            // conflicting duplicate for the slot, which must never reach
            // local clients. Forwarding it anyway would hand them a decision
            // this relay's own cache just flagged as disagreeing with what it
            // already holds.
            if !crate::consensus::observe_leave(&mesh.decision_makers, &key, &leave) {
                return;
            }
            mesh.decision_makers.flight_recorder().record(
                &key,
                crate::observability::flight_recorder::FlightEvent::LeaveMeshAccepted {
                    source_relay: peer_id.0,
                    slot: slot.0,
                    reason: leave.reason,
                    apply_frame: leave.apply_at_frame,
                    leave_seq: leave.leave_seq,
                    finalized: leave.finalized,
                    final_turn_count: leave.final_turn_count,
                },
            );
            // A peer authority's final leave also resolves any older local drop
            // hold for this subject. Keeping it would not permit resurrection --
            // atomic admission rejects the decided leave -- but it would let the
            // cheap handshake precheck report an avoidable provisional success.
            let _ = mesh.drop_holds.release(&key, slot);
            // A final leave can outrun the matching SlotDeparted on another
            // peer link after this relay already admitted a replacement. The
            // subject intentionally does not receive its own LeaveDirective,
            // so explicitly stop any locally-homed link for it; survivors still
            // receive the directive below and apply the coordinated leave.
            routing::close_slots(sessions, &key, &[slot]);
            routing::fan_out_leave(sessions, &key, slot, leave);
            // A peer authority deciding a slot this relay homes may have been
            // the last undecided departure deferring this relay's
            // session-emptied close — re-evaluate it.
            routing::maybe_close_emptied_session(sessions, mesh, &key);
        }
        Some(mesh_control_frame::Kind::OversizeTurn(payload)) => {
            let Ok(slot) = u8::try_from(payload.slot).map(SlotId) else {
                tracing::warn!(
                    session = session_id.0,
                    slot = payload.slot,
                    "mesh OversizeTurn names a slot id out of range; dropping",
                );
                return;
            };
            // The same receive step a datagram-delivered mesh turn runs: the
            // shared local delivery (dedup, frame observation, stamp, local
            // fan-out). Delivery below the fan-out needs nothing new — a slot
            // link whose client's path can't take the turn diverts it onto
            // that client's own control stream. The transport-level dedup fold
            // for this stream-delivered seq already ran in the driver's own
            // select branch (`fold_oversize_into_link`), which has the link
            // access this dispatch doesn't.
            deliver_mesh_turn(sessions, mesh, &key, slot, payload, peer_id);
        }
        Some(mesh_control_frame::Kind::LobbyCommand(command)) => {
            // A lobby command a peer relay's member authored, already slot-stamped
            // by the origin. Fold it into this relay's local delivery (append to
            // the replay log, fan out to local members — the remote author is not
            // one of them, so every local member receives it). Deliberately NOT
            // re-broadcast across the mesh: the origin already sent a copy to every
            // link serving the session, exactly as with the oversize turn above.
            crate::session::lobby::deliver(&mesh.lobby, &key, command);
        }
        Some(mesh_control_frame::Kind::GameChat(chat_msg)) => {
            // A chat message a peer relay's member authored, already
            // slot-stamped by the origin — its size and rate caps already
            // applied there, so a mesh copy is trusted, not re-checked (mirrors
            // how a mesh-received lobby command's bytes are not re-validated).
            // No log to append to; deliberately NOT re-broadcast across the
            // mesh, exactly as the lobby command and oversize turn above.
            crate::session::chat::deliver(&mesh.chat, &key, chat_msg);
        }
        Some(mesh_control_frame::Kind::PlayerSkin(skin)) => {
            // A cosmetic-skin blob a peer relay's member authored, already
            // slot-stamped by the origin — its size and rate caps already applied
            // there, so a mesh copy is trusted, not re-checked. Store it in this
            // relay's latest-per-slot map (so its own late-dialing or reconnecting
            // local members still replay it on register — like the lobby command
            // appending to this relay's log) and fan it to local members.
            // Deliberately NOT re-broadcast across the mesh: the origin already
            // sent a copy to every link serving the session, so re-flooding would
            // only echo. `deliver`'s return is ignored here — the map cap only
            // gates whether this relay stores/fans the blob, and there is nothing
            // to re-broadcast either way.
            crate::session::skin::deliver(&mesh.skins, &key, skin);
        }
        Some(mesh_control_frame::Kind::SlotPresent(present)) => {
            let Ok(slot) = u8::try_from(present.slot).map(SlotId) else {
                tracing::warn!(
                    session = session_id.0,
                    slot = present.slot,
                    "mesh SlotPresent names a slot id out of range; dropping",
                );
                return;
            };
            // Accumulate the reported slot into this session's live-slot set. On
            // the authority, full coverage of the expected set fires the one
            // `SessionStart` — fanned to this relay's local slots and broadcast to
            // every peer (including the origin, harmlessly: it latches started and
            // fans to its own locals, but the frame is idempotent). A non-authority
            // relay just records it, for a later promotion.
            if crate::consensus::note_slot_present(&mesh.decision_makers, &key, slot) {
                // Coverage fired here (this relay is the authority): the maker
                // sized and stored the initial buffer depth as the latch fired, so
                // both fan-out legs carry it.
                let initial_buffer_turns =
                    crate::consensus::session_initial_buffer_turns(&mesh.decision_makers, &key);
                routing::fan_out_session_start(sessions, &key, initial_buffer_turns);
                fan_out_session_start(&mesh.links, &key, initial_buffer_turns);
            }
        }
        Some(mesh_control_frame::Kind::SlotStarted(started)) => {
            let Ok(slot) = u8::try_from(started.slot).map(SlotId) else {
                tracing::warn!(
                    session = session_id.0,
                    slot = started.slot,
                    "mesh SlotStarted names a slot id out of range; dropping",
                );
                return;
            };
            // A peer relay's home client left loading behind. Record it so this
            // relay's silent-slot watch can weigh that slot at all — a slot with
            // no start report anywhere has no stop time this relay may trust,
            // because a loading client still flushes lobby turns. Deliberately
            // fires no coordinator notice: the home already reported the slot,
            // and a second relay reporting it would attribute one load twice.
            // Not re-broadcast either — the origin sent a copy to every peer.
            crate::consensus::record_peer_slot_started(&mesh.decision_makers, &key, slot);
        }
        Some(mesh_control_frame::Kind::SessionStart(start)) => {
            // The authority's session-start directive. Adopt the carried initial
            // buffer depth into this relay's maker — its buffer and its stored
            // depth — so a later promotion reasons from the right base and this
            // relay's own re-pushes stamp the same depth; a depth-less directive (an
            // old authority, or a resumed re-home re-push) leaves the buffer
            // untouched. Latching started keeps this relay's own late-registering
            // local slots getting a re-push. Then fan it down every current local
            // slot. Deliberately NOT re-broadcast across the mesh: the authority
            // already sent a copy to every link serving the session, so re-flooding
            // would only echo.
            crate::consensus::adopt_session_start(
                &mesh.decision_makers,
                &key,
                start.initial_buffer_turns,
            );
            let initial_buffer_turns =
                crate::consensus::session_initial_buffer_turns(&mesh.decision_makers, &key);
            routing::fan_out_session_start(sessions, &key, initial_buffer_turns);
        }
        Some(mesh_control_frame::Kind::SlotConnectivity(change)) => {
            let Ok(slot) = u8::try_from(change.slot).map(SlotId) else {
                tracing::warn!(
                    session = session_id.0,
                    slot = change.slot,
                    "mesh SlotConnectivity names a slot id out of range; dropping",
                );
                return;
            };
            // A peer relay's home client's link changed. Fan it down this relay's
            // local slots so their connectivity displays reflect it. Deliberately
            // NOT re-broadcast across the mesh: the origin already sent a copy to
            // every peer, so re-flooding would only echo (mirroring chat above).
            // A `connected` of true is a slot coming *back* — a client that
            // re-registered on the origin relay while its drop was still undecided.
            // This relay marked its own hold on the slot's earlier `SlotDeparted`, so
            // claim it: the symmetric "it's back" signal that reaches a peer-homed
            // authority (or any peer holding a marker) so the drop can never later be
            // honored. A no-op when no hold is pending — a fresh connect, or a slot
            // this relay never held.
            //
            // Hold claim, state restoration, and epoch activation are one
            // Holds→Maker transition, mirroring the home relay's own re-register
            // (`server.rs`). A failed admission is terminal for this frame: the
            // hold may already have been decided, or a final leave may have
            // arrived first, and fanning out true would resurrect that slot.
            if change.connected {
                if crate::consensus::admit_reconnect(
                    &mesh.decision_makers,
                    &mesh.drop_holds,
                    &key,
                    slot,
                    change.connection_epoch,
                ) == crate::consensus::ReconnectAdmission::Rejected
                {
                    return;
                }
            } else if !crate::consensus::mark_connection_down(
                &mesh.decision_makers,
                &key,
                slot,
                change.connection_epoch,
            ) {
                return;
            }
            routing::fan_out_connectivity(
                sessions,
                &key,
                slot,
                change.connected,
                change.connection_epoch,
            );
        }
        Some(mesh_control_frame::Kind::RequestDrop(request)) => {
            let Ok(target) = u8::try_from(request.slot).map(SlotId) else {
                tracing::warn!(
                    session = session_id.0,
                    slot = request.slot,
                    "mesh RequestDrop names a slot id out of range; dropping",
                );
                return;
            };
            // A manual drop request one peer relay's surviving member authored,
            // already `requester`-stamped by the origin. Honor it only if this relay
            // is the session authority and the target's drop has stood past the
            // unlock floor; otherwise ignore it. Deliberately NOT re-broadcast across
            // the mesh — the origin already sent a copy to every peer, so the
            // authority is among the receivers and re-flooding would only echo (the
            // same no-echo rule the chat and leave arms follow).
            routing::honor_drop_request(sessions, mesh, &key, target, request.requester);
            // An honored request just decided a held drop; if it was the last
            // undecided departure deferring this relay's session-emptied close
            // (the requester survives on a peer relay, so the local roster can
            // be empty here), re-evaluate the close.
            routing::maybe_close_emptied_session(sessions, mesh, &key);
        }
        Some(mesh_control_frame::Kind::FinalizeDrop(request)) => {
            dispatch_finalize_drop(request, &key, mesh);
        }
        Some(mesh_control_frame::Kind::FinalizeDropResult(result)) => {
            dispatch_finalize_drop_result(result, sessions, &key, mesh);
        }
        Some(mesh_control_frame::Kind::DeliveryCursors(delivery)) => {
            // A peer-homed destination's delivered-through cursors: fold each
            // pair into the session's end-to-end delivery tracking. The mesh
            // link the frame arrived on IS the destination's home relay (the
            // same inference the origin side uses), and the fold ignores
            // regressing cursors, so a reordered share is harmless. Never
            // re-broadcast — the home relay sent a copy to every session peer.
            let Ok(dest) = u8::try_from(delivery.dest_slot).map(SlotId) else {
                tracing::warn!(
                    session = session_id.0,
                    slot = delivery.dest_slot,
                    "mesh DeliveryCursors names a dest slot id out of range; dropping",
                );
                return;
            };
            for cursor in &delivery.cursors {
                let Ok(origin) = u8::try_from(cursor.origin_slot).map(SlotId) else {
                    continue;
                };
                crate::consensus::observe_delivery(
                    &mesh.decision_makers,
                    &key,
                    dest,
                    origin,
                    cursor.delivered_seq,
                    crate::consensus::delivery::DeliveryHome::Peer(peer_id),
                );
            }
        }
        Some(mesh_control_frame::Kind::MeshResumeCursors(_)) => {
            // Handled before this dispatch runs, by `resume_replay_for_frame` +
            // `send_resume_replay` in the driver's own select branch — the reply
            // must go out over this driver's own link, not through anything this
            // function has access to. Nothing left to update here: unlike every
            // other kind, a resume ask carries no session state to fold, only a
            // reply to send.
        }
        Some(mesh_control_frame::Kind::MeshAckCursors(_)) => {
            // Handled before this dispatch runs, by `apply_ack_cursors` in the
            // driver's own select branch — it force-retires this link's own
            // transport state, which this function has no access to.
        }
        // A kind this build predates (or the empty keepalive, already dropped by
        // the reader): nothing to do.
        None => {
            tracing::debug!(
                session = session_id.0,
                "unknown mesh control frame kind; skipping"
            );
        }
    }
}
