//! One authorized client's link, driven until it closes: the setup that has to
//! land before a turn may flow, the `select!` serve loop that multiplexes the
//! client's datagrams against everything the session wants pushed at it, and the
//! teardown every exit converges on.
//!
//! The loop's own locals live in [`SlotLinkCtx`] so each arm can be a function
//! over `&mut` state; `link` and the receivers stay outside it because the
//! `select!` futures borrow them while the arm bodies run.

use super::*;

use std::ops::ControlFlow;

use rally_point_transport::beacon::{BeaconWriter, spawn_beacon_reader};
use rally_point_transport::control::ControlInbound;
use rally_point_transport::noq::VarInt;
use rally_point_transport::{Link, LinkError, Received};

use inbound::log_link_closed;
use tokio::time::{Instant, sleep_until};

use crate::consensus;
use crate::consensus::LEAVE_REASON_LEFT;
use crate::routing::departure::report_own_presence;
use crate::routing::drops::handle_drop_request;
use crate::routing::forward::game_result_admissible;
use crate::routing::lifecycle::record_leave_control_write;

mod control;
mod inbound;
mod maintenance;
mod pushes;
mod setup;
mod teardown;

#[cfg(test)]
pub(in crate::routing) use inbound::should_sample_active_conditions;
pub(in crate::routing) use teardown::end_slot_link;

/// Everything one slot link's serve loop carries across its arms: the session it
/// belongs to, the registries it publishes into, the streams it writes down, and
/// the small pieces of loop state the arms hand to each other.
///
/// `link` and the loop's receivers are deliberately NOT here: the `select!`
/// futures borrow those while an arm body holds `&mut` on this, so keeping them
/// separate is what lets each arm be an ordinary function.
pub(super) struct SlotLinkCtx {
    key: SessionKey,
    slot: SlotId,
    connection_epoch: u64,
    sessions: Sessions,
    /// The whole mesh bundle, cloned before the destructure below pulled it
    /// apart, so every exit path can hand it to `end_slot_link` and the gate,
    /// journal and seen-registry reads can reach the fields not broken out here.
    mesh_for_teardown: crate::mesh::MeshState,
    mesh_links: crate::mesh::MeshLinks,
    conditions: crate::mesh::ConditionsRegistry,
    decision_makers: Arc<crate::consensus::DecisionMakers>,
    lobby: crate::session::lobby::LobbyRegistry,
    chat: crate::session::chat::ChatRegistry,
    skins: crate::session::skin::SkinRegistry,
    drop_holds: crate::session::drop_hold::DropHolds,
    turn_ring: crate::session::turn_ring::TurnRing,
    load_fence: crate::coordinator::load_fence::LoadStateFence,
    /// The flight recorder's per-slot counter handle, fetched once so the
    /// per-turn arms bump plain atomics with no lock and no map lookup.
    flight_counters: Arc<crate::observability::flight_recorder::SlotCounters>,
    /// The relay's half of the reliable control stream: everything pushed at
    /// this client, plus the oversize-turn divert, is written here.
    control_send: rally_point_transport::noq::SendStream,
    /// The relay's half of the ack-beacon side-channel.
    beacon_send: rally_point_transport::noq::SendStream,
    beacon_writer: BeaconWriter,
    delivery_share: crate::consensus::delivery::CursorShare,
    /// Whether we've received from this client since we last sent it a packet.
    acks_owed: bool,
    /// The next maintenance flush.
    flush_deadline: Instant,
    /// Whether to keep resampling this slot's link conditions on the pre-start
    /// tick.
    pre_start_sampling: bool,
    pre_start_deadline: Instant,
    /// Whether this slot's departure has already been announced to the mesh and
    /// decided (a clean leave-intent, handled inline with the "left" reason).
    leave_announced: bool,
    /// Whether this client has already reported its game loop started on this
    /// link.
    game_started_reported: bool,
}

/// Drives one authorized client's link until it closes.
///
/// Owns `link` outright and alternates between receiving its client's turns
/// (validate, then fan out to the group's other slots), sending it the turns other
/// slots produced, flushing idle acks, and obeying a relay shutdown signal. Any
/// link error, a failed validation, or that signal ends the loop; the slot is
/// deregistered on the way out so peers stop routing to a connection that's gone.
/// Because deregistration happens here, on exit, the slot stays occupied for this
/// connection's whole life — a lagging peer is asked to leave via the shutdown
/// signal, not by yanking its roster entry out from under it.
#[allow(clippy::too_many_arguments)]
pub async fn run_slot_link(
    mut link: Link,
    key: SessionKey,
    slot: SlotId,
    connection_epoch: u64,
    mut resume_cursors: std::collections::HashMap<SlotId, u64>,
    inbox: SlotInbox,
    sessions: Sessions,
    mesh: crate::mesh::MeshState,
) {
    let SlotInbox {
        mut forward_rx,
        mut leave_push_rx,
        mut start_push_rx,
        mut conn_push_rx,
        mut region_push_rx,
        mut phase_push_rx,
        mut probe_push_rx,
        shutdown,
        close_reason,
        provisional_reap,
    } = inbox;
    // Cloned (cheap — every field is an `Arc`) before the destructure below
    // pulls `mesh` apart, so every exit path can hand the whole bundle to
    // `end_slot_link` without ballooning that function's argument count.
    let mesh_for_teardown = mesh.clone();
    // The flight recorder's per-slot counter handle, fetched ONCE here so the
    // per-turn arms below bump plain atomics — no lock, no map lookup on the
    // hot path. The connect event marks a resumed dial (any presented resume
    // cursors: a reconnect or a re-home re-dial) apart from a fresh one.
    let flight_counters = mesh
        .decision_makers
        .flight_recorder()
        .slot_counters(&key, slot);
    // Any presented resume cursors mean a re-dial (a reconnect or a re-home),
    // not this slot's first arrival. Read before the cursors are consumed below,
    // and reported both to the recording and up the coordinator connection.
    let resumed_dial = !resume_cursors.is_empty();
    mesh.decision_makers.flight_recorder().record(
        &key,
        crate::observability::flight_recorder::FlightEvent::SlotConnected {
            slot: slot.0,
            resumed: resumed_dial,
        },
    );
    let crate::mesh::MeshState {
        links: mesh_links,
        conditions,
        decision_makers,
        lobby,
        chat,
        skins,
        drop_holds,
        turn_ring,
        load_fence,
        ..
    } = mesh;
    if !setup::activate_slot(
        &link,
        &sessions,
        &mesh_for_teardown,
        &mesh_links,
        &conditions,
        &decision_makers,
        &key,
        slot,
        connection_epoch,
        resumed_dial,
    ) {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            slot = slot.0,
            "session retired before slot-link activation; closing the link",
        );
        link.connection().close(
            VarInt::from_u32(crate::server::SESSION_RETIRED_CLOSE),
            b"session retired",
        );
        end_slot_link(
            &sessions,
            &mesh_for_teardown,
            &key,
            slot,
            connection_epoch,
            false,
        );
        return;
    }
    // The ack-beacon side-channel, mirroring the client driver. The relay opens
    // its outbound uni-stream (open_uni completes locally); the client's stream
    // is accepted lazily inside the reader task so a one-way-traffic client that
    // never sends a beacon doesn't block on an accept that never completes. The
    // reader assembles complete frames off a cancel-safe path and folds each
    // `(slot, cursor)` into a per-slot latest-value cell — a cursor is
    // cumulative within its slot, so the newest is all this loop needs, and the
    // final cursor before traffic stops survives however slowly this loop
    // drains (see `BeaconCursors`).
    let beacon_send = match link.connection().open_uni().await {
        Ok(send) => send,
        Err(error) => {
            log_link_closed(&key, slot, &LinkError::from(error));
            // The slot registered but never got a stream up, so it forwarded
            // nothing — still run the full departure/close protocol below so
            // peers and the coordinator hear about it now rather than only
            // after the coordinator's holdout reap.
            end_slot_link(
                &sessions,
                &mesh_for_teardown,
                &key,
                slot,
                connection_epoch,
                false,
            );
            return;
        }
    };
    let mut beacon_rx = spawn_beacon_reader(link.connection().clone());
    // The reliable control stream — the divert path for a turn too large to
    // ever ride a datagram, in both directions: the client's own oversize turn
    // arrives on the stream the client opened (read by the reader task below),
    // and an oversize forwarded turn goes out on this stream the relay opens.
    // Each side writes only on the stream it opened, so this send half exists
    // from here on; the reader accepts the client's lazily.
    let (control_send, _our_stream_recv) = match link.connection().open_bi().await {
        Ok(halves) => halves,
        Err(error) => {
            log_link_closed(&key, slot, &LinkError::from(error));
            // Same rationale as the open_uni failure above: the beacon stream
            // came up but the control stream didn't, so this slot still never
            // forwarded a turn and gets the same full teardown.
            end_slot_link(
                &sessions,
                &mesh_for_teardown,
                &key,
                slot,
                connection_epoch,
                false,
            );
            return;
        }
    };
    let mut control_rx =
        rally_point_transport::control::spawn_control_reader(link.connection().clone());
    // Whether this slot's leave-push channel still has a sender. It lives in the
    // roster while the slot is registered, so `None` is unreachable during the
    // loop; the flag disarms the branch defensively so a closed channel can't spin.
    let mut leave_push_alive = true;
    // Mirrors `leave_push_alive` for the session-start push channel: it lives in
    // the roster while the slot is registered, so `None` is unreachable during the
    // loop; the flag disarms the branch defensively.
    let mut start_push_alive = true;
    // Mirrors `leave_push_alive` for the connectivity push channel, disarmed
    // defensively the same way.
    let mut conn_push_alive = true;
    // Mirrors `leave_push_alive` for the region-label push channel, disarmed
    // defensively the same way.
    let mut region_push_alive = true;
    // Mirrors `leave_push_alive` for the send-phase push channel, disarmed
    // defensively the same way.
    let mut phase_push_alive = true;
    // Mirrors `leave_push_alive` for the load-state fence-probe push channel,
    // disarmed defensively the same way.
    let mut probe_push_alive = true;
    setup::push_connect_time_state(&sessions, &decision_makers, &key, slot);
    // Register this member for lobby fan-out now that its control stream is up:
    // it starts receiving other members' lobby commands, and — crucially — the
    // per-session replay log is snapshotted into `lobby_rx` under the lobby lock
    // right here, so a member that joined after the host already sent its setup
    // commands catches up on every earlier command, in order, before any live
    // one. The exactly-once handoff is the lobby module's (append + fan-out and
    // register + snapshot share one lock); this task just drains `lobby_rx` in the
    // branch below and writes each command down its own control stream.
    let mut lobby_rx = crate::session::lobby::register_member(&lobby, &key, slot);
    // Mirrors `leave_push_alive`: this member's lobby sender lives in the lobby
    // registry until its own teardown drops it, so a `None` is unreachable during
    // the loop; the flag disarms the branch defensively.
    let mut lobby_alive = true;
    // Register this member for chat fan-out too — the mid-game counterpart to
    // the lobby registration above. No log to snapshot: chat keeps none, so this
    // member simply starts tailing whatever other members send from here on.
    let mut chat_rx = crate::session::chat::register_member(&chat, &key, slot);
    // Mirrors `lobby_alive`: this member's chat sender lives in the chat
    // registry until its own teardown drops it, so a `None` is unreachable
    // during the loop; the flag disarms the branch defensively.
    let mut chat_alive = true;
    // Register this member for cosmetic-skin fan-out too. Like the lobby log,
    // the per-session latest-blob-per-slot map is snapshotted into `skin_rx`
    // under the skin lock right here, so a member that dialed in after other
    // members already broadcast their blobs replays each one (before any live
    // blob); unlike the lobby log the replay is unordered (a map, not a
    // sequence). The exactly-once handoff is the skin module's (store + fan-out
    // and register + snapshot share one lock); this task drains `skin_rx` in the
    // branch below and writes each blob down its own control stream.
    let mut skin_rx = crate::session::skin::register_member(&skins, &key, slot);
    // Mirrors `chat_alive`: this member's skin sender lives in the skin registry
    // until its own teardown drops it, so a `None` is unreachable during the
    // loop; the flag disarms the branch defensively.
    let mut skin_alive = true;
    // Pushes only advancing cursors and reuses one batch buffer for the life of
    // this link.
    let beacon_writer = BeaconWriter::new();
    // This destination's end-to-end cursor share to the session's mesh peers:
    // push-on-advance, at most one complete-map frame per
    // `DELIVERY_SYNC_MIN_INTERVAL`, so the authority (wherever it is) can fold
    // final delivery without the share ever getting chatty.
    let delivery_share = crate::consensus::delivery::CursorShare::new(
        crate::consensus::delivery::DELIVERY_SYNC_MIN_INTERVAL,
    );
    // Whether the inbound beacon reader task is still feeding cursors. Once it
    // ends (the client's beacon uni-stream closed or errored), `recv()` returns
    // `None` — an always-ready future that would spin the loop at 100% CPU.
    // Disabling this branch on the first `None` keeps the task asleep; the real
    // link failure surfaces via `link.recv()`.
    let mut beacon_alive = true;
    // Whether this slot's departure has already been announced to the mesh and
    // decided (a clean leave-intent, handled inline with the "left" reason). The
    // post-loop Trigger-A departure pass is the fallback for every *other* exit (a
    // dropped link, an isolation): it announces a "dropped" departure. Skipping it
    // once a clean leave was announced avoids a redundant "dropped" SlotDeparted
    // chasing the "left" one across the mesh (which is idempotent, but noise).
    let leave_announced = false;
    // Whether this client has already reported its game loop started on this
    // link. One report per slot per link: a repeat is dropped (the fact is
    // already up the pipeline), and a reconnect starts a fresh link that may
    // report again — harmless, since the coordinator dedups per slot.
    let game_started_reported = false;
    // Whether we've received from this client since we last sent it a packet. Every
    // packet we send folds in the latest acks, so a forwarded turn clears this too,
    // and the flush only needs to carry acks when no forward has.
    let acks_owed = false;
    // The next maintenance flush. Pushed out whenever a forwarded turn re-carries
    // unacked turns (recovery is riding the forward stream, so no flush is due); left
    // to fire when a forward carries no redundancy or the link is idle, so a turn the
    // fresh packets can't re-carry is still retransmitted.
    let flush_deadline = Instant::now() + FLUSH_INTERVAL;
    // Whether to keep resampling this slot's link conditions on the pre-start tick.
    // Armed only while the session has not started (a late slot joining an already
    // started session leaves it to the receive-driven sampler); disarmed the tick
    // it observes the session started, so post-start sampling is never doubled.
    let pre_start_sampling = !consensus::session_started(&decision_makers, &key);
    let pre_start_deadline = Instant::now() + PRE_START_SAMPLE_INTERVAL;

    let mut ctx = SlotLinkCtx {
        key,
        slot,
        connection_epoch,
        sessions,
        mesh_for_teardown,
        mesh_links,
        conditions,
        decision_makers,
        lobby,
        chat,
        skins,
        drop_holds,
        turn_ring,
        load_fence,
        flight_counters,
        control_send,
        beacon_send,
        beacon_writer,
        delivery_share,
        acks_owed,
        flush_deadline,
        pre_start_sampling,
        pre_start_deadline,
        leave_announced,
        game_started_reported,
    };

    if setup::apply_resume_anchor(&mut link, &mut ctx, &mut resume_cursors).is_break() {
        return;
    }
    if setup::replay_to_reconnecting_client(&mut ctx, &resume_cursors)
        .await
        .is_break()
    {
        return;
    }

    'serve: loop {
        tokio::select! {
            received = link.recv() => {
                if inbound::handle_received(&mut link, &mut ctx, received)
                    .await
                    .is_break()
                {
                    break 'serve;
                }
            }
            // A synced leave for another slot, to push down this client's reliable
            // control stream. This is the whole fix for the turn-envelope deadlock:
            // a departing peer stalls this client and stops its datagram turn flow,
            // so the leave that must unstall it can only arrive on the reliable
            // stream, which keeps flowing.
            pushed = leave_push_rx.recv(), if leave_push_alive => {
                match pushed {
                    Some(leave) => {
                        if pushes::push_leave(&mut ctx, leave).await.is_break() {
                            break 'serve;
                        }
                    }
                    None => leave_push_alive = false,
                }
            }
            // The session-start directive for this client, to push down its
            // reliable control stream. Fired session-wide when the authority
            // decides every expected slot has connected, or re-pushed to this slot
            // alone if it registered after the session already started. A write
            // failure ends the link like every other control-stream write here —
            // the stream is dead regardless of which frame kind hit it.
            pushed = start_push_rx.recv(), if start_push_alive => {
                match pushed {
                    Some(initial_buffer_turns) => {
                        if pushes::push_session_start(&mut ctx, initial_buffer_turns).await.is_break() {
                            break 'serve;
                        }
                    }
                    None => start_push_alive = false,
                }
            }
            // A load-state fence probe for this client, to push down its reliable
            // control stream: this relay is about to tell the coordinator what it
            // holds for the session and needs the client to confirm the stream's
            // position first. Unlike every other push here, a write failure does
            // NOT end the link — the probe asks a question about the stream rather
            // than delivering anything the game depends on, and a link that is
            // genuinely gone surfaces through the paths that matter. The fence
            // simply never hears this slot's ack and reads it as unfenced.
            pushed = probe_push_rx.recv(), if probe_push_alive => {
                match pushed {
                    Some(probe_id) => {
                        if pushes::push_load_state_probe(&mut ctx, probe_id).await.is_break() {
                            break 'serve;
                        }
                    }
                    None => probe_push_alive = false,
                }
            }
            // A slot-connectivity change for this client, to push down its reliable
            // control stream: some member's link died or (re)registered. Rides the
            // reliable stream like a leave, so it still reaches a client whose
            // datagram turn flow has stalled behind the very disconnect being
            // reported. A write failure ends the link like every other
            // control-stream write here.
            pushed = conn_push_rx.recv(), if conn_push_alive => {
                match pushed {
                    Some(change) => {
                        if pushes::push_connectivity(&mut ctx, change).await.is_break() {
                            break 'serve;
                        }
                    }
                    None => conn_push_alive = false,
                }
            }
            // The session's relay → region-label map, to push down this client's
            // reliable control stream. Only ever queued once the session's release
            // gate has opened, so nothing this branch writes can reach a client
            // before enough gameplay elapsed that departing scores as a result.
            // Each message is the complete map, so a repeat (the gate's fan-out
            // racing this slot's own connect push, a re-fan after a re-home) costs
            // only a frame. A write failure ends the link like every other
            // control-stream write here.
            pushed = region_push_rx.recv(), if region_push_alive => {
                match pushed {
                    Some(labels) => {
                        if pushes::push_region_labels(&mut ctx, labels).await.is_break() {
                            break 'serve;
                        }
                    }
                    None => region_push_alive = false,
                }
            }
            // THIS client's send-phase directive, to push down its reliable
            // control stream. Sparse (the controller dwells for seconds
            // between corrections) and absolute — each frame carries the whole
            // commanded delay, so a repeat (a correction racing this slot's
            // own connect re-push) is idempotent. A write failure ends the
            // link like every other control-stream write here.
            pushed = phase_push_rx.recv(), if phase_push_alive => {
                match pushed {
                    Some(directive) => {
                        if pushes::push_phase_directive(&mut ctx, directive).await.is_break() {
                            break 'serve;
                        }
                    }
                    None => phase_push_alive = false,
                }
            }
            // A lobby command another member authored (or the replay of an earlier
            // one), to push down this client's reliable control stream. Like a
            // leave, it rides the reliable stream because a lobby has no datagram
            // turn flow to piggyback on; unlike a leave, this branch also drains
            // the per-session replay log that `register_member` queued here, so an
            // early command and a live one write down the stream on one ordered
            // path. The `slot` is the relay-stamped author, so the receiving game
            // attributes the bytes correctly.
            pushed = lobby_rx.recv(), if lobby_alive => {
                match pushed {
                    Some(command) => {
                        if pushes::push_lobby(&mut ctx, command).await.is_break() {
                            break 'serve;
                        }
                    }
                    None => lobby_alive = false,
                }
            }
            // A game-chat message another member authored (or a mesh-forwarded
            // one), to push down this client's reliable control stream — the
            // mid-game counterpart to the lobby branch above. Unlike lobby, there
            // is no replay log to drain first: this branch only ever tails live
            // messages, so a member whose stream comes up after a message
            // already flowed simply never sees it. A write failure here ends the
            // link exactly like every other control-stream write in this loop —
            // the underlying stream is dead regardless of which frame kind hit
            // it — which is a different call than the client-edge driver makes
            // for its own *outbound* chat sends (best-effort, logged and
            // ignored): there, the link may still be otherwise healthy; here,
            // the failure *is* evidence the link is not.
            pushed = chat_rx.recv(), if chat_alive => {
                match pushed {
                    Some(chat_msg) => {
                        if pushes::push_chat(&mut ctx, chat_msg).await.is_break() {
                            break 'serve;
                        }
                    }
                    None => chat_alive = false,
                }
            }
            // A cosmetic-skin blob another member authored (or a mesh-forwarded
            // one), or the replay of an earlier stored blob, to push down this
            // client's reliable control stream. Like the lobby branch this drains
            // the per-session replay the skin `register_member` snapshotted here,
            // so a stored blob and a live one write down the stream on one path;
            // like the chat branch the `slot` is the relay-stamped author and a
            // write failure ends the link exactly as every other control-stream
            // write in this loop does — the underlying stream is dead regardless
            // of which frame kind hit it (a different call than the client-edge
            // driver makes for its own *outbound* skin sends, which are
            // best-effort: there the link may still be healthy; here the failure
            // *is* evidence it is not).
            pushed = skin_rx.recv(), if skin_alive => {
                match pushed {
                    Some(skin) => {
                        if pushes::push_skin(&mut ctx, skin).await.is_break() {
                            break 'serve;
                        }
                    }
                    None => skin_alive = false,
                }
            }
            forwarded = forward_rx.recv() => {
                if inbound::handle_forwarded(&mut link, &mut ctx, forwarded)
                    .await
                    .is_break()
                {
                    break 'serve;
                }
            }
            // The client's oversize turn, arriving over the reliable control
            // stream because no datagram could carry it. It is the same
            // attacker-facing ingress as a datagram turn: fold it through the
            // link's dedup first (a duplicate must not double-forward; a seq
            // beyond the window closes the link exactly as on the datagram
            // path), then validate and forward it like any other turn.
            received = control_rx.recv() => {
                if control::handle_control_frame(&mut link, &mut ctx, received).is_break() {
                    break 'serve;
                }
            }
            // The client pushed a delivered-through cursor over the beacon stream.
            // The reader task assembled the complete frame off a cancel-safe path;
            // `mpsc::Receiver::recv` is cancel-safe in select!. The
            // `if beacon_alive` precondition disables this branch once the reader
            // task ends — otherwise `recv()` returns `None` on every poll, an
            // always-ready future that would spin the loop at 100% CPU.
            received = beacon_rx.recv(), if beacon_alive => {
                match received {
                    Some((beacon_slot, cursor)) => {
                        if inbound::handle_beacon_cursor(&mut link, &mut ctx, beacon_slot, cursor)
                            .is_break()
                        {
                            break 'serve;
                        }
                    }
                    // The reader task ended (client's beacon stream closed or
                    // errored). Stop polling it: the real link failure, if any,
                    // surfaces via `link.recv()`.
                    None => beacon_alive = false,
                }
            }
            _ = sleep_until(ctx.flush_deadline) => {
                if maintenance::maintenance_flush(&mut link, &mut ctx).is_break() {
                    break 'serve;
                }
            }
            _ = sleep_until(ctx.pre_start_deadline), if ctx.pre_start_sampling => {
                maintenance::resample_pre_start(&link, &mut ctx);
            }
            _ = shutdown.notified() => {
                maintenance::handle_shutdown(&mut link, &ctx, &close_reason);
                break 'serve;
            }
            _ = provisional_reap.notified() => {
                maintenance::handle_provisional_reap(&mut link, &ctx);
                break 'serve;
            }
        }
    }

    // Every exit path above converges here. Some already closed the
    // connection with a specific reason code (an invalid turn, an isolated
    // slot, an out-of-range resume anchor); a redundant close on one already
    // closing is a no-op. The paths that didn't — a plain client disconnect
    // (`link.recv()`'s own `Err` arm), a maintenance-flush send failure, and
    // and the shutdown signal's generic branch, which logs and breaks without
    // a close of its own — need this: the beacon
    // and control-stream reader tasks spawned above each hold their own
    // `connection.clone()`, parked on `accept_uni`/`accept_bi`, so `link`'s
    // own handle going out of scope at the end of this function is never the
    // last one. Without an explicit close, the connection — and the
    // relay-side slot it's still notionally serving — lingers until QUIC's
    // own idle timeout instead of freeing promptly.
    link.connection()
        .close(VarInt::from_u32(0), b"slot link ended");
    end_slot_link(
        &ctx.sessions,
        &ctx.mesh_for_teardown,
        &ctx.key,
        ctx.slot,
        ctx.connection_epoch,
        ctx.leave_announced,
    );
}
