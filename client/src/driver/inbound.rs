//! What arrives from the relay: a received datagram's fresh turns, and the
//! frames the reliable control stream carries. Both hand turns to the game
//! through one ordered per-slot release, so a turn is delivered the same way
//! whichever path brought it.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{LeaveDirective, Payload};
use rally_point_transport::beacon::BeaconWriter;
use rally_point_transport::control::{
    ControlInbound, send_control_game_started, send_control_load_state_probe_ack,
    send_control_phase_applied,
};
use rally_point_transport::{Link, LinkError, Received, noq};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::leave_announcer::LeaveAnnouncer;
use crate::phase::{PhaseSlew, PhaseStatus};

use super::backoff::{GamePush, push_to_game};
use super::send::{Release, check_cap, flush_delivered_cursors, release_ready};
use super::session::ArmFlow;
use super::state::{ConnectivityEpochStates, admit_connectivity_epoch};
use super::*;

/// One packet the link received: fold its acks in, buffer its fresh turns by
/// transport seq, release the contiguous prefix to the game, push the peer our
/// delivered-through cursors, and check the unacked-window cap. The link dedups
/// and orders within a datagram but follows arrival order across them, so the
/// ordering the game sees is restored here, never on the wire.
#[allow(clippy::too_many_arguments)]
pub(super) async fn on_received(
    received: Result<Received, LinkError>,
    link: &mut Link,
    control_send: &mut noq::SendStream,
    beacon_send: &mut noq::SendStream,
    beacon_writer: &mut BeaconWriter,
    acks_owed: &mut bool,
    next_seq: &mut HashMap<SlotId, u64>,
    pending: &mut HashMap<SlotId, BTreeMap<u64, Payload>>,
    inbound: &mpsc::Sender<Payload>,
    outbound: &mpsc::Receiver<Payload>,
    announcer: &mut LeaveAnnouncer,
    held: &VecDeque<(Instant, Payload)>,
) -> ArmFlow {
    let received = match received {
        Ok(received) => received,
        // Once the intent is written, the relay closing this link
        // is the expected confirmation it processed the leave, not
        // a link failure — `absorb_link_close` turns it into a
        // clean stop; before that it is a real failure.
        Err(error) => {
            return ArmFlow::End(announcer.absorb_link_close(Err(error.into())));
        }
    };
    // Only a payload-bearing packet needs an ack in return; owing one
    // for the relay's ack-only flush would just bounce ack-only packets
    // back and forth on an otherwise idle link.
    if received.carried_payloads {
        *acks_owed = true;
    }
    for payload in received.fresh {
        // A slot id past `u8` range names no real slot; a
        // truncating cast would alias it onto `slot % 256` and
        // corrupt another player's turn stream. Drop it (defensive
        // — the wire values are validated upstream).
        let Ok(slot_id) = u8::try_from(payload.slot) else {
            tracing::warn!(
                slot = payload.slot,
                "received turn names a slot id out of range; dropping it",
            );
            continue;
        };
        let slot = SlotId(slot_id);
        let slot_next = next_seq.entry(slot).or_insert(0);
        if payload.seq >= *slot_next {
            pending
                .entry(slot)
                .or_default()
                .insert(payload.seq, payload);
        }
    }
    match release_ready(next_seq, pending, inbound) {
        Release::Delivered => {}
        Release::GameClosed => return ArmFlow::Teardown,
        Release::GameStalled => return ArmFlow::End(Err(DriverError::GameStalled)),
    }
    flush_delivered_cursors(link, beacon_send, beacon_writer, next_seq).await;
    if check_cap(link.payloads_in_flight()) {
        return ArmFlow::End(Err(DriverError::UnackedWindowExhausted {
            in_flight: link.payloads_in_flight(),
            cap: UNACKED_WINDOW_CAP,
        }));
    }
    // An ack folded into the manager above may be the last one
    // a pending leave intent was waiting on.
    if let Err(error) = announcer
        .maybe_send(control_send, outbound, held.is_empty(), link)
        .await
    {
        return ArmFlow::End(Err(DriverError::from(error)));
    }
    ArmFlow::Serve
}

/// One frame off the reliable control stream. It carries everything a datagram
/// cannot: the synced leaves and session directives a stalled turn stream must
/// not gate, the best-effort lobby/chat/skin fan-out, the relay's phase and
/// load-state asks, and an oversize turn diverted here because no datagram
/// could hold it. An oversize turn is folded through the link's dedup so both
/// delivery paths stay one stream.
///
/// An oversize turn from the relay, delivered over the reliable control stream
/// because no datagram could carry it. Folding it through the link's dedup
/// keeps the two delivery paths one stream: the per-slot delivered cursor
/// advances across it and a copy that somehow arrived both ways collapses to
/// one delivery. It then joins the same per-slot reorder buffer, so the game
/// sees one ordered stream regardless of which path each turn took.
#[allow(clippy::too_many_arguments)]
pub(super) async fn on_control_frame(
    received: Option<ControlInbound>,
    link: &mut Link,
    control_send: &mut noq::SendStream,
    beacon_send: &mut noq::SendStream,
    beacon_writer: &mut BeaconWriter,
    next_seq: &mut HashMap<SlotId, u64>,
    pending: &mut HashMap<SlotId, BTreeMap<u64, Payload>>,
    inbound: &mpsc::Sender<Payload>,
    leaves: &mpsc::Sender<LeaveDirective>,
    lobby_in: &mpsc::Sender<(SlotId, Vec<u8>)>,
    chat_in: &mpsc::Sender<(SlotId, ChatOut)>,
    skin_in: &mpsc::Sender<(SlotId, Vec<u8>)>,
    session_start: &mpsc::Sender<Option<u32>>,
    connectivity: &mpsc::Sender<(SlotId, bool)>,
    region_labels: &mpsc::Sender<Vec<(u64, String)>>,
    phase_status: &watch::Sender<PhaseStatus>,
    phase_slew: &mut PhaseSlew,
    announcer: &mut LeaveAnnouncer,
    game_started: &mut bool,
    game_started_announced: &mut bool,
    game_started_out: &mut mpsc::Receiver<()>,
    game_started_on_stream: &mut bool,
    connectivity_states: &mut ConnectivityEpochStates,
    terminal_connectivity_slots: &mut HashSet<SlotId>,
) -> ArmFlow {
    match received {
        // A relay-pushed synced leave: hand it to the game's leave
        // tracker. This is the delivery path a drop needs — the turn
        // stream has stalled, but the reliable control stream still
        // flows. Correctness-critical: a lost leave strands lockstep
        // on a slot that will never send another turn, so a game
        // that stopped draining these is a stall, not a skip.
        Some(ControlInbound::Leave(leave)) => {
            // A final leave dominates every physical-link update,
            // including a delayed true from a replacement epoch.
            // Latch the tombstone before forwarding the directive
            // so it also survives a game-channel stall/reconnect.
            let Ok(slot_id) = u8::try_from(leave.slot) else {
                tracing::warn!(
                    slot = leave.slot,
                    "leave directive names a slot id out of range; dropping it",
                );
                return ArmFlow::Serve;
            };
            terminal_connectivity_slots.insert(SlotId(slot_id));
            match push_to_game(leaves, leave) {
                GamePush::Sent => {}
                GamePush::Full => {
                    tracing::warn!("game stopped draining synced leaves");
                    return ArmFlow::End(Err(DriverError::GameStalled));
                }
                GamePush::Closed => return ArmFlow::Teardown,
            }
        }
        // A client only ever *sends* a leave intent up; it never
        // receives one back (the relay is the only recipient).
        // Ignore a stray one, mirroring how the relay edge
        // ignores a stray client-sent `Leave`.
        Some(ControlInbound::LeaveIntent) => {
            tracing::warn!("ignoring unexpected relay-sent leave-intent control frame");
        }
        // Likewise a result report only ever travels client → relay;
        // a client never receives one back, so ignore a stray one.
        Some(ControlInbound::GameResult(_)) => {
            tracing::warn!("ignoring unexpected relay-sent game-result control frame");
        }
        // Likewise a game-started report only ever travels client
        // → relay; a client never receives one back, so ignore a
        // stray one.
        Some(ControlInbound::GameStarted) => {
            tracing::warn!("ignoring unexpected relay-sent game-started control frame");
        }
        // A drop request only ever travels client → relay; a client
        // never receives one back, so ignore a stray one.
        Some(ControlInbound::RequestDrop(_)) => {
            tracing::warn!("ignoring unexpected relay-sent drop-request control frame");
        }
        // A lobby command another member authored, relay-stamped
        // with the author's slot. Hand it to the game tagged with
        // that slot so it applies the bytes to that member's lobby
        // turn. Replayed earlier commands and live ones arrive on
        // this one path, in order. Correctness-critical: a lost
        // setup command leaves a member's pre-game state
        // incomplete, so a game that stopped draining these is a
        // stall, not a skip.
        Some(ControlInbound::Lobby(command)) => {
            // A slot id past `u8` range names no real member; a
            // truncating cast would misattribute the command. Drop
            // it (defensive — the relay stamps a real slot).
            let Ok(slot_id) = u8::try_from(command.slot) else {
                tracing::warn!(
                    slot = command.slot,
                    "lobby command names a slot id out of range; dropping it",
                );
                return ArmFlow::Serve;
            };
            match push_to_game(lobby_in, (SlotId(slot_id), command.payload.to_vec())) {
                GamePush::Sent => {}
                GamePush::Full => {
                    tracing::warn!("game stopped draining lobby commands");
                    return ArmFlow::End(Err(DriverError::GameStalled));
                }
                GamePush::Closed => return ArmFlow::Teardown,
            }
        }
        // An in-game chat message another member authored,
        // relay-stamped with the author's slot — the mid-game
        // counterpart to the lobby branch above. No replay here
        // (chat keeps no log): every message that arrives on
        // this path is live. Best-effort: a full buffer just
        // drops the message — chat has no state a lost line
        // could corrupt, and it must never stall the turns.
        Some(ControlInbound::Chat(chat)) => {
            // As above: a slot id past `u8` range names no real
            // member; drop it rather than misattribute it.
            let Ok(slot_id) = u8::try_from(chat.slot) else {
                tracing::warn!(
                    slot = chat.slot,
                    "game-chat message names a slot id out of range; dropping it",
                );
                return ArmFlow::Serve;
            };
            let out = ChatOut {
                target_kind: chat.target_kind,
                target_slot: chat.target_slot,
                text: chat.text,
            };
            match push_to_game(chat_in, (SlotId(slot_id), out)) {
                GamePush::Sent => {}
                GamePush::Full => {
                    tracing::debug!("dropping game-chat message; the game is not draining chat");
                }
                GamePush::Closed => return ArmFlow::Teardown,
            }
        }
        // A cosmetic-skin blob another member authored,
        // relay-stamped with the author's slot. The relay may
        // deliver it more than once (a replay overlapping a live
        // one across a reconnect), so the game applies it
        // idempotently. Best-effort: a full buffer just drops the
        // blob — a skin is cosmetic, non-synced state, so a lost
        // one costs only a wrong cosmetic and it must never stall
        // the turns.
        Some(ControlInbound::Skin(skin)) => {
            // As above: a slot id past `u8` range names no real
            // member; drop it rather than misattribute it.
            let Ok(slot_id) = u8::try_from(skin.slot) else {
                tracing::warn!(
                    slot = skin.slot,
                    "player-skin blob names a slot id out of range; dropping it",
                );
                return ArmFlow::Serve;
            };
            match push_to_game(skin_in, (SlotId(slot_id), skin.payload.to_vec())) {
                GamePush::Sent => {}
                GamePush::Full => {
                    tracing::debug!("dropping player-skin blob; the game is not draining skins");
                }
                GamePush::Closed => return ArmFlow::Teardown,
            }
        }
        // The relay-driven session-start directive: every expected
        // slot has connected, so the game may begin. Hand it to the
        // game thread; a repeat (a re-push on late register or an
        // authority handoff) is idempotent for the game.
        // Correctness-critical: a game waiting on a start it never
        // hears waits forever, so a full buffer here is a stall.
        Some(ControlInbound::SessionStart(initial_buffer_turns)) => {
            // The game has started: from here a dead home relay may
            // escalate to coordinator-mediated failover. Latched, and
            // kept across reconnects via the persistent state.
            *game_started = true;
            match push_to_game(session_start, initial_buffer_turns) {
                GamePush::Sent => {}
                GamePush::Full => {
                    tracing::warn!("game stopped draining session-start directives");
                    return ArmFlow::End(Err(DriverError::GameStalled));
                }
                GamePush::Closed => return ArmFlow::Teardown,
            }
        }
        // A relay-pushed slot-connectivity change: a member's link
        // died or (re)registered. Hand it to the game thread tagged
        // with the slot; the game drives its "player X disconnected"
        // display off it, independent of the synced leave. Best-
        // effort — an unknown slot is the game's no-op, and a full
        // buffer just drops the change (a stale display beats a
        // stalled session; the synced leave rides its own path).
        Some(ControlInbound::Connectivity(change)) => {
            // A slot id past `u8` range names no real member; a
            // truncating cast would misattribute the change. Drop it
            // (defensive — the relay stamps a real slot).
            let Ok(slot_id) = u8::try_from(change.slot) else {
                tracing::warn!(
                    slot = change.slot,
                    "slot-connectivity names a slot id out of range; dropping it",
                );
                return ArmFlow::Serve;
            };
            let subject = SlotId(slot_id);
            if !admit_connectivity_epoch(
                connectivity_states,
                terminal_connectivity_slots,
                subject,
                change.connected,
                change.connection_epoch,
            ) {
                return ArmFlow::Serve;
            }
            match push_to_game(connectivity, (subject, change.connected)) {
                GamePush::Sent => {}
                GamePush::Full => {
                    tracing::debug!("dropping connectivity change; the game is not draining them");
                }
                GamePush::Closed => return ArmFlow::Teardown,
            }
        }
        // The session's relay → region labels, released by the
        // relay once a stretch of real gameplay elapsed on its own
        // clock. Hand the complete map to the game thread, which replaces
        // whatever it held; a repeat (the release racing this
        // client's own connect push, a re-send after a re-home)
        // is idempotent. Best-effort — a full buffer just drops
        // the map, since a missing display label must never stall
        // the turns, and a later map carries the whole thing
        // again.
        Some(ControlInbound::RegionLabels(map)) => {
            let labels = map
                .labels
                .into_iter()
                .map(|label| (label.relay_id, label.region))
                .collect();
            match push_to_game(region_labels, labels) {
                GamePush::Sent => {}
                GamePush::Full => {
                    tracing::debug!("dropping region labels; the game is not draining them");
                }
                GamePush::Closed => return ArmFlow::Teardown,
            }
        }
        // A relay send-phase directive: the total delay to hold
        // each outbound turn's wire handoff by, so this
        // client's arrival phase at the relay aligns with the
        // other slots'. Applied entirely inside the driver —
        // the game is not involved (its local echo already ran
        // by the time a turn gets here) and only observes the
        // state through the `phase_status` watch. Absolute and
        // newest-wins; a repeat (a correction racing the
        // connect-time re-push) is idempotent, and the relay's
        // next measurement cycle corrects any residue.
        Some(ControlInbound::PhaseDirective(directive)) => {
            phase_slew.retarget(directive.delay_us, directive.slew_us_per_s, Instant::now());
            let _ = phase_status.send_replace(phase_slew.status());
            tracing::debug!(
                delay_us = directive.delay_us,
                slew_us_per_s = directive.slew_us_per_s,
                "applying send-phase directive",
            );
            // Acknowledge adoption so the relay releases this
            // slot's command fence — without the ack it parks
            // the command after one step, the safe reading of
            // silence. Best-effort: on a dead stream the
            // session is about to end anyway, and the parked
            // command costs only unfinished alignment.
            if let Err(error) = send_control_phase_applied(control_send, directive.delay_us).await {
                tracing::debug!(
                    %error,
                    "phase-applied ack failed; the relay parks this slot's command",
                );
            }
        }
        // A relay fence probe: the relay is about to tell the
        // coordinator what it holds for this session and needs to
        // rule out a report of ours still sitting unwritten. Drain
        // the game's announcement channel and write any owed
        // `GameStarted` FIRST, then the ack. The stream is ordered,
        // so a report the game had signalled at any point before
        // this probe was handled is on the wire ahead of the ack,
        // and the relay can read the ack as "nothing of this slot's
        // is behind it". That reading only holds if the report
        // actually went out, so a failed report write withholds the
        // ack: the relay's fence then lapses, which it reads as this
        // slot being unfenced — the safe direction — and the report
        // stays owed for the next stream. The ack write itself is
        // best-effort for the same reason. Answering consumes the
        // signal, so the live arm below has nothing left to re-send.
        Some(ControlInbound::LoadStateProbe(probe_id)) => {
            if game_started_out.try_recv().is_ok() {
                *game_started_announced = true;
            }
            if *game_started_announced && !*game_started_on_stream {
                match send_control_game_started(control_send).await {
                    Ok(()) => *game_started_on_stream = true,
                    Err(error) => tracing::debug!(
                        %error,
                        "game-started send ahead of a fence ack failed; withholding the ack"
                    ),
                }
            }
            let report_owed = *game_started_announced && !*game_started_on_stream;
            if !report_owed
                && let Err(error) = send_control_load_state_probe_ack(control_send, probe_id).await
            {
                tracing::debug!(
                    %error,
                    "load-state fence ack send failed; dropping the ack"
                );
            }
        }
        // A fence ack only ever travels client → relay; a client
        // never receives one back, so ignore a stray one.
        Some(ControlInbound::LoadStateProbeAck(_)) => {
            tracing::warn!("ignoring unexpected relay-sent load-state probe-ack control frame");
        }
        // A phase-applied ack only ever travels client → relay;
        // a client never receives one back, so ignore a stray
        // one.
        Some(ControlInbound::PhaseApplied(_)) => {
            tracing::warn!("ignoring unexpected relay-sent phase-applied control frame");
        }
        Some(ControlInbound::OversizeTurn(payload)) => {
            // As on the datagram path: a slot id past `u8` range
            // names no real slot, and a truncating cast would alias
            // it onto another player's stream. Drop it rather than
            // deliver it.
            let Ok(slot_id) = u8::try_from(payload.slot) else {
                tracing::warn!(
                    slot = payload.slot,
                    "oversize turn names a slot id out of range; dropping it",
                );
                return ArmFlow::Serve;
            };
            let slot = SlotId(slot_id);
            let fresh = match link.deliver_external(slot, payload.seq) {
                Ok(fresh) => fresh,
                Err(error) => return ArmFlow::End(Err(DriverError::from(error))),
            };
            if fresh {
                next_seq.entry(slot).or_insert(0);
                pending
                    .entry(slot)
                    .or_default()
                    .insert(payload.seq, payload);
                match release_ready(next_seq, pending, inbound) {
                    Release::Delivered => {}
                    Release::GameClosed => return ArmFlow::Teardown,
                    Release::GameStalled => return ArmFlow::End(Err(DriverError::GameStalled)),
                }
                flush_delivered_cursors(link, beacon_send, beacon_writer, next_seq).await;
            }
        }
        // The reader task ended: a one-sided stream reset, an
        // over-cap frame, a decode failure, or a clean EOF. This
        // is the only channel a synced `LeaveDirective`,
        // `SessionStart`, and `SlotConnectivity` ever arrive on
        // — unlike the beacon side-channel (a pure one-way
        // cursor feed a real link failure surfaces separately
        // via `link.recv()`), nothing else in this loop will
        // ever notice this is gone. So this ends the session
        // rather than disarming and limping on: treated as a
        // link failure, the reconnect loop re-dials and
        // `session` re-spawns a fresh control reader from
        // scratch on the rebound link. `absorb_link_close`
        // still applies — the connection may be closing for
        // the very reason this reader ended (e.g. right after
        // our own leave intent was processed), in which case
        // this becomes the same clean stop `link.recv()`'s
        // error arm would have produced.
        None => {
            tracing::info!("control stream reader ended");
            return ArmFlow::End(announcer.absorb_link_close(Err(DriverError::ControlStreamLost)));
        }
    }
    ArmFlow::Serve
}
