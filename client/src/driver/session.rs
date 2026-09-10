//! One connection's turn loop: opening this link's beacon and control streams,
//! replaying whatever a resume deferred to them, then multiplexing every arm of
//! the game seam over a single `select!` until the game stops or the link fails.
//!
//! The large arms live in [`inbound`] and [`outbound`]; each hands back an
//! [`ArmFlow`] because an arm body moved out of the loop can no longer `break`
//! to the teardown drain or `return` from the whole session on its own.

use std::time::Duration;

use rally_point_proto::ids::SlotId;
use rally_point_transport::beacon::{BeaconWriter, spawn_beacon_reader};
use rally_point_transport::control::{send_control_game_started, spawn_control_reader};
use rally_point_transport::{Link, LinkError};
use tokio::time::{Instant, sleep_until};

use super::retention::redivert_pending_control;
use super::send::{OutboundSend, check_cap, send_game_turn, send_packet};
use super::state::{GameSeam, LoopState};
use super::{inbound, outbound, teardown};

use super::*;

/// What one extracted `select!` arm asks the loop to do next.
///
/// An arm body that lives in its own function can no longer `break` to the
/// teardown drain or `return` out of the whole session, so it says which it
/// meant and the call site does it.
pub(super) enum ArmFlow {
    /// Nothing further this iteration; keep serving.
    Serve,
    /// Leave the loop for the teardown drain — the game stopped.
    Teardown,
    /// End the session with this result.
    End(Result<(), DriverError>),
}

impl LinkDriver {
    pub(super) async fn session_body(
        link: &mut Link,
        seam: &mut GameSeam,
        state: &mut LoopState,
        own_slot: SlotId,
    ) -> Result<(), DriverError> {
        let GameSeam {
            outbound,
            inbound,
            leaves,
            leave_intent,
            result,
            // Bound apart from `LoopState::game_started`, which records the
            // opposite direction: the relay's start directive arriving, not this
            // client's own announcement going out.
            game_started: game_started_out,
            lobby_out,
            lobby_in,
            chat_out,
            chat_in,
            skin_out,
            skin_in,
            request_drop,
            session_start,
            connectivity,
            region_labels,
            phase_status,
        } = seam;
        // The reorder/dedup cursors, the outbound seq counter, the leave announcer,
        // and any turns buffered during a prior outage all persist across a
        // reconnect, so they come from the caller's state, not fresh locals.
        let LoopState {
            next_seq,
            pending,
            next_outbound_seq,
            announcer,
            outbound_buffer,
            game_started_announced,
            game_started,
            retention,
            retention_bytes,
            pending_control_redivert,
            connectivity_states,
            terminal_connectivity_slots,
            phase_slew,
            held,
        } = state;

        // The ack-beacon side-channel. The client opens its outbound uni-stream
        // (open_uni completes locally, no peer round-trip); the peer's stream is
        // accepted lazily inside the reader task, so a one-way-traffic link that
        // never sends a beacon doesn't block the dial on an accept that never
        // completes. The reader decodes complete frames and folds each
        // `(slot, cursor)` into a per-slot latest-value cell — a cursor is
        // cumulative within its slot, so the newest is all this loop needs,
        // and the final cursor before traffic stops survives however slowly
        // this loop drains (see `BeaconCursors`).
        let mut beacon_send = link
            .connection()
            .open_uni()
            .await
            .map_err(|error| DriverError::Link(LinkError::from(error)))?;
        let mut beacon_rx = spawn_beacon_reader(link.connection().clone());

        // The reliable control stream — the divert path for a turn too large
        // to ever ride a datagram. Each side opens one bidirectional stream
        // and writes on it alone; the peer reads the stream it accepted. Our
        // send half exists from here on (open_bi completes locally); the
        // relay's frames arrive via the reader task, which accepts lazily so
        // a session that never sees an oversize turn parks it harmlessly.
        // The recv half of our own stream is unused by convention (the relay
        // writes on the stream *it* opened) and dropped.
        let (mut control_send, _our_stream_recv) = link
            .connection()
            .open_bi()
            .await
            .map_err(|error| DriverError::Link(LinkError::from(error)))?;
        let mut control_rx = spawn_control_reader(link.connection().clone());
        // Pushes only advancing cursors and reuses one batch buffer for the
        // life of this link.
        let mut beacon_writer = BeaconWriter::new();
        // Whether the inbound beacon reader task is still feeding cursors. Once it
        // ends (the peer's beacon uni-stream closed or errored), `recv()` returns
        // `None` immediately on every poll — an always-ready future that would spin
        // the loop at 100% CPU. Disabling this branch on the first `None` keeps the
        // driver asleep; the real link failure surfaces separately via `link.recv()`.
        let mut beacon_alive = true;

        // Whether we've received from the relay since we last sent it a packet.
        // Every packet we send folds in the latest acks, so any outgoing turn
        // clears this too; the flush only needs to carry acks when no turn has.
        let mut acks_owed = false;
        // The next maintenance flush. Pushed out whenever an outbound turn re-carries
        // unacked turns (recovery is riding the stream, so no flush is due); left to
        // fire when a send carries no redundancy or the link is idle, so a turn the
        // fresh packets can't re-carry is still retransmitted.
        let mut flush_deadline = Instant::now() + FLUSH_INTERVAL;
        // Re-carry any oversize turns a resume deferred to this connection's control
        // stream. Too large to ride a datagram, they were kept out of the unacked
        // window (where the redundancy pass would skip them forever) and staged
        // here instead — by `reinject_retention` on a re-home, and by
        // `redivert_oversize_retention_on_same_relay_resume` on a same-relay
        // resume (a control-stream write carries no acknowledgment, so a drop
        // between the local write succeeding and the relay processing it is
        // otherwise invisible). They ride the fresh control stream — the same
        // divert path an oversize turn takes when first sent — before the
        // buffered live turns below, preserving seq order (a retained turn's seq
        // always precedes a turn produced during the outage).
        if let Err(error) =
            redivert_pending_control(&mut control_send, pending_control_redivert).await
        {
            return announcer.absorb_link_close(Err(DriverError::from(error)));
        }
        // Re-assert the game's own "my loop is running" announcement on this
        // connection's fresh control stream. The fact is session state, not link
        // state, so every stream carries it: an announcement whose write raced a
        // link drop — or one the game made while the driver was between links —
        // would otherwise be lost, since nothing acknowledges a control-stream
        // write. The relay latches one report per link and the coordinator dedups
        // per slot, so a repeat is absorbed. Best-effort like every send of it: a
        // failure leaves the fact pending for the next stream rather than ending
        // the session over a report nothing depends on.
        //
        // Whether the frame actually made it onto THIS stream is tracked
        // separately from the retained fact: a relay fence probe answers the
        // question "is anything this client owes still unwritten here", which a
        // re-assertion whose write failed leaves as yes.
        let mut game_started_on_stream = false;
        if *game_started_announced {
            match send_control_game_started(&mut control_send).await {
                Ok(()) => game_started_on_stream = true,
                Err(error) => tracing::debug!(
                    %error,
                    "re-asserting the game-started announcement failed; retrying on the next stream"
                ),
            }
        }
        // Flush any turns the game produced while the link was down, in seq order,
        // before live turns resume. On a fresh dial the buffer is empty; on a
        // reconnect these are the turns buffered during the outage. Each goes out
        // exactly like a live outbound turn: assigned its origin seq from the
        // persistent counter, sent on the datagram path when it fits or diverted to
        // the control stream when it cannot, and able to release a pending leave
        // intent it was the last thing holding. `next_outbound_seq`, the reorder
        // cursors, and the announcer all live in the persistent `state`, so a
        // resumed session continues the seq stream rather than rewinding it.
        while let Some((_, payload)) = held.pop_front() {
            // Turns still waiting out a send-phase delay when the last link
            // ended go first: their deadlines are long past (any outage dwarfs
            // a sub-turn phase delay) and they predate everything buffered
            // during the outage, so sending them immediately keeps production
            // order and re-holds nothing. Popped one at a time (never drained
            // wholesale into the loop) so a send failure leaves the unsent
            // tail in place for the next session — these turns are unstamped
            // and unretained, so nothing else could ever recover them.
            match send_game_turn(
                link,
                &mut control_send,
                announcer,
                next_outbound_seq,
                retention,
                retention_bytes,
                own_slot,
                &mut flush_deadline,
                &mut acks_owed,
                payload,
            )
            .await
            {
                OutboundSend::Sent => {}
                OutboundSend::EndSession(result) => return result,
            }
            announcer
                .maybe_send(&mut control_send, outbound, held.is_empty(), link)
                .await?;
        }
        // Popped one at a time for the same reason as the held turns above: a
        // send failure must leave the unsent tail for the next session.
        while let Some(buffered) = outbound_buffer.pop_front() {
            match send_game_turn(
                link,
                &mut control_send,
                announcer,
                next_outbound_seq,
                retention,
                retention_bytes,
                own_slot,
                &mut flush_deadline,
                &mut acks_owed,
                buffered,
            )
            .await
            {
                OutboundSend::Sent => {}
                OutboundSend::EndSession(result) => return result,
            }
            announcer
                .maybe_send(&mut control_send, outbound, held.is_empty(), link)
                .await?;
        }
        // Mirrors `beacon_alive`: the game signals at most once, so this disarms
        // on the channel's first resolution (the real signal, or the sender
        // dropping without one) rather than only on `None` — either way there is
        // nothing further to receive, and leaving the branch armed past that
        // would either spin on a closed channel or just poll a channel that will
        // never produce anything else.
        let mut leave_intent_alive = true;

        // Mirrors `leave_intent_alive`: the game announces its loop starting at
        // most once, so the branch is disarmed on the channel's first resolution
        // (the signal, or the sender dropping without one) to keep an
        // always-ready `None` from spinning the loop.
        let mut game_started_alive = true;

        // Mirrors `leave_intent_alive`: the game hands over a result at most
        // once, so this disarms on the channel's first resolution — the payload,
        // or the sender dropping without one — rather than spinning on a closed
        // channel.
        let mut result_alive = true;

        // Whether the game's lobby-command sender is still live. Unlike the
        // single-shot channels above, lobby commands stream during setup, so this
        // disarms only on the sender dropping (a `None`) — the game finished
        // authoring lobby commands (the game started, or it left) — after which
        // `recv()` is an always-ready `None` that would spin the loop.
        let mut lobby_out_alive = true;

        // Whether the game's chat sender is still live. Unlike lobby, chat
        // streams for the whole game, not just pre-game setup, but the disarm
        // rule is the same: only on the sender dropping (a `None`), after which
        // `recv()` is an always-ready `None` that would spin the loop.
        let mut chat_out_alive = true;

        // Whether the game's skin sender is still live. Skin blobs flow near game
        // start (and on the relay's reconnect replays), with the same disarm rule
        // as chat: only on the sender dropping (a `None`), after which `recv()` is
        // an always-ready `None` that would spin the loop.
        let mut skin_out_alive = true;

        // Whether the game's drop-request sender is still live. Like chat it
        // streams for the whole game, with the same disarm rule: only on the
        // sender dropping (a `None`), after which `recv()` is an always-ready
        // `None` that would spin the loop.
        let mut request_drop_alive = true;

        // Game-initiated teardown exits `break` here rather than `return`, so
        // they funnel through the held-turn drain below the loop; link-failure
        // exits `return` directly, keeping their held turns for the reconnect
        // flush.
        'serve: loop {
            // Armed only once the game has signaled its departure (the announcer
            // has a `deadline`); the day-out fallback keeps the branch dormant,
            // and the type checker satisfied, otherwise.
            let leave_deadline = announcer
                .deadline()
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
            // Armed only while a turn is held for its send-phase delay; the
            // day-out fallback keeps the branch dormant, and the type checker
            // satisfied, otherwise — mirroring `leave_deadline`.
            let held_due = held
                .front()
                .map(|&(due, _)| due)
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));

            tokio::select! {
                received = link.recv() => {
                    match inbound::on_received(
                        received,
                        link,
                        &mut control_send,
                        &mut beacon_send,
                        &mut beacon_writer,
                        &mut acks_owed,
                        next_seq,
                        pending,
                        inbound,
                        outbound,
                        announcer,
                        held,
                    )
                    .await
                    {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                received = control_rx.recv() => {
                    match inbound::on_control_frame(
                        received,
                        link,
                        &mut control_send,
                        &mut beacon_send,
                        &mut beacon_writer,
                        next_seq,
                        pending,
                        inbound,
                        leaves,
                        lobby_in,
                        chat_in,
                        skin_in,
                        session_start,
                        connectivity,
                        region_labels,
                        phase_status,
                        phase_slew,
                        announcer,
                        game_started,
                        game_started_announced,
                        game_started_out,
                        &mut game_started_on_stream,
                        connectivity_states,
                        terminal_connectivity_slots,
                    )
                    .await
                    {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                outgoing = outbound.recv() => {
                    match outbound::on_outgoing_turn(
                        outgoing,
                        link,
                        &mut control_send,
                        announcer,
                        next_outbound_seq,
                        retention,
                        retention_bytes,
                        own_slot,
                        &mut flush_deadline,
                        &mut acks_owed,
                        outbound,
                        held,
                        phase_slew,
                        phase_status,
                    )
                    .await
                    {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                () = sleep_until(held_due), if !held.is_empty() => {
                    match outbound::on_held_due(
                        link,
                        &mut control_send,
                        announcer,
                        next_outbound_seq,
                        retention,
                        retention_bytes,
                        own_slot,
                        &mut flush_deadline,
                        &mut acks_owed,
                        outbound,
                        held,
                    )
                    .await
                    {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                // The game signaling its own clean departure (F10 quit, game
                // over). This branch only arms the announcer — it never sends the
                // frame itself, since the relay must still see every turn this
                // client already produced. The announcer's `maybe_send` below (and
                // after every other branch that can change drain state) does the
                // actual write once the outbound queue and unacked window are both
                // empty, and the safety-timeout branch below covers the case where
                // they never drain. Disarmed after this
                // resolves once, whether or not the game actually signaled —
                // the game signals at most once, so there is nothing further to
                // receive either way, and leaving the branch armed on a `None`
                // (the sender dropped without signaling) would spin the loop on
                // an always-ready `None`.
                signal = leave_intent.recv(), if leave_intent_alive => {
                    leave_intent_alive = false;
                    if signal.is_some() {
                        announcer.arm(LEAVE_INTENT_TIMEOUT);
                        announcer.maybe_send(&mut control_send, outbound, held.is_empty(), link).await?;
                    }
                    // A `None` (the game dropped its sender without ever
                    // signaling — an unclean teardown) needs no further action:
                    // the driver keeps running exactly as if leave-intent
                    // didn't exist, and the relay falls back to detecting the
                    // eventual link death itself.
                }
                payload = result.recv(), if result_alive => {
                    match outbound::on_result(
                        payload,
                        link,
                        &mut control_send,
                        announcer,
                        outbound,
                        held,
                        &mut result_alive,
                    )
                    .await
                    {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                signal = game_started_out.recv(), if game_started_alive => {
                    match outbound::on_game_started(
                        signal,
                        &mut control_send,
                        game_started_announced,
                        &mut game_started_on_stream,
                        &mut game_started_alive,
                    )
                    .await
                    {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                bytes = lobby_out.recv(), if lobby_out_alive => {
                    match outbound::on_lobby_out(
                        bytes,
                        &mut control_send,
                        announcer,
                        &mut lobby_out_alive,
                    )
                    .await
                    {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                chat = chat_out.recv(), if chat_out_alive => {
                    match outbound::on_chat_out(chat, &mut control_send, &mut chat_out_alive).await
                    {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                bytes = skin_out.recv(), if skin_out_alive => {
                    match outbound::on_skin_out(bytes, &mut control_send, &mut skin_out_alive).await
                    {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                target = request_drop.recv(), if request_drop_alive => {
                    match outbound::on_request_drop(
                        target,
                        &mut control_send,
                        &mut request_drop_alive,
                    )
                    .await
                    {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                // Safety timeout: the game signaled its departure but the
                // outbound queue or unacked window hadn't drained within
                // `LEAVE_INTENT_TIMEOUT`. If acks aren't coming the link is
                // effectively dead and the ordinary drop path (idle timeout)
                // covers it regardless; sending here anyway is harmless even if
                // the link is fine — the relay stops forwarding this slot's
                // turns the moment it sees the intent, so a few turns still
                // technically unacked changes nothing.
                _ = sleep_until(leave_deadline), if announcer.deadline().is_some() => {
                    announcer.force_send(&mut control_send).await?;
                }
                // The peer pushed a per-slot delivered-through cursor over the beacon
                // stream. The reader task already assembled the complete frame off a
                // cancel-safe path, so receiving here can never be a partial read.
                // `mpsc::Receiver::recv` is cancel-safe in select!. The
                // `if beacon_alive` precondition disables this branch once the reader
                // task ends — otherwise `recv()` returns `None` on every poll, an
                // always-ready future that would spin the loop at 100% CPU (the
                // connection may still be up, so `link.recv()` wouldn't surface it).
                received = beacon_rx.recv(), if beacon_alive => {
                    match received {
                        Some((slot, cursor)) => {
                            link.retire_through(slot, cursor);
                            if check_cap(link.payloads_in_flight()) {
                                return Err(DriverError::UnackedWindowExhausted {
                                    in_flight: link.payloads_in_flight(),
                                    cap: UNACKED_WINDOW_CAP,
                                });
                            }
                            // The beacon force-retiring turns may have just
                            // emptied the unacked window a pending leave intent
                            // was waiting on.
                            announcer.maybe_send(&mut control_send, outbound, held.is_empty(), link).await?;
                        }
                        // The reader task ended (peer's beacon stream closed or
                        // errored). Stop polling it: the real link failure, if any,
                        // surfaces via `link.recv()`; a beacon-only stream reset must
                        // not spin the loop. The cap still bounds the window without
                        // beacons — the driver just stops force-advancing.
                        None => beacon_alive = false,
                    }
                }
                // The game dropped its receiver. This is its own branch so the stop
                // is noticed even on a quiet link with nothing to deliver — without
                // it, the closure would surface only on the next `try_send`, leaving
                // the connection (and the relay slot) open indefinitely.
                _ = inbound.closed() => break 'serve,
                _ = sleep_until(flush_deadline) => {
                    // The maintenance flush, reached because the outbound stream
                    // stopped re-carrying unacked turns (near-MTU) or went idle. When
                    // a turn is unacked or we owe acks, send an ack-only packet: it
                    // re-carries unacked turns oldest-first (its full budget has room
                    // the near-MTU fresh packets did not) and folds in any acks owed.
                    // It stays silent when nothing is unacked and nothing is owed.
                    if acks_owed || link.payloads_in_flight() > 0 {
                        match send_packet(link, None) {
                            Ok(_) => {}
                            // Post-announce, the relay closing the link under this
                            // flush is the expected confirmation, not a failure.
                            Err(error) => return announcer.absorb_link_close(Err(error)),
                        }
                        acks_owed = false;
                    }
                    flush_deadline = Instant::now() + FLUSH_INTERVAL;
                }
            }
        }

        teardown::drain_and_settle(
            link,
            &mut control_send,
            announcer,
            next_outbound_seq,
            retention,
            retention_bytes,
            own_slot,
            &mut flush_deadline,
            &mut acks_owed,
            outbound,
            held,
            leave_intent,
            result,
            game_started_out,
            game_started_announced,
        )
        .await
    }
}
