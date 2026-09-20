//! One connection's turn loop: opening this link's beacon and control streams,
//! replaying whatever a resume deferred to them, then multiplexing every arm of
//! the game seam over a single `select!` until the game stops or the link fails.
//!
//! The large arms live in [`inbound`] and [`outbound`]; each hands back an
//! [`ArmFlow`] because an arm body moved out of the loop can no longer `break`
//! to the teardown drain or `return` from the whole session on its own. The
//! arms that can only ever keep serving return nothing at all.

use std::time::Duration;

use rally_point_proto::ids::SlotId;
use rally_point_transport::Link;
use rally_point_transport::control::send_control_game_started;
use tokio::time::{Instant, sleep_until};

use super::retention::redivert_pending_control;
use super::send::{OutboundSend, send_game_turn, send_packet, window_cap_error};
use super::state::{GameSeam, LoopState};
use super::wire::Wire;
use super::{DriverError, LinkDriver, inbound, outbound, teardown};

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
        // The reorder cursors, the outbound seq counter, the leave announcer,
        // and any turns buffered during a prior outage all persist across a
        // reconnect, so they live in the caller's `state`. Everything this one
        // connection owns — its two stream halves, the acks it owes, the flush
        // it is counting down to, which seam arms are still armed — is opened
        // fresh here as the `Wire`. The two reader receivers stay outside both:
        // the `select!` below polls them directly.
        let (mut wire, mut readers) = Wire::open(link, state.timing).await?;

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
            redivert_pending_control(&mut wire.control_send, &mut state.pending_control_redivert)
                .await
        {
            return state
                .announcer
                .absorb_link_close(Err(DriverError::from(error)));
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
        // separately from the retained fact, in `Wire::game_started_on_stream`:
        // a relay fence probe answers the question "is anything this client
        // owes still unwritten here", which a re-assertion whose write failed
        // leaves as yes.
        if state.game_started_announced {
            match send_control_game_started(&mut wire.control_send).await {
                Ok(()) => wire.game_started_on_stream = true,
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
        while let Some((_, payload)) = state.held.pop_front() {
            // Turns still waiting out a send-phase delay when the last link
            // ended go first: their deadlines are long past (any outage dwarfs
            // a sub-turn phase delay) and they predate everything buffered
            // during the outage, so sending them immediately keeps production
            // order and re-holds nothing. Popped one at a time (never drained
            // wholesale into the loop) so a send failure leaves the unsent
            // tail in place for the next session — these turns are unstamped
            // and unretained, so nothing else could ever recover them.
            match send_game_turn(link, &mut wire, state, own_slot, payload).await {
                OutboundSend::Sent => {}
                OutboundSend::EndSession(result) => return result,
            }
            state
                .announcer
                .maybe_send(
                    &mut wire.control_send,
                    &seam.outbound,
                    state.held.is_empty(),
                    link,
                )
                .await?;
        }
        // Popped one at a time for the same reason as the held turns above: a
        // send failure must leave the unsent tail for the next session.
        while let Some(buffered) = state.outbound_buffer.pop_front() {
            match send_game_turn(link, &mut wire, state, own_slot, buffered).await {
                OutboundSend::Sent => {}
                OutboundSend::EndSession(result) => return result,
            }
            state
                .announcer
                .maybe_send(
                    &mut wire.control_send,
                    &seam.outbound,
                    state.held.is_empty(),
                    link,
                )
                .await?;
        }

        // Game-initiated teardown exits `break` here rather than `return`, so
        // they funnel through the held-turn drain below the loop; link-failure
        // exits `return` directly, keeping their held turns for the reconnect
        // flush.
        'serve: loop {
            // Armed only once the game has signaled its departure (the announcer
            // has a `deadline`); the day-out fallback keeps the branch dormant,
            // and the type checker satisfied, otherwise.
            let leave_deadline = state
                .announcer
                .deadline()
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
            // Armed only while a turn is held for its send-phase delay; the
            // day-out fallback keeps the branch dormant, and the type checker
            // satisfied, otherwise — mirroring `leave_deadline`.
            let held_due = state
                .held
                .front()
                .map(|&(due, _)| due)
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));

            tokio::select! {
                received = link.recv() => {
                    match inbound::on_received(received, link, &mut wire, state, seam).await {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                received = readers.control.recv() => {
                    match inbound::on_control_frame(received, link, &mut wire, state, seam).await {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                outgoing = seam.outbound.recv() => {
                    match outbound::on_outgoing_turn(
                        outgoing,
                        link,
                        &mut wire,
                        state,
                        seam,
                        own_slot,
                    )
                    .await
                    {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                () = sleep_until(held_due), if !state.held.is_empty() => {
                    match outbound::on_held_due(link, &mut wire, state, seam, own_slot).await {
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
                signal = seam.leave_intent.recv(), if wire.leave_intent_alive => {
                    wire.leave_intent_alive = false;
                    if signal.is_some() {
                        state.announcer.arm(state.timing.leave_intent_timeout);
                        state.announcer.maybe_send(
                            &mut wire.control_send,
                            &seam.outbound,
                            state.held.is_empty(),
                            link,
                        ).await?;
                    }
                    // A `None` (the game dropped its sender without ever
                    // signaling — an unclean teardown) needs no further action:
                    // the driver keeps running exactly as if leave-intent
                    // didn't exist, and the relay falls back to detecting the
                    // eventual link death itself.
                }
                payload = seam.result.recv(), if wire.result_alive => {
                    match outbound::on_result(payload, link, &mut wire, state, seam).await {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                // `GameSeam::game_started` is the opposite direction from
                // `LoopState::game_started`: this client's own announcement
                // going out, not the relay's start directive arriving.
                signal = seam.game_started.recv(), if wire.game_started_alive => {
                    outbound::on_game_started(signal, &mut wire, state).await;
                }
                bytes = seam.lobby_out.recv(), if wire.lobby_out_alive => {
                    match outbound::on_lobby_out(bytes, &mut wire, state).await {
                        ArmFlow::Serve => {}
                        ArmFlow::Teardown => break 'serve,
                        ArmFlow::End(result) => return result,
                    }
                }
                chat = seam.chat_out.recv(), if wire.chat_out_alive => {
                    outbound::on_chat_out(chat, &mut wire).await;
                }
                bytes = seam.skin_out.recv(), if wire.skin_out_alive => {
                    outbound::on_skin_out(bytes, &mut wire).await;
                }
                target = seam.request_drop.recv(), if wire.request_drop_alive => {
                    outbound::on_request_drop(target, &mut wire).await;
                }
                // Safety timeout: the game signaled its departure but the
                // outbound queue or unacked window hadn't drained within
                // the leave-intent timeout. If acks aren't coming the link is
                // effectively dead and the ordinary drop path (idle timeout)
                // covers it regardless; sending here anyway is harmless even if
                // the link is fine — the relay stops forwarding this slot's
                // turns the moment it sees the intent, so a few turns still
                // technically unacked changes nothing.
                _ = sleep_until(leave_deadline), if state.announcer.deadline().is_some() => {
                    state.announcer.force_send(&mut wire.control_send).await?;
                }
                // The peer pushed a per-slot delivered-through cursor over the beacon
                // stream. The reader task already assembled the complete frame off a
                // cancel-safe path, so receiving here can never be a partial read.
                // `mpsc::Receiver::recv` is cancel-safe in select!. The
                // `if wire.beacon_alive` precondition disables this branch once the
                // reader task ends — otherwise `recv()` returns `None` on every poll,
                // an always-ready future that would spin the loop at 100% CPU (the
                // connection may still be up, so `link.recv()` wouldn't surface it).
                received = readers.beacon.recv(), if wire.beacon_alive => {
                    match received {
                        Some((slot, cursor)) => {
                            link.retire_through(slot, cursor);
                            if let Some(error) = window_cap_error(link) {
                                return Err(error);
                            }
                            // The beacon force-retiring turns may have just
                            // emptied the unacked window a pending leave intent
                            // was waiting on.
                            state.announcer.maybe_send(
                                &mut wire.control_send,
                                &seam.outbound,
                                state.held.is_empty(),
                                link,
                            ).await?;
                        }
                        // The reader task ended (peer's beacon stream closed or
                        // errored). Stop polling it: the real link failure, if any,
                        // surfaces via `link.recv()`; a beacon-only stream reset must
                        // not spin the loop. The cap still bounds the window without
                        // beacons — the driver just stops force-advancing.
                        None => wire.beacon_alive = false,
                    }
                }
                // The game dropped its receiver. This is its own branch so the stop
                // is noticed even on a quiet link with nothing to deliver — without
                // it, the closure would surface only on the next `try_send`, leaving
                // the connection (and the relay slot) open indefinitely.
                _ = seam.inbound.closed() => break 'serve,
                _ = sleep_until(wire.flush_deadline) => {
                    // The maintenance flush, reached because the outbound stream
                    // stopped re-carrying unacked turns (near-MTU) or went idle. When
                    // a turn is unacked or we owe acks, send an ack-only packet: it
                    // re-carries unacked turns oldest-first (its full budget has room
                    // the near-MTU fresh packets did not) and folds in any acks owed.
                    // It stays silent when nothing is unacked and nothing is owed.
                    if wire.acks_owed || link.payloads_in_flight() > 0 {
                        match send_packet(link, None) {
                            Ok(_) => {}
                            // Post-announce, the relay closing the link under this
                            // flush is the expected confirmation, not a failure.
                            Err(error) => {
                                return state.announcer.absorb_link_close(Err(error));
                            }
                        }
                        wire.acks_owed = false;
                    }
                    wire.flush_deadline = Instant::now() + state.timing.flush_interval;
                }
            }
        }

        teardown::drain_and_settle(link, &mut wire, state, seam, own_slot).await
    }
}
