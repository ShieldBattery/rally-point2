//! Teardown after the game closes its seam: draining everything it produced in
//! its final moments, then fencing delivery — waiting out the unacked datagram
//! window with the flush re-carry running, and waiting for the relay's own
//! close to prove the reliable control stream was read in full.

use std::collections::VecDeque;

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;
use rally_point_transport::control::{send_control_game_result, send_control_game_started};
use rally_point_transport::{Link, noq};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};

use crate::leave_announcer::LeaveAnnouncer;

use super::send::{OutboundSend, send_game_turn, send_packet};
use super::*;

/// The game closed its seam. Everything it produced in its final
/// moments must still reach the relay — lockstep stalls forever on a
/// missing turn, and a clean leave that dies here books the departure
/// as a dropped link — and the closed-seam select arms race the
/// channel-consuming arms, so a "hand it over, then drop the seam"
/// sequence may leave any of it sitting unread in the channels. Drain
/// it all, in production order: turns still waiting out their
/// send-phase delay first (they are oldest), then turns still queued
/// in the outbound channel, then a queued leave-intent signal and a
/// queued result report. A link failure mid-drain classifies exactly
/// as a live send's would.
#[allow(clippy::too_many_arguments)]
pub(super) async fn drain_and_settle(
    link: &mut Link,
    control_send: &mut noq::SendStream,
    announcer: &mut LeaveAnnouncer,
    next_outbound_seq: &mut u64,
    retention: &mut VecDeque<Payload>,
    retention_bytes: &mut usize,
    own_slot: SlotId,
    flush_deadline: &mut Instant,
    acks_owed: &mut bool,
    outbound: &mut mpsc::Receiver<Payload>,
    held: &mut VecDeque<(Instant, Payload)>,
    leave_intent: &mut mpsc::Receiver<()>,
    result: &mut mpsc::Receiver<Vec<u8>>,
    game_started_out: &mut mpsc::Receiver<()>,
    game_started_announced: &mut bool,
) -> Result<(), DriverError> {
    while let Some((_, payload)) = held.pop_front() {
        match send_game_turn(
            link,
            control_send,
            announcer,
            next_outbound_seq,
            retention,
            retention_bytes,
            own_slot,
            flush_deadline,
            acks_owed,
            payload,
        )
        .await
        {
            OutboundSend::Sent => {}
            OutboundSend::EndSession(result) => return result,
        }
    }
    while let Ok(payload) = outbound.try_recv() {
        match send_game_turn(
            link,
            control_send,
            announcer,
            next_outbound_seq,
            retention,
            retention_bytes,
            own_slot,
            flush_deadline,
            acks_owed,
            payload,
        )
        .await
        {
            OutboundSend::Sent => {}
            OutboundSend::EndSession(result) => return result,
        }
    }
    if leave_intent.try_recv().is_ok() {
        announcer.arm(LEAVE_INTENT_TIMEOUT);
    }
    if game_started_out.try_recv().is_ok() && !*game_started_announced {
        // The game closed its seam with the announcement still unread, so
        // this is the only stream that will ever carry it — there is no next
        // one to re-assert on. Retained anyway, so the whole session agrees
        // on the fact, and written best-effort like the live arm.
        *game_started_announced = true;
        if let Err(error) = send_control_game_started(control_send).await {
            tracing::debug!(%error, "game-started send failed at teardown; dropping it");
        }
    }
    if let Ok(payload) = result.try_recv()
        && !announcer.result_sent()
        && !announcer.sent()
    {
        // Mirrors the live result arm: best-effort, latched as sent
        // either way so the leave-intent hold below releases.
        if let Err(error) = send_control_game_result(control_send, payload.into()).await {
            tracing::debug!(%error, "game-result send failed at teardown; dropping the report");
        }
        announcer.note_result_sent();
    }

    // Sending is not delivering: the caller closes the connection the
    // moment this returns, and a close outruns both datagrams and stream
    // data on the wire. Fence one, datagrams: wait for the unacked window
    // to clear — the turns drained above and any zero-delay final turn
    // sent moments before the seam closed — with the ordinary flush
    // re-carry running so a lost datagram is retransmitted, the same
    // recovery a live turn gets, compressed into teardown.
    let settle_deadline = Instant::now() + TEARDOWN_SETTLE;
    let mut settle_flush = Instant::now() + FLUSH_INTERVAL;
    let mut link_gone = false;
    while link.payloads_in_flight() > 0 {
        tokio::select! {
            received = link.recv() => {
                if received.is_err() {
                    // The relay closed first; nothing more can be learned.
                    link_gone = true;
                    break;
                }
            }
            () = sleep_until(settle_flush) => {
                if send_packet(link, None).is_err() {
                    link_gone = true;
                    break;
                }
                settle_flush = Instant::now() + FLUSH_INTERVAL;
            }
            () = sleep_until(settle_deadline) => break,
        }
    }
    if link.payloads_in_flight() > 0 {
        // The fence gave up: the link died, or a settle window of
        // re-carries drew no acks (which means the same thing in
        // practice). The remaining turns are lost — deliberately, with no
        // reconnect-to-deliver path: the relay is the session's single
        // distribution point, so a turn it never acked reached *nobody*,
        // and the survivors stay mutually consistent without it (the
        // leave/drop machinery removes this slot at a frame every
        // survivor applies identically). All that is lost is a departing
        // player's final few commands; re-dialing after the game died, to
        // deliver commands from a player who is gone, would keep dead
        // games' drivers dialing for cosmetic gain.
        tracing::warn!(
            unacked = link.payloads_in_flight(),
            "closing with final turns unacknowledged; survivors reconcile via the leave path",
        );
    }

    // With everything drained — and, as far as the fence can tell,
    // delivered — an armed clean leave is finally ready: it was withheld
    // while turns were outstanding, and losing it here would book the
    // departure as a dropped link instead of completing the clean-leave
    // handshake. If the window never cleared, send it anyway: if acks are
    // not coming the link is effectively dead and announcing is harmless,
    // the same call the live loop's safety timeout makes. A failed write
    // keeps its classification instead of being shrugged into a clean
    // stop — the connection may be perfectly alive around a broken
    // control stream, and that difference is what the caller's error
    // handling (and the operator reading the logs) keys on.
    if !link_gone {
        if let Err(error) = announcer
            .maybe_send(control_send, outbound, held.is_empty(), link)
            .await
        {
            return announcer.absorb_link_close(Err(DriverError::from(error)));
        }
        if announcer.deadline().is_some()
            && let Err(error) = announcer.force_send(control_send).await
        {
            return announcer.absorb_link_close(Err(DriverError::from(error)));
        }
    }

    // Fence two, stream data: a successful write proves nothing about
    // receipt, and *any* write this session may still be undelivered —
    // not just what teardown drained, but an oversize turn the live arm
    // sent moments before the seam dropped, a mid-game result, the leave
    // intent above. So the stream is always FINed and fenced: wait for
    // the relay to close the link — its reader treats the EOF (or the
    // leave intent directly) as this client done and closes, and that
    // close arriving here proves the stream was read in full. On a
    // healthy link the relay's close arrives within a round trip, so the
    // full window is spent only against an unresponsive relay. Its own
    // window, not fence one's remainder: a stalled datagram settle can
    // exhaust that entirely, and the leave intent force-sent just above
    // would then race the connection close with zero time on the clock —
    // the very hole this fence exists to close. The finish itself is
    // best-effort: if the stream is already reset, the wait below still
    // observes whatever the relay does about it.
    if !link_gone {
        let _ = control_send.finish();
        let stream_deadline = Instant::now() + TEARDOWN_SETTLE;
        loop {
            tokio::select! {
                received = link.recv() => {
                    if received.is_err() {
                        break;
                    }
                }
                () = sleep_until(stream_deadline) => break,
            }
        }
    }
    Ok(())
}
