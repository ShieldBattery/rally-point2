//! One turn's wire handoff and the small primitives around it: assigning a
//! turn its origin identity and choosing the datagram or control-stream path,
//! sending a packet, releasing received turns to the game in seq order,
//! pushing delivered-through cursors, and the unacked-window cap check.

use std::collections::{BTreeMap, HashMap, VecDeque};

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;
use rally_point_transport::beacon::BeaconWriter;
use rally_point_transport::control::send_control_turn;
use rally_point_transport::{Link, LinkError, noq};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::leave_announcer::LeaveAnnouncer;

use super::state::retain_sent;
use super::*;

/// The outcome of one turn's wire handoff: sent (keep looping), or the session
/// must end with the given result — an absorbed post-leave close (`Ok`) or a
/// real failure, exactly as if the send site had returned it inline.
pub(super) enum OutboundSend {
    Sent,
    EndSession(Result<(), DriverError>),
}

/// One game-produced turn's wire handoff, shared by every path that sends one
/// (the live outbound arm, the send-phase hold drain, and the reconnect
/// flush): stamp the origin seq and slot, retain a re-home copy, and send — on
/// the datagram path when it fits, diverted to the reliable control stream
/// when it cannot. Stamping happens here, at actual send, so however a turn
/// reached this point the seq stream is assigned in wire order.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_game_turn(
    link: &mut Link,
    control_send: &mut noq::SendStream,
    announcer: &LeaveAnnouncer,
    next_outbound_seq: &mut u64,
    retention: &mut VecDeque<Payload>,
    retention_bytes: &mut usize,
    own_slot: SlotId,
    flush_deadline: &mut Instant,
    acks_owed: &mut bool,
    mut payload: Payload,
) -> OutboundSend {
    // Assign this turn its origin seq and slot — the client is the sole
    // authority for both its own slot's identity and its production order. The
    // embedder leaves `slot` at 0 on every outbound turn (as it does `seq`);
    // stamping our authorized slot here keys the AckManager's unacked window
    // under the same `own_slot` the resume anchor and ack-beacon retirement
    // use, so an in-flight turn is not stranded under a phantom slot-0 key
    // across a reconnect.
    payload.seq = *next_outbound_seq;
    payload.slot = u32::from(own_slot.0);
    *next_outbound_seq += 1;
    // Retain a copy for a possible re-home re-injection before the turn is
    // handed to the link (which moves it).
    retain_sent(retention, retention_bytes, &payload);
    let fits = match link.payload_fits(&payload) {
        Ok(fits) => fits,
        Err(error) => return OutboundSend::EndSession(Err(DriverError::from(error))),
    };
    if fits {
        // It goes out carrying our acks; if it also re-carried unacked turns,
        // recovery is riding the stream, so push the flush out. If it carried
        // none (a near-MTU turn that filled the datagram), leave the timer so
        // the flush retransmits.
        match send_packet(link, Some(payload)) {
            Ok(carried_redundancy) => {
                *acks_owed = false;
                if carried_redundancy {
                    *flush_deadline = Instant::now() + FLUSH_INTERVAL;
                }
                if check_cap(link.payloads_in_flight()) {
                    return OutboundSend::EndSession(Err(DriverError::UnackedWindowExhausted {
                        in_flight: link.payloads_in_flight(),
                        cap: UNACKED_WINDOW_CAP,
                    }));
                }
            }
            // The connection went down while sending this turn. If we already
            // announced our leave, the relay closing the link out from under
            // this send is the expected confirmation, not a failure.
            Err(error) => {
                return OutboundSend::EndSession(announcer.absorb_link_close(Err(error)));
            }
        }
    } else {
        // Too large for any datagram: divert to the reliable control stream,
        // whose QUIC-level reliability replaces redundancy for this turn — it
        // never enters the unacked window and no ack retires it. A write
        // failure is normally fatal (nothing re-carries this turn, and
        // dropping it would desync lockstep) — but once the leave intent is
        // out, the relay closing the stream under this write is the expected
        // confirmation, not a failure.
        if let Err(error) = send_control_turn(control_send, payload).await {
            return OutboundSend::EndSession(
                announcer.absorb_link_close(Err(DriverError::from(error))),
            );
        }
    }
    OutboundSend::Sent
}

/// Sends one packet, returning whether it re-carried any still-unacked turn — if so,
/// retransmission is already riding the outbound stream and the flush can rest.
///
/// A refused datagram (`PayloadTooLarge`) here is a *bundle* that outgrew a
/// path-MTU shrink between sizing and sending — a recoverable loss the next,
/// smaller bundle re-carries, so it is not an error. It can never be a lone
/// turn too big for the path: the caller pre-checks with
/// [`Link::payload_fits`] and diverts those to the control stream before they
/// reach here (and the link itself refuses one pre-registration as a second
/// line of defense).
pub(super) fn send_packet(link: &mut Link, payload: Option<Payload>) -> Result<bool, DriverError> {
    match link.send(payload) {
        Ok(redundant) => Ok(redundant > 0),
        Err(LinkError::PayloadTooLarge { needed, budget }) => {
            tracing::debug!(
                needed,
                budget,
                "datagram refused by a shrunken path; will re-carry"
            );
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

/// What [`release_ready`] observed while handing released turns to the game.
pub(super) enum Release {
    /// Every releasable turn was handed off (possibly none).
    Delivered,
    /// The game dropped its receiver: a clean stop.
    GameClosed,
    /// The game stopped draining and the inbound buffer filled.
    GameStalled,
}

/// Releases each slot's contiguous run of pending turns to the game, holding
/// the rest. Hands off without ever awaiting: blocking on a full channel would
/// park the whole driver — no acks, no outbound turns, no link-failure
/// detection — behind a stalled consumer. Shared by the datagram and
/// control-stream delivery paths, so a turn is released the same way no matter
/// which path delivered it.
pub(super) fn release_ready(
    next_seq: &mut HashMap<SlotId, u64>,
    pending: &mut HashMap<SlotId, BTreeMap<u64, Payload>>,
    inbound: &mpsc::Sender<Payload>,
) -> Release {
    for (slot, slot_next) in next_seq.iter_mut() {
        let Some(slot_pending) = pending.get_mut(slot) else {
            continue;
        };
        while let Some(payload) = slot_pending.remove(slot_next) {
            match inbound.try_send(payload) {
                Ok(()) => *slot_next += 1,
                Err(mpsc::error::TrySendError::Full(payload)) => {
                    // Put the held turn back before surfacing the stall.
                    slot_pending.insert(*slot_next, payload);
                    return Release::GameStalled;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return Release::GameClosed,
            }
        }
    }
    Release::Delivered
}

/// Pushes each slot's delivered-through cursor to the peer so it can
/// force-advance its unacked window past turns it now knows we received.
/// `BeaconWriter` pushes only cursors that advanced past its last-sent state, so a
/// static cursor (a genuine forward gap) sends nothing — the cap handles that.
pub(super) async fn flush_delivered_cursors(
    link: &Link,
    beacon_send: &mut noq::SendStream,
    beacon_writer: &mut BeaconWriter,
    next_seq: &HashMap<SlotId, u64>,
) {
    beacon_writer
        .flush(
            beacon_send,
            next_seq
                .keys()
                .filter_map(|&slot| link.delivered_through(slot).map(|c| (slot, c))),
        )
        .await;
}

/// Returns `true` if the unacked window has crossed the hard cap — the
/// sustained forward-loss case the beacon cannot rescue (the peer is genuinely
/// behind, not just ack-starved). The caller surfaces
/// [`DriverError::UnackedWindowExhausted`], which the reconnect loop treats as
/// terminal rather than re-dialing (see [`is_link_failure`]).
pub(super) fn check_cap(in_flight: usize) -> bool {
    in_flight > UNACKED_WINDOW_CAP
}
