//! The ring of this client's own recently-sent turns, and re-delivering them
//! after a resume: which turns a re-home re-injects into the unacked window,
//! which are too large for any datagram and must ride the fresh control stream
//! instead, and the own-slot receive-window anchors a resume declares so
//! nothing it re-sends is refused.

use std::collections::VecDeque;

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;
use rally_point_transport::control::{ControlSendError, send_control_turn};
use rally_point_transport::{Link, noq};

use super::state::LoopState;

/// How many of this client's own recently-sent turns the retention ring keeps for
/// re-injection after a re-home. Independent of ack retirement — a turn the old
/// relay acked is dropped from the unacked window but kept here — so the ring can
/// re-carry it to a replacement relay whose turn ring is empty. A few times the
/// deepest realistic latency buffer; the byte cap ([`RETENTION_BYTE_CAP`]) bounds it
/// too, so an oversize turn can't blow the memory budget.
const RETENTION_TURN_CAP: usize = 512;

/// The byte ceiling on the retention ring, enforced alongside
/// [`RETENTION_TURN_CAP`] so a run of large turns can't grow it past this even
/// under the turn cap. 256 KiB comfortably holds 512 ordinary (tens-of-bytes)
/// turns and still bounds a pathological run of near-MTU ones.
const RETENTION_BYTE_CAP: usize = 256 * 1024;

/// A drop-oldest ring of this client's own recently-sent turns, bounded by both
/// [`RETENTION_TURN_CAP`] and [`RETENTION_BYTE_CAP`]. Every turn the driver
/// sends for its own slot goes in (datagram or diverted), so a re-home can
/// re-inject them onto a replacement relay whose turn ring is empty.
///
/// The running byte total is the ring's own business — it exists only so the
/// byte cap is enforced without re-summing the ring on every push — which is
/// why nothing outside carries it.
#[derive(Default)]
pub(super) struct RetentionRing {
    turns: VecDeque<Payload>,
    bytes: usize,
}

impl RetentionRing {
    /// Records one sent turn, evicting the oldest turns until both caps hold.
    /// The last remaining entry is never evicted on the byte cap alone: a lone
    /// turn larger than the whole budget is still the only copy of a turn some
    /// peer may be stalled on.
    pub(super) fn push(&mut self, payload: &Payload) {
        self.turns.push_back(payload.clone());
        self.bytes += retained_size(payload);
        while self.turns.len() > RETENTION_TURN_CAP
            || (self.bytes > RETENTION_BYTE_CAP && self.turns.len() > 1)
        {
            let Some(dropped) = self.turns.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(retained_size(&dropped));
        }
    }

    /// The retained turns, oldest first — what a resume walks to decide which
    /// go back into the unacked window and which must ride the control stream.
    pub(super) fn iter(&self) -> impl Iterator<Item = &Payload> {
        self.turns.iter()
    }

    /// The seq of the oldest retained turn: the front a re-home's own-slot
    /// anchor descends from, or `None` when nothing is retained.
    pub(super) fn front_seq(&self) -> Option<u64> {
        self.turns.front().map(|turn| turn.seq)
    }

    /// The oldest retained turn a same-relay resume will restage onto the fresh
    /// control stream — the entries too large to ride any datagram (see
    /// [`redivert_oversize_retention_on_same_relay_resume`], which stages
    /// exactly these). Judged against the transport's static floor: the live
    /// admission equals it on every connection the session can hold
    /// (under-floor peers are refused at establishment), and the dead link this
    /// is computed beside no longer has a live budget to ask.
    pub(super) fn oldest_oversize_seq(&self) -> Option<u64> {
        self.turns
            .iter()
            .filter(|turn| !rally_point_transport::ack_manager::fits_guaranteed_datagram(turn))
            .map(|turn| turn.seq)
            .min()
    }

    /// How many turns are retained.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.turns.len()
    }

    /// What the ring counts against its byte cap.
    #[cfg(test)]
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }
}

/// The size a retained turn counts against [`RETENTION_BYTE_CAP`]: its command
/// bytes (the variable bulk) plus a fixed allowance for the small fixed fields.
/// An estimate, not the exact encoded length — the byte cap is a memory safety
/// bound, so an approximation that avoids pulling a prost dependency into the lib
/// is enough.
fn retained_size(payload: &Payload) -> usize {
    payload.commands.len() + 32
}

/// Drains the retained oversize turns a re-home staged for the fresh connection's
/// control stream onto `control_send`, oldest-first — the same divert path an
/// oversize turn takes when first sent.
///
/// Each turn is removed from `pending` only *after* its send succeeds, so if the
/// stream fails partway (the fresh connection dropped again) the unsent remainder
/// stays staged and the next session over the re-dialed link retries it. Draining
/// with a `mem::take` up front would instead move the whole batch out and drop the
/// unsent tail on a mid-batch failure — and a later same-relay resume does not
/// re-run [`reinject_retention`], so those oversize turns would be lost for good,
/// permanently stalling a peer that never received them from the dead relay on that
/// seq. The clone is cheap next to that risk (these turns are rare and the batch
/// tiny), and paid only while turns remain to send.
pub(super) async fn redivert_pending_control(
    control_send: &mut noq::SendStream,
    pending: &mut Vec<Payload>,
) -> Result<(), ControlSendError> {
    while let Some(turn) = pending.first().cloned() {
        send_control_turn(control_send, turn).await?;
        pending.remove(0);
    }
    Ok(())
}

/// The own-slot receive-window anchor a re-home dial presents to the fresh relay:
/// the retention front, extended downward only through *contiguously* unacked
/// seqs (see [`Link::contiguous_replayable_anchor`]).
///
/// Two sources feed the re-home's own-slot re-send: the rebound link's unacked
/// window (redundancy re-carries it) and [`reinject_retention`]'s retained ring
/// (`[front..]`). The anchor promises the fresh relay that every seq above it
/// will arrive and close its receive window's contiguous prefix — and the
/// unacked window is *sparse* (selective packet acks leave holes), so the
/// promise only holds as far below the front as unacked seqs run contiguously.
/// An acked hole below the front is in neither source; anchoring beneath one
/// would base the window on a permanent void that eventually rejects the live
/// stream as out-of-window. Unacked seqs below the first hole are still
/// replayed and arrive below the relay's base, where they are discarded — the
/// accepted trade: their hole can only have aged out of retention if turn
/// production continued past it, which means no peer was wedged beneath it and
/// the old relay had already fanned those turns.
///
/// The contiguous descent still covers the outgrown-retention case this helper
/// has always guarded ([`UNACKED_WINDOW_CAP`] is twice [`RETENTION_TURN_CAP`]):
/// sustained forward-path loss leaves 513..=1024 turns in flight *unacked and
/// contiguous*, and the descent walks below the front through all of them —
/// stranding none, exactly as the plain minimum once did, while refusing the
/// sparse descent the minimum wrongly took. With no retention at all, the
/// anchor falls back to the oldest unacked seq (a slot that never sent
/// anything has neither source, and no anchor is declared: the window
/// correctly bases at 0).
pub(super) fn rehome_own_slot_anchor(
    link: &Link,
    own_slot: SlotId,
    retention_front: Option<u64>,
) -> Option<u64> {
    match retention_front {
        Some(front) => Some(link.contiguous_replayable_anchor(own_slot, front)),
        None => link.oldest_replayable_seq(own_slot),
    }
}

/// The cursor set a same-relay re-dial presents: every peer cursor plus this
/// client's own-slot resume anchor — the oldest seq the resume will re-send
/// over EITHER of its paths (the datagram redundancy's oldest replayable
/// unacked seq, or the oldest retained oversize turn the resume restages onto
/// the control stream), or with neither the next seq this client will
/// produce. Both paths must anchor: the relay's receive dedup gates the
/// control-delivered restage exactly as it gates a datagram, so an anchor
/// above a restaged oversize seq would have its retry discarded as a
/// duplicate — permanently stranding every peer on that seq.
///
/// The own-slot cursor is ALWAYS included, an anchor of 0 included. Its value
/// bases the relay's fresh receive window, but its *presence* is what makes
/// the relay seed that window's acked holes from its session-lifetime receipt
/// records — and an anchor of 0 with an acked seq 1 above it needs that
/// seeding exactly as a nonzero anchor does. "0 is the window's default base
/// anyway" must never optimize the cursor away: it would leave the seeding
/// unrequested and wedge the resumed window's prefix on the first acked hole.
pub(super) fn same_relay_resume_cursors(
    peer_cursors: &[(SlotId, u64)],
    oldest_replayable: Option<u64>,
    oldest_restaged_oversize: Option<u64>,
    own_slot: SlotId,
    next_outbound_seq: u64,
) -> Vec<(SlotId, u64)> {
    let anchor = match (oldest_replayable, oldest_restaged_oversize) {
        (Some(datagram), Some(oversize)) => datagram.min(oversize),
        (Some(only), None) | (None, Some(only)) => only,
        (None, None) => next_outbound_seq,
    };
    let mut cursors = peer_cursors.to_vec();
    cursors.push((own_slot, anchor));
    cursors
}

/// Stages one turn for reliable-control delivery unless an identical
/// `(slot, seq)` is already staged — both rebind-time paths (the re-home's
/// retention re-injection and the same-relay oversize redivert) can nominate
/// the same turn across a run of failed resumes, and one control-stream copy
/// suffices (the peer dedups by origin identity anyway; the check just saves
/// the bytes).
pub(super) fn stage_control_redivert(pending: &mut Vec<Payload>, turn: Payload) {
    if !pending
        .iter()
        .any(|staged| staged.slot == turn.slot && staged.seq == turn.seq)
    {
        pending.push(turn);
    }
}

/// Re-carries the retained turns onto a freshly re-homed link so the replacement
/// relay's empty turn ring re-delivers them to peers (each deduping by origin
/// `(slot, seq)`). Only ever called on a re-home — a same-relay resume keeps the
/// old relay's ring, so there is nothing to re-carry.
///
/// A turn that still fits a datagram goes back into the unacked window, where the
/// next packet's redundancy pass re-carries it. A turn too large for any datagram
/// cannot go there: [`AckManager::build_outgoing`] skips a payload that can't fit a
/// lone packet on every pass, so a re-injected oversize turn would sit in the
/// window forever — never re-delivered (inflating `payloads_in_flight`) and, worse,
/// leaving a peer that never received it from the dead relay stalled on its seq.
/// Those are staged in [`LoopState::pending_control_redivert`] instead, which
/// [`session`](Driver::session) drains onto the new connection's reliable control
/// stream — the same divert path an oversize turn takes when first sent. A path
/// that can't currently size a datagram is treated as oversize, so the turn is
/// re-carried reliably rather than risk being lost.
pub(super) fn reinject_retention(link: &mut Link, state: &mut LoopState) {
    let LoopState {
        retention,
        pending_control_redivert,
        ..
    } = state;
    for turn in retention.iter() {
        if matches!(link.payload_fits(turn), Ok(true)) {
            link.reinject_unacked(turn.clone());
        } else {
            stage_control_redivert(pending_control_redivert, turn.clone());
        }
    }
}

/// Re-divert this session's still-retained OVERSIZE turns onto a same-relay
/// resume's control stream — the same-connection counterpart of
/// [`reinject_retention`]'s oversize half.
///
/// A same-relay resume deliberately does NOT touch the datagram/unacked
/// window at all: the rebound link's own redundancy re-carries the unacked
/// tail, and the relay covers everything it already received. Re-injecting
/// the retention ring's ordinary-sized turns on top of that — as a re-home
/// does — would risk a permanent prefix gap (see the same-relay anchor
/// comment in `reconnect_link`); that risk is real and this function does not
/// touch it.
///
/// An oversize turn is different in kind, not just size: it never rode the
/// datagram/ack path in the first place (there is no acknowledgment for a
/// control-stream write to check against), so there is no equivalent gap risk
/// here — a turn the relay already fanned out is simply deduped again on
/// arrival (the relay's ingress dedup keys on origin `(slot, seq)` regardless
/// of which path delivered it, exactly as a datagram-delivered turn would
/// be), and one the relay never received before the drop is finally
/// delivered. Safe and cheap to run unconditionally on every same-relay
/// resume, not gated on anything provably missing — there is no
/// acknowledgment to check in the first place. A turn already staged (from a
/// prior resume whose own redivert only partially drained before failing
/// again) is not re-staged, so a run of same-relay failures doesn't grow the
/// pending list without bound.
pub(super) fn redivert_oversize_retention_on_same_relay_resume(link: &Link, state: &mut LoopState) {
    let LoopState {
        retention,
        pending_control_redivert,
        ..
    } = state;
    for turn in retention.iter() {
        if matches!(link.payload_fits(turn), Ok(false)) {
            stage_control_redivert(pending_control_redivert, turn.clone());
        }
    }
}
