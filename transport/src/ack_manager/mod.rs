//! Per-link send/ack bookkeeping: the redundancy + acknowledgement layer that
//! makes recovery *ours* rather than QUIC's.
//!
//! A link's payloads ride unreliable QUIC datagrams, each one carried in a
//! [`Packet`]. Every packet carries a fresh payload plus copies of still-unacked
//! older payloads, so a single dropped packet rarely loses a payload outright —
//! the next packet re-carries it. How much redundancy a packet spends, and how
//! often one payload is re-carried, is governed by the link's [`RecarryPolicy`]
//! (see its docs for why the refill must be bounded); the datagram's size
//! budget always applies on top, and the fresh payload always rides. Each packet
//! also acks the peer's recent packets (a most-recent `ack` plus a 32-bit
//! [`Packet::ack_bits`] history). When a packet of ours is acked, every payload
//! it carried is retired and stops being re-sent.
//!
//! Two independent sequence spaces are tracked, mirroring the wire:
//!
//! - **packet seq** ([`Packet::seq`], a per-connection `u32` that resets each
//!   QUIC connection) identifies a datagram so the peer can ack it.
//! - **payload seq** ([`Payload::seq`], a `u64`) is the **origin** identity of a
//!   command unit — assigned once by the sending client (the sole authority for
//!   its own slot's turn stream; it alone knows production order) and preserved
//!   end-to-end across every hop, never restamped. Each slot carries its own
//!   monotonic seq space starting at 0, so the dedup/ack/retirement key is
//!   `(slot, seq)`, not `seq` alone: two slots both have a seq 0.
//!
//! One [`AckManager`] runs per link at each endpoint (client ↔ home relay, and
//! relay ↔ relay across the mesh). It owns no I/O: the driver pulls a built
//! [`Packet`] from [`build_outgoing`](AckManager::build_outgoing) and sends it,
//! and feeds every received [`Packet`] to
//! [`handle_incoming`](AckManager::handle_incoming).
//!
//! [`Packet`]: rally_point_proto::messages::Packet
//! [`Packet::seq`]: rally_point_proto::messages::Packet::seq
//! [`Packet::ack_bits`]: rally_point_proto::messages::Packet::ack_bits
//! [`Payload::seq`]: rally_point_proto::messages::Payload::seq

mod history;
mod policy;
mod recv;
mod send;
mod sent;

#[cfg(test)]
mod tests;

pub use policy::{CarrySpacing, RecarryPolicy};
pub(crate) use sent::lone_packet_len;
pub use sent::{
    AckError, GUARANTEED_DATAGRAM_BUDGET, PacketSeqExhausted, fits_guaranteed_datagram,
};

use std::collections::BTreeMap;

use rally_point_proto::ids::SlotId;

use crate::sequence_buffer::SequenceBuffer;
use history::ReceivedPacketHistory;
use sent::{SentPacket, SentPayload};

/// How many of our own recently-sent packets to remember so we can map an
/// incoming ack back to the payloads that packet carried. Chosen large enough
/// that any packet old enough to fall out of the buffer can safely be treated as
/// lost (its payloads are still re-sent until separately acked).
const SENT_PACKETS_SIZE: usize = 256;

/// Manages sending packets and processing acknowledgements for one link.
///
/// Packets contain one or more payloads, each identified by `(slot, seq)` — its
/// origin identity, preserved end-to-end. When an ack for a packet arrives,
/// every payload that packet carried is considered delivered and is dropped from
/// the re-send set.
pub struct AckManager {
    /// Seq to assign to the next packet we build, mirroring the `u32` wire field
    /// exactly so there's no narrowing on the way out. The QUIC connection is
    /// per-game, so at the turn rate this never approaches `u32::MAX` (that bound
    /// is years of uninterrupted play); a connection that somehow reached it
    /// would need to be reset rather than allowed to wrap.
    packet_seq: u32,
    /// Our recently-sent packets, keyed by packet seq, recording which payloads
    /// each carried so an ack can retire them.
    sent_packets: SequenceBuffer<SentPacket>,
    /// Payloads we've sent at least once that have not yet been acked, keyed by
    /// `(slot, seq)` — the origin identity. Iterated per slot, oldest-seq-first
    /// within each slot, to refill each outgoing packet's redundancy budget.
    unacked_payloads: BTreeMap<(SlotId, u64), SentPayload>,
    /// Sum of each unacked payload's encoded repeated-field element size.
    /// Single-entry mutations keep it exact; bulk cursor retirement invalidates
    /// it for one lazy refresh. This makes the common all-fit decision O(1),
    /// without imposing a pre-scan on the constrained path.
    unacked_payload_wire_len: Option<usize>,
    /// The peer's recently-received packets, keyed by their packet seq. Drives
    /// the `ack` / `ack_bits` we send back.
    received_packets: ReceivedPacketHistory,
    /// How the redundancy refill spends bytes and rotates coverage.
    policy: RecarryPolicy,
}

impl AckManager {
    pub fn new() -> Self {
        Self::with_policy(RecarryPolicy::default())
    }

    /// An `AckManager` with an explicit redundancy policy. `new` uses
    /// [`RecarryPolicy::default`].
    pub fn with_policy(policy: RecarryPolicy) -> Self {
        Self {
            packet_seq: 0,
            sent_packets: SequenceBuffer::with_capacity(SENT_PACKETS_SIZE),
            unacked_payloads: BTreeMap::new(),
            unacked_payload_wire_len: Some(0),
            received_packets: ReceivedPacketHistory::default(),
            policy,
        }
    }

    /// Resets the state bound to one QUIC connection, keeping the still-unacked
    /// payloads, for a re-dial that resumed the same session on a fresh connection.
    ///
    /// The packet seq space, the record of our sent packets, and the peer's
    /// received-packet history all belong to the old connection and start over: the
    /// new connection assigns packet seqs from zero and has its own ack history. The
    /// unacked payloads are deliberately *kept* — the redundancy pass re-carries them
    /// over the new connection, and every hop dedups by each turn's origin
    /// `(slot, seq)`, so a turn the peer already received before the drop is dropped
    /// as a duplicate while one it missed still arrives. Losing them here would drop
    /// any turn in flight at the moment the link failed, desyncing lockstep.
    pub fn reset_connection(&mut self) {
        self.packet_seq = 0;
        self.sent_packets = SequenceBuffer::with_capacity(SENT_PACKETS_SIZE);
        self.received_packets = ReceivedPacketHistory::default();
        // unacked_payloads intentionally preserved for re-carry over the new
        // connection — but their coverage history is not: every carry (and the
        // packet seq it rode) belongs to the connection that died, so each
        // survivor starts the new connection uncovered and immediately eligible
        // for dense re-carry.
        for sent in self.unacked_payloads.values_mut() {
            sent.send_count = 0;
            sent.last_carried_packet_seq = None;
            sent.registered_at_packet_seq = 0;
        }
    }

    /// The peer's most recently received packet seq, or `None` if we've seen
    /// nothing from the peer yet.
    fn last_seen_remote(&self) -> Option<u64> {
        self.received_packets.most_recent.map(u64::from)
    }

    /// Number of payloads sent at least once that are not yet acked.
    ///
    /// This is the live in-flight backlog. The driver watches it as the
    /// real "sent − delivered" depth and as the signal that the unacked window
    /// is growing under sustained loss — at which point it force-advances the
    /// window via [`retire_payloads_through`](Self::retire_payloads_through)
    /// against a reliable side-channel. Whether and when to do that is a policy
    /// decision the driver owns, since dropping a payload outright would break
    /// lockstep.
    pub fn payloads_in_flight(&self) -> usize {
        self.unacked_payloads.len()
    }

    /// Seq that will be assigned to the next packet built.
    pub fn next_packet_seq(&self) -> u32 {
        self.packet_seq
    }

    /// The lowest still-unacked payload seq for `slot` — the oldest seq the
    /// datagram redundancy pass will replay over a rebound connection — or
    /// `None` if nothing is in flight for it.
    ///
    /// This is the **same-relay** resume anchor: the relay bases that slot's
    /// receive-window prefix here (see
    /// [`Link::anchor_receive_window`](crate::Link::anchor_receive_window)).
    /// Selective packet acks make the unacked window *sparse* — an acked seq
    /// can sit between two unacked ones — so the seqs above this anchor are
    /// NOT all replayable from here; the anchor's contiguity contract holds on
    /// a same-relay resume only because the relay reconciles the acked holes
    /// from its own session-lifetime receipt records (an acked seq is one it
    /// received and recorded), seeding them as already delivered in the fresh
    /// receive window. A replacement relay has no first-hand ack history to
    /// reconcile from, so a **re-home** must anchor with
    /// [`contiguous_replayable_anchor`](Self::contiguous_replayable_anchor)
    /// instead.
    pub fn oldest_replayable_seq(&self, slot: SlotId) -> Option<u64> {
        self.unacked_payloads
            .range((slot, u64::MIN)..=(slot, u64::MAX))
            .next()
            .map(|(&(_, seq), _)| seq)
    }

    /// The lowest anchor a **re-home** resume may advertise for `slot`: the
    /// retention `front` extended downward only through *contiguously* unacked
    /// seqs.
    ///
    /// A fresh relay's receive window treats the anchor as a promise that
    /// every seq above it will arrive and close the window's contiguous
    /// prefix. A re-home's replay sources are the unacked window (redundancy
    /// re-carries it) and the retained ring (`[front..]`, re-injected on
    /// resume) — and the unacked window is sparse: selective packet acks
    /// leave holes that are in *neither* source once they age below `front`.
    /// Anchoring below such a hole would base the window on a permanent void:
    /// the prefix could never pass it, and the live stream would eventually
    /// run a receive window's length beyond the base and be rejected. So the
    /// anchor descends from `front` exactly as far as unacked seqs remain
    /// contiguous, and no further. Unacked seqs below the first hole are
    /// still replayed (redundancy doesn't consult the anchor); the fresh
    /// relay discards them as below-base, which is the accepted trade: a
    /// hole above them can only have aged out of retention if turn production
    /// continued past it, which means the session was not wedged on anything
    /// beneath it — the old relay had received and fanned those turns, and
    /// the discarded replay was a duplicate.
    pub fn contiguous_replayable_anchor(&self, slot: SlotId, front: u64) -> u64 {
        let mut anchor = front;
        for (&(_, seq), _) in self
            .unacked_payloads
            .range((slot, u64::MIN)..(slot, front))
            .rev()
        {
            if seq + 1 == anchor {
                anchor = seq;
            } else {
                break;
            }
        }
        anchor
    }

    /// Builds the `ack_bits` field: bit `N` is set when the peer's packet
    /// `(most_recent - N - 1)` has been received.
    fn ack_bits(&self) -> u32 {
        self.received_packets.ack_bits
    }

    /// Peer packets that never arrived, cumulative for this connection. See
    /// `ReceivedPacketHistory::lost` for what it counts and why nothing that
    /// makes decisions may read it.
    pub fn upstream_lost_packets(&self) -> u64 {
        self.received_packets.lost
    }

    /// Returns the complete repeated-field wire cost of the unacked window,
    /// refreshing it after a bulk cursor retirement invalidated the cache.
    fn unacked_payload_wire_len(&mut self) -> usize {
        if let Some(total) = self.unacked_payload_wire_len {
            return total;
        }
        let total = self
            .unacked_payloads
            .values()
            .fold(0usize, |total, sent| total.saturating_add(sent.wire_len));
        self.unacked_payload_wire_len = Some(total);
        total
    }
}

impl Default for AckManager {
    fn default() -> Self {
        Self::new()
    }
}
