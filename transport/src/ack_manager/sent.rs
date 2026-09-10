//! The send side's units and the sizing rules around them: what one sent
//! packet carried, one payload still awaiting an ack, and the wire arithmetic
//! that decides whether a payload may ride a datagram at all.
//!
//! The two error types the manager surfaces sit here too, next to the size and
//! seq limits that produce them.

use prost::Message;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{Packet, Payload};

use super::policy::CarrySpacing;

/// What one of our sent packets carried, so an ack can retire its payloads.
#[derive(Default, Clone)]
pub(super) struct SentPacket {
    /// The `(slot, seq)` of each payload this packet carried — the origin
    /// identity, which a later ack retires in full.
    pub(super) payload_slots_seqs: Box<[(SlotId, u64)]>,
}

/// A payload we've sent and are still re-sending until it's acked.
pub(super) struct SentPayload {
    /// How many packets this payload has been recorded as riding on the
    /// current connection. Feeds the [`CarrySpacing`] schedule; reset (with
    /// the carry stamp) when the connection it counted carries on dies.
    pub(super) send_count: u32,
    /// The packet seq that last carried this payload on the current connection,
    /// or `None` if it has not been carried on it yet — the [`CarrySpacing`]
    /// schedule's clock.
    pub(super) last_carried_packet_seq: Option<u32>,
    /// The packet seq current when this payload entered the window on this
    /// connection — the ranking clock until a carry is recorded. Anchoring a
    /// never-carried payload's waiting age here (instead of granting it
    /// absolute priority) keeps the ranking key monotone for *everyone*: a
    /// recurring stream of never-carried arrivals (repeated refused builds)
    /// each starts at age zero and cannot indefinitely outrank an older
    /// payload whose age keeps growing.
    pub(super) registered_at_packet_seq: u32,
    /// Cached size of its complete repeated-field wire element, so refilling a
    /// packet and maintaining the aggregate do not recalculate its varint.
    pub(super) wire_len: usize,
    pub(super) payload: Payload,
}

impl SentPayload {
    /// Whether the spacing schedule permits carrying this payload in the packet
    /// currently being built (`building_seq`). No schedule, or no carry yet on
    /// this connection, means always due.
    pub(super) fn is_due(&self, spacing: Option<CarrySpacing>, building_seq: u32) -> bool {
        let Some(spacing) = spacing else {
            return true;
        };
        match self.last_carried_packet_seq {
            None => true,
            Some(last) => {
                building_seq.saturating_sub(last) >= spacing.required_gap(self.send_count)
            }
        }
    }

    /// Packets this payload has waited since its last recorded carry — or
    /// since it entered the window, if nothing has carried it yet. The
    /// constrained refill's ranking key: it grows every packet a candidate is
    /// passed over, for carried and never-carried payloads alike.
    pub(super) fn waiting_age(&self, building_seq: u32) -> u32 {
        building_seq.saturating_sub(
            self.last_carried_packet_seq
                .unwrap_or(self.registered_at_packet_seq),
        )
    }
}

/// On-wire size of one element of the repeated `payloads` field: the field tag,
/// the length-delimiter varint, and the encoded payload body.
pub(super) fn payload_element_len(payload_len: usize) -> usize {
    1 + prost::encoding::encoded_len_varint(payload_len as u64) + payload_len
}

/// The datagram budget every QUIC connection is guaranteed to offer at every
/// moment of its life — the admission ceiling for datagram-carried payloads.
///
/// Admission must be judged against a floor, never the *live*
/// `max_datagram_size()`: noq's path-MTU discovery raises the live budget,
/// and its black-hole detector lowers it back to the configured minimum after
/// suspicious loss — precisely the weather the redundancy layer exists for. A
/// payload admitted against a discovered budget can therefore out-size every
/// packet the connection will ever send again, at which point the refill's
/// head-of-line gate blocks redundancy on every build — maintenance flushes
/// included — and the payload strands silently while its seq wedges the
/// peer's delivered prefix.
///
/// The floor is static by construction: noq clamps `min_mtu` to at least
/// 1200 bytes (the QUIC-guaranteed datagram size; its setter refuses lower),
/// and 1200 minus the worst-case short-header overhead (first byte, a 20-byte
/// connection id, 4-byte packet number, 16-byte AEAD tag, ~3-byte datagram
/// frame header) leaves at least ~1156. 1024 sits comfortably under that, so
/// a payload admitted against it fits a fresh-free, sidecar-free packet alone
/// at any legal MTU — the invariant the head-of-line liveness argument rests
/// on. This is the **outer datagram** floor: each link type derives its own
/// admission number from it — the client edge caps it by the peer's
/// advertised datagram limit (a handshake constant that may legally be
/// smaller), and the mesh additionally reserves the wrapper costs riding
/// *every* packet of a session (the `MeshPacket` overhead and the session's
/// tenant framing). Larger payloads divert to the reliable control streams,
/// which carry any size.
pub const GUARANTEED_DATAGRAM_BUDGET: usize = 1024;

/// The encoded size of a packet carrying `payload` alone, assuming worst-case
/// header state (maximal seq/ack varints, full ack bitfield). If this exceeds
/// [`GUARANTEED_DATAGRAM_BUDGET`], some packet in the connection's lifetime
/// may be unable to carry the payload — the caller's signal to refuse it up
/// front (or divert it to a reliable stream) rather than register it as
/// unacked, where redundancy could try and fail to re-carry it forever while
/// its seq holds a permanent gap in the peer's delivered prefix.
pub(crate) fn lone_packet_len(payload: &Payload) -> usize {
    let header = Packet {
        seq: u32::MAX,
        ack: Some(u32::MAX),
        ack_bits: u32::MAX,
        payloads: Vec::new(),
    };
    header.encoded_len() + payload_element_len(payload.encoded_len())
}

/// Whether `payload` can ride the datagram path at all: its worst-case lone
/// packet (`lone_packet_len`) fits [`GUARANTEED_DATAGRAM_BUDGET`]. This is
/// the static, connection-free half of `Link::payload_fits` — and since every
/// establishment path refuses a peer whose advertised datagram limit
/// undercuts the floor, the two agree on every connection a session can
/// actually hold. For callers with no live connection at hand: a reconnect
/// deciding, from its retained turns alone, which ones the resume will
/// re-send over the reliable control stream rather than the datagram window.
pub fn fits_guaranteed_datagram(payload: &Payload) -> bool {
    lone_packet_len(payload) <= GUARANTEED_DATAGRAM_BUDGET
}

/// The per-connection packet sequence space is exhausted: every `u32` packet
/// seq has been assigned, so [`AckManager::build_outgoing`] can mint no more.
///
/// A per-game QUIC connection resets its seq space and can't approach this at
/// the turn rate — reaching it would take years of uninterrupted play — so it
/// means the connection is broken. It is terminal: wrapping the seq would
/// silently corrupt acking, so the connection must be torn down and, if the
/// session continues, resumed on a fresh connection with a new seq space via
/// [`AckManager::reset_connection`], rather than kept alive.
///
/// [`AckManager::build_outgoing`]: super::AckManager::build_outgoing
/// [`AckManager::reset_connection`]: super::AckManager::reset_connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("packet seq space exhausted for this connection")]
pub struct PacketSeqExhausted;

/// An incoming packet was internally inconsistent and could not be processed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AckError {
    /// The peer acked a packet seq we have not sent.
    #[error("peer acked packet {ack} but only {sent} packets have been sent")]
    AckAheadOfSent { ack: u32, sent: u32 },
    /// The peer set `ack_bits` without an `ack`, so the bits reference nothing.
    #[error("peer sent ack_bits with no ack")]
    AckBitsWithoutAck,
    /// The peer set `ack_bits` referencing packets before seq 0 (a bit at index
    /// `>= ack`).
    #[error("peer sent ack_bits {ack_bits:#x} referencing packets before ack {ack}")]
    AckBitsOutOfRange { ack: u32, ack_bits: u32 },
}
