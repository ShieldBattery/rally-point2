//! Per-link send/ack bookkeeping: the redundancy + acknowledgement layer that
//! makes recovery *ours* rather than QUIC's.
//!
//! A link's payloads ride unreliable QUIC datagrams, each one carried in a
//! [`Packet`]. Every packet carries a fresh payload plus copies of still-unacked
//! older payloads, up to the datagram's size budget, so a single dropped packet
//! rarely loses a payload outright — the next packet re-carries it. Each packet
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

use std::collections::BTreeMap;

use prost::Message;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{Packet, Payload};

use crate::sequence_buffer::SequenceBuffer;

/// How many of our own recently-sent packets to remember so we can map an
/// incoming ack back to the payloads that packet carried. Chosen large enough
/// that any packet old enough to fall out of the buffer can safely be treated as
/// lost (its payloads are still re-sent until separately acked).
const SENT_PACKETS_SIZE: usize = 256;

/// The peer packet history represented directly in the wire format's shape.
///
/// `most_recent` is the packet named by `Packet::ack`; bit `N` of `ack_bits`
/// records `most_recent - (N + 1)`. Receiving a newer packet shifts the window
/// forward, while a late packet sets its one bit if it is still insertable by
/// the prior 33-entry [`SequenceBuffer`] semantics. Keeping this rolling form
/// makes reading the outgoing ack state constant-time instead of probing a ring
/// 32 times for every packet built.
#[derive(Default)]
struct ReceivedPacketHistory {
    most_recent: Option<u32>,
    ack_bits: u32,
}

impl ReceivedPacketHistory {
    fn record(&mut self, seq: u32) {
        let Some(most_recent) = self.most_recent else {
            self.most_recent = Some(seq);
            return;
        };

        match seq.cmp(&most_recent) {
            std::cmp::Ordering::Greater => {
                let advanced = seq - most_recent;
                self.ack_bits = if advanced <= 32 {
                    self.ack_bits.checked_shl(advanced).unwrap_or(0) | (1u32 << (advanced - 1))
                } else {
                    0
                };
                self.most_recent = Some(seq);
            }
            std::cmp::Ordering::Less => {
                let behind = most_recent - seq;
                // The old 33-entry SequenceBuffer's next-free cursor is one
                // beyond `most_recent`, so a packet exactly 32 behind is already
                // one full capacity behind that cursor and is not inserted.
                if behind < 32 {
                    self.ack_bits |= 1u32 << (behind - 1);
                }
            }
            std::cmp::Ordering::Equal => {}
        }
    }
}

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
}

impl AckManager {
    pub fn new() -> Self {
        Self {
            packet_seq: 0,
            sent_packets: SequenceBuffer::with_capacity(SENT_PACKETS_SIZE),
            unacked_payloads: BTreeMap::new(),
            unacked_payload_wire_len: Some(0),
            received_packets: ReceivedPacketHistory::default(),
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
        // connection.
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

    /// The lowest still-unacked payload seq for `slot`, or `None` if the slot has
    /// nothing in flight.
    ///
    /// This is the oldest seq the redundancy pass will re-carry over a rebound
    /// connection (it repacks the unacked window oldest-seq-first within each slot),
    /// so it is exactly the lowest seq a peer will receive from this slot after a
    /// same-relay resume. A fresh relay uses it to anchor that slot's receive window
    /// there instead of at 0, so a session resumed past the window is accepted and
    /// its delivered prefix advances from the resume point (see
    /// [`Link::anchor_receive_window`](crate::Link::anchor_receive_window)).
    pub fn oldest_unacked_seq(&self, slot: SlotId) -> Option<u64> {
        self.unacked_payloads
            .range((slot, u64::MIN)..=(slot, u64::MAX))
            .next()
            .map(|(&(_, seq), _)| seq)
    }

    /// Builds the `ack_bits` field: bit `N` is set when the peer's packet
    /// `(most_recent - N - 1)` has been received.
    fn ack_bits(&self) -> u32 {
        self.received_packets.ack_bits
    }

    /// Builds the next outgoing [`Packet`].
    ///
    /// The packet is stamped with the next packet seq and the current ack state.
    /// If `payload` is `Some`, it is included verbatim — its `(slot, seq)` is its
    /// origin identity, already assigned by the sending client and preserved
    /// untouched here — always included (even if it alone exceeds `max_packet_len`
    /// — the current turn is never dropped), and tracked for re-sending until
    /// acked. The remaining space up to `max_packet_len` is then filled with
    /// still-unacked payloads, oldest-seq-first within each slot, for redundancy.
    /// If `payload` is `None`, there is no fresh payload, but still-unacked
    /// payloads are packed as redundancy when they fit. The result is truly
    /// ack-only only when the unacked window is empty (or none of it fits).
    ///
    /// `max_packet_len` is the live datagram budget (e.g. quinn's
    /// `max_datagram_size()`); pass the current value each call so the bundle
    /// tracks path MTU changes. Built packets are assumed to be sent: skipping a
    /// send can delay payload delivery.
    ///
    /// Returns [`PacketSeqExhausted`] if the connection's `u32` packet seq space
    /// is used up. This is unreachable within a game at the turn rate (see the
    /// `packet_seq` field docs); it is surfaced rather than
    /// wrapped (which would silently break acking) so the caller can tear the
    /// connection down and reset rather than the process aborting on a panic. No
    /// state is mutated when it is returned, so a caller that resets can retry.
    pub fn build_outgoing(
        &mut self,
        payload: Option<Payload>,
        max_packet_len: usize,
    ) -> Result<Packet, PacketSeqExhausted> {
        // Reserve the next packet seq before mutating anything else: a wrapped
        // packet seq would silently break acking, so exhaustion is terminal for
        // the connection and surfaced (not wrapped, not panicked) here, before any
        // state changes, so a caller that resets starts clean.
        let advanced = self.packet_seq.checked_add(1).ok_or(PacketSeqExhausted)?;

        let mut packet = Packet {
            seq: self.packet_seq,
            ack: self.last_seen_remote().map(|s| s as u32),
            ack_bits: self.ack_bits(),
            payloads: Vec::new(),
        };
        self.packet_seq = advanced;

        // Running size of the encoded packet, kept in step with `packet.payloads`
        // so we never overrun the datagram budget.
        let mut used = packet.encoded_len();

        // The `(slot, seq)` of every payload placed in this packet, in push order,
        // so the sent-packets record keys on the same `SlotId` each payload was
        // tracked under instead of narrowing the wire slot a second time.
        let mut payload_keys: Vec<(SlotId, u64)> = Vec::new();

        // The fresh payload is included verbatim. Its `(slot, seq)` origin identity
        // is already assigned upstream and is never rewritten here. Its wire slot
        // must fit a `SlotId` to be tracked without aliasing onto a different
        // slot's bookkeeping: a truncating narrowing would map slot `256 + n` onto
        // slot `n`'s window while the wire payload kept its original value. The send
        // layer refuses an out-of-range slot before building a packet for it, so a
        // payload reaching here with one is malformed and is dropped from both the
        // wire and the bookkeeping together — never tracked under an aliased key
        // while riding a datagram.
        let fresh = payload.and_then(|p| match u8::try_from(p.slot) {
            Ok(raw) => {
                let len = p.encoded_len();
                Some((SlotId(raw), p, len))
            }
            Err(_) => {
                tracing::debug!(
                    slot = p.slot,
                    "dropping outbound payload whose slot is out of SlotId range"
                );
                None
            }
        });
        if let Some((slot, p, len)) = &fresh {
            used += payload_element_len(*len);
            packet.payloads.push(p.clone());
            payload_keys.push((*slot, p.seq));
        }

        // When the whole unacked window fits, ranking cannot affect coverage:
        // every candidate rides this packet. Check that case from the cached
        // encoded lengths and refill directly in the BTreeMap's stable
        // `(slot, seq)` order, avoiding both the temporary candidate allocation
        // and its sort on the common small-window path.
        let unacked_payload_wire_len = self.unacked_payload_wire_len();
        let all_candidates_fit = max_packet_len
            .checked_sub(used)
            .is_some_and(|remaining| unacked_payload_wire_len <= remaining);
        if all_candidates_fit {
            packet.payloads.reserve(self.unacked_payloads.len());
            payload_keys.reserve(self.unacked_payloads.len());
            for (key, sent) in &mut self.unacked_payloads {
                sent.send_count += 1;
                packet.payloads.push(sent.payload.clone());
                payload_keys.push(*key);
            }
        } else {
            // A constrained packet refills least-resent-first: it must not let
            // the same low `(slot, seq)` subset starve everything ranked after
            // it. Sorting by `send_count` spreads redundancy coverage fairly
            // across every slot. The stable sort keeps tied candidates in the
            // BTreeMap's underlying `(slot, seq)` order, oldest per slot first.
            // The fresh payload isn't in `unacked_payloads` yet, so it cannot
            // double up.
            let mut candidates: Vec<(&(SlotId, u64), &mut SentPayload)> =
                self.unacked_payloads.iter_mut().collect();
            candidates.sort_by_key(|(_, sent)| sent.send_count);
            for (key, sent) in candidates {
                let element = sent.wire_len;
                if used + element > max_packet_len {
                    continue;
                }
                sent.send_count += 1;
                used += element;
                packet.payloads.push(sent.payload.clone());
                payload_keys.push(*key);
            }
        }

        // Record the fresh payload as unacked only after the redundancy pass.
        if let Some((slot, p, len)) = fresh {
            self.insert_unacked(
                (slot, p.seq),
                SentPayload {
                    send_count: 1,
                    wire_len: payload_element_len(len),
                    payload: p,
                },
            );
        }

        self.sent_packets.insert(
            u64::from(packet.seq),
            SentPacket {
                payload_slots_seqs: payload_keys.into(),
            },
        );

        Ok(packet)
    }

    /// Processes a received [`Packet`]: records it for our own acking and retires
    /// any of our payloads that its acks cover.
    ///
    /// Returns [`AckError`] for an internally inconsistent packet: one acking a
    /// packet we never sent, carrying ack bits with no ack, or carrying ack bits
    /// that reference packets before the start of the stream. The caller decides
    /// what to do with that — a relay may disconnect the peer; a client may log
    /// and continue.
    pub fn handle_incoming(&mut self, incoming: &Packet) -> Result<(), AckError> {
        match incoming.ack {
            Some(ack) => {
                if ack >= self.packet_seq {
                    return Err(AckError::AckAheadOfSent {
                        ack,
                        sent: self.packet_seq,
                    });
                }
                // Bit `b` references packet `ack - (b + 1)`, so any bit at index
                // `b >= ack` references a packet before seq 0 — impossible.
                if ack < 32 && incoming.ack_bits >> ack != 0 {
                    return Err(AckError::AckBitsOutOfRange {
                        ack,
                        ack_bits: incoming.ack_bits,
                    });
                }
            }
            None => {
                if incoming.ack_bits != 0 {
                    return Err(AckError::AckBitsWithoutAck);
                }
            }
        }

        self.received_packets.record(incoming.seq);

        if let Some(ack) = incoming.ack {
            let ack = u64::from(ack);
            self.retire_packet(ack);

            let mut bits = incoming.ack_bits;
            for i in 1u64..=32 {
                if ack < i {
                    break;
                }
                if bits & 1 == 1 {
                    self.retire_packet(ack - i);
                }
                bits >>= 1;
            }
        }

        Ok(())
    }

    /// Force-retires every still-unacked payload in `slot` with seq `<= through_seq`,
    /// returning how many were dropped.
    ///
    /// Per-packet acks are selective; this is the cumulative counterpart. When a
    /// reliable side-channel confirms the peer has received one slot's command
    /// stream through a given payload seq — the force-advance the driver uses
    /// when the unacked window grows under sustained datagram loss — this
    /// advances that slot's window past it without waiting for the corresponding
    /// datagram acks. It retires only that slot's seqs: each slot has its own seq
    /// space, so a cursor for slot A must not touch slot B's window. Stale
    /// `sent_packets` entries that still reference a retired payload are harmless:
    /// a later ack for them simply finds nothing left to remove.
    pub fn retire_payloads_through(&mut self, slot: SlotId, through_seq: u64) -> usize {
        // BTreeMap has no range-drain operation. Repeatedly finding and removing
        // the range front looks targeted, but pays a tree search/rebalance for
        // every retired entry and measures no better than this single traversal.
        let before = self.unacked_payloads.len();
        self.unacked_payloads
            .retain(|&(candidate_slot, seq), _| candidate_slot != slot || seq > through_seq);
        let retired = before - self.unacked_payloads.len();
        if retired > 0 {
            // Computing the removed range's exact encoded size inside `retain`
            // measurably slows this cursor path. Invalidate instead; the next
            // packet build refreshes the total once, and reliable-cursor
            // retirement is only the fallback when ordinary packet acks missed.
            self.unacked_payload_wire_len = None;
        }
        retired
    }

    /// Re-registers a payload as still-unacked so the redundancy pass re-carries
    /// it, **without** sending a packet — the re-inject half of a coordinator-
    /// mediated re-home.
    ///
    /// After a client re-homes onto a replacement relay, that relay's turn ring is
    /// empty: turns the client sent that the *old* relay had already acked (and so
    /// were retired from this window) would otherwise never reach the new relay to
    /// be fanned out to peers. Re-injecting them here puts them back in the unacked
    /// set so the next packet's redundancy carries them over the new connection,
    /// where peers dedup by origin `(slot, seq)`. A payload already unacked (one in
    /// flight at the drop, kept by [`reset_connection`](Self::reset_connection)) is
    /// left untouched, so a re-inject never resets its `send_count` or double-tracks
    /// it.
    pub fn reinject_unacked(&mut self, payload: Payload) {
        // The wire slot must fit a `SlotId` to be tracked without aliasing onto a
        // different slot's window: a truncating narrowing would map slot `256 + n`
        // onto slot `n`. A turn a client produced always names its own in-range
        // slot, so one that does not is malformed and is dropped rather than
        // re-injected under an aliased key.
        let Ok(raw) = u8::try_from(payload.slot) else {
            tracing::debug!(
                slot = payload.slot,
                "dropping re-injected payload whose slot is out of SlotId range"
            );
            return;
        };
        let key = (SlotId(raw), payload.seq);
        if !self.unacked_payloads.contains_key(&key) {
            let encoded_len = payload.encoded_len();
            self.insert_unacked(
                key,
                SentPayload {
                    send_count: 0,
                    wire_len: payload_element_len(encoded_len),
                    payload,
                },
            );
        }
    }

    /// Inserts or replaces one unacked payload while keeping the aggregate wire
    /// size exact. Replacement is defensive; normal origin seqs are unique.
    fn insert_unacked(&mut self, key: (SlotId, u64), sent: SentPayload) {
        let new_len = sent.wire_len;
        if let Some(previous) = self.unacked_payloads.insert(key, sent)
            && let Some(total) = self.unacked_payload_wire_len.as_mut()
        {
            *total = total.saturating_sub(previous.wire_len);
        }
        if let Some(total) = self.unacked_payload_wire_len.as_mut() {
            *total = total.saturating_add(new_len);
        }
    }

    fn remove_unacked(&mut self, key: &(SlotId, u64)) -> Option<SentPayload> {
        let removed = self.unacked_payloads.remove(key)?;
        if let Some(total) = self.unacked_payload_wire_len.as_mut() {
            *total = total.saturating_sub(removed.wire_len);
        }
        Some(removed)
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

    /// Marks one of our sent packets as acked, retiring every payload it carried.
    fn retire_packet(&mut self, packet_seq: u64) {
        if let Some(packet) = self.sent_packets.remove(packet_seq) {
            for (slot, seq) in packet.payload_slots_seqs.iter() {
                self.remove_unacked(&(*slot, *seq));
            }
        }
    }
}

impl Default for AckManager {
    fn default() -> Self {
        Self::new()
    }
}

/// On-wire size of one element of the repeated `payloads` field: the field tag,
/// the length-delimiter varint, and the encoded payload body.
fn payload_element_len(payload_len: usize) -> usize {
    1 + prost::encoding::encoded_len_varint(payload_len as u64) + payload_len
}

/// The encoded size of a packet carrying `payload` alone, assuming worst-case
/// header state (maximal seq/ack varints, full ack bitfield). If this exceeds
/// the datagram budget, no packet on this link can ever carry the payload — the
/// caller's signal to refuse it up front (or divert it to a reliable stream)
/// rather than register it as unacked, where redundancy would try and fail to
/// re-carry it forever while its seq holds a permanent gap in the peer's
/// delivered prefix.
pub(crate) fn lone_packet_len(payload: &Payload) -> usize {
    let header = Packet {
        seq: u32::MAX,
        ack: Some(u32::MAX),
        ack_bits: u32::MAX,
        payloads: Vec::new(),
    };
    header.encoded_len() + payload_element_len(payload.encoded_len())
}

/// What one of our sent packets carried, so an ack can retire its payloads.
#[derive(Default, Clone)]
struct SentPacket {
    /// The `(slot, seq)` of each payload this packet carried — the origin
    /// identity, which a later ack retires in full.
    payload_slots_seqs: Box<[(SlotId, u64)]>,
}

/// A payload we've sent and are still re-sending until it's acked.
struct SentPayload {
    /// How many packets this payload has been included in (diagnostics).
    send_count: u32,
    /// Cached size of its complete repeated-field wire element, so refilling a
    /// packet and maintaining the aggregate do not recalculate its varint.
    wire_len: usize,
    payload: Payload,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A generous datagram budget that leaves room for redundancy with the small
    /// payloads used in these tests.
    const MTU: usize = 1200;

    /// A payload for `slot` with seq `seq`. Under the origin-identity model the
    /// seq is assigned upstream (by the sender's home relay) and preserved, so
    /// tests set it directly rather than expecting the manager to assign it.
    fn test_payload(slot: u8, seq: u64) -> Payload {
        Payload {
            seq,
            slot: u32::from(slot),
            commands: vec![0u8; 4].into(),
            ..Default::default()
        }
    }

    /// A packet as it would arrive from a peer: `acked` lists the peer-side
    /// packet seqs to flag in `ack_bits` (those within range of `ack`).
    fn incoming(seq: u32, ack: Option<u32>, acked: &[u32]) -> Packet {
        let mut ack_bits = 0u32;
        if let Some(ack) = ack {
            for &id in acked {
                if id >= ack || id < ack.saturating_sub(32) {
                    continue;
                }
                ack_bits |= 1 << (ack - id - 1);
            }
        }
        Packet {
            seq,
            ack,
            ack_bits,
            payloads: Vec::new(),
        }
    }

    fn assert_unacked_wire_len_is_exact(manager: &mut AckManager) {
        let actual = manager
            .unacked_payloads
            .values()
            .map(|sent| sent.wire_len)
            .sum::<usize>();
        assert_eq!(manager.unacked_payload_wire_len(), actual);
    }

    #[derive(Clone, Default)]
    struct ModelReceivedPacket;

    fn model_ack_state(history: &SequenceBuffer<ModelReceivedPacket>) -> (Option<u32>, u32) {
        let Some(most_recent) = history.sequence().checked_sub(1) else {
            return (None, 0);
        };
        let mut bits = 0u32;
        for behind in 1u64..=32 {
            if most_recent < behind {
                break;
            }
            if history.exists(most_recent - behind) {
                bits |= 1u32 << (behind - 1);
            }
        }
        (Some(most_recent as u32), bits)
    }

    fn rolling_ack_state(history: &ReceivedPacketHistory) -> (Option<u32>, u32) {
        (history.most_recent, history.ack_bits)
    }

    #[test]
    fn rolling_ack_history_matches_sequence_buffer_for_exhaustive_short_traces() {
        // Reset plus values chosen around the 32-bit history boundary and the
        // u32 sequence ceiling. Exhausting every trace through length five
        // covers in-order delivery, duplicates, arbitrary reordering, exact and
        // beyond-window late arrivals, large forward jumps, and reset at every
        // position.
        const ACTIONS: [Option<u32>; 10] = [
            None,
            Some(0),
            Some(1),
            Some(2),
            Some(31),
            Some(32),
            Some(33),
            Some(u32::MAX - 32),
            Some(u32::MAX - 1),
            Some(u32::MAX),
        ];

        for len in 0..=5u32 {
            for case in 0..ACTIONS.len().pow(len) {
                let mut rolling = ReceivedPacketHistory::default();
                let mut model = SequenceBuffer::with_capacity(33);
                let mut encoded = case;

                for step in 0..len {
                    let action = ACTIONS[encoded % ACTIONS.len()];
                    encoded /= ACTIONS.len();
                    match action {
                        Some(seq) => {
                            rolling.record(seq);
                            let _ = model.insert(u64::from(seq), ModelReceivedPacket);
                        }
                        None => {
                            rolling = ReceivedPacketHistory::default();
                            model = SequenceBuffer::with_capacity(33);
                        }
                    }

                    assert_eq!(
                        rolling_ack_state(&rolling),
                        model_ack_state(&model),
                        "history diverged for len={len}, case={case}, step={step}, action={action:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn rolling_ack_history_matches_sequence_buffer_for_deterministic_randomized_traces() {
        let mut rolling = ReceivedPacketHistory::default();
        let mut model = SequenceBuffer::with_capacity(33);
        let mut most_recent = None::<u32>;
        let mut random = 0xD1B5_4A32_D192_ED03u64;
        let boundaries = [
            0,
            1,
            31,
            32,
            33,
            u32::MAX - 33,
            u32::MAX - 32,
            u32::MAX - 1,
            u32::MAX,
        ];

        for step in 0..100_000u32 {
            // A fixed xorshift stream keeps the test deterministic while
            // exercising far more interleavings than the short exhaustive set.
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;

            if random.is_multiple_of(97) {
                rolling = ReceivedPacketHistory::default();
                model = SequenceBuffer::with_capacity(33);
                most_recent = None;
            } else {
                let current = most_recent.unwrap_or(0);
                let seq = match random % 7 {
                    0 => random as u32,
                    1 => current,
                    2 => current.saturating_sub((random as u32) % 40),
                    3 => current.saturating_add((random as u32) % 4_096),
                    4 => boundaries[(random as usize) % boundaries.len()],
                    5 => (random as u32) % 64,
                    _ => current.saturating_sub(32 + (random as u32) % 4_096),
                };
                rolling.record(seq);
                let _ = model.insert(u64::from(seq), ModelReceivedPacket);
                most_recent = Some(most_recent.map_or(seq, |recent| recent.max(seq)));
            }

            assert_eq!(
                rolling_ack_state(&rolling),
                model_ack_state(&model),
                "history diverged at deterministic randomized step {step}",
            );
        }
    }

    #[test]
    fn packet_seq_numbers_increment_and_payload_seq_is_preserved() {
        let mut manager = AckManager::new();
        for i in 0..10u64 {
            let packet = manager
                .build_outgoing(Some(test_payload(0, i)), MTU)
                .unwrap();
            assert_eq!(packet.seq, i as u32);
            // The fresh payload is always pushed first, its seq preserved.
            assert_eq!(packet.payloads[0].seq, i);
        }
    }

    #[test]
    fn build_outgoing_surfaces_packet_seq_exhaustion_instead_of_panicking() {
        let mut manager = AckManager::new();
        // Drive the seq counter to its ceiling directly; assigning 2^32 seqs to
        // reach it for real is infeasible in a test. The next build would have to
        // wrap u32::MAX, which is refused.
        manager.packet_seq = u32::MAX;
        assert_eq!(
            manager.build_outgoing(Some(test_payload(0, 0)), MTU),
            Err(PacketSeqExhausted),
        );
        // No state was mutated: the counter is untouched and nothing was tracked,
        // so a caller that resets the connection can retry cleanly.
        assert_eq!(manager.next_packet_seq(), u32::MAX);
        assert_eq!(manager.payloads_in_flight(), 0);
    }

    #[test]
    fn ack_only_packet_has_no_payloads() {
        let mut manager = AckManager::new();
        let packet = manager.build_outgoing(None, MTU).unwrap();

        assert!(packet.payloads.is_empty());
        assert_eq!(packet.ack, None);
        assert_eq!(packet.ack_bits, 0);
        // No payload was carried, but a packet seq was.
        assert_eq!(manager.next_packet_seq(), 1);
        assert_eq!(manager.payloads_in_flight(), 0);
    }

    #[test]
    fn ack_with_early_receives() {
        // Budget of 0 suppresses redundancy so each payload rides exactly one
        // packet — giving fine-grained control over what's acked.
        let mut manager = AckManager::new();
        for i in 0..10u64 {
            manager.build_outgoing(Some(test_payload(0, i)), 0).unwrap();
        }
        assert_eq!(manager.payloads_in_flight(), 10);

        // A packet with no ack retires nothing.
        manager.handle_incoming(&incoming(0, None, &[])).unwrap();
        assert_eq!(manager.payloads_in_flight(), 10);

        manager.handle_incoming(&incoming(1, Some(0), &[])).unwrap();
        assert_eq!(manager.payloads_in_flight(), 9);

        manager
            .handle_incoming(&incoming(2, Some(1), &[0]))
            .unwrap();
        manager
            .handle_incoming(&incoming(3, Some(1), &[0]))
            .unwrap();
        manager
            .handle_incoming(&incoming(4, Some(2), &[0, 1]))
            .unwrap();
        // Our packet 3 was dropped on the way to the peer.
        manager
            .handle_incoming(&incoming(5, Some(4), &[0, 1, 2]))
            .unwrap();
        // Peer packets 5 and 6 reach us out of order acking up to our packet 9.
        manager
            .handle_incoming(&incoming(6, Some(9), &[0, 1, 2, 4, 7, 8]))
            .unwrap();
        assert_eq!(manager.payloads_in_flight(), 3);

        let packet = manager
            .build_outgoing(Some(test_payload(0, 10)), 0)
            .unwrap();
        // We've received peer packets 0..=6, all present.
        assert_eq!(packet.ack, Some(6));
        assert_eq!(packet.ack_bits, 0b0011_1111);

        // Peer packet 7 was dropped; 8 arrives acking up to our packet 10.
        manager
            .handle_incoming(&incoming(8, Some(10), &[0, 1, 2, 3, 4, 7, 8, 9]))
            .unwrap();
        assert_eq!(manager.payloads_in_flight(), 2);

        let packet = manager
            .build_outgoing(Some(test_payload(0, 11)), 0)
            .unwrap();
        assert_eq!(packet.ack, Some(8));
        // Bit 0 (peer packet 7) is clear; the rest of the window is set.
        assert_eq!(packet.ack_bits, 0b1111_1110);
    }

    #[test]
    fn rejects_ack_for_unsent_packet() {
        let mut manager = AckManager::new();
        manager
            .build_outgoing(Some(test_payload(0, 0)), MTU)
            .unwrap(); // only packet 0 sent

        assert_eq!(
            manager.handle_incoming(&incoming(0, Some(1), &[])),
            Err(AckError::AckAheadOfSent { ack: 1, sent: 1 })
        );
    }

    #[test]
    fn rejects_ack_bits_without_ack() {
        let mut manager = AckManager::new();
        let mut packet = incoming(0, None, &[]);
        packet.ack_bits = 0b1;

        assert_eq!(
            manager.handle_incoming(&packet),
            Err(AckError::AckBitsWithoutAck)
        );
    }

    #[test]
    fn rejects_ack_bits_referencing_prehistory() {
        // Send one packet so ack 0 is itself valid (0 < 1 sent).
        let mut manager = AckManager::new();
        manager
            .build_outgoing(Some(test_payload(0, 0)), MTU)
            .unwrap();

        // ack 0 with bit 0 set claims to ack packet -1, which cannot exist.
        let packet = Packet {
            seq: 0,
            ack: Some(0),
            ack_bits: 0b1,
            payloads: Vec::new(),
        };

        assert_eq!(
            manager.handle_incoming(&packet),
            Err(AckError::AckBitsOutOfRange {
                ack: 0,
                ack_bits: 0b1
            })
        );
    }

    #[test]
    fn retire_payloads_through_advances_only_one_slots_window() {
        // No redundancy, so each payload rides exactly one packet and none is
        // retired by datagram acks during this test.
        let mut manager = AckManager::new();
        // Sparse seqs exercise cursors below, exactly at, and beyond the live
        // range. Both slots carry the same seqs but remain independent.
        for seq in [2u64, 4, 6, 8, 10] {
            manager
                .build_outgoing(Some(test_payload(0, seq)), 0)
                .unwrap();
            manager
                .build_outgoing(Some(test_payload(1, seq)), 0)
                .unwrap();
        }
        assert_eq!(manager.payloads_in_flight(), 10);

        // A cursor below the oldest live seq visits/removes nothing.
        assert_eq!(manager.retire_payloads_through(SlotId(0), 1), 0);
        assert_eq!(manager.payloads_in_flight(), 10);

        // A cursor exactly at the oldest entry removes just that one. Slot 1's
        // identical seq remains untouched.
        assert_eq!(manager.retire_payloads_through(SlotId(0), 2), 1);
        assert_eq!(manager.payloads_in_flight(), 9);
        assert!(manager.unacked_payloads.contains_key(&(SlotId(1), 2)));

        // Idempotent: re-confirming an already-passed cursor retires nothing.
        assert_eq!(manager.retire_payloads_through(SlotId(0), 2), 0);
        assert_eq!(manager.payloads_in_flight(), 9);

        // A later cursor removes multiple entries from only the requested slot.
        assert_eq!(manager.retire_payloads_through(SlotId(0), 8), 3);
        assert_eq!(manager.payloads_in_flight(), 6); // slot 1's 5 + slot 0's seq 10
        for seq in [2u64, 4, 6, 8, 10] {
            assert!(manager.unacked_payloads.contains_key(&(SlotId(1), seq)));
        }

        // A subsequent packet only repacks the payloads still in flight.
        let packet = manager.build_outgoing(None, MTU).unwrap();
        let keys: Vec<(u8, u64)> = packet
            .payloads
            .iter()
            .map(|p| (p.slot as u8, p.seq))
            .collect();
        assert_eq!(keys, vec![(0, 10), (1, 2), (1, 4), (1, 6), (1, 8), (1, 10)]);

        // The ceiling removes the final slot-0 entry without touching slot 1.
        assert_eq!(manager.retire_payloads_through(SlotId(0), u64::MAX), 1);
        assert_eq!(manager.payloads_in_flight(), 5);
    }

    #[test]
    fn cached_unacked_wire_len_tracks_every_window_mutation() {
        let mut manager = AckManager::new();
        assert_unacked_wire_len_is_exact(&mut manager);

        manager
            .build_outgoing(Some(test_payload(0, 0)), MTU)
            .unwrap();
        manager
            .build_outgoing(Some(test_payload(0, 1)), MTU)
            .unwrap();
        assert_unacked_wire_len_is_exact(&mut manager);

        manager.reinject_unacked(test_payload(1, 7));
        manager.reinject_unacked(test_payload(1, 7));
        assert_unacked_wire_len_is_exact(&mut manager);

        assert_eq!(manager.retire_payloads_through(SlotId(0), 0), 1);
        assert_unacked_wire_len_is_exact(&mut manager);

        // Packet 1 carried seq 1 fresh (and seq 0 as redundancy). Acking it
        // removes the surviving slot-0 payload but leaves the re-injected slot.
        manager.handle_incoming(&incoming(0, Some(1), &[])).unwrap();
        assert_unacked_wire_len_is_exact(&mut manager);
        assert_eq!(manager.payloads_in_flight(), 1);

        assert_eq!(manager.retire_payloads_through(SlotId(1), u64::MAX), 1);
        assert_unacked_wire_len_is_exact(&mut manager);
    }

    #[test]
    fn oldest_unacked_seq_is_the_lowest_in_flight_per_slot() {
        let mut manager = AckManager::new();
        // Nothing in flight yet.
        assert_eq!(manager.oldest_unacked_seq(SlotId(0)), None);

        // No redundancy, so each payload rides one packet and stays in flight.
        for seq in [7u64, 8, 9] {
            manager
                .build_outgoing(Some(test_payload(0, seq)), 0)
                .unwrap();
        }
        manager.build_outgoing(Some(test_payload(1, 3)), 0).unwrap();
        assert_eq!(manager.oldest_unacked_seq(SlotId(0)), Some(7));
        assert_eq!(manager.oldest_unacked_seq(SlotId(1)), Some(3));
        // A slot with nothing in flight is still None.
        assert_eq!(manager.oldest_unacked_seq(SlotId(2)), None);

        // Retiring the oldest advances the answer to the next in flight.
        manager.retire_payloads_through(SlotId(0), 7);
        assert_eq!(manager.oldest_unacked_seq(SlotId(0)), Some(8));
    }

    #[test]
    fn reinject_re_carries_an_already_retired_payload() {
        // The rehome re-inject: a payload that was acked (retired) is put back in
        // the unacked set so the next packet's redundancy re-carries it — the case
        // where the old relay acked a turn but never fanned it out before dying.
        let mut manager = AckManager::new();
        manager
            .build_outgoing(Some(test_payload(0, 0)), MTU)
            .unwrap();
        // Ack it: it retires from the window.
        manager.handle_incoming(&incoming(1, Some(0), &[])).unwrap();
        assert_eq!(manager.payloads_in_flight(), 0);

        // Re-inject it (as after a rehome rebind). It is unacked again and the next
        // packet re-carries it.
        manager.reinject_unacked(test_payload(0, 0));
        assert_eq!(manager.payloads_in_flight(), 1);
        let packet = manager.build_outgoing(None, MTU).unwrap();
        let seqs: Vec<(u8, u64)> = packet
            .payloads
            .iter()
            .map(|p| (p.slot as u8, p.seq))
            .collect();
        assert_eq!(seqs, vec![(0, 0)]);
    }

    #[test]
    fn reinject_does_not_double_track_a_still_unacked_payload() {
        // A payload still in flight (kept across a reset) must not be re-tracked by
        // a re-inject — the window stays at one, not two.
        let mut manager = AckManager::new();
        manager
            .build_outgoing(Some(test_payload(0, 0)), MTU)
            .unwrap();
        assert_eq!(manager.payloads_in_flight(), 1);
        manager.reinject_unacked(test_payload(0, 0));
        assert_eq!(manager.payloads_in_flight(), 1);
    }

    #[test]
    fn an_out_of_range_slot_does_not_alias_another_slots_bookkeeping() {
        // A wire slot past `u8` range narrows to a valid slot under a raw `as u8`
        // (256 becomes slot 0), so tracking it would silently poison that slot's
        // window while the forwarded wire payload kept its original slot. It must
        // instead be dropped from the bookkeeping entirely.
        let mut manager = AckManager::new();
        // A genuine slot-0 turn establishes slot 0's window at seq 5.
        manager
            .build_outgoing(Some(test_payload(0, 5)), MTU)
            .unwrap();
        assert_eq!(manager.oldest_unacked_seq(SlotId(0)), Some(5));

        // Slot 256 aliases onto slot 0 under a truncating cast; seq 3 would then
        // become slot 0's new oldest unacked seq.
        let aliasing = Payload {
            seq: 3,
            slot: 256,
            commands: vec![0u8; 4].into(),
            ..Default::default()
        };
        let packet = manager.build_outgoing(Some(aliasing), MTU).unwrap();

        // Slot 0's bookkeeping is untouched: its oldest unacked seq is still 5, and
        // only the one genuine turn is in flight.
        assert_eq!(manager.oldest_unacked_seq(SlotId(0)), Some(5));
        assert_eq!(manager.payloads_in_flight(), 1);
        // The malformed payload rode no datagram either, so the packet carries only
        // the genuine slot-0 turn as redundancy.
        assert!(
            packet.payloads.iter().all(|p| p.slot == 0 && p.seq == 5),
            "the out-of-range payload must not ride the wire: {:?}",
            packet
                .payloads
                .iter()
                .map(|p| (p.slot, p.seq))
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn redundancy_repacks_all_unacked_payloads_within_a_slot() {
        // With a generous budget, each new packet should re-carry every earlier
        // unacked payload alongside the fresh one. Their serialization order is
        // immaterial when every candidate fits; the fresh payload remains first.
        let mut manager = AckManager::new();
        manager
            .build_outgoing(Some(test_payload(0, 0)), MTU)
            .unwrap();
        manager
            .build_outgoing(Some(test_payload(0, 1)), MTU)
            .unwrap();
        let third = manager
            .build_outgoing(Some(test_payload(0, 2)), MTU)
            .unwrap();

        assert_eq!(third.payloads.first().map(|payload| payload.seq), Some(2));
        let mut redundant_seqs: Vec<u64> = third.payloads[1..]
            .iter()
            .map(|payload| payload.seq)
            .collect();
        redundant_seqs.sort_unstable();
        assert_eq!(redundant_seqs, vec![0, 1]);
    }

    #[test]
    fn redundancy_refills_across_slots_oldest_per_slot_first() {
        // Two slots each with one unacked payload, tied on send_count (both
        // sent exactly once, as their own fresh payload). A tie falls back to
        // the underlying BTreeMap order on (slot, seq) — slot 0 before slot
        // 1, not a single global seq order (each slot has its own seq space,
        // so seq alone would be meaningless across slots).
        let mut manager = AckManager::new();
        manager
            .build_outgoing(Some(test_payload(0, 100)), 0)
            .unwrap(); // slot 0, high seq
        manager.build_outgoing(Some(test_payload(1, 5)), 0).unwrap(); // slot 1, low seq

        // A packet with room for both unacked payloads.
        let packet = manager.build_outgoing(None, MTU).unwrap();
        let keys: Vec<(u8, u64)> = packet
            .payloads
            .iter()
            .map(|p| (p.slot as u8, p.seq))
            .collect();
        // Slot 0's seq 100 comes before slot 1's seq 5 because the key orders by
        // slot first — "oldest per slot", not "lowest seq globally".
        assert_eq!(keys, vec![(0, 100), (1, 5)]);
    }

    #[test]
    fn all_fit_refill_carries_every_candidate_and_increments_each_once() {
        let mut manager = AckManager::new();
        let candidates = [test_payload(0, 7), test_payload(1, 3), test_payload(2, 11)];
        for payload in &candidates {
            manager.reinject_unacked(payload.clone());
        }

        // Give the candidates deliberately different coverage histories. When
        // all fit, their ranking is immaterial: every one must be carried and
        // incremented exactly once without constructing the sorted candidate
        // list used by the constrained path.
        let counts = [5, 1, 3];
        for (payload, count) in candidates.iter().zip(counts) {
            manager
                .unacked_payloads
                .get_mut(&(SlotId(payload.slot as u8), payload.seq))
                .expect("candidate was re-injected")
                .send_count = count;
        }

        let fresh = test_payload(3, 19);
        let exact_budget = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: std::iter::once(fresh.clone())
                .chain(candidates.iter().cloned())
                .collect(),
        }
        .encoded_len();
        let packet = manager
            .build_outgoing(Some(fresh.clone()), exact_budget)
            .unwrap();

        assert_eq!(packet.encoded_len(), exact_budget);
        assert_eq!(packet.payloads.first(), Some(&fresh));
        let mut carried: Vec<(u8, u64)> = packet.payloads[1..]
            .iter()
            .map(|payload| (payload.slot as u8, payload.seq))
            .collect();
        carried.sort_unstable();
        assert_eq!(carried, vec![(0, 7), (1, 3), (2, 11)]);
        for (payload, old_count) in candidates.iter().zip(counts) {
            assert_eq!(
                manager
                    .unacked_payloads
                    .get(&(SlotId(payload.slot as u8), payload.seq))
                    .expect("candidate stayed in flight")
                    .send_count,
                old_count + 1,
            );
        }
        assert_eq!(
            manager
                .unacked_payloads
                .get(&(SlotId(3), fresh.seq))
                .expect("fresh payload entered the window")
                .send_count,
            1,
        );

        // The sent-packet record still contains every carried identity: one ack
        // retires the fresh payload and all fast-path redundancy candidates.
        manager.handle_incoming(&incoming(0, Some(0), &[])).unwrap();
        assert_eq!(manager.payloads_in_flight(), 0);
    }

    #[test]
    fn constrained_refill_keeps_least_sent_then_key_order() {
        let mut manager = AckManager::new();
        for slot in 0u8..4 {
            manager.reinject_unacked(test_payload(slot, 0));
        }
        // Slot 1 is least covered; slots 2 and 3 tie and therefore retain key
        // order; slot 0 is most covered and should be the one excluded.
        for (slot, count) in [2, 0, 1, 1].into_iter().enumerate() {
            manager
                .unacked_payloads
                .get_mut(&(SlotId(slot as u8), 0))
                .expect("candidate was re-injected")
                .send_count = count;
        }

        let header = Packet::default().encoded_len();
        let exact_budget = header
            + (1u8..=3)
                .map(|slot| payload_element_len(test_payload(slot, 0).encoded_len()))
                .sum::<usize>();
        let packet = manager.build_outgoing(None, exact_budget).unwrap();
        let keys: Vec<(u8, u64)> = packet
            .payloads
            .iter()
            .map(|payload| (payload.slot as u8, payload.seq))
            .collect();

        assert_eq!(packet.encoded_len(), exact_budget);
        assert_eq!(keys, vec![(1, 0), (2, 0), (3, 0)]);
        assert_eq!(manager.unacked_payloads[&(SlotId(0), 0)].send_count, 2);
        assert_eq!(manager.unacked_payloads[&(SlotId(1), 0)].send_count, 1);
        assert_eq!(manager.unacked_payloads[&(SlotId(2), 0)].send_count, 2);
        assert_eq!(manager.unacked_payloads[&(SlotId(3), 0)].send_count, 2);
    }

    /// A tight, permanently-full budget must not let low slot numbers
    /// monopolize redundancy coverage forever: over a long run where the
    /// budget only ever fits ONE redundant payload per packet, every slot's
    /// unacked payload should get roughly equal turns, not lose every single
    /// time to whichever slot happens to sort first. Regression coverage for
    /// the fairness fix — with the old `(slot, seq)` iteration order, slot
    /// 0's payload would win every refill and slots 1-3 would never be
    /// re-carried at all for as long as the budget stayed this tight.
    #[test]
    fn a_permanently_tight_budget_spreads_redundancy_coverage_across_slots() {
        let mut manager = AckManager::new();
        // Four slots, each with one unacked payload that is never touched
        // again as "fresh" -- from here on each is purely along for the
        // redundancy ride, competing for the same tight budget.
        for slot in 0u8..4 {
            manager
                .build_outgoing(Some(test_payload(slot, 0)), MTU)
                .unwrap();
        }
        assert_eq!(manager.payloads_in_flight(), 4);

        // A tight budget -- `lone_packet_len` sizes a packet for exactly one
        // payload under worst-case header state, so real (smaller) headers
        // can occasionally leave room for a second small element too. Either
        // way, which candidate(s) get chosen each round is the fairness
        // question: count how many times each slot's payload is picked
        // across many rounds.
        let tight_budget = lone_packet_len(&test_payload(0, 0));

        let mut picks_per_slot = [0u32; 4];
        for _ in 0..40 {
            let packet = manager.build_outgoing(None, tight_budget).unwrap();
            assert!(
                !packet.payloads.is_empty() && packet.payloads.len() <= 2,
                "expected a tight pick of one or two candidates, got {}",
                packet.payloads.len(),
            );
            for payload in &packet.payloads {
                picks_per_slot[payload.slot as usize] += 1;
            }
        }

        // Fair spreading: every slot's payload gets picked repeatedly across
        // the 40 rounds -- none is starved. With the old `(slot, seq)`
        // iteration order, slot 0 would win literally every round and slots
        // 1-3 would sit at 0 picks for as long as the budget stayed tight.
        for (slot, &picks) in picks_per_slot.iter().enumerate() {
            assert!(
                picks > 0,
                "slot {slot} was never picked across 40 rounds of a tight budget -- \
                 starved instead of getting a fair share of redundancy coverage",
            );
        }
    }

    #[test]
    fn redundancy_respects_size_budget() {
        let mut manager = AckManager::new();
        manager
            .build_outgoing(Some(test_payload(0, 0)), MTU)
            .unwrap();

        // A budget that fits only the fresh payload leaves no room to repack the
        // earlier one.
        let only_fresh = manager.build_outgoing(Some(test_payload(0, 1)), 0).unwrap();
        assert_eq!(only_fresh.payloads.len(), 1);
        assert_eq!(only_fresh.payloads[0].seq, 1);
    }

    #[test]
    fn symmetric_500_sends_without_loss() {
        let mut local = AckManager::new();
        let mut remote = AckManager::new();

        for i in 0..500u64 {
            let outgoing = local.build_outgoing(Some(test_payload(0, i)), MTU).unwrap();
            let incoming = remote
                .build_outgoing(Some(test_payload(0, i)), MTU)
                .unwrap();
            remote.handle_incoming(&outgoing).unwrap();
            local.handle_incoming(&incoming).unwrap();
        }

        // Only the final payload from each side is still in flight: nothing was
        // built after it was seen, so it was never acked.
        assert_eq!(local.payloads_in_flight(), 1);
        assert_eq!(remote.payloads_in_flight(), 1);
    }

    #[test]
    fn symmetric_100_sends_with_25pct_loss() {
        let mut local = AckManager::new();
        let mut remote = AckManager::new();

        let mut drop_count = 0;
        for i in 0..100u64 {
            let outgoing = local.build_outgoing(Some(test_payload(0, i)), MTU).unwrap();
            let incoming = remote
                .build_outgoing(Some(test_payload(0, i)), MTU)
                .unwrap();

            // Drop every 4th local -> remote packet.
            if i % 4 == 0 {
                drop_count += 1;
            } else {
                remote.handle_incoming(&outgoing).unwrap();
            }
            local.handle_incoming(&incoming).unwrap();
        }
        assert_eq!(drop_count, 25);

        // Redundancy still delivers every payload (bar the last, never acked).
        assert_eq!(local.payloads_in_flight(), 1);
        assert_eq!(remote.payloads_in_flight(), 1);

        // remote -> local had no loss, so local sees a full ack window.
        let packet = local
            .build_outgoing(Some(test_payload(0, 100)), MTU)
            .unwrap();
        assert_eq!(packet.ack, Some(99));
        assert_eq!(packet.ack_bits, 0xFFFF_FFFF);

        // local -> remote dropped every 4th packet; reading right-to-left from
        // peer packet 98 down to 66, every 4th bit is clear.
        let packet = remote
            .build_outgoing(Some(test_payload(0, 100)), MTU)
            .unwrap();
        assert_eq!(packet.ack, Some(99));
        assert_eq!(packet.ack_bits, 0b1011_1011_1011_1011_1011_1011_1011_1011);
    }
}
