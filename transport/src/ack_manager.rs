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

/// How many of the peer's most recent packets to remember. The ack bitfield is
/// 32 bits wide, plus the most-recent `ack` itself, so remembering more than 33
/// adds nothing to what we can acknowledge.
const RECEIVED_PACKETS_SIZE: usize = 32 + 1;

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
    /// The peer's recently-received packets, keyed by their packet seq. Drives
    /// the `ack` / `ack_bits` we send back.
    received_packets: SequenceBuffer<ReceivedPacket>,
}

impl AckManager {
    pub fn new() -> Self {
        Self {
            packet_seq: 0,
            sent_packets: SequenceBuffer::with_capacity(SENT_PACKETS_SIZE),
            unacked_payloads: BTreeMap::new(),
            received_packets: SequenceBuffer::with_capacity(RECEIVED_PACKETS_SIZE),
        }
    }

    /// The peer's most recently received packet seq, or `None` if we've seen
    /// nothing from the peer yet.
    fn last_seen_remote(&self) -> Option<u64> {
        match self.received_packets.sequence() {
            0 => None,
            next => Some(next - 1),
        }
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

    /// Builds the `ack_bits` field: bit `N` is set when the peer's packet
    /// `(most_recent - N - 1)` has been received.
    fn ack_bits(&self) -> u32 {
        let Some(most_recent) = self.last_seen_remote() else {
            return 0;
        };

        let mut bits: u32 = 0;
        let mut mask: u32 = 1;
        for i in 1u64..=32 {
            if most_recent < i {
                // Not enough history yet to fill the rest of the bitfield.
                break;
            }
            if self.received_packets.exists(most_recent - i) {
                bits |= mask;
            }
            mask <<= 1;
        }
        bits
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
    /// If `payload` is `None`, the result is an ack-only packet with no payloads.
    ///
    /// `max_packet_len` is the live datagram budget (e.g. quinn's
    /// `max_datagram_size()`); pass the current value each call so the bundle
    /// tracks path MTU changes. Built packets are assumed to be sent: skipping a
    /// send can delay payload delivery.
    pub fn build_outgoing(&mut self, payload: Option<Payload>, max_packet_len: usize) -> Packet {
        let mut packet = Packet {
            seq: self.packet_seq,
            ack: self.last_seen_remote().map(|s| s as u32),
            ack_bits: self.ack_bits(),
            payloads: Vec::new(),
        };
        // Fail loudly rather than wrap: a wrapped packet seq would silently break
        // acking. A per-game connection can't reach this at the turn rate (see the
        // field docs), so a connection that did is broken and must be reset.
        self.packet_seq = self
            .packet_seq
            .checked_add(1)
            .expect("packet seq space exhausted for this connection");

        // Running size of the encoded packet, kept in step with `packet.payloads`
        // so we never overrun the datagram budget.
        let mut used = packet.encoded_len();

        // The fresh payload is included verbatim. Its `(slot, seq)` origin identity
        // is already assigned upstream and is never rewritten here.
        let fresh = payload.map(|p| {
            let len = p.encoded_len();
            (p, len)
        });
        if let Some((p, len)) = &fresh {
            used += payload_element_len(*len);
            packet.payloads.push(p.clone());
        }

        // Refill with still-unacked payloads, oldest-seq-first within each slot.
        // The key is `(slot, seq)`, so a BTreeMap iteration visits each slot's
        // payloads in ascending seq order — the turns whose loss would stall a peer
        // soonest within that slot. The fresh payload isn't in
        // `unacked_payloads` yet, so it can't double up. When a near-MTU stream
        // keeps the budget full for a long run this under-covers the newer
        // unacked turns; spreading coverage by `send_count` (re-sending the
        // least-sent ones) is a future refinement, which is why it is tracked.
        for sent in self.unacked_payloads.values_mut() {
            let element = payload_element_len(sent.encoded_len);
            if used + element > max_packet_len {
                continue;
            }
            sent.send_count += 1;
            used += element;
            packet.payloads.push(sent.payload.clone());
        }

        // Record the fresh payload as unacked only after the redundancy pass.
        if let Some((p, len)) = fresh {
            self.unacked_payloads.insert(
                (SlotId(p.slot as u8), p.seq),
                SentPayload {
                    send_count: 1,
                    encoded_len: len,
                    payload: p,
                },
            );
        }

        self.sent_packets.insert(
            u64::from(packet.seq),
            SentPacket {
                payload_slots_seqs: packet
                    .payloads
                    .iter()
                    .map(|p| (SlotId(p.slot as u8), p.seq))
                    .collect(),
            },
        );

        packet
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

        self.received_packets
            .insert(u64::from(incoming.seq), ReceivedPacket);

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
        let before = self.unacked_payloads.len();
        self.unacked_payloads
            .retain(|&(s, seq), _| s != slot || seq > through_seq);
        before - self.unacked_payloads.len()
    }

    /// Marks one of our sent packets as acked, retiring every payload it carried.
    fn retire_packet(&mut self, packet_seq: u64) {
        if let Some(packet) = self.sent_packets.remove(packet_seq) {
            for (slot, seq) in packet.payload_slots_seqs.iter() {
                self.unacked_payloads.remove(&(*slot, *seq));
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
    /// Cached encoded size, so refilling a packet doesn't re-encode it.
    encoded_len: usize,
    payload: Payload,
}

/// Marker for a packet received from the peer; presence in the buffer is all the
/// ack machinery needs.
#[derive(Clone, Default)]
struct ReceivedPacket;

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
            game_frame_count: None,
            commands: vec![0u8; 4].into(),
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

    #[test]
    fn packet_seq_numbers_increment_and_payload_seq_is_preserved() {
        let mut manager = AckManager::new();
        for i in 0..10u64 {
            let packet = manager.build_outgoing(Some(test_payload(0, i)), MTU);
            assert_eq!(packet.seq, i as u32);
            // The fresh payload is always pushed first, its seq preserved.
            assert_eq!(packet.payloads[0].seq, i);
        }
    }

    #[test]
    fn ack_only_packet_has_no_payloads() {
        let mut manager = AckManager::new();
        let packet = manager.build_outgoing(None, MTU);

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
            manager.build_outgoing(Some(test_payload(0, i)), 0);
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

        let packet = manager.build_outgoing(Some(test_payload(0, 10)), 0);
        // We've received peer packets 0..=6, all present.
        assert_eq!(packet.ack, Some(6));
        assert_eq!(packet.ack_bits, 0b0011_1111);

        // Peer packet 7 was dropped; 8 arrives acking up to our packet 10.
        manager
            .handle_incoming(&incoming(8, Some(10), &[0, 1, 2, 3, 4, 7, 8, 9]))
            .unwrap();
        assert_eq!(manager.payloads_in_flight(), 2);

        let packet = manager.build_outgoing(Some(test_payload(0, 11)), 0);
        assert_eq!(packet.ack, Some(8));
        // Bit 0 (peer packet 7) is clear; the rest of the window is set.
        assert_eq!(packet.ack_bits, 0b1111_1110);
    }

    #[test]
    fn rejects_ack_for_unsent_packet() {
        let mut manager = AckManager::new();
        manager.build_outgoing(Some(test_payload(0, 0)), MTU); // only packet 0 sent

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
        manager.build_outgoing(Some(test_payload(0, 0)), MTU);

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
        // Slot 0: seqs 0..=4, slot 1: seqs 0..=4 — independent seq spaces.
        for i in 0..5u64 {
            manager.build_outgoing(Some(test_payload(0, i)), 0);
            manager.build_outgoing(Some(test_payload(1, i)), 0);
        }
        assert_eq!(manager.payloads_in_flight(), 10);

        // A side-channel confirms delivery of slot 0 through payload seq 2.
        // Only slot 0's seqs 0,1,2 retire; slot 1 is untouched.
        let retired = manager.retire_payloads_through(SlotId(0), 2);
        assert_eq!(retired, 3);
        assert_eq!(manager.payloads_in_flight(), 7); // slot 1's 5 + slot 0's 2

        // Idempotent: re-confirming an already-passed cursor retires nothing.
        assert_eq!(manager.retire_payloads_through(SlotId(0), 2), 0);
        assert_eq!(manager.payloads_in_flight(), 7);

        // Retiring slot 1 through 4 drops all of slot 1; slot 0's survivors stay.
        let retired = manager.retire_payloads_through(SlotId(1), 4);
        assert_eq!(retired, 5);
        assert_eq!(manager.payloads_in_flight(), 2); // slot 0's seqs 3, 4

        // A subsequent packet only repacks the payloads still in flight.
        let packet = manager.build_outgoing(None, MTU);
        let keys: Vec<(u8, u64)> = packet
            .payloads
            .iter()
            .map(|p| (p.slot as u8, p.seq))
            .collect();
        assert_eq!(keys, vec![(0, 3), (0, 4)]);
    }

    #[test]
    fn redundancy_repacks_unacked_payloads_within_a_slot() {
        // With a real budget, each new packet should re-carry the earlier
        // unacked payloads alongside the fresh one.
        let mut manager = AckManager::new();
        manager.build_outgoing(Some(test_payload(0, 0)), MTU);
        manager.build_outgoing(Some(test_payload(0, 1)), MTU);
        let third = manager.build_outgoing(Some(test_payload(0, 2)), MTU);

        // Fresh payload (seq 2) plus the two still-unacked ones (seq 0, 1).
        let seqs: Vec<u64> = third.payloads.iter().map(|p| p.seq).collect();
        assert_eq!(seqs, vec![2, 0, 1]);
    }

    #[test]
    fn redundancy_refills_across_slots_oldest_per_slot_first() {
        // Two slots each with unacked payloads. Refill visits slot 0's oldest
        // then slot 1's oldest (BTreeMap order on (slot, seq)), not a single
        // global seq order — the correct semantics when each slot has its own
        // seq space.
        let mut manager = AckManager::new();
        manager.build_outgoing(Some(test_payload(0, 100)), 0); // slot 0, high seq
        manager.build_outgoing(Some(test_payload(1, 5)), 0); // slot 1, low seq

        // A packet with room for both unacked payloads.
        let packet = manager.build_outgoing(None, MTU);
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
    fn redundancy_respects_size_budget() {
        let mut manager = AckManager::new();
        manager.build_outgoing(Some(test_payload(0, 0)), MTU);

        // A budget that fits only the fresh payload leaves no room to repack the
        // earlier one.
        let only_fresh = manager.build_outgoing(Some(test_payload(0, 1)), 0);
        assert_eq!(only_fresh.payloads.len(), 1);
        assert_eq!(only_fresh.payloads[0].seq, 1);
    }

    #[test]
    fn symmetric_500_sends_without_loss() {
        let mut local = AckManager::new();
        let mut remote = AckManager::new();

        for i in 0..500u64 {
            let outgoing = local.build_outgoing(Some(test_payload(0, i)), MTU);
            let incoming = remote.build_outgoing(Some(test_payload(0, i)), MTU);
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
            let outgoing = local.build_outgoing(Some(test_payload(0, i)), MTU);
            let incoming = remote.build_outgoing(Some(test_payload(0, i)), MTU);

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
        let packet = local.build_outgoing(Some(test_payload(0, 100)), MTU);
        assert_eq!(packet.ack, Some(99));
        assert_eq!(packet.ack_bits, 0xFFFF_FFFF);

        // local -> remote dropped every 4th packet; reading right-to-left from
        // peer packet 98 down to 66, every 4th bit is clear.
        let packet = remote.build_outgoing(Some(test_payload(0, 100)), MTU);
        assert_eq!(packet.ack, Some(99));
        assert_eq!(packet.ack_bits, 0b1011_1011_1011_1011_1011_1011_1011_1011);
    }
}
