//! The receive half of the manager: taking in a peer packet and retiring what
//! its acks cover, plus the cursor-driven force-retirement the driver falls
//! back on when datagram acks alone stop clearing the window.
//!
//! Grouped apart from the packing side because everything here shrinks the
//! unacked window, where the send side grows and re-carries it.

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Packet;

use super::AckManager;
use super::sent::{AckError, SentPayload};

impl AckManager {
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

    /// Marks one of our sent packets as acked, retiring every payload it carried.
    fn retire_packet(&mut self, packet_seq: u64) {
        if let Some(packet) = self.sent_packets.remove(packet_seq) {
            for (slot, seq) in packet.payload_slots_seqs.iter() {
                self.remove_unacked(&(*slot, *seq));
            }
        }
    }

    fn remove_unacked(&mut self, key: &(SlotId, u64)) -> Option<SentPayload> {
        let removed = self.unacked_payloads.remove(key)?;
        if let Some(total) = self.unacked_payload_wire_len.as_mut() {
            *total = total.saturating_sub(removed.wire_len);
        }
        Some(removed)
    }
}
