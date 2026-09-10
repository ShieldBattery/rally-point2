//! Shared fixtures for the ack-manager tests and the topic modules that use
//! them.
//!
//! The helpers here build the payloads and peer packets every topic needs, so
//! each topic file can stay about one behaviour: ack exchange, the unacked
//! window, redundancy refill, oversized payloads, or refused sends.

mod acks;
mod history;
mod redundancy;
mod refused_sends;
mod wide_payloads;
mod window;

use rally_point_proto::messages::{Packet, Payload};

use super::*;

/// A generous datagram budget that leaves room for redundancy with the small
/// payloads used in these tests.
const MTU: usize = 1200;

/// A payload for `slot` with seq `seq`. Under the origin-identity model the
/// seq is assigned upstream (by the sender's home relay) and preserved, so
/// tests set it directly rather than expecting the manager to assign it.
fn test_payload(slot: u8, seq: u64) -> Payload {
    test_payload_sized(slot, seq, 4)
}

/// Builds a packet and records it as sent — the success path every live
/// caller follows.
fn build_sent(manager: &mut AckManager, payload: Option<Payload>, budget: usize) -> Packet {
    let packet = manager.build_outgoing(payload, budget).unwrap();
    manager.record_sent(&packet);
    packet
}

fn test_payload_sized(slot: u8, seq: u64, command_bytes: usize) -> Payload {
    Payload {
        seq,
        slot: u32::from(slot),
        commands: vec![0u8; command_bytes].into(),
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
