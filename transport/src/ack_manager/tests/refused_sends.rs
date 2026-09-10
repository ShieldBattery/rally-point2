//! Builds the wire never accepted: a payload registered by a refused build
//! competes by its waiting age like any other, and the unsent packet itself
//! leaves no carry state and no ack anything can act on.

use prost::Message;

use crate::ack_manager::sent::payload_element_len;

use super::*;

/// A fresh payload registered by a refused build (never carried) competes
/// by its waiting age from registration, so under a constrained budget it
/// neither jumps the whole line nor displaces older carried payloads whose
/// waits are longer — everyone is served oldest-wait-first.
#[test]
fn a_refused_fresh_payload_competes_by_age_without_displacing_older_carries() {
    // Budget of one small element per packet keeps every refill
    // constrained, so the ranking (not capacity) decides who rides.
    let mut manager = AckManager::with_policy(RecarryPolicy {
        redundancy_byte_budget: Some(payload_element_len(test_payload(0, 0).encoded_len())),
        spacing: Some(CarrySpacing {
            dense_carries: 2,
            max_spacing: 8,
        }),
    });

    // Three payloads with recorded carries, oldest first.
    for seq in 0..3u64 {
        build_sent(&mut manager, Some(test_payload(0, seq)), MTU);
    }
    // A fresh build the wire refuses: registered, never carried, waiting
    // from its registration.
    let _refused = manager
        .build_outgoing(Some(test_payload(0, 3)), MTU)
        .unwrap();

    // Successful flushes serve everyone within one round, longest wait
    // first — which puts the refused payload (the youngest wait in the
    // window) last, not first: no absolute priority in either direction.
    let mut served: Vec<u64> = Vec::new();
    for _ in 0..4 {
        let flush = build_sent(&mut manager, None, MTU);
        served.extend(flush.payloads.first().map(|p| p.seq));
    }
    let mut sorted = served.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        vec![0, 1, 2, 3],
        "every payload must be served within one round (served: {served:?})",
    );
    assert_eq!(
        served.last(),
        Some(&3),
        "the refused payload has the youngest wait and joins in age order, \
         not at the head (served: {served:?})",
    );
}

/// The interleaved-refusal pattern: an old carried payload is lost, and
/// refused builds keep minting never-carried candidates between accepted
/// packets. Ranking never-carried payloads by registration age (rather
/// than absolute priority) keeps the old payload's growing wait dominant,
/// so the recurring refusals cannot starve it.
#[test]
fn recurring_refused_builds_cannot_starve_an_older_carried_payload() {
    let mut manager = AckManager::with_policy(RecarryPolicy {
        redundancy_byte_budget: Some(payload_element_len(test_payload(0, 0).encoded_len())),
        spacing: Some(CarrySpacing {
            dense_carries: 2,
            max_spacing: 8,
        }),
    });

    // Seq 0 rides once and is lost (never acked).
    build_sent(&mut manager, Some(test_payload(0, 0)), MTU);

    // Alternate refused builds (registered, never carried) with accepted
    // packets whose one redundancy slot the ranking assigns.
    let mut seq0_carried = 0u32;
    for i in 1..=16u64 {
        if i % 2 == 1 {
            // Refused: built but never recorded.
            let _ = manager
                .build_outgoing(Some(test_payload(0, i)), MTU)
                .unwrap();
        } else {
            let packet = build_sent(&mut manager, Some(test_payload(0, i)), MTU);
            if packet.payloads.iter().any(|p| p.seq == 0 && p.slot == 0) {
                seq0_carried += 1;
            }
        }
    }
    assert!(
        seq0_carried >= 2,
        "seq 0 rode only {seq0_carried} of 8 accepted packets — starved \
         by the stream of never-carried refusals",
    );
}

/// A built-but-never-recorded packet (the transport refused the datagram)
/// must leave no trace: the payloads it would have carried stay due on
/// their pre-existing schedule rather than entering the spacing gap of a
/// carry that never happened, and an ack naming the unsent packet's seq
/// retires nothing.
#[test]
fn an_unrecorded_packet_leaves_carry_state_untouched_and_its_ack_is_inert() {
    let mut manager = AckManager::new();
    let sent = manager
        .build_outgoing(Some(test_payload(0, 0)), MTU)
        .unwrap();
    manager.record_sent(&sent);

    // The next build re-carries the payload, but the wire refuses the
    // datagram, so nothing is recorded.
    let unsent = manager.build_outgoing(None, MTU).unwrap();
    assert_eq!(unsent.payloads.len(), 1);

    // The payload's schedule is undisturbed by the phantom carry: it is
    // still due on the very next packet (its one recorded carry keeps it
    // in the dense phase).
    let retry = manager.build_outgoing(None, MTU).unwrap();
    assert_eq!(retry.payloads.len(), 1);

    // An ack naming the unsent packet retires nothing — the peer cannot
    // have received a packet that never rode the wire.
    manager
        .handle_incoming(&incoming(0, Some(unsent.seq), &[]))
        .unwrap();
    assert_eq!(manager.payloads_in_flight(), 1);
}
