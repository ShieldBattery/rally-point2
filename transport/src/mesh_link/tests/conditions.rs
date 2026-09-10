//! The per-client conditions sidecar a `MeshPacket` optionally carries.
//!
//! Grouped because they share one question: what the sidecar costs on the
//! wire, and whether it survives the trip intact. The exact-cost probe is
//! what keeps an optional field from permanently taxing the redundancy
//! budget.

use super::*;

/// Conditions attached to a `MeshPacket` round-trip: the sender attaches
/// per-client link stats, the receiver gets them back on `MeshReceived`.
/// This is the transport-level proof that conditions cross the mesh — the
/// relay E2E is not needed because the transport carries them, not stored
/// relay state.
#[tokio::test]
async fn conditions_round_trip_through_send_and_recv() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(1);
    sender.open_session(session);
    receiver.open_session(session);

    // Two home-client link stats, the shape a relay would gather from its
    // own noq connections: slot 0 at 12ms RTT with 3/1000 lost; slot 1
    // at 45ms with 10/500 lost.
    let conditions = LinkConditions {
        slots: vec![
            rally_point_proto::messages::SlotConditions {
                slot: 0,
                rtt_us: 12_000,
                lost_packets: 3,
                sent_packets: 1000,
                connection_epoch: Some(0xC0DE_0000_0000_0000),
            },
            rally_point_proto::messages::SlotConditions {
                slot: 1,
                rtt_us: 45_000,
                lost_packets: 10,
                sent_packets: 500,
                connection_epoch: Some(0xC0DE_0000_0000_0001),
            },
        ],
    };

    sender
        .send(session, Some(turn(0, 0, 0xA0)), Some(conditions.clone()))
        .unwrap();

    let received = receiver.recv().await.unwrap();
    assert_eq!(received.session, session);
    assert_eq!(received.delivery.fresh.len(), 1);
    let got = received
        .conditions
        .as_ref()
        .expect("conditions should be present on the received MeshPacket");
    assert_eq!(got.slots.len(), 2);
    assert_eq!(got.slots[0].slot, 0);
    assert_eq!(got.slots[0].rtt_us, 12_000);
    assert_eq!(got.slots[0].lost_packets, 3);
    assert_eq!(got.slots[0].sent_packets, 1000);
    assert_eq!(got.slots[0].connection_epoch, Some(0xC0DE_0000_0000_0000));
    assert_eq!(got.slots[1].slot, 1);
    assert_eq!(got.slots[1].rtt_us, 45_000);
    assert_eq!(got.slots[1].lost_packets, 10);
    assert_eq!(got.slots[1].sent_packets, 500);
    assert_eq!(got.slots[1].connection_epoch, Some(0xC0DE_0000_0000_0001));
}

/// A large conditions sidecar reserves exactly its wire cost — not a fixed
/// worst case — so the redundancy budget shrinks by the sidecar's actual
/// size and no more. This is the property the dynamic `encoded_len` probe
/// exists for: a fixed worst-case reservation would steal budget that
/// defends lockstep latency.
#[tokio::test]
async fn large_conditions_reserve_their_exact_wire_cost_not_a_worst_case() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(1);
    sender.open_session(session);
    receiver.open_session(session);

    // A conditions sidecar with all 8 slots filled — the largest a real
    // game (≤8 players) produces. Small enough that even with redundancy
    // packed alongside it, the datagram fits — which is what we assert.
    let conditions = full_epoch_conditions();

    // Send with conditions + sustained unacked redundancy (acks withheld).
    // The dynamic probe subtracts the sidecar's exact wire cost, so the
    // inner packet is sized to fit alongside it — no PayloadTooLarge.
    let drain = tokio::spawn(async move { while receiver.recv().await.is_ok() {} });

    for i in 0..100u64 {
        let payload = Payload {
            seq: i,
            slot: 0,
            commands: vec![i as u8; 4].into(),
            ..Default::default()
        };
        match sender.send(session, Some(payload), Some(conditions.clone())) {
            Ok(_) => {}
            Err(MeshLinkError::PayloadTooLarge { needed, budget }) => {
                panic!(
                    "send {i} with conditions returned PayloadTooLarge: needed {needed}, \
                     budget {budget} — the dynamic probe should reserve exact wire cost, \
                     not a worst case that over-reserves"
                );
            }
            Err(error) => panic!("send {i} failed unexpectedly: {error:?}"),
        }
    }

    drop(sender);
    let _ = drain.await;
}

/// `conditions_element_len` accounts for the field tag and length-prefix
/// varint that wrap `LinkConditions` when it's embedded as
/// `MeshPacket.conditions`, not just the message's own body
/// (`LinkConditions::encoded_len` alone). One slot's worth of conditions is
/// small enough that the length-prefix varint is a single byte, so the
/// expected overhead is exactly `1 (tag) + 1 (length varint) + body_len`.
#[test]
fn conditions_element_len_accounts_for_the_tag_and_length_prefix_not_just_the_body() {
    let conditions = LinkConditions {
        slots: vec![rally_point_proto::messages::SlotConditions {
            slot: 0,
            rtt_us: 12_000,
            lost_packets: 3,
            sent_packets: 1000,
            connection_epoch: Some(0xC0DE_0000_0000_0000),
        }],
    };
    let body_len = conditions.encoded_len();
    // A single-slot conditions message is well under 128 bytes, so its
    // length-delimiter varint is exactly one byte.
    assert!(body_len < 128, "test assumption: a one-byte length varint");
    assert_eq!(
        conditions_element_len(&conditions),
        body_len + 2,
        "tag (1) + length-prefix varint (1) + body -- not the body alone",
    );
}

/// A production P8 sidecar crosses protobuf's 127-byte boundary once its
/// eight fixed-width connection epochs are present. Lock in both the body
/// and complete embedded-field cost so the live datagram budget keeps
/// accounting for the two-byte length varint, not the legacy one-byte path.
#[test]
fn full_epoch_conditions_account_for_the_two_byte_length_prefix() {
    let conditions = full_epoch_conditions();
    let body_len = conditions.encoded_len();

    assert_eq!(body_len, 172, "P8 production conditions wire body");
    assert_eq!(
        prost::encoding::encoded_len_varint(body_len as u64),
        2,
        "a 172-byte embedded message needs a two-byte length varint",
    );
    assert_eq!(
        conditions_element_len(&conditions),
        175,
        "field tag (1) + length varint (2) + body (172)",
    );
}
