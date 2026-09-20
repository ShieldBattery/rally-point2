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

/// `conditions_element_len` charges the field tag and the length-prefix
/// varint that wrap `LinkConditions` when it is embedded as
/// `MeshPacket.conditions`, not just the message's own body
/// (`LinkConditions::encoded_len` alone) — and it charges the varint's real
/// width. A one-slot sidecar stays under protobuf's 127-byte boundary and
/// needs a single length byte; a production eight-slot sidecar crosses it
/// once its fixed-width connection epochs are present and needs two, so the
/// live datagram budget must not be sized on the legacy one-byte path.
#[test]
fn conditions_element_len_charges_the_tag_and_the_full_length_prefix() {
    let one_slot = LinkConditions {
        slots: vec![rally_point_proto::messages::SlotConditions {
            slot: 0,
            rtt_us: 12_000,
            lost_packets: 3,
            sent_packets: 1000,
            connection_epoch: Some(0xC0DE_0000_0000_0000),
        }],
    };

    // (sidecar, expected length-varint width), tag included on top of both.
    for (conditions, varint_len) in [(one_slot, 1usize), (full_epoch_conditions(), 2)] {
        let body_len = conditions.encoded_len();
        assert_eq!(
            prost::encoding::encoded_len_varint(body_len as u64),
            varint_len,
            "a {body_len}-byte embedded message needs a {varint_len}-byte length varint",
        );
        assert_eq!(
            conditions_element_len(&conditions),
            body_len + 1 + varint_len,
            "field tag (1) + length varint ({varint_len}) + body ({body_len})",
        );
    }
}
