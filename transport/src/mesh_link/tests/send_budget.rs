//! What a mesh send is allowed to carry, and what it leaves in flight.
//!
//! Every test here pushes on the datagram budget: the wrapper and tenant
//! framing carved out of it, the admission floor that keeps an accepted
//! payload re-carryable for the connection's life, and the unacked window
//! that grows when nothing ever comes back.

use super::*;

/// A floor-admitted payload whose *current* envelope is too large — a full
/// conditions sidecar on a datagram budget near the floor — must fail as a
/// recoverable bundle race (registered, datagram refused, unrecorded), not
/// be refused before registration: the pre-registration guard re-samples
/// the live budget, which can shrink between the caller's `payload_fits`
/// preflight and the send, and the callers consume that refusal by
/// dropping the fresh turn. The sidecar-free flush then recovers it.
#[tokio::test]
async fn a_conditions_crowded_send_downgrades_to_a_recoverable_bundle_race() {
    let (mut sender, mut receiver, _client_ep, _server_ep) =
        connected_mesh_links_with_datagram_limit(800).await;

    let session = SessionId(3);
    let key = MeshSessionKey::from(session);
    sender.open_session(key.clone());
    receiver.open_session(key.clone());

    // Admissible against the session's floor, but too wide to share a
    // datagram with the largest conditions sidecar at this budget.
    let payload = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0u8; 700].into(),
        ..Default::default()
    };
    assert!(sender.payload_fits(&payload, None, None).unwrap());

    // The conditions-bearing send outgrows the datagram: refused by the
    // wire, but the payload is registered (and the carry unrecorded).
    match sender.send(key.clone(), Some(payload), Some(full_epoch_conditions())) {
        Err(MeshLinkError::PayloadTooLarge { .. }) => {}
        other => panic!("expected a datagram-level PayloadTooLarge, got {other:?}"),
    }
    assert_eq!(
        sender.payloads_in_flight(key.clone()),
        1,
        "the turn must be registered for re-carry, not dropped pre-registration",
    );

    // The sidecar-free flush recovers it.
    assert_eq!(sender.send(key.clone(), None, None).unwrap(), 1);
    let received = receiver.recv().await.unwrap();
    assert_eq!(received.delivery.fresh.len(), 1);
    assert_eq!(received.delivery.fresh[0].seq, 0);
}

/// A session's tenant framing rides *every* one of its packets, so mesh
/// admission must reserve it out of the guaranteed floor. Without the
/// reservation, a payload admitted near the bare floor on a large
/// discovered path could — after black-hole fallback to the MTU floor —
/// exceed what a maintenance flush can carry once the tenant and wrapper
/// are paid for, and the head-of-line gate would emit ack-only flushes
/// forever.
#[tokio::test]
async fn admission_reserves_the_persistent_tenant_framing() {
    let (mut sender, _receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(9);
    let max_tenant = "t".repeat(255);
    let key = MeshSessionKey::new(session, max_tenant.as_str());
    sender.open_session(key.clone());

    // Sized to pass the bare floor comfortably but not survive the
    // 255-byte tenant's framing plus the wrapper being carved from it.
    let wide = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0u8; 900].into(),
        ..Default::default()
    };
    assert!(
        sender.payload_fits(&wide, None, None).unwrap(),
        "premise: the payload is admissible on a tenant-less session",
    );
    assert!(
        !sender
            .payload_fits(&wide, None, Some(max_tenant.as_str()))
            .unwrap(),
        "a maximum-length tenant must shrink the admission floor",
    );
    // The send guard agrees (second line of defense): refused, and never
    // registered for re-carry.
    match sender.send(key.clone(), Some(wide), None) {
        Err(MeshLinkError::PayloadTooLarge { .. }) => {}
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }

    // An ordinary turn still rides the tenant session.
    assert!(
        sender
            .payload_fits(&turn(0, 0, 0x22), None, Some(max_tenant.as_str()))
            .unwrap()
    );
    sender.send(key, Some(turn(0, 0, 0x22)), None).unwrap();
}

/// The inner `Packet` is built to `max_datagram_size() - MESH_PACKET_OVERHEAD`
/// minus whatever the conditions sidecar actually costs, so the `MeshPacket`
/// wrapper still fits the datagram even when `build_outgoing` fills the inner
/// packet with redundancy under sustained loss. This is the regression the
/// overhead reservation exists to prevent: dropping the `saturating_sub`, a
/// too-small const, or a worst-case sidecar reservation instead of the
/// dynamic `encoded_len` probe would make `send` return `PayloadTooLarge`
/// exactly when redundancy matters most — and an over-reserving probe would
/// steal budget that defends lockstep latency on every ordinary send.
///
/// With acks withheld, each new send re-carries prior unacked payloads, so the
/// inner packet fills to `packet_budget` after a few turns. The run covers
/// both sidecar states — absent, where the probe must reserve exactly zero,
/// and the largest an eight-player game produces — and ends each with an
/// ack-only flush, the packet that carries redundancy with no fresh payload to
/// make room for.
#[tokio::test]
async fn send_fits_the_datagram_when_redundancy_fills_the_inner_packet() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(1);
    sender.open_session(session);
    receiver.open_session(session);

    // Drain the receiver in the background so its datagram buffer can't
    // backpressure the sender's sends (noq datagrams are bounded). It never
    // sends anything back, so no ack ever returns: the unacked window only
    // grows and every send re-carries as much of it as the budget allows.
    let drain = tokio::spawn(async move { while receiver.recv().await.is_ok() {} });

    // Tiny (4-byte) commands so build_outgoing packs many payloads per packet,
    // filling the inner Packet to within one payload element (~11 bytes) of
    // packet_budget. That's the window MESH_PACKET_OVERHEAD protects: with the
    // reservation the inner packet is at most (max_datagram_size - 16), so the
    // ~6-byte MeshPacket wrapper still fits; without it build_outgoing fills to
    // max_datagram_size and the wrapper overflows. Large payloads leave
    // hundreds of bytes of slack and mask the bug this test exists to catch.
    const SENDS_PER_SIDECAR: u64 = 200;
    let mut seq = 0u64;
    for conditions in [None, Some(full_epoch_conditions())] {
        for _ in 0..SENDS_PER_SIDECAR {
            let payload = Payload {
                seq,
                slot: 0,
                commands: vec![seq as u8; 4].into(),
                ..Default::default()
            };
            seq += 1;
            match sender.send(session, Some(payload), conditions.clone()) {
                Ok(_) => {}
                Err(MeshLinkError::PayloadTooLarge { needed, budget }) => panic!(
                    "send {seq} returned PayloadTooLarge: needed {needed}, budget {budget} \
                     — the envelope outgrew the datagram it was sized against",
                ),
                Err(error) => panic!("send {seq} failed unexpectedly: {error:?}"),
            }
        }

        // An explicit ack-only flush: the inner packet re-carries unacked
        // payloads with no fresh turn of its own, and must still fit.
        match sender.send(session, None, conditions.clone()) {
            Ok(_) => {}
            Err(MeshLinkError::PayloadTooLarge { needed, budget }) => panic!(
                "the ack-only flush returned PayloadTooLarge: needed {needed}, budget {budget}",
            ),
            Err(error) => panic!("the ack-only flush failed unexpectedly: {error:?}"),
        }
    }

    // Nothing ever came back, so nothing retired: every turn sent is still in
    // flight. This is the unbounded growth under sustained forward loss that
    // the relay's own unacked-window cap exists to catch — no spurious
    // retirement papers over it here.
    assert_eq!(
        sender.payloads_in_flight(session),
        (2 * SENDS_PER_SIDECAR) as usize,
    );

    drop(sender);
    let _ = drain.await;
}

/// `payload_fits` sizes against the same budget `send` applies: a routine
/// turn fits (with or without a conditions sidecar), a turn beyond any
/// datagram budget does not — the caller's cue to divert it to the mesh
/// control stream instead of losing it to a refused `send`.
#[tokio::test]
async fn payload_fits_mirrors_the_send_budget() {
    let (mut sender, _receiver, _client_ep, _server_ep) = connected_mesh_links().await;
    let session = SessionId(1);
    sender.open_session(session);

    let small = turn(0, 0, 0xA0);
    assert!(sender.payload_fits(&small, None, None).unwrap());

    // A full 8-slot conditions sidecar shrinks the budget but not enough to
    // evict a routine turn.
    let conditions = full_epoch_conditions();
    assert!(
        sender
            .payload_fits(&small, Some(&conditions), None)
            .unwrap()
    );

    // A tenant string shrinks the budget the same way -- not enough to
    // evict a routine turn either, even at the maximum tenant-id length.
    let max_tenant = "t".repeat(255);
    assert!(
        sender
            .payload_fits(&small, None, Some(&max_tenant))
            .unwrap()
    );

    // A turn far past any datagram budget must be diverted, and `send`
    // agrees: it refuses the same payload the pre-check rejected.
    let oversize = Payload {
        seq: 1,
        slot: 0,
        commands: vec![0xAB; 5000].into(),
        ..Default::default()
    };
    assert!(!sender.payload_fits(&oversize, None, None).unwrap());
    assert!(matches!(
        sender.send(session, Some(oversize), None),
        Err(MeshLinkError::PayloadTooLarge { .. })
    ));
}
