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
/// so the `MeshPacket` wrapper still fits the datagram even when
/// `build_outgoing` fills the inner packet with redundancy under sustained
/// loss. This is the one regression the overhead reservation exists to
/// prevent: dropping the `saturating_sub`, or a too-small const, would make
/// `send` return `PayloadTooLarge` exactly when redundancy matters most.
///
/// With acks withheld, each new send re-carries every prior unacked payload,
/// so the inner packet fills to `packet_budget` after a few turns. The test
/// sizes payloads to near the per-payload budget so this fill happens with
/// few sends, then asserts `send` stays `Ok` across a sustained run.
#[tokio::test]
async fn send_fits_the_datagram_when_redundancy_fills_the_inner_packet() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(1);
    sender.open_session(session);
    receiver.open_session(session);

    // Use tiny (4-byte) commands so build_outgoing packs many payloads per
    // packet, filling the inner Packet to within one payload element (~11
    // bytes) of packet_budget. That's the window MESH_PACKET_OVERHEAD
    // protects: with the reservation, the inner packet is at most
    // (max_datagram_size - 16), so the ~6-byte MeshPacket wrapper still fits.
    // Without it, build_outgoing fills to max_datagram_size and the wrapper
    // overflows → PayloadTooLarge. Large payloads leave hundreds of bytes of
    // slack and mask the bug this test exists to catch.
    let tiny_commands = 4;

    // Drain the receiver in the background so its datagram buffer can't
    // backpressure the sender's sends (noq datagrams are bounded).
    let drain = tokio::spawn(async move {
        // Withhold acks: never send anything back, so the sender's
        // unacked_payloads set grows and every send re-carries them all.
        while receiver.recv().await.is_ok() {}
    });

    // Send enough tiny turns to fill the inner packet to near budget on
    // every send after the first ~budget/payload_size. With acks withheld,
    // each send packs as many unacked payloads as fit.
    for i in 0..200u64 {
        let payload = Payload {
            seq: i,
            slot: 0,
            commands: vec![i as u8; tiny_commands].into(),
            ..Default::default()
        };
        match sender.send(session, Some(payload), None) {
            Ok(_) => {}
            Err(MeshLinkError::PayloadTooLarge { needed, budget }) => {
                panic!(
                    "send {i} returned PayloadTooLarge: needed {needed}, budget {budget} \
                     — the MeshPacket wrapper overflowed the datagram because \
                     MESH_PACKET_OVERHEAD is too small or missing"
                );
            }
            Err(error) => panic!("send {i} failed unexpectedly: {error:?}"),
        }
    }

    // The sends succeeded: the inner packet filled to near packet_budget on
    // every send, and the MeshPacket wrapper still fit the datagram. The
    // drain task confirms the datagrams actually went on the wire.
    drop(sender);
    let _ = drain.await;
}

/// An ack-only flush carries no conditions, and the dynamic overhead probe
/// leaves the redundancy budget intact when conditions are absent — so the
/// existing budget regression (`send_fits_the_datagram_when_redundancy_fills_the_inner_packet`)
/// still holds with `None` conditions. This is the load-bearing property:
/// ack-only flushes must not steal redundancy budget for a conditions
/// reservation they don't use.
#[tokio::test]
async fn ack_only_flush_with_no_conditions_keeps_full_budget() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(1);
    sender.open_session(session);
    receiver.open_session(session);

    // Fill the unacked window with tiny turns (acks withheld), then send an
    // ack-only flush with no conditions. The flush must fit the datagram
    // even when the inner packet is packed with redundant re-carries — the
    // dynamic probe reserves zero for absent conditions.
    let drain = tokio::spawn(async move { while receiver.recv().await.is_ok() {} });

    for i in 0..200u64 {
        let payload = Payload {
            seq: i,
            slot: 0,
            commands: vec![i as u8; 4].into(),
            ..Default::default()
        };
        match sender.send(session, Some(payload), None) {
            Ok(_) => {}
            Err(MeshLinkError::PayloadTooLarge { needed, budget }) => {
                panic!(
                    "send {i} returned PayloadTooLarge: needed {needed}, budget {budget} \
                     — absent conditions should reserve zero overhead"
                );
            }
            Err(error) => panic!("send {i} failed unexpectedly: {error:?}"),
        }
    }

    // An explicit ack-only flush (None payload) with no conditions: the
    // inner packet re-carries every unacked payload, and must still fit.
    match sender.send(session, None, None) {
        Ok(_) => {}
        Err(MeshLinkError::PayloadTooLarge { needed, budget }) => {
            panic!(
                "ack-only flush returned PayloadTooLarge: needed {needed}, budget {budget} \
                 — None conditions must not reserve overhead"
            );
        }
        Err(error) => panic!("ack-only flush failed unexpectedly: {error:?}"),
    }

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

/// The physics `MESH_UNACKED_WINDOW_CAP` (relay crate) exists to bound:
/// under genuine forward-path loss -- the peer never receives anything at
/// all, so its own acks and any ack-cursor push it might send both never
/// arrive -- a session's unacked window on this link grows without bound
/// as the sender keeps producing. Mirrors the client edge's own
/// `forward_path_sustained_loss_trips_the_unacked_window_cap`
/// (`client::driver`) at `MeshLink` granularity: the peer's connection
/// drains raw datagrams (so noq's own buffer can't stall the sender)
/// but never turns them into a `MeshLink`, so nothing is ever sent back.
#[tokio::test]
async fn sustained_forward_loss_grows_a_sessions_unacked_window_without_a_beacon_to_rescue_it() {
    let (mut sender, receiver, _client_ep, _server_ep) = connected_mesh_links().await;
    let session = SessionId(1);
    sender.open_session(session);

    let drainer = {
        let conn = receiver.connection().clone();
        tokio::spawn(async move {
            // "Receives" at the transport level (so the sender's datagrams
            // don't back up) but never becomes a MeshLink -- no dedup
            // advances, so nothing is ever sent back to the sender.
            while conn.read_datagram().await.is_ok() {}
        })
    };

    for i in 0..300u64 {
        let payload = Payload {
            seq: i,
            slot: 0,
            commands: vec![i as u8; 4].into(),
            ..Default::default()
        };
        sender.send(session, Some(payload), None).unwrap();
    }

    assert_eq!(
        sender.payloads_in_flight(session),
        300,
        "with nothing ever received back, every sent turn stays unacked -- \
         unbounded growth under sustained forward loss, exactly what the \
         relay's hard cap exists to catch",
    );

    drop(sender);
    drainer.abort();
}
