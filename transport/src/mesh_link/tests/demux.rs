//! Routing an arriving datagram to the right session's transport state.
//!
//! These tests all turn on the demux key: sessions sharing one connection
//! must not see each other's payloads, acks, or retirements; tenants must
//! separate sessions that collide on a numeric id; and an id that names
//! nothing must be refused rather than silently dropped.

use super::*;

/// Two sessions share one `MeshLink`. Both send `(slot=0, seq=0)` — identical
/// identities. Each session's dedup treats the other's as new (not a
/// duplicate), and a beacon cursor for one session's slot 0 retires only
/// that session's payloads. This is the load-bearing proof for the
/// shared-connection design: the session never enters the `(slot, seq)` key,
/// so per-session instances keep the two streams independent.
#[tokio::test]
async fn two_sessions_on_one_link_do_not_cross_dedup_ack_or_retire() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session_a = SessionId(1);
    let session_b = SessionId(2);
    sender.open_session(session_a);
    sender.open_session(session_b);
    receiver.open_session(session_a);
    receiver.open_session(session_b);

    // Both sessions send (slot=0, seq=0). A shared-dedup bug would make the
    // second a duplicate; per-session dedup makes both new.
    sender
        .send(session_a, Some(turn(0, 0, 0xA0)), None)
        .unwrap();
    sender
        .send(session_b, Some(turn(0, 0, 0xB0)), None)
        .unwrap();

    // Receive session A's turn — exactly one payload, session A's.
    let received = receiver.recv().await.unwrap();
    assert_eq!(received.session, session_a);
    assert_eq!(received.delivery.fresh.len(), 1);
    assert_eq!(received.delivery.fresh[0].commands[0], 0xA0);

    // Receive session B's turn — also exactly one payload, session B's. If
    // the sessions shared dedup, this would be dropped as a duplicate of
    // session A's (slot=0, seq=0).
    let received = receiver.recv().await.unwrap();
    assert_eq!(received.session, session_b);
    assert_eq!(received.delivery.fresh.len(), 1);
    assert_eq!(received.delivery.fresh[0].commands[0], 0xB0);

    // Both sessions have one payload in flight (the turns above). A
    // retire_through for session A's slot 0 must retire only session A's
    // payload, leaving session B's in flight.
    assert_eq!(sender.payloads_in_flight(session_a), 1);
    assert_eq!(sender.payloads_in_flight(session_b), 1);

    // Simulate a beacon cursor for session A: force-retire its slot 0
    // through seq 0.
    let retired = sender.retire_through(session_a, SlotId(0), 0);
    assert_eq!(retired, 1, "session A's payload should retire");

    // Session A is now retired; session B is not.
    assert_eq!(sender.payloads_in_flight(session_a), 0);
    assert_eq!(
        sender.payloads_in_flight(session_b),
        1,
        "session B's payload must survive session A's retire"
    );
}

/// The headline proof for tenant-scoped mesh sessions: two tenants happen
/// to use the *same* numeric session id on one `MeshLink`, plus a third,
/// tenant-less session also sharing that id (the legacy path an old peer,
/// or a caller with nothing to scope by, still uses) — all three coexist
/// with fully independent transport state and no cross-delivery. Mirrors
/// `two_sessions_on_one_link_do_not_cross_dedup_ack_or_retire`'s design
/// (identical `(slot, seq)` on every one of them), but demuxing by
/// `MeshSessionKey` instead of by distinct session ids — proving the
/// tenant (or its absence) is what disambiguates, not merely the numeric
/// id.
#[tokio::test]
async fn two_tenants_sharing_a_session_id_exchange_turns_without_cross_delivery() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(1);
    let key_bare = MeshSessionKey::from(session);
    let key_prod = MeshSessionKey::new(session, "sb-prod");
    let key_staging = MeshSessionKey::new(session, "sb-staging");

    for key in [&key_bare, &key_prod, &key_staging] {
        sender.open_session(key.clone());
        receiver.open_session(key.clone());
    }

    // All three send the identical (slot=0, seq=0) identity. A shared-demux
    // bug would make the second and third arrivals duplicates.
    sender
        .send(key_bare.clone(), Some(turn(0, 0, 0xB0)), None)
        .unwrap();
    sender
        .send(key_prod.clone(), Some(turn(0, 0, 0xA0)), None)
        .unwrap();
    sender
        .send(key_staging.clone(), Some(turn(0, 0, 0xC0)), None)
        .unwrap();

    let mut by_tenant: HashMap<Option<String>, u8> = HashMap::new();
    for _ in 0..3 {
        let received = receiver.recv().await.unwrap();
        assert_eq!(
            received.session, session,
            "all three share the same numeric id"
        );
        assert_eq!(
            received.delivery.fresh.len(),
            1,
            "each arrival is new, not a duplicate of another tenant's identical (slot, seq)",
        );
        by_tenant.insert(
            received.tenant.clone(),
            received.delivery.fresh[0].commands[0],
        );
    }
    assert_eq!(
        by_tenant.get(&None),
        Some(&0xB0),
        "the tenant-less send delivered its own byte"
    );
    assert_eq!(by_tenant.get(&Some("sb-prod".to_owned())), Some(&0xA0));
    assert_eq!(by_tenant.get(&Some("sb-staging".to_owned())), Some(&0xC0));

    // Independent in-flight/retire accounting too, exactly like the
    // bare-id sibling test proves for distinct session ids.
    assert_eq!(sender.payloads_in_flight(key_bare.clone()), 1);
    assert_eq!(sender.payloads_in_flight(key_prod.clone()), 1);
    assert_eq!(sender.payloads_in_flight(key_staging.clone()), 1);

    let retired = sender.retire_through(key_prod.clone(), SlotId(0), 0);
    assert_eq!(retired, 1, "sb-prod's payload should retire");
    assert_eq!(sender.payloads_in_flight(key_prod), 0);
    assert_eq!(
        sender.payloads_in_flight(key_bare),
        1,
        "the tenant-less session's payload must survive sb-prod's retire"
    );
    assert_eq!(
        sender.payloads_in_flight(key_staging),
        1,
        "sb-staging's payload must survive sb-prod's retire"
    );
}

/// `MeshPacket.tenant` round-trips through `send`/`recv`: a tenant-scoped
/// send is observed with that same tenant on the receive side.
#[tokio::test]
async fn mesh_packet_tenant_round_trips_through_send_and_recv() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(7);
    let scoped = MeshSessionKey::new(session, "sb-test");
    sender.open_session(scoped.clone());
    receiver.open_session(scoped.clone());

    sender.send(scoped, Some(turn(0, 0, 0xAA)), None).unwrap();
    let received = receiver.recv().await.unwrap();
    assert_eq!(received.session, session);
    assert_eq!(received.tenant.as_deref(), Some("sb-test"));
    assert_eq!(received.delivery.fresh.len(), 1);
}

/// The ack-beacon cursor delivered_through is per-session: a delivery on
/// session A does not advance session B's cursor for the same slot.
#[tokio::test]
async fn delivered_through_is_per_session_not_shared() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session_a = SessionId(1);
    let session_b = SessionId(2);
    sender.open_session(session_a);
    sender.open_session(session_b);
    receiver.open_session(session_a);
    receiver.open_session(session_b);

    // Send + receive session A's (slot=0, seq=0).
    sender
        .send(session_a, Some(turn(0, 0, 0xA0)), None)
        .unwrap();
    let received = receiver.recv().await.unwrap();
    assert_eq!(received.session, session_a);
    assert_eq!(received.delivery.fresh.len(), 1);

    // Session A's delivered_through advanced to 0; session B's did not.
    assert_eq!(
        receiver.delivered_through(session_a, SlotId(0)),
        Some(0),
        "session A delivered through seq 0"
    );
    assert_eq!(
        receiver.delivered_through(session_b, SlotId(0)),
        None,
        "session B has not delivered slot 0 yet"
    );

    // Now send + receive session B's (slot=0, seq=0) — the same (slot, seq)
    // as session A's. If delivered_through were shared, it would already be
    // Some(0) and the payload would be a duplicate.
    sender
        .send(session_b, Some(turn(0, 0, 0xB0)), None)
        .unwrap();
    let received = receiver.recv().await.unwrap();
    assert_eq!(received.session, session_b);
    assert_eq!(
        received.delivery.fresh.len(),
        1,
        "session B's (slot=0, seq=0) is new, not a duplicate of session A's"
    );
}

/// A `MeshPacket` for a session that was never opened is an error, not a
/// silent drop — the two relays' session rosters have desynced.
#[tokio::test]
async fn rejects_a_packet_for_an_unopened_session() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let known_session = SessionId(1);
    let unknown_session = SessionId(2);
    // The sender opens session 2 so its send succeeds; the receiver does
    // not, so the recv surfaces UnknownSession — the two relays' session
    // rosters have desynced.
    sender.open_session(known_session);
    sender.open_session(unknown_session);
    receiver.open_session(known_session);

    sender
        .send(unknown_session, Some(turn(0, 0, 0xA0)), None)
        .unwrap();

    match receiver.recv().await {
        Err(MeshLinkError::UnknownSession(sid)) => assert_eq!(sid, unknown_session),
        other => panic!("expected UnknownSession, got {other:?}"),
    }
}

/// A `MeshPacket` with a zero session id is malformed, not a valid session.
#[tokio::test]
async fn rejects_a_packet_with_a_zero_session_id() {
    let (sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    // Craft a MeshPacket with session=0 directly on the wire.
    let mesh_packet = MeshPacket {
        session: 0,
        packet: Some(Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![turn(0, 0, 0xA0)],
        }),
        conditions: None,
        tenant: None,
    };
    sender
        .connection()
        .send_datagram(mesh_packet.encode_to_vec().into())
        .unwrap();

    match receiver.recv().await {
        Err(MeshLinkError::ZeroSession) => {}
        other => panic!("expected ZeroSession, got {other:?}"),
    }
}
