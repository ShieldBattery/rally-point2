//! Routing an arriving datagram to the right session's transport state.
//!
//! These tests all turn on the demux key: sessions sharing one connection
//! must not see each other's payloads, acks, or retirements; tenants must
//! separate sessions that collide on a numeric id; and an id that names
//! nothing must be refused rather than silently dropped.

use super::*;

/// The headline proof for the shared-connection design: four sessions on one
/// `MeshLink`, each sending the identical `(slot=0, seq=0)` identity — two
/// tenants that happen to use the *same* numeric session id, a third
/// tenant-less session also sharing that id (the legacy path an old peer, or
/// a caller with nothing to scope by, still uses), and a fourth on a distinct
/// id. All four keep fully independent transport state: each arrival is new
/// rather than a duplicate of another's identical key, each receiver cursor
/// advances alone, and a retire for one leaves the rest in flight. The
/// `MeshSessionKey` — the tenant, or its absence, as much as the numeric id —
/// is what disambiguates; the session never enters the `(slot, seq)` key.
#[tokio::test]
async fn sessions_sharing_one_link_do_not_cross_dedup_ack_or_retire() {
    let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

    let session = SessionId(1);
    let key_bare = MeshSessionKey::from(session);
    let key_prod = MeshSessionKey::new(session, "sb-prod");
    let key_staging = MeshSessionKey::new(session, "sb-staging");
    let key_other_id = MeshSessionKey::from(SessionId(2));

    for key in [&key_bare, &key_prod, &key_staging, &key_other_id] {
        sender.open_session(key.clone());
        receiver.open_session(key.clone());
    }

    // The tenant-less session goes first on its own, so the receiver's
    // per-session cursors can be read before any other session has arrived.
    sender
        .send(key_bare.clone(), Some(turn(0, 0, 0xB0)), None)
        .unwrap();
    let received = receiver.recv().await.unwrap();
    assert_eq!(received.session, session);
    assert_eq!(received.tenant, None);
    assert_eq!(received.delivery.fresh.len(), 1);
    assert_eq!(
        receiver.delivered_through(key_bare.clone(), SlotId(0)),
        Some(0),
    );
    for other in [&key_prod, &key_staging, &key_other_id] {
        assert_eq!(
            receiver.delivered_through(other.clone(), SlotId(0)),
            None,
            "one session's delivery must not advance another's ack cursor",
        );
    }

    // The remaining three send the same identity. A shared-demux bug would
    // make every one of them a duplicate of the first.
    sender
        .send(key_prod.clone(), Some(turn(0, 0, 0xA0)), None)
        .unwrap();
    sender
        .send(key_staging.clone(), Some(turn(0, 0, 0xC0)), None)
        .unwrap();
    sender
        .send(key_other_id.clone(), Some(turn(0, 0, 0xD0)), None)
        .unwrap();

    let mut by_key: HashMap<(SessionId, Option<String>), u8> = HashMap::new();
    for _ in 0..3 {
        let received = receiver.recv().await.unwrap();
        assert_eq!(
            received.delivery.fresh.len(),
            1,
            "each arrival is new, not a duplicate of another session's identical (slot, seq)",
        );
        by_key.insert(
            (received.session, received.tenant.clone()),
            received.delivery.fresh[0].commands[0],
        );
    }
    assert_eq!(
        by_key.get(&(session, Some("sb-prod".to_owned()))),
        Some(&0xA0),
    );
    assert_eq!(
        by_key.get(&(session, Some("sb-staging".to_owned()))),
        Some(&0xC0),
    );
    assert_eq!(
        by_key.get(&(SessionId(2), None)),
        Some(&0xD0),
        "a distinct numeric id stays distinct too",
    );

    // Independent in-flight and retire accounting: a beacon cursor for one
    // session's slot 0 retires only that session's payload.
    for key in [&key_bare, &key_prod, &key_staging, &key_other_id] {
        assert_eq!(sender.payloads_in_flight(key.clone()), 1);
    }
    let retired = sender.retire_through(key_prod.clone(), SlotId(0), 0);
    assert_eq!(retired, 1, "sb-prod's payload should retire");
    assert_eq!(sender.payloads_in_flight(key_prod), 0);
    for key in [key_bare, key_staging, key_other_id] {
        assert_eq!(
            sender.payloads_in_flight(key.clone()),
            1,
            "{key:?} must survive sb-prod's retire",
        );
    }
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
