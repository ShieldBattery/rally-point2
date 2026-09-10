//! Handshake authorization and admission: proofs the relay must refuse, tenant
//! isolation, the in-flight handshake cap, and the gate a reconnecting or
//! wrongly-homed slot meets.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_proto::token::{
    CHALLENGE_LEN, CHANNEL_BINDING_EXPORTER_LABEL, CHANNEL_BINDING_LEN, ConnectionChallenge,
};
use rally_point_relay::server;
use rally_point_transport::noq;
use rally_point_transport::quic::server_config;

#[tokio::test]
async fn rejects_a_bad_connection_binding_proof() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);

    // A valid token, but the challenge is answered with a key that isn't the one
    // the token commits to.
    let client_key = keypair();
    let wrong_key = keypair();
    let token = mint_token(&tenant, SessionId(1), SlotId(0), client_key.public);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    assert!(
        handshake(&connection, &token, &wrong_key, &[])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejects_a_challenge_proof_bound_to_another_connection() {
    // Simulates a relay-in-the-middle: a proof the client produced for one TLS
    // session must not authorize a different session. The signature is over the
    // right challenge with the right key, but bound to a second connection's
    // channel — exactly what a forwarding relay would hold — so the relay, checking
    // against this connection's binding, must reject it.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let client_key = keypair();

    // Victim connection: present a valid token and read the challenge, then pause.
    let victim = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut send, mut recv) = victim.open_bi().await.unwrap();
    let token = mint_token(&tenant, SessionId(9), SlotId(0), client_key.public);
    let encoded = token.encode().unwrap();
    let len = u16::try_from(encoded.len()).unwrap();
    send.write_all(&len.to_le_bytes()).await.unwrap();
    send.write_all(&encoded).await.unwrap();
    let mut challenge = [0u8; CHALLENGE_LEN];
    recv.read_exact(&mut challenge).await.unwrap();

    // A second, independent connection: a different TLS session, hence a different
    // channel binding — the separate session a forwarding relay would have.
    let other = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let mut other_binding = [0u8; CHANNEL_BINDING_LEN];
    other
        .export_keying_material(&mut other_binding, CHANNEL_BINDING_EXPORTER_LABEL, &[])
        .unwrap();

    // Answer the victim's challenge bound to the wrong connection's channel.
    let response = client_key.sign(&ConnectionChallenge(challenge).signed_message(&other_binding));
    send.write_all(&response).await.unwrap();

    let mut ack = [0u8; 1];
    assert!(
        recv.read_exact(&mut ack).await.is_err(),
        "relay accepted a proof bound to a different connection",
    );
}

#[tokio::test]
async fn rejects_a_token_from_an_unknown_tenant_key() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);

    // The token is signed by a tenant key the relay's registry has never seen.
    let impostor = make_tenant("impostor-key", "impostor");
    let client_key = keypair();
    let token = mint_token(&impostor, SessionId(1), SlotId(0), client_key.public);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    assert!(
        handshake(&connection, &token, &client_key, &[])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejects_a_second_client_on_the_same_slot() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(5);

    // First client takes slot 0 and stays connected (keep the link alive).
    let _slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;

    // A second client presenting a valid token for the same slot completes the
    // crypto but is refused at registration, so it never sees the acknowledgement.
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(0), client_key.public);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    assert!(
        handshake(&connection, &token, &client_key, &[])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn isolates_identical_session_ids_across_tenants() {
    // Two tenants the relay trusts, each with its own signing key.
    let tenant_a = make_tenant("tenant-a-key", "tenant-a");
    let tenant_b = make_tenant("tenant-b-key", "tenant-b");
    let (addr, ca) = start_relay(registry_for(&[&tenant_a, &tenant_b]));
    let endpoint = client_endpoint(&ca);

    // The same numeric session id is live for both tenants at once. Session ids are
    // unique only within a tenant, so this must not be treated as one game.
    let session = SessionId(100);

    let mut a0 = connect_slot(&endpoint, addr, &tenant_a, session, SlotId(0)).await;
    let mut a1 = connect_slot(&endpoint, addr, &tenant_a, session, SlotId(1)).await;

    // Tenant B claims slot 1 in the same numeric session. Keyed on the session
    // number alone this would collide with tenant A's slot 1 and be refused; it
    // connects cleanly here, proving the groups are kept apart.
    let mut b1 = connect_slot(&endpoint, addr, &tenant_b, session, SlotId(1)).await;

    // Tenant A, slot 0, submits a build.
    a0.send(Some(Payload {
        seq: 0,
        slot: 0,
        commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
        ..Default::default()
    }))
    .unwrap();

    // It reaches tenant A's other slot.
    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = a1.recv().await.unwrap().fresh;
    }
    assert_eq!(delivered[0].slot, 0);
    assert_eq!(&delivered[0].commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);

    // It must never reach tenant B, despite the shared session number. The turn has
    // already fanned out by the time tenant A's peer holds it, so a short wait that
    // yields nothing is conclusive that no cross-tenant copy was queued.
    let leaked = tokio::time::timeout(Duration::from_millis(300), b1.recv()).await;
    assert!(leaked.is_err(), "tenant B received tenant A's turn");
}

#[tokio::test]
async fn refuses_connections_beyond_the_handshake_limit() {
    let tenant = make_tenant(KID, TENANT);

    // A relay that allows only one authorization handshake in flight at a time.
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let relay = noq::Endpoint::server(server_cfg, bind).unwrap();
    let addr = relay.local_addr().unwrap();
    tokio::spawn(server::serve_with_max_pending(
        relay,
        Arc::new(registry_for(&[&tenant])),
        std::sync::Arc::default(),
        rally_point_relay::mesh::new_mesh_state(),
        None,
        1,
    ));

    let endpoint = client_endpoint(&ca);

    // First client connects but never opens the auth stream, so the relay parks in
    // the handshake holding the only admission slot.
    let _stalled = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    // A second connection is refused while that slot is occupied.
    let refused = endpoint.connect(addr, "localhost").unwrap().await;
    assert!(
        refused.is_err(),
        "second connection should be refused at the handshake limit"
    );
}

#[tokio::test]
async fn a_reconnect_after_the_leave_is_decided_is_refused_terminally() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_relay::server::SLOT_DEPARTED_CLOSE;
    use rally_point_transport::control::send_control_leave_intent;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(301);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Authority over {0, 1} so the session starts and a decided leave is real.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let _slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // A framed turn gives the leave a basis (realistic, though not required for the
    // reject to fire). Authored by slot 1 itself — fan-out excludes the source, so
    // slot 1 never receives its own turn back and `expect_closed` below sees only
    // the eventual close, not a stray pending datagram.
    slot1
        .send(Some(Payload {
            seq: 0,
            slot: 1,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Slot 1 leaves cleanly: a clean leave is decided immediately, no hold, so the
    // slot's departure is final. The relay closes slot 1's link as confirmation.
    let (mut leave_send, _unused) = slot1.connection().open_bi().await.unwrap();
    send_control_leave_intent(&mut leave_send).await.unwrap();
    expect_closed(&mut slot1).await;

    // Re-dialing that slot is now too late — its leave is decided and the game has
    // moved on. The relay refuses the re-register with the terminal "departed" close,
    // distinct from any transport error, before ever acknowledging the handshake.
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(1), client_key.public);
    let redial = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    assert!(
        handshake(&redial, &token, &client_key, &[]).await.is_err(),
        "a decided-departure re-register is never acknowledged",
    );
    match redial.closed().await {
        noq::ConnectionError::ApplicationClosed(app) => assert_eq!(
            u32::try_from(u64::from(app.error_code)).unwrap(),
            SLOT_DEPARTED_CLOSE,
            "the re-register is refused with the terminal departed close code",
        ),
        other => panic!("expected the terminal departed application close, got {other:?}"),
    }
}

/// The provisional journal's session ceiling refuses a pre-descriptor
/// admission BEFORE the handshake acknowledgment: the client is never told
/// its slot is routable (so nothing can be acknowledged that the relay
/// retains nowhere), the close carries the distinct retryable capacity
/// code, and an already-tracked session's other slots keep admitting at the
/// ceiling.
#[tokio::test]
async fn a_pre_descriptor_admission_is_refused_at_the_journal_ceiling() {
    use rally_point_relay::server::PROVISIONAL_CAPACITY_CLOSE;

    let tenant = make_tenant(KID, TENANT);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_journal_ceiling(1);
    mesh.provisional_turns.arm();
    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    // The first session takes the only journal slot and serves normally; a
    // second slot of the SAME (tracked) session is still admitted.
    let _a0 = connect_slot(&endpoint, addr, &tenant, SessionId(320), SlotId(0)).await;
    let _a1 = connect_slot(&endpoint, addr, &tenant, SessionId(320), SlotId(1)).await;

    // A distinct session past the ceiling is refused before HANDSHAKE_OK.
    let client_key = keypair();
    let token = mint_token(&tenant, SessionId(321), SlotId(0), client_key.public);
    let dial = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    assert!(
        handshake(&dial, &token, &client_key, &[]).await.is_err(),
        "a ceiling-refused admission is never acknowledged",
    );
    match dial.closed().await {
        noq::ConnectionError::ApplicationClosed(app) => assert_eq!(
            u32::try_from(u64::from(app.error_code)).unwrap(),
            PROVISIONAL_CAPACITY_CLOSE,
            "refused with the distinct retryable capacity close code",
        ),
        other => panic!("expected the capacity application close, got {other:?}"),
    }
}

#[tokio::test]
async fn a_slot_not_homed_on_this_relay_is_refused() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_relay::server::SLOT_NOT_HOMED_CLOSE;

    // A token binds tenant/session/slot/key but not the specific relay, so
    // without this check a misrouted (or malicious) client could register the
    // same slot on two relays in a true multi-relay session, feeding each a
    // different turn at the same (slot, seq) -- exactly the split the mesh's
    // topological dedup can only mask the symptom of, never prevent. The
    // descriptor's homed set is the fix: a slot absent from a non-empty set
    // is refused before the handshake ever completes, while a slot present in
    // it (or a set left empty, the legacy/dev default) is admitted exactly as
    // before this check existed.
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(302);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // The descriptor assigns only slot 0 to this relay -- standing in for a
    // multi-relay session where slot 1 is homed elsewhere.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        None,
        false,
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    // Slot 0 is homed here: admitted normally.
    let _slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;

    // Slot 1 is homed elsewhere: refused before the handshake ever completes,
    // distinct from every other close code so a misrouted client is
    // diagnosable.
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(1), client_key.public);
    let redial = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    assert!(
        handshake(&redial, &token, &client_key, &[]).await.is_err(),
        "a slot not homed on this relay is never acknowledged",
    );
    match redial.closed().await {
        noq::ConnectionError::ApplicationClosed(app) => assert_eq!(
            u32::try_from(u64::from(app.error_code)).unwrap(),
            SLOT_NOT_HOMED_CLOSE,
            "the misrouted slot is refused with the not-homed close code",
        ),
        other => panic!("expected the not-homed application close, got {other:?}"),
    }
}
