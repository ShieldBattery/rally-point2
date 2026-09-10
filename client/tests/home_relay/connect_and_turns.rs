//! Dialing a relay: the happy path (plain bind, IPv4/IPv6, wildcard), the
//! failure modes (wrong signing key, untrusted cert, a stalled peer), and the
//! basic turn path once connected — including the oversize-turn control-stream
//! detour and the initial buffer depth the driver surfaces at session start.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rally_point_client::{ClientEndpoint, DialError, Identity};
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_proto::token::PUBLIC_KEY_LEN;
use rally_point_transport::quic::server_config;
use rally_point_transport::{noq, rustls};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::helpers::{
    KID, TENANT, client_endpoint, identity_for, make_tenant, mint_token, registry_for, self_signed,
    start_relay, start_relay_on, start_relay_with_mesh,
};

#[tokio::test]
async fn two_clients_exchange_a_turn_through_the_relay() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(42);

    // Both clients must be authorized before the turn is sent, or fan-out has no
    // peer to reach — the relay does not buffer for not-yet-connected slots.
    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let mut slot0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let mut slot1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();

    // A build, sent with a wire slot the relay must overwrite with the authorized 0.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 9,
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();

    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot1.recv().await.unwrap().fresh;
    }

    assert_eq!(delivered.len(), 1);
    let turn = &delivered[0];
    // Bound to the authorized slot, not the value on the wire.
    assert_eq!(turn.slot, 0);
    // The gameplay command passes through verbatim.
    assert_eq!(&turn.commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);
}

#[tokio::test]
async fn an_oversize_turn_crosses_the_relay_via_control_streams() {
    use rally_point_client::LinkDriver;

    // The full production path for a turn too large to ever ride a datagram:
    // the sending driver diverts it onto its control stream, the relay
    // validates it like any turn and fans it out, the relay's egress diverts
    // it again onto the recipient's control stream, and the receiving driver
    // folds it back into the ordered turn stream between its datagram
    // neighbors.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(43);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver0, chan0) = LinkDriver::new(link0);
    let (driver1, chan1) = LinkDriver::new(link1);
    let task0 = tokio::spawn(driver0.run());
    let task1 = tokio::spawn(driver1.run());

    // The oversize turn must survive the relay's validator, so it is a long
    // run of well-formed commands, not padding: 500 build commands ≈ 4KB —
    // far past any datagram budget.
    let build = [0x0C, 1, 2, 3, 4, 5, 6, 7];
    let oversize: Vec<u8> = build
        .iter()
        .copied()
        .cycle()
        .take(build.len() * 500)
        .collect();

    let turn = |commands: &[u8]| Payload {
        commands: commands.to_vec().into(),
        ..Default::default()
    };
    chan0.outbound.send(turn(&build)).await.unwrap();
    chan0.outbound.send(turn(&oversize)).await.unwrap();
    chan0.outbound.send(turn(&build)).await.unwrap();

    let mut inbound1 = chan1.inbound;
    let mut got = Vec::new();
    while got.len() < 3 {
        let payload = tokio::time::timeout(Duration::from_secs(5), inbound1.recv())
            .await
            .expect("the oversize turn never crossed the relay")
            .expect("driver 1 closed early");
        got.push(payload);
    }
    assert_eq!(
        got.iter().map(|p| p.seq).collect::<Vec<_>>(),
        vec![0, 1, 2],
        "one ordered stream regardless of which path each turn took",
    );
    assert_eq!(got[1].commands.len(), oversize.len());
    assert_eq!(&got[1].commands[..], &oversize[..]);
    // Bound to the sender's authorized slot at the relay, like any turn.
    assert!(got.iter().all(|p| p.slot == 0));

    drop(chan0.outbound);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

#[tokio::test]
async fn connect_fails_when_the_signing_key_does_not_match_the_token() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);

    // Mint a token committing to one client key, but build the identity from a
    // different, unrelated key — so the challenge is answered with the wrong key.
    let rng = SystemRandom::new();
    let committed =
        Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
    let committed_pub: [u8; PUBLIC_KEY_LEN] = committed.public_key().as_ref().try_into().unwrap();
    let token = mint_token(&tenant, SessionId(1), SlotId(0), committed_pub);

    let other_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let identity = Identity::from_pkcs8(token, other_pkcs8.as_ref()).unwrap();

    // The relay rejects the challenge response and closes the connection, so the
    // client never reads an acknowledgement.
    assert!(
        endpoint
            .connect(addr, "localhost", &identity)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn connect_fails_against_an_untrusted_relay_certificate() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, _ca) = start_relay(registry_for(&[&tenant]));

    // A client that trusts a *different* CA than the one the relay presents must
    // fail the TLS handshake before any authorization happens.
    let (_chain, _key, unrelated_ca) = self_signed();
    let endpoint = client_endpoint(&unrelated_ca);
    let identity = identity_for(&tenant, SessionId(1), SlotId(0));

    assert!(
        endpoint
            .connect(addr, "localhost", &identity)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn connect_times_out_when_the_peer_stalls_during_authorization() {
    // A peer that completes TLS with a cert the client trusts and accepts the
    // connection, but never sends the connection-binding challenge — the exact
    // stall the dial must bound rather than wait on forever.
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let stalled = noq::Endpoint::server(server_cfg, bind).unwrap();
    let addr = stalled.local_addr().unwrap();
    tokio::spawn(async move {
        // Accept the connection and the handshake stream, then keep both stream
        // halves open — never sending the challenge, never finishing the stream,
        // never closing the connection — so the client blocks on its challenge read.
        if let Some(incoming) = stalled.accept().await
            && let Ok(connection) = incoming.await
            && let Ok((_send, _recv)) = connection.accept_bi().await
        {
            std::future::pending::<()>().await;
        }
    });

    let tenant = make_tenant(KID, TENANT);
    let endpoint = client_endpoint(&ca);
    let identity = identity_for(&tenant, SessionId(1), SlotId(0));

    // Map the link away so the outcome is `Debug` for the assertion message.
    let outcome = endpoint
        .connect_with_timeout(addr, "localhost", &identity, Duration::from_millis(300))
        .await
        .map(|_link| ());
    assert!(
        matches!(outcome, Err(DialError::TimedOut { .. })),
        "expected a timeout, got {outcome:?}"
    );
}

#[tokio::test]
async fn bind_builds_a_usable_endpoint() {
    // The convenience constructor binds a real local socket even with no trusted
    // roots; trust only matters once it dials a relay.
    let endpoint = ClientEndpoint::bind(rustls::RootCertStore::empty()).unwrap();
    assert!(endpoint.endpoint().local_addr().is_ok());
}

#[tokio::test]
async fn bind_dials_an_ipv6_relay() {
    // The deployment is IPv6-primary, so the dual-stack default endpoint must reach
    // a relay listening on IPv6 — the case an IPv4-only endpoint would reject.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay_on((Ipv6Addr::LOCALHOST, 0).into(), registry_for(&[&tenant]));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let endpoint = ClientEndpoint::bind(roots).unwrap();
    let identity = identity_for(&tenant, SessionId(7), SlotId(0));

    let outcome = endpoint
        .connect(addr, "localhost", &identity)
        .await
        .map(|_link| ());
    assert!(
        outcome.is_ok(),
        "dual-stack bind failed to dial IPv6 relay: {outcome:?}"
    );
}

#[tokio::test]
async fn wildcard_relay_accepts_ipv4_and_ipv6_clients() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay_on((Ipv6Addr::UNSPECIFIED, 0).into(), registry_for(&[&tenant]));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let endpoint = ClientEndpoint::bind(roots).unwrap();

    let ipv4 = (Ipv4Addr::LOCALHOST, addr.port()).into();
    let ipv6 = (Ipv6Addr::LOCALHOST, addr.port()).into();
    let id0 = identity_for(&tenant, SessionId(8), SlotId(0));
    let id1 = identity_for(&tenant, SessionId(8), SlotId(1));
    let _link0 = endpoint.connect(ipv4, "localhost", &id0).await.unwrap();
    let _link1 = endpoint.connect(ipv6, "localhost", &id1).await.unwrap();
}

/// The relay-computed initial buffer depth stamped onto SessionStart reaches the
/// game through the client driver's `session_start` channel — the end-to-end
/// surface the DLL reads to seed the game's turn buffer before frame 0.
#[tokio::test]
async fn the_driver_surfaces_the_initial_buffer_depth_on_the_session_start_channel() {
    use std::collections::HashSet;

    use rally_point_client::LinkDriver;
    use rally_point_proto::control::BufferBounds;
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(71);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Seed the authority over the two expected slots, then feed it a large one-way
    // latency hint (400ms) and the multi-relay flag, so the initial-depth
    // computation is hint-dominated and deterministic: 400ms is 10 turns, a
    // multi-relay session is never fully observed, so the depth is
    // max(observed, 10) + 1 hop cushion = 11 (the localhost handshake RTT stays
    // far below the hint).
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let _ = consensus::sync_maker(
        &mesh.decision_makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    consensus::set_session_shape(&mesh.decision_makers, &key, Some(400), false);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));

    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let (driver0, mut chan0) = LinkDriver::new(link0);
    let task0 = tokio::spawn(driver0.run());
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver1, _chan1) = LinkDriver::new(link1);
    let task1 = tokio::spawn(driver1.run());

    // Both connected: session-start fires, and the driver surfaces the stamped
    // depth on the channel the game reads before frame 0.
    let depth = tokio::time::timeout(Duration::from_secs(5), chan0.session_start.recv())
        .await
        .expect("session start never fired")
        .expect("slot 0's session-start channel closed");
    assert_eq!(
        depth,
        Some(11),
        "the driver surfaces the relay-computed initial buffer depth",
    );

    drop(chan0);
    let _ = tokio::time::timeout(Duration::from_secs(5), task0).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), task1).await;
}
