//! Closes the `C–S–C` loop with real code on both ends: real clients (this
//! crate) authorize against a real relay (`rally-point-relay`) over loopback
//! QUIC, and a turn from one client is validated and fanned out to the other.
//!
//! Where `relay/tests/client_edge.rs` drove the client side of the handshake by
//! hand, these exercise the actual client transport — the same handshake codec on
//! both ends — so a drift in the wire framing would fail here.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_client::{ClientEndpoint, DialError, Identity};
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_proto::token::{
    ClientPublicKey, ExpiresAt, KeyId, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, SignedToken,
    TokenClaims,
};
use rally_point_relay::auth::Registry;
use rally_point_relay::server;
use rally_point_transport::quic::{client_config, server_config};
use rally_point_transport::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rally_point_transport::{quinn, rustls};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const KID: &str = "staging-key-1";
const TENANT: &str = "sb-staging";

/// A tenant the relay trusts: a signing key, the `kid` that names it, and the
/// tenant id it's bound to.
struct Tenant {
    kid: String,
    name: String,
    key: Ed25519KeyPair,
    public: [u8; PUBLIC_KEY_LEN],
}

fn make_tenant(kid: &str, name: &str) -> Tenant {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public = key.public_key().as_ref().try_into().unwrap();
    Tenant {
        kid: kid.to_owned(),
        name: name.to_owned(),
        key,
        public,
    }
}

/// Mints a token for `slot` in `session`, signed by `tenant`'s key and carrying
/// its `kid` and tenant id, embedding `client_pub` as the connection-binding key
/// and never expiring.
fn mint_token(
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
    client_pub: [u8; PUBLIC_KEY_LEN],
) -> SignedToken {
    let claims = TokenClaims::new(
        TenantId(tenant.name.clone()),
        session,
        slot,
        ExpiresAt(u64::MAX),
        ClientPublicKey(client_pub),
    );
    let mut token = SignedToken::from_parts(
        KeyId(tenant.kid.clone()),
        claims,
        Signature([0; SIGNATURE_LEN]),
    );
    let mut message = Vec::new();
    token.signed_message(&mut message).unwrap();
    token.signature = Signature(tenant.key.sign(&message).as_ref().try_into().unwrap());
    token
}

/// A self-signed cert + key for the relay, plus the cert alone to seed a client's
/// trust roots.
fn self_signed() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (vec![cert_der.clone()], key, cert_der)
}

/// Binds a relay endpoint on `bind` serving `registry`, returning its actual
/// address and the CA a client trusts to reach it.
fn start_relay_on(bind: SocketAddr, registry: Registry) -> (SocketAddr, CertificateDer<'static>) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let endpoint = quinn::Endpoint::server(server_cfg, bind).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry),
        std::sync::Arc::default(),
        rally_point_relay::mesh::new_mesh_state(),
        None,
    ));
    (addr, ca)
}

/// Binds an ephemeral IPv4-loopback relay endpoint serving `registry`.
fn start_relay(registry: Registry) -> (SocketAddr, CertificateDer<'static>) {
    start_relay_on((Ipv4Addr::LOCALHOST, 0).into(), registry)
}

/// A registry trusting each of `tenants`.
fn registry_for(tenants: &[&Tenant]) -> Registry {
    let mut registry = Registry::new();
    for tenant in tenants {
        registry.insert(
            KeyId(tenant.kid.clone()),
            TenantId(tenant.name.clone()),
            tenant.public,
        );
    }
    registry
}

/// A client endpoint trusting `ca`, bound to loopback so the test is deterministic.
fn client_endpoint(ca: &CertificateDer<'static>) -> ClientEndpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let mut endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    endpoint.set_default_client_config(client_config(roots).unwrap());
    ClientEndpoint::from_endpoint(endpoint)
}

/// Generates a fresh client keypair, mints a matching token for `slot`, and bundles
/// them as an [`Identity`] — the credentials the app would hand the game DLL.
fn identity_for(tenant: &Tenant, session: SessionId, slot: SlotId) -> Identity {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public: [u8; PUBLIC_KEY_LEN] = pair.public_key().as_ref().try_into().unwrap();
    let token = mint_token(tenant, session, slot, public);
    Identity::from_pkcs8(token, pkcs8.as_ref()).unwrap()
}

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
async fn two_clients_exchange_lobby_commands_through_the_relay() {
    use rally_point_client::LinkDriver;

    // The full pre-game path through the real client transport: each client
    // authors lobby commands on its `lobby_out` seam, the driver sends them up
    // its control stream, the relay stamps the authoring slot and fans them down
    // the other member's control stream, and that driver surfaces them on
    // `lobby_in` tagged with the author's slot. The relay never parses the bytes.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(50);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver0, mut chan0) = LinkDriver::new(link0);
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let task0 = tokio::spawn(driver0.run());
    let task1 = tokio::spawn(driver1.run());

    // Host (slot 0) authors a lobby command; slot 1 receives it stamped slot 0.
    chan0.lobby_out.send(vec![0x0C, 1, 2, 3]).await.unwrap();
    let (author, bytes) = tokio::time::timeout(Duration::from_secs(5), chan1.lobby_in.recv())
        .await
        .expect("slot 1 never received the host's lobby command")
        .expect("driver 1 closed early");
    assert_eq!(author, SlotId(0));
    assert_eq!(bytes, vec![0x0C, 1, 2, 3]);

    // Slot 1 replies with its own; the host receives it stamped slot 1 — the
    // relay binds the author to the authenticated slot, never the wire value.
    chan1.lobby_out.send(vec![0x09, 0xAB]).await.unwrap();
    let (author, bytes) = tokio::time::timeout(Duration::from_secs(5), chan0.lobby_in.recv())
        .await
        .expect("the host never received slot 1's lobby command")
        .expect("driver 0 closed early");
    assert_eq!(author, SlotId(1));
    assert_eq!(bytes, vec![0x09, 0xAB]);

    drop(chan0.outbound);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

#[tokio::test]
async fn a_lobby_command_is_replayed_to_a_late_joining_client() {
    use rally_point_client::LinkDriver;

    // A member dialing in after the host already sent its setup commands still
    // receives the whole sequence, in order — the relay's per-session replay log
    // catches it up before it tails live commands.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(51);

    // Only the host connects and authors its setup commands — before the peer
    // exists, so a plain fan-out would lose them.
    let id0 = identity_for(&tenant, session, SlotId(0));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let (driver0, chan0) = LinkDriver::new(link0);
    let task0 = tokio::spawn(driver0.run());
    for command in [vec![0x01u8], vec![0x02], vec![0x03]] {
        chan0.lobby_out.send(command).await.unwrap();
    }
    // Let the driver send them up and the relay append them to its log.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The peer dials late and replays the whole sequence, in order, stamped with
    // the host's slot.
    let id1 = identity_for(&tenant, session, SlotId(1));
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let task1 = tokio::spawn(driver1.run());

    let mut got = Vec::new();
    while got.len() < 3 {
        let (author, bytes) = tokio::time::timeout(Duration::from_secs(5), chan1.lobby_in.recv())
            .await
            .expect("the late-joining peer's replay stalled")
            .expect("driver 1 closed early");
        assert_eq!(author, SlotId(0));
        got.push(bytes);
    }
    assert_eq!(got, vec![vec![0x01], vec![0x02], vec![0x03]]);

    drop(chan0.outbound);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

#[tokio::test]
async fn a_game_chat_message_reaches_other_members_with_the_relay_stamped_slot() {
    use rally_point_client::{ChatOut, LinkDriver};

    // The full production path for in-game chat: a member authors a message on
    // its `chat_out` seam, the driver sends it up its control stream, the relay
    // stamps the authoring slot and fans it down every other member's control
    // stream, and each driver surfaces it on `chat_in` tagged with the author's
    // slot. Three members (A sends, B and C receive) proves the fan-out, and the
    // relay-stamp proof mirrors the lobby test: the driver always sends `slot: 0`
    // regardless of which client it's wrapping, so the different authoritative
    // slots each peer sees can only come from the relay's own stamp.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(60);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let id2 = identity_for(&tenant, session, SlotId(2));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let link2 = endpoint.connect(addr, "localhost", &id2).await.unwrap();
    let (driver0, mut chan0) = LinkDriver::new(link0);
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let (driver2, mut chan2) = LinkDriver::new(link2);
    let task0 = tokio::spawn(driver0.run());
    let task1 = tokio::spawn(driver1.run());
    let task2 = tokio::spawn(driver2.run());

    // Slot 0 sends an all-chat message; slots 1 and 2 both receive it, tagged
    // with the author's slot, and its scope fields pass through verbatim.
    chan0
        .chat_out
        .send(ChatOut {
            target_kind: 0,
            target_slot: 0,
            text: "gl hf".to_owned(),
        })
        .await
        .unwrap();
    for chan in [&mut chan1, &mut chan2] {
        let (author, msg) = tokio::time::timeout(Duration::from_secs(5), chan.chat_in.recv())
            .await
            .expect("member never received the chat message")
            .expect("driver closed early");
        assert_eq!(author, SlotId(0));
        assert_eq!(msg.target_kind, 0);
        assert_eq!(msg.target_slot, 0);
        assert_eq!(msg.text, "gl hf");
    }

    // Slot 1 replies with a targeted message; slot 0 receives it stamped slot 1
    // with the target fields preserved — the relay never interprets them.
    chan1
        .chat_out
        .send(ChatOut {
            target_kind: 3,
            target_slot: 2,
            text: "psst".to_owned(),
        })
        .await
        .unwrap();
    let (author, msg) = tokio::time::timeout(Duration::from_secs(5), chan0.chat_in.recv())
        .await
        .expect("slot 0 never received slot 1's message")
        .expect("driver 0 closed early");
    assert_eq!(author, SlotId(1));
    assert_eq!(msg.target_kind, 3);
    assert_eq!(msg.target_slot, 2);
    assert_eq!(msg.text, "psst");

    drop(chan0.outbound);
    drop(chan1.outbound);
    drop(chan2.outbound);
    let _ = task0.await;
    let _ = task1.await;
    let _ = task2.await;
}

#[tokio::test]
async fn an_oversize_game_chat_message_is_dropped_but_the_session_keeps_working() {
    use rally_point_client::{ChatOut, LinkDriver};

    // The relay's size cap drops an over-cap chat message without closing the
    // connection — the client driver enforces no cap of its own, so this proves
    // the relay is the one refusing it, and that a well-formed message right
    // after still gets through.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(61);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver0, chan0) = LinkDriver::new(link0);
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let task0 = tokio::spawn(driver0.run());
    let task1 = tokio::spawn(driver1.run());

    // 257 bytes: one past the relay's 256-byte cap.
    let oversize = "x".repeat(257);
    chan0
        .chat_out
        .send(ChatOut {
            target_kind: 0,
            target_slot: 0,
            text: oversize,
        })
        .await
        .unwrap();

    // A well-formed message right behind it still arrives — proving the
    // connection survived the drop rather than being closed.
    chan0
        .chat_out
        .send(ChatOut {
            target_kind: 0,
            target_slot: 0,
            text: "still here".to_owned(),
        })
        .await
        .unwrap();

    let (author, msg) = tokio::time::timeout(Duration::from_secs(5), chan1.chat_in.recv())
        .await
        .expect("the well-formed message following the oversize one never arrived")
        .expect("driver 1 closed early");
    assert_eq!(author, SlotId(0));
    assert_eq!(msg.text, "still here");

    // Confirm the oversize message was truly dropped, not just delayed: nothing
    // else is waiting.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), chan1.chat_in.recv())
            .await
            .is_err(),
        "the oversize message must never have been delivered"
    );

    drop(chan0.outbound);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

#[tokio::test]
async fn a_burst_of_game_chat_past_the_rate_cap_is_dropped_then_recovers() {
    use rally_point_client::{ChatOut, LinkDriver};

    // The relay's per-slot rate cap allows a burst of 8, then drops further
    // messages until the token bucket refills (one token per 500ms) — proving
    // both the drop and the later recovery, with the session staying up
    // throughout.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(62);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver0, chan0) = LinkDriver::new(link0);
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let task0 = tokio::spawn(driver0.run());
    let task1 = tokio::spawn(driver1.run());

    let send = |text: &str| {
        let text = text.to_owned();
        let sender = chan0.chat_out.clone();
        async move {
            sender
                .send(ChatOut {
                    target_kind: 0,
                    target_slot: 0,
                    text,
                })
                .await
                .unwrap();
        }
    };

    // A burst of 9: the cap's burst size (8) plus one over.
    for i in 0..9u32 {
        send(&format!("msg{i}")).await;
    }

    // Exactly 8 arrive — the 9th was dropped by the relay's rate cap.
    let mut got = Vec::new();
    for _ in 0..8 {
        let (author, msg) = tokio::time::timeout(Duration::from_secs(5), chan1.chat_in.recv())
            .await
            .expect("expected message never arrived")
            .expect("driver 1 closed early");
        assert_eq!(author, SlotId(0));
        got.push(msg.text);
    }
    assert_eq!(
        got,
        (0..8).map(|i| format!("msg{i}")).collect::<Vec<_>>(),
        "only the first 8 of the burst were admitted"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), chan1.chat_in.recv())
            .await
            .is_err(),
        "the 9th message must have been dropped by the rate cap"
    );

    // After the refill interval (500ms/token) passes, the slot has budget again.
    tokio::time::sleep(Duration::from_millis(600)).await;
    send("recovered").await;
    let (author, msg) = tokio::time::timeout(Duration::from_secs(5), chan1.chat_in.recv())
        .await
        .expect("the post-refill message never arrived")
        .expect("driver 1 closed early");
    assert_eq!(author, SlotId(0));
    assert_eq!(msg.text, "recovered");

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
    let stalled = quinn::Endpoint::server(server_cfg, bind).unwrap();
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
