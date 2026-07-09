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

/// Binds an ephemeral IPv4-loopback relay serving `registry` over a caller-supplied
/// mesh state, so a test can seed the session's decision-maker (marking it started
/// with an expected-slot set) before any client connects — which is what makes the
/// relay fire session-start and record forwarded turns in its per-session replay
/// ring, exactly as a coordinator descriptor would in production.
fn start_relay_with_mesh(
    registry: Registry,
    mesh: rally_point_relay::mesh::MeshState,
) -> (SocketAddr, CertificateDer<'static>) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let endpoint = quinn::Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry),
        std::sync::Arc::default(),
        mesh,
        None,
    ));
    (addr, ca)
}

/// Binds an ephemeral IPv4-loopback relay over a caller-supplied mesh state,
/// returning its address, CA, *and* the endpoint — so a test can `close()` the
/// endpoint to simulate the relay dying (client links drop and re-dials fail),
/// which is what forces the driver to escalate to re-home.
fn start_relay_killable(
    registry: Registry,
    mesh: rally_point_relay::mesh::MeshState,
) -> (SocketAddr, CertificateDer<'static>, quinn::Endpoint) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let endpoint = quinn::Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(server::serve(
        endpoint.clone(),
        Arc::new(registry),
        std::sync::Arc::default(),
        mesh,
        None,
    ));
    (addr, ca, endpoint)
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

/// Awaits one forwarded turn on `inbound`, bounded so a stall fails rather than
/// hangs.
async fn recv_turn(inbound: &mut tokio::sync::mpsc::Receiver<Payload>) -> Payload {
    tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .expect("a turn never arrived")
        .expect("the inbound channel closed")
}

/// Drains the connectivity channel until the wanted `(slot, connected)` shows,
/// ignoring the relay's own peer-connectivity frames that share the channel.
async fn wait_connectivity(
    rx: &mut tokio::sync::mpsc::Receiver<(SlotId, bool)>,
    want: (SlotId, bool),
) {
    loop {
        let got = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("connectivity signal never arrived")
            .expect("connectivity channel closed");
        if got == want {
            return;
        }
    }
}

#[tokio::test]
async fn a_dropped_client_reconnects_and_replays_the_missed_turns_exactly_once() {
    use std::collections::HashSet;

    use rally_point_client::{LinkDriver, Reconnect};
    use rally_point_proto::control::BufferBounds;
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    // The full reconnect path against a real relay: a client's link drops mid-game,
    // its driver re-dials itself while its drop is still held (undecided) presenting
    // resume cursors, the relay releases the hold and replays the turns missed
    // during the outage, and the driver folds them into the ordered stream exactly
    // once — while signalling its own disconnect then reconnect on the connectivity
    // channel, the channels staying alive throughout.
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(70);

    // Seed the session as started with the two expected slots, so the relay records
    // forwarded turns in its replay ring.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let _ = consensus::sync_maker(
        &makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));

    // Slot 0 runs with reconnection. Keep a handle to its connection so the test can
    // sever it, simulating a network drop (not a clean leave), which marks the
    // relay's drop hold and keeps the session alive.
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let conn0 = link0.connection().clone();
    let (driver0, mut chan0) = LinkDriver::new(link0);
    let reconnect0 = Reconnect {
        endpoint: ClientEndpoint::from_endpoint(endpoint.endpoint().clone()),
        relay_addr: addr,
        server_name: "localhost".to_owned(),
        relay_id: 1,
        identity: id0,
        rehome: None,
        escalate_after: None,
        escalate_retry: None,
    };
    let task0 = tokio::spawn(driver0.run_reconnecting(reconnect0));

    // Slot 1 runs plainly; it is the peer whose turns slot 0 will miss and replay.
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver1, chan1) = LinkDriver::new(link1);
    let task1 = tokio::spawn(driver1.run());

    // Both slots connected: session-start fires, so the ring now records turns.
    tokio::time::timeout(Duration::from_secs(5), chan0.session_start.recv())
        .await
        .expect("session start never fired")
        .expect("slot 0's session-start channel closed");

    // A valid SC:R build command the relay's turn validator accepts; the four turns
    // are told apart by the origin seq the sender's driver assigns (0..3), not by
    // their bytes.
    let turn = || Payload {
        commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
        ..Default::default()
    };

    // Slot 1 sends two turns; slot 0 receives them, advancing its cursor to seq 2.
    chan1.outbound.send(turn()).await.unwrap();
    chan1.outbound.send(turn()).await.unwrap();
    assert_eq!(recv_turn(&mut chan0.inbound).await.seq, 0);
    assert_eq!(recv_turn(&mut chan0.inbound).await.seq, 1);

    // Sever slot 0's link. Its driver must surface its own disconnect, not close the
    // channels.
    conn0.close(quinn::VarInt::from_u32(0), b"simulated network drop");
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), false)).await;

    // While slot 0 is away, slot 1 produces two more turns; the relay records them
    // for replay.
    chan1.outbound.send(turn()).await.unwrap();
    chan1.outbound.send(turn()).await.unwrap();

    // Slot 0 re-establishes its link while its drop is still held.
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), true)).await;

    // The relay replays the two missed turns (seq 2, 3); the driver folds them back
    // into the ordered stream, in order, each exactly once.
    let third = recv_turn(&mut chan0.inbound).await;
    let fourth = recv_turn(&mut chan0.inbound).await;
    assert_eq!(third.seq, 2);
    assert_eq!(fourth.seq, 3);
    assert_eq!(&third.commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);

    // No duplicate delivery: the dedup absorbed any overlap between the replay and
    // the resumed live stream.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), chan0.inbound.recv())
            .await
            .is_err(),
        "the missed turns must be delivered exactly once",
    );

    drop(chan0.outbound);
    drop(chan0.inbound);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

#[tokio::test]
async fn a_survivor_manually_drops_a_disconnected_peer_past_the_unlock() {
    use std::collections::HashSet;

    use rally_point_client::LinkDriver;
    use rally_point_proto::control::BufferBounds;
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    // The full manual-drop path against a real relay: one client's link dies, and
    // the surviving client asks the relay to drop it. Before the unlock floor the
    // request is refused (the drop may still be a blip); past it, the relay honors
    // the request and pushes the synced leave down the survivor's stream — the
    // dropped slot is never removed on its own, only on this human decision. The
    // dropped client's later re-dial is then refused terminally.
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(71);

    // A tiny drop-unlock floor so the test can cross it quickly. Seed this relay as
    // the authority over an expected {0, 1} set so the session starts and a decided
    // leave is real.
    let unlock = Duration::from_millis(300);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_drop_unlock(unlock);
    let makers = mesh.decision_makers.clone();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let _ = consensus::sync_maker(
        &makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));

    // Slot 0 is the client that will disconnect; keep its connection handle so the
    // test can sever it. It runs plainly (no reconnection) — its link death is the
    // disconnect the survivor then resolves manually.
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let conn0 = link0.connection().clone();
    let (driver0, chan0) = LinkDriver::new(link0);
    let task0 = tokio::spawn(driver0.run());

    // Slot 1 is the survivor who requests the drop.
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let task1 = tokio::spawn(driver1.run());

    // Both connected: the session started.
    tokio::time::timeout(Duration::from_secs(5), chan1.session_start.recv())
        .await
        .expect("session start never fired")
        .expect("slot 1's session-start channel closed");

    // A framed turn from slot 0 gives its leave an apply-frame basis; slot 1
    // receives it, so the relay has observed slot 0's frame before it disconnects.
    chan0
        .outbound
        .send(Payload {
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            game_frame_count: Some(10),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(recv_turn(&mut chan1.inbound).await.seq, 0);

    // Sever slot 0's link — a network drop, not a clean leave. Slot 1 hears the
    // disconnect; the relay records the departure and marks the drop hold.
    conn0.close(quinn::VarInt::from_u32(0), b"simulated network drop");
    wait_connectivity(&mut chan1.connectivity, (SlotId(0), false)).await;

    // Pre-unlock: the survivor requests the drop, but the hold has not stood past
    // the floor, so no leave is decided — the slot could still be a blip.
    chan1.request_drop.send(SlotId(0)).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), chan1.leaves.recv())
            .await
            .is_err(),
        "a pre-unlock request must not remove the disconnected slot",
    );

    // Past the unlock floor, the survivor requests again — now the authority honors
    // it and pushes the synced leave for slot 0 down the survivor's stream.
    tokio::time::sleep(unlock).await;
    chan1.request_drop.send(SlotId(0)).await.unwrap();
    let leave = tokio::time::timeout(Duration::from_secs(5), chan1.leaves.recv())
        .await
        .expect("the leave arrives once the request is honored past the unlock")
        .expect("slot 1's leaves channel stays open");
    assert_eq!(leave.slot, 0);
    assert_eq!(
        leave.reason, 0x4000_0006,
        "a manual drop uses the native dropped reason",
    );

    // Slot 0's later re-dial is refused terminally with the slot-departed close: its
    // leave was decided, so the game has moved on without it. This is the same
    // re-dial path the driver's own reconnection uses, which classifies that close
    // code as terminal rather than a retryable transport error.
    match endpoint
        .reconnect_with_timeout(addr, "localhost", &id0, &[], Duration::from_secs(5))
        .await
    {
        Err(DialError::SlotDeparted) => {}
        Err(other) => panic!("expected a slot-departed refusal, got {other:?}"),
        Ok(_) => panic!("the re-dial was accepted even though the slot had departed"),
    }

    drop(chan0);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

/// A re-home provider that always hands back a fixed replacement relay's target,
/// building a fresh client endpoint that pins the replacement's cert on each call —
/// standing in for the embedder's coordinator round-trip + cert pinning. It also
/// asserts the driver passes the relay id it is homed on as the dead relay, and
/// hands back the replacement relay's own id — the driver-owns-the-id contract.
struct FixedTarget {
    ca: CertificateDer<'static>,
    addr: SocketAddr,
    /// The relay id the driver must name as dead (the home relay it is on).
    expected_dead: u64,
    /// The replacement relay's id, returned in the `NewTarget` outcome.
    relay_id: u64,
}

impl rally_point_client::RehomeProvider for FixedTarget {
    fn rehome(&self, dead_relay_id: u64) -> rally_point_client::RehomeFuture<'_> {
        assert_eq!(
            dead_relay_id, self.expected_dead,
            "the driver must name the relay it is homed on as the dead one",
        );
        let ca = self.ca.clone();
        let addr = self.addr;
        let relay_id = self.relay_id;
        Box::pin(async move {
            rally_point_client::RehomeOutcome::NewTarget {
                relay_id,
                endpoint: client_endpoint(&ca),
                relay_addr: addr,
                server_name: "localhost".to_owned(),
            }
        })
    }
}

#[tokio::test]
async fn a_group_re_homes_to_a_replacement_relay_when_the_home_dies() {
    use std::collections::HashSet;

    use rally_point_client::{LinkDriver, Reconnect};
    use rally_point_proto::control::BufferBounds;
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    // The full coordinator-mediated failover path against two real relays: both
    // slots home on relay A; A dies; each driver escalates to its re-home provider,
    // which hands relay B's target; both re-home onto B (which the coordinator would
    // have pushed a `resumed` descriptor to — here seeded as already-started); a turn
    // slot 0 sent before the death reaches slot 1 exactly once (the retention ring's
    // re-injection deduped against what slot 1 already had), and a fresh turn after
    // the re-home flows over B.
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(80);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Relay A (the home). Seed its maker started with the two expected slots so it
    // records forwarded turns and fires session-start.
    let mesh_a = rally_point_relay::mesh::new_mesh_state();
    let _ = consensus::sync_maker(
        &mesh_a.decision_makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
    );
    let (addr_a, ca_a, endpoint_a) = start_relay_killable(registry_for(&[&tenant]), mesh_a);

    // Relay B (the replacement). Seed it as a resumed session (already started), as a
    // rehome descriptor from the coordinator would.
    let mesh_b = rally_point_relay::mesh::new_mesh_state();
    let _ = consensus::sync_maker(
        &mesh_b.decision_makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
    );
    consensus::mark_session_started(&mesh_b.decision_makers, &key);
    let (addr_b, ca_b, _endpoint_b) = start_relay_killable(registry_for(&[&tenant]), mesh_b);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));

    // Per-slot client endpoints trusting relay A, used for the initial connect and
    // then moved into each `Reconnect` for same-relay re-dials.
    let ep0 = client_endpoint(&ca_a);
    let ep1 = client_endpoint(&ca_a);

    let link0 = ep0.connect(addr_a, "localhost", &id0).await.unwrap();
    let (driver0, mut chan0) = LinkDriver::new(link0);
    let link1 = ep1.connect(addr_a, "localhost", &id1).await.unwrap();
    let (driver1, mut chan1) = LinkDriver::new(link1);

    // Both drivers re-home to relay B when A stays unreachable. A short escalation
    // window keeps the test fast (a cert/pin rejection would escalate at once; here
    // the dead relay just stops responding, so the timed window drives it).
    // Relay A is id 1 (the home the drivers start on); relay B is id 2 (the
    // replacement). The drivers seed their current relay id as A's and must name it
    // as the dead relay when they escalate.
    let reconnect0 = Reconnect {
        endpoint: ep0,
        relay_addr: addr_a,
        server_name: "localhost".to_owned(),
        relay_id: 1,
        identity: id0,
        rehome: Some(Arc::new(FixedTarget {
            ca: ca_b.clone(),
            addr: addr_b,
            expected_dead: 1,
            relay_id: 2,
        })),
        escalate_after: Some(Duration::from_millis(50)),
        escalate_retry: Some(Duration::from_millis(50)),
    };
    let reconnect1 = Reconnect {
        endpoint: ep1,
        relay_addr: addr_a,
        server_name: "localhost".to_owned(),
        relay_id: 1,
        identity: id1,
        rehome: Some(Arc::new(FixedTarget {
            ca: ca_b.clone(),
            addr: addr_b,
            expected_dead: 1,
            relay_id: 2,
        })),
        escalate_after: Some(Duration::from_millis(50)),
        escalate_retry: Some(Duration::from_millis(50)),
    };
    let task0 = tokio::spawn(driver0.run_reconnecting(reconnect0));
    let task1 = tokio::spawn(driver1.run_reconnecting(reconnect1));

    // Both connected to A: session-start fires.
    tokio::time::timeout(Duration::from_secs(5), chan0.session_start.recv())
        .await
        .expect("session start never fired on slot 0")
        .expect("slot 0's session-start channel closed");

    let turn = || Payload {
        commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
        ..Default::default()
    };

    // Slot 0 sends a turn over relay A; slot 1 receives it (seq 0).
    chan0.outbound.send(turn()).await.unwrap();
    assert_eq!(recv_turn(&mut chan1.inbound).await.seq, 0);

    // Relay A dies: closing its endpoint drops both client links and makes re-dials
    // to A fail, so each driver escalates to its re-home provider.
    endpoint_a.close(quinn::VarInt::from_u32(0), b"relay A down");

    // Each driver surfaces its own disconnect, then re-homes onto relay B.
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), false)).await;
    wait_connectivity(&mut chan1.connectivity, (SlotId(1), false)).await;
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), true)).await;
    wait_connectivity(&mut chan1.connectivity, (SlotId(1), true)).await;

    // A fresh turn slot 0 sends after the re-home flows over relay B to slot 1 —
    // and it is the very next turn slot 1 sees, so the pre-death turn (which slot 0's
    // retention ring re-injected onto B) was deduped, delivered exactly once.
    chan0.outbound.send(turn()).await.unwrap();
    let after = recv_turn(&mut chan1.inbound).await;
    assert_eq!(
        after.seq, 1,
        "slot 1 sees the post-rehome turn next; the re-injected seq 0 was deduped, not re-delivered",
    );
    assert_eq!(&after.commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);

    drop(chan0.outbound);
    drop(chan0.inbound);
    drop(chan1.outbound);
    drop(chan1.inbound);
    let _ = task0.await;
    let _ = task1.await;
}

#[tokio::test]
async fn a_re_homed_clients_high_seq_own_turn_is_accepted_by_the_fresh_relay() {
    use std::collections::HashSet;

    use rally_point_proto::control::BufferBounds;
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    // Regression for the re-home receive-window bug (the confirmed-disconnect-tier
    // failure). A client re-homing onto a fresh relay resumes its own slot's seq
    // stream mid-way — it kept counting across the move and re-injects only a recent
    // retention ring, never seq 0 onward. The fresh relay's dedup would base that
    // slot's receive window at 0, so once the resumed seq passed the window (4096) it
    // was rejected as out-of-window and the link dropped. Because every re-homed slot
    // crosses the window at the same absolute seq, that tore down the whole group at
    // once — so a peer death after the re-home never reached the survivor as a
    // relay-confirmed disconnect (the game stayed at "stall", never "confirmed").
    //
    // The driver now declares an own-slot resume anchor on the re-home dial and the
    // relay bases the window there, so the resumed high-seq stream is accepted and
    // the link survives — which is what lets the ordinary post-drop connectivity /
    // leave machinery (covered by the drop/reconnect tests above) confirm to the
    // survivor exactly as in a non-re-homed game.
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(90);

    // Seed the relay as a resumed, already-started session over {0, 1}, standing in
    // for the replacement relay the coordinator pushed a `resumed` descriptor to.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let _ = consensus::sync_maker(
        &mesh.decision_makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
    );
    consensus::mark_session_started(&mesh.decision_makers, &key);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));

    // The seq the re-homing client resumes at — far past the from-zero window (4096).
    const ANCHOR: u64 = 5000;

    // The peer receives on a raw link whose receive window for the sender's slot is
    // anchored to the resume point — modeling a survivor already caught up on slot 0's
    // stream over the game (its own dedup never resets: the driver rebinds and keeps
    // it). The bug under test is the *relay's* fresh own-slot window, not this one.
    let mut peer = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    peer.anchor_receive_window(SlotId(0), ANCHOR);

    // Slot 0 dials as a re-home: it presents an own-slot resume anchor at the high
    // seq, exactly as the driver now does from its retention ring's front.
    let mut link0 = endpoint
        .reconnect_with_timeout(
            addr,
            "localhost",
            &id0,
            &[(SlotId(0), ANCHOR)],
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    // Slot 0 sends a turn at the anchored high seq — beyond a from-zero window. With
    // the anchor the relay accepts and forwards it; without it the relay would reject
    // it as out-of-window and close slot 0's link, and the peer would never see it. A
    // raw link runs no redundancy of its own, so re-send until it lands (or the outer
    // timeout fails the test), skipping the relay's ack-only maintenance packets.
    let turn = Payload {
        seq: ANCHOR,
        slot: 0,
        commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
        ..Default::default()
    };
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            link0.send(Some(turn.clone())).unwrap();
            if let Ok(Ok(received)) =
                tokio::time::timeout(Duration::from_millis(200), peer.recv()).await
                && let Some(payload) = received.fresh.into_iter().find(|p| p.seq == ANCHOR)
            {
                return payload;
            }
        }
    })
    .await
    .expect("the re-homed high-seq turn never crossed the relay (window not anchored)");
    assert_eq!(got.seq, ANCHOR);
    assert_eq!(got.slot, 0, "bound to the sender's authorized slot, like any turn");
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
