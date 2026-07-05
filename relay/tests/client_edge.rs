//! End-to-end coverage of the relay's client-facing edge over loopback QUIC.
//!
//! Each test stands up a real relay endpoint and drives the client side of the
//! authorization handshake by hand — there is no client crate doing it yet, so
//! these tests are also the executable spec for the handshake's wire shape: a
//! `u16`-LE-prefixed token, a 32-byte challenge, a 64-byte response, then the
//! relay's one acknowledgement byte. Past that the connection carries turns as
//! transport [`Link`] datagrams exactly as the client will.

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_proto::token::{
    CHALLENGE_LEN, CHANNEL_BINDING_EXPORTER_LABEL, CHANNEL_BINDING_LEN, ClientPublicKey,
    ConnectionChallenge, ExpiresAt, KeyId, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, SignedToken,
    TokenClaims,
};
use rally_point_relay::auth::{HANDSHAKE_OK, Registry};
use rally_point_relay::server;
use rally_point_transport::quic::{client_config, server_config};
use rally_point_transport::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rally_point_transport::{Link, quinn, rustls};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const KID: &str = "staging-key-1";
const TENANT: &str = "sb-staging";

type AnyError = Box<dyn Error + Send + Sync>;

/// An Ed25519 keypair usable both to sign (tenant or client) and to publish its
/// public key.
struct Keypair {
    pair: Ed25519KeyPair,
    public: [u8; PUBLIC_KEY_LEN],
}

fn keypair() -> Keypair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public = pair.public_key().as_ref().try_into().unwrap();
    Keypair { pair, public }
}

impl Keypair {
    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.pair.sign(message).as_ref().try_into().unwrap()
    }
}

/// A tenant the relay trusts: a signing key, the `kid` that names it, and the
/// tenant id it's bound to.
struct Tenant {
    kid: String,
    name: String,
    key: Keypair,
}

fn make_tenant(kid: &str, name: &str) -> Tenant {
    Tenant {
        kid: kid.to_owned(),
        name: name.to_owned(),
        key: keypair(),
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
    token.signature = Signature(tenant.key.sign(&message));
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

/// Binds an ephemeral relay endpoint serving `registry`, returning its address
/// and the CA a client trusts to reach it.
fn start_relay(registry: Registry) -> (SocketAddr, CertificateDer<'static>) {
    start_relay_with_mesh(registry, rally_point_relay::mesh::new_mesh_state())
}

/// [`start_relay`] with a caller-supplied [`MeshState`], so a test can hold its
/// decision-maker registry (to seed a pending buffer change) or its mesh links.
fn start_relay_with_mesh(
    registry: Registry,
    mesh: rally_point_relay::mesh::MeshState,
) -> (SocketAddr, CertificateDer<'static>) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let endpoint = quinn::Endpoint::server(server_cfg, bind).unwrap();
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

/// A client endpoint trusting `ca`. One endpoint can dial the relay for several
/// slots; the caller keeps it alive for as long as its connections are needed.
fn client_endpoint(ca: &CertificateDer<'static>) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let mut endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    endpoint.set_default_client_config(client_config(roots).unwrap());
    endpoint
}

/// A registry trusting each of `tenants`.
fn registry_for(tenants: &[&Tenant]) -> Registry {
    let mut registry = Registry::new();
    for tenant in tenants {
        registry.insert(
            KeyId(tenant.kid.clone()),
            TenantId(tenant.name.clone()),
            tenant.key.public,
        );
    }
    registry
}

/// Runs the client side of the handshake on `connection`: present `token`, answer
/// the relay's challenge with `signing_key`, and confirm the acknowledgement.
///
/// `signing_key` is passed separately from the token's embedded public key so a
/// test can deliberately answer with the wrong key.
async fn handshake(
    connection: &quinn::Connection,
    token: &SignedToken,
    signing_key: &Keypair,
) -> Result<(), AnyError> {
    let (mut send, mut recv) = connection.open_bi().await?;

    let encoded = token.encode()?;
    let len = u16::try_from(encoded.len())?;
    send.write_all(&len.to_le_bytes()).await?;
    send.write_all(&encoded).await?;

    let mut challenge = [0u8; CHALLENGE_LEN];
    recv.read_exact(&mut challenge).await?;
    let mut channel_binding = [0u8; CHANNEL_BINDING_LEN];
    connection
        .export_keying_material(&mut channel_binding, CHANNEL_BINDING_EXPORTER_LABEL, &[])
        .map_err(|_| "deriving channel binding failed")?;
    let response =
        signing_key.sign(&ConnectionChallenge(challenge).signed_message(&channel_binding));
    send.write_all(&response).await?;

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await?;
    if ack[0] != HANDSHAKE_OK {
        return Err("relay did not acknowledge".into());
    }
    Ok(())
}

/// Connects a client for `slot`, completes the handshake, and returns the
/// connection wrapped as a transport link ready to carry turns.
async fn connect_slot(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
) -> Link {
    let client_key = keypair();
    let token = mint_token(tenant, session, slot, client_key.public);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    handshake(&connection, &token, &client_key).await.unwrap();
    Link::new(connection)
}

#[tokio::test]
async fn fans_a_validated_turn_to_the_other_slot() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(42);

    // Both clients must be registered before the turn is sent, or fan-out has no
    // peer to reach — the relay does not buffer for not-yet-connected slots.
    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // A keep-alive, a client-injected latency change (relay strips it), and a
    // build. The wire slot is a lie the relay must overwrite with the authorized 0.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 9,
            commands: vec![0x05, 0x55, 0x02, 0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
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
    // The latency control is stripped; gameplay commands pass through verbatim.
    assert_eq!(&turn.commands[..], &[0x05, 0x0C, 1, 2, 3, 4, 5, 6, 7]);
}

#[tokio::test]
async fn stamps_a_pending_buffer_directive_onto_a_forwarded_turn() {
    use rally_point_proto::ids::GameFrameCount;
    use rally_point_proto::messages::{LinkConditions, SlotConditions};
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(77);

    // Seed a buffer decision into the relay's decision-maker before any client
    // connects: create the session's maker as the authority, then feed it a
    // high-RTT sample so it decides to raise the buffer and queues that change
    // for broadcast. Holding the registry that `MeshState` carries is what lets
    // the test set this up; the relay's turn path then stamps it.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
    );
    // A framed turn was observed at frame 1, then a 150ms RTT sample -> target
    // 4 turns, raised from the min of 0, so the pending directive names buffer
    // 4 applied a horizon past frame 1.
    consensus::observe_frame(&makers, &key, SlotId(0), GameFrameCount(1));
    let seed = LinkConditions {
        slots: vec![SlotConditions {
            slot: 0,
            rtt_us: 150_000,
            lost_packets: 0,
            sent_packets: 100,
        }],
    };
    let decision = consensus::ingest_local_conditions(&makers, &key, &seed)
        .expect("the seeded high-RTT sample raises the buffer");

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // Slot 0 sends a plain build with no frame of its own. The relay's live
    // loopback samples can't displace the seeded decision (a raise needs a
    // worse target than the seeded 150ms; a lower is dwell-gated), so the
    // pending directive stands, and the relay forwards the turn to slot 1.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();

    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot1.recv().await.unwrap().fresh;
    }

    // The forwarded turn carries the buffer change the relay decided: slot 1 now
    // learns the new buffer and the frame to apply it at, riding the turn stream
    // it already receives — no separate channel, no forged command.
    let turn = &delivered[0];
    let directive = turn
        .buffer_directive
        .as_ref()
        .expect("the forwarded turn carries the pending buffer directive");
    assert_eq!(directive.buffer_turns, 4);
    assert_eq!(directive.apply_at_frame, decision.applied_frame.0);
    // The command bytes are untouched — the directive is envelope metadata, not a
    // command the game parses.
    assert_eq!(&turn.commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);
}

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

    assert!(handshake(&connection, &token, &wrong_key).await.is_err());
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

    assert!(handshake(&connection, &token, &client_key).await.is_err());
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

    assert!(handshake(&connection, &token, &client_key).await.is_err());
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
    let relay = quinn::Endpoint::server(server_cfg, bind).unwrap();
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
async fn frees_the_slot_when_a_client_disconnects() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(11);

    // A client authorizes for slot 0, then drops its connection.
    {
        let _slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    }

    // The slot must not stay occupied: a fresh client reclaims it. Allow a few
    // attempts for the relay to observe the departure and deregister the slot.
    let mut reclaimed = false;
    for _ in 0..20 {
        let client_key = keypair();
        let token = mint_token(&tenant, session, SlotId(0), client_key.public);
        let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        if handshake(&connection, &token, &client_key).await.is_ok() {
            reclaimed = true;
            break;
        }
    }
    assert!(
        reclaimed,
        "slot stayed occupied after the client disconnected"
    );
}

/// Waits for the relay to close `link`'s connection, failing the test (rather
/// than hanging) if it never does.
async fn expect_closed(link: &mut Link) {
    let result = tokio::time::timeout(Duration::from_secs(5), link.recv()).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "expected the relay to have closed the link",
    );
}

#[tokio::test]
async fn a_leave_intent_broadcasts_reason_left_and_closes_the_sender() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{
        ControlInbound, send_control_leave_intent, spawn_control_reader,
    };

    // The native SC:R `pending_leave_reason` a voluntary quit writes -- see
    // `relay::routing::LEAVE_REASON_LEFT`.
    const LEAVE_REASON_LEFT: u32 = 3;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(200);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Seed this relay as the session's authority: `decide_leave` is a no-op on
    // a non-authority relay, and a lone relay with no descriptor never becomes
    // one on its own outside a real coordinator-driven deployment.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    // Accept the relay's own control stream to slot 1 so its pushed leave
    // directive lands here.
    let mut ctrl1 = spawn_control_reader(slot1.connection().clone());

    // A framed turn from slot 0 gives `decide_leave` a basis to schedule
    // against -- without any observed frame (pure lobby) it would hold.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    // Give the relay a moment to observe the frame before the intent lands.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Slot 0 announces its own clean departure on the control stream it opens
    // (mirroring the real client driver, which never reuses the relay's
    // opened stream to send its own frames).
    let (mut leave_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_leave_intent(&mut leave_send).await.unwrap();

    let frame = tokio::time::timeout(Duration::from_secs(5), ctrl1.recv())
        .await
        .expect("leave directive never arrived at the survivor")
        .expect("control reader ended early");
    let ControlInbound::Leave(leave) = frame else {
        panic!("expected a LeaveDirective, got {frame:?}");
    };
    assert_eq!(leave.slot, 0);
    assert_eq!(
        leave.reason, LEAVE_REASON_LEFT,
        "an intent-decided leave uses the native quit path's reason, not the drop one",
    );

    // The relay's confirmation that it processed the intent is closing the
    // departing client's own link.
    expect_closed(&mut slot0).await;
}

#[tokio::test]
async fn an_intent_decided_leave_is_not_redecided_when_the_link_then_closes() {
    // The same task that decides the leave from the intent also runs the
    // post-loop Trigger-A cleanup on its way out (deregister, decide_leave,
    // remove_slot, presence). This proves that follow-through doesn't produce
    // a *second* directive for the same slot: the survivor sees exactly one
    // leave push, not two.
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{
        ControlInbound, send_control_leave_intent, spawn_control_reader,
    };

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(201);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut ctrl1 = spawn_control_reader(slot1.connection().clone());

    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (mut leave_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_leave_intent(&mut leave_send).await.unwrap();

    let first = tokio::time::timeout(Duration::from_secs(5), ctrl1.recv())
        .await
        .expect("leave directive never arrived at the survivor")
        .expect("control reader ended early");
    assert!(matches!(first, ControlInbound::Leave(_)));

    // Let the slot's task finish tearing down (deregister, the post-loop
    // Trigger-A decide_leave, remove_slot, presence) well past when it would
    // have run, then confirm no second leave push ever follows.
    expect_closed(&mut slot0).await;
    let second = tokio::time::timeout(Duration::from_millis(300), ctrl1.recv()).await;
    assert!(
        second.is_err(),
        "the post-loop cleanup must not re-decide and re-broadcast the same slot's leave",
    );
}

#[tokio::test]
async fn a_turn_sent_after_the_leave_intent_is_never_forwarded() {
    // The relay stops serving a slot's link the moment it processes that
    // slot's leave-intent (the determinism cut), so nothing sent afterward
    // can still reach a survivor. Sending only once the relay has confirmed
    // the intent by closing the link (rather than racing the intent and a
    // turn on the wire) is what makes this deterministic to test.
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::send_control_leave_intent;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(202);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    // Drain that first turn at slot 1 so it can't be mistaken for the later,
    // forbidden one.
    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot1.recv().await.unwrap().fresh;
    }
    assert_eq!(&delivered[0].commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);

    let (mut leave_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_leave_intent(&mut leave_send).await.unwrap();
    expect_closed(&mut slot0).await;

    // Only now, with the relay's slot-0 link task confirmed gone, try to send
    // a further turn. Nothing on the relay is left reading this connection,
    // so it can never be forwarded.
    let _ = slot0.send(Some(Payload {
        seq: 1,
        slot: 0,
        game_frame_count: Some(11),
        commands: vec![0x0C, 8, 8, 8, 8, 8, 8, 8].into(),
        ..Default::default()
    }));

    // Drain whatever the relay's own idle-ack flush still sends slot 1 (it
    // owes acks regardless of the leave) for a few flush cycles, and confirm
    // none of it ever carries the forbidden turn.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now()) {
        match tokio::time::timeout(remaining, slot1.recv()).await {
            Ok(Ok(received)) => assert!(
                received.fresh.is_empty(),
                "a turn sent after the leave intent must never reach a survivor: {:?}",
                received.fresh,
            ),
            // The relay's ack-only flush timed out this cycle (nothing owed,
            // or the window elapsed) or the link itself ended -- either way,
            // no leaked turn arrived.
            Ok(Err(_)) | Err(_) => break,
        }
    }
}

#[tokio::test]
async fn a_result_report_is_forwarded_before_the_departure_and_leaves_survivors_alone() {
    // A client writes its result report then its leave intent on the one control
    // stream it opens. The relay processes that stream in order, so it fires the
    // result notice (stamped with the reporting slot, payload, and frames) before
    // the departure notice, and the surviving second client still gets the synced
    // leave and keeps its link.
    use rally_point_relay::consensus::{self, Authority, RelayNotice};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{
        ControlInbound, send_control_game_result, send_control_leave_intent, spawn_control_reader,
    };

    // The native SC:R `pending_leave_reason` a voluntary quit writes.
    const LEAVE_REASON_LEFT: u32 = 3;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(203);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
    );
    // Watch the notices the relay would send up its coordinator connection.
    let (notice_tx, mut notice_rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut ctrl1 = spawn_control_reader(slot1.connection().clone());

    // A framed turn from slot 0 gives the result its frame stamps and gives
    // `decide_leave` a basis to schedule against.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Slot 0 writes its result report then its leave intent on the one control
    // stream it opens — the ordering the relay must preserve on the wire.
    let (mut ctrl0_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_game_result(&mut ctrl0_send, vec![0xDE, 0xAD, 0xBE, 0xEF].into())
        .await
        .unwrap();
    send_control_leave_intent(&mut ctrl0_send).await.unwrap();

    // The relay processes the stream in order, so the result notice fires before
    // the departure notice.
    let first = tokio::time::timeout(Duration::from_secs(5), notice_rx.recv())
        .await
        .expect("the result notice never arrived")
        .expect("the notice channel closed early");
    let RelayNotice::Result(result) = first else {
        panic!("expected the result notice first, got {first:?}");
    };
    assert_eq!(result.tenant, TenantId(TENANT.to_owned()));
    assert_eq!(result.session, session);
    assert_eq!(
        result.slot,
        SlotId(0),
        "the reporting slot is the authenticated connection's",
    );
    assert_eq!(result.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(result.session_frame, Some(10));
    assert_eq!(result.slot_frame, Some(10));
    assert!(result.arrival_ms > 0, "a wall-clock arrival stamp is set");

    let second = tokio::time::timeout(Duration::from_secs(5), notice_rx.recv())
        .await
        .expect("the departure notice never arrived")
        .expect("the notice channel closed early");
    let RelayNotice::Departure(departure) = second else {
        panic!("expected the departure notice second, got {second:?}");
    };
    assert_eq!(departure.slot, SlotId(0));
    assert_eq!(
        departure.reason, LEAVE_REASON_LEFT,
        "an intent-decided leave uses the native quit reason",
    );

    // The surviving second client is unaffected: it still receives the synced
    // leave for slot 0 over its own control stream.
    let pushed = tokio::time::timeout(Duration::from_secs(5), ctrl1.recv())
        .await
        .expect("the survivor never got the leave directive")
        .expect("control reader ended early");
    let ControlInbound::Leave(leave) = pushed else {
        panic!("expected a LeaveDirective at the survivor, got {pushed:?}");
    };
    assert_eq!(leave.slot, 0);

    // The departing client's link is closed by the relay; the survivor's is not.
    expect_closed(&mut slot0).await;
    assert!(
        slot1.connection().close_reason().is_none(),
        "the surviving client's link must stay open",
    );
}

#[tokio::test]
async fn an_oversize_result_report_is_dropped_without_closing_the_link() {
    // A result payload past the size cap is an ill-formed report: the relay drops
    // it (no notice) but keeps the link — a within-cap report that follows on the
    // same stream is still accepted, proving the stream wasn't torn down.
    use rally_point_relay::consensus::{self, Authority, RelayNotice};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::send_control_game_result;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(204);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
    );
    let (notice_tx, mut notice_rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;

    // A payload past the 4096-byte cap, well within the 64 KiB control-frame cap
    // (so it reaches the relay's own size check rather than the framing guard).
    let (mut ctrl0_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_game_result(&mut ctrl0_send, vec![0x7u8; 5000].into())
        .await
        .unwrap();

    // No result notice fires for the oversize report.
    assert!(
        tokio::time::timeout(Duration::from_millis(400), notice_rx.recv())
            .await
            .is_err(),
        "an oversize result payload must fire no notice",
    );

    // The link is still up: a within-cap report on the same stream is accepted
    // and fires its notice — the first record for the slot, since the oversize
    // one was dropped rather than recorded.
    send_control_game_result(&mut ctrl0_send, vec![0x1u8, 0x2, 0x3].into())
        .await
        .unwrap();
    let notice = tokio::time::timeout(Duration::from_secs(5), notice_rx.recv())
        .await
        .expect("the within-cap result never fired a notice — the link was torn down")
        .expect("the notice channel closed early");
    let RelayNotice::Result(result) = notice else {
        panic!("expected a result notice, got {notice:?}");
    };
    assert_eq!(result.slot, SlotId(0));
    assert_eq!(result.payload, vec![0x1, 0x2, 0x3]);

    // And the relay never closed the connection over the oversize report.
    assert!(
        slot0.connection().close_reason().is_none(),
        "an oversize result must not close the link",
    );
}

#[tokio::test]
async fn an_over_cap_oversize_turn_is_rejected_and_never_reaches_the_peer() {
    // The oversize-turn divert path fans a client's control-stream turn out to the
    // other slots' count-bounded forward queues, so a turn far larger than any real
    // one would occupy disproportionate buffered bytes there. A turn past the
    // amplification cap is not one any real client produces, so the relay rejects it
    // like a malformed turn — closing the link — before it can be buffered or fanned
    // out, rather than dropping it and stranding the peer on the seq gap.
    use rally_point_transport::control::send_control_turn;

    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(205);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // 9000 well-formed keep-alives: past the 8 KiB amplification cap, but under the
    // 64 KiB control-frame cap, so it reaches the relay's own size check rather than
    // the framing guard.
    let (mut ctrl0_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    let over_cap = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0x05u8; 9000].into(),
        game_frame_count: Some(1),
        ..Default::default()
    };
    send_control_turn(&mut ctrl0_send, over_cap).await.unwrap();

    // The relay closes the offending slot's link rather than buffering the turn.
    expect_closed(&mut slot0).await;

    // The peer never receives it: rejected before fan-out. Drain any maintenance
    // packets over a short window and assert none carries a fresh turn.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
    while let Ok(received) = tokio::time::timeout_at(deadline, slot1.recv()).await {
        match received {
            Ok(delivery) => assert!(
                delivery.fresh.is_empty(),
                "an over-cap oversize turn must not reach the peer",
            ),
            Err(_) => break,
        }
    }
}

#[tokio::test]
async fn acks_a_one_way_sender_with_no_peer_traffic() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);

    // A lone slot: nothing is ever fanned back to it, so the relay has no forwarded
    // turn to carry acks on and must flush ack-only packets on its own cadence.
    let mut solo = connect_slot(&endpoint, addr, &tenant, SessionId(7), SlotId(0)).await;

    for seq in 0..3u64 {
        solo.send(Some(Payload {
            seq,
            slot: 0,
            commands: vec![0x05].into(),
            ..Default::default()
        }))
        .unwrap();
    }
    assert_eq!(solo.payloads_in_flight(), 3);

    // Draining the relay's ack-only packets must retire everything in flight, even
    // though no turn ever comes back the other way. Each recv yields the relay's
    // idle ack flush; the per-recv timeout sits above the flush delay, and the loop
    // is bounded so a missing flush fails rather than hangs.
    let mut retired = false;
    for _ in 0..15 {
        let _ = tokio::time::timeout(Duration::from_millis(400), solo.recv()).await;
        if solo.payloads_in_flight() == 0 {
            retired = true;
            break;
        }
    }
    assert!(
        retired,
        "relay never acked the one-way sender; {} payloads still in flight",
        solo.payloads_in_flight()
    );
}
