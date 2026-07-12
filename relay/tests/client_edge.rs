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
/// the relay's challenge with `signing_key`, present `resume_cursors`, and confirm
/// the acknowledgement.
///
/// `signing_key` is passed separately from the token's embedded public key so a
/// test can deliberately answer with the wrong key. `resume_cursors` is the
/// per-peer-slot delivery position a reconnecting client resumes from; a fresh dial
/// passes an empty slice.
async fn handshake(
    connection: &quinn::Connection,
    token: &SignedToken,
    signing_key: &Keypair,
    resume_cursors: &[(SlotId, u64)],
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

    let cursor_frame = rally_point_proto::handshake::encode_resume_cursors(resume_cursors)?;
    send.write_all(&cursor_frame).await?;

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await?;
    if ack[0] != HANDSHAKE_OK {
        return Err("relay did not acknowledge".into());
    }
    Ok(())
}

/// Connects a client for `slot`, completes the handshake as a fresh dial (no resume
/// cursors), and returns the connection wrapped as a transport link ready to carry
/// turns.
async fn connect_slot(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
) -> Link {
    connect_slot_resuming(endpoint, addr, tenant, session, slot, &[]).await
}

/// [`connect_slot`] presenting `resume_cursors`, so a reconnect test can ask the
/// relay to replay the turns it missed from each named peer slot.
async fn connect_slot_resuming(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
    resume_cursors: &[(SlotId, u64)],
) -> Link {
    let client_key = keypair();
    let token = mint_token(tenant, session, slot, client_key.public);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    handshake(&connection, &token, &client_key, resume_cursors)
        .await
        .unwrap();
    Link::new(connection)
}

/// Reads the next control frame that carries real meaning, skipping the
/// informational `SlotConnectivity` frames the relay now fans on every register
/// and disconnect. Panics on timeout or a closed stream. Tests asserting on a
/// leave or session-start frame use this so a connectivity frame that legitimately
/// precedes it does not fail the match.
async fn recv_meaningful(
    reader: &mut tokio::sync::mpsc::Receiver<rally_point_transport::control::ControlInbound>,
) -> rally_point_transport::control::ControlInbound {
    use rally_point_transport::control::ControlInbound;
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("a control frame arrives before the timeout")
            .expect("the control stream stays open");
        if !matches!(frame, ControlInbound::Connectivity(_)) {
            return frame;
        }
    }
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
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
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
async fn fires_session_start_when_every_expected_slot_connects() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(88);

    // Seed the session's maker as the authority with two expected slots, before
    // any client connects — exactly as a coordinator descriptor would.
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
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    // Slot 0 connects; it does not cover {0, 1}, so no session-start is sent yet.
    // The relay does fan slot 0 its own connectivity(true), which is fine to see —
    // what must NOT arrive is a session-start.
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut reader0 = spawn_control_reader(slot0.connection().clone());
    loop {
        match tokio::time::timeout(Duration::from_millis(300), reader0.recv()).await {
            Ok(Some(ControlInbound::Connectivity(_))) => continue,
            Ok(Some(other)) => {
                panic!("no session-start until every expected slot connects, got {other:?}")
            }
            Ok(None) => panic!("slot 0's control stream closed early"),
            // Timed out with no session-start — the correct outcome.
            Err(_) => break,
        }
    }

    // Slot 1 connects, completing the expected set: every slot receives the
    // session-start directive over its reliable control stream (past any
    // connectivity frame slot 1's own register fanned).
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    assert!(
        matches!(
            recv_meaningful(&mut reader0).await,
            ControlInbound::SessionStart(_)
        ),
        "slot 0 receives the session-start directive once slot 1 completes the set",
    );
    assert!(
        matches!(
            recv_meaningful(&mut reader1).await,
            ControlInbound::SessionStart(_)
        ),
        "the slot that completed the set receives the directive too",
    );
}

#[tokio::test]
async fn a_late_slot_receives_session_start_on_register() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(89);

    // A one-slot expected set: slot 0 alone starts the session. A later slot then
    // registers after start and must be re-pushed the directive on register.
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
        std::collections::HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    // Slot 0 covers the expected set on its own: the session starts immediately
    // (past slot 0's own connectivity(true) frame).
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut reader0 = spawn_control_reader(slot0.connection().clone());
    assert!(
        matches!(
            recv_meaningful(&mut reader0).await,
            ControlInbound::SessionStart(_)
        ),
        "the sole expected slot starts the session on connect",
    );

    // A second slot registers well after the session has already started, and is
    // re-pushed the directive on register rather than left waiting.
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    assert!(
        matches!(
            recv_meaningful(&mut reader1).await,
            ControlInbound::SessionStart(_)
        ),
        "a slot that registers after start still receives the directive",
    );
}

#[tokio::test]
async fn session_start_carries_the_computed_initial_buffer_depth() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::spawn_control_reader;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(91);

    // Seed the maker as authority over two expected slots, then feed it the
    // session shape: a large one-way latency hint (400ms) and the multi-relay
    // flag, so the initial-depth computation is hint-dominated and deterministic.
    // 400ms is ceil(400000/41666) = 10 turns; a multi-relay session is never
    // "fully observed" (its per-slot conditions never cross the mesh pre-start),
    // so the depth is max(observed, 10) + 1 hop cushion = 11 — the localhost
    // handshake RTT the slots contribute stays far below 10, so it never lifts the
    // max above the hint.
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
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );
    consensus::set_session_shape(&makers, &key, Some(400), false);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut reader0 = spawn_control_reader(slot0.connection().clone());
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());

    assert_eq!(
        recv_meaningful(&mut reader0).await.session_start_depth(),
        Some(Some(11)),
        "slot 0's session-start carries the computed initial buffer depth",
    );
    assert_eq!(
        recv_meaningful(&mut reader1).await.session_start_depth(),
        Some(Some(11)),
        "the slot that completed the set gets the same stamped depth",
    );
}

/// Test helper: the initial buffer depth a `SessionStart` control frame carried,
/// or `None` for any other frame kind. `Some(None)` is a depth-less directive.
trait SessionStartDepth {
    fn session_start_depth(&self) -> Option<Option<u32>>;
}

impl SessionStartDepth for rally_point_transport::control::ControlInbound {
    fn session_start_depth(&self) -> Option<Option<u32>> {
        match self {
            rally_point_transport::control::ControlInbound::SessionStart(depth) => Some(*depth),
            _ => None,
        }
    }
}

#[tokio::test]
async fn a_slots_connect_fans_a_connectivity_up_to_the_other_slots() {
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(90);

    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);

    // Slot 0 connects first and opens its control reader.
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut reader0 = spawn_control_reader(slot0.connection().clone());

    // Slot 1 then connects: its registration broadcasts a `connected = true`
    // connectivity change to every slot in the session, so slot 0 hears that
    // slot 1 is connected over its reliable control stream. (Slot 0 also receives
    // its own `connected = true` frame; read past it to the one naming slot 1.)
    let _slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut saw_slot1_connected = false;
    for _ in 0..4 {
        match tokio::time::timeout(Duration::from_secs(5), reader0.recv()).await {
            Ok(Some(ControlInbound::Connectivity(change))) => {
                if change.slot == 1 {
                    assert!(change.connected, "slot 1's link is up");
                    saw_slot1_connected = true;
                    break;
                }
                // Slot 0's own `connected = true` frame — keep reading.
            }
            Ok(Some(other)) => panic!("unexpected control frame: {other:?}"),
            Ok(None) => panic!("slot 0's control stream closed early"),
            Err(_) => panic!("timed out waiting for slot 1's connectivity frame"),
        }
    }
    assert!(
        saw_slot1_connected,
        "slot 0 learns slot 1 connected via a fanned connectivity frame",
    );
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

/// A coordinator reap (`routing::close_slots`, the same signal a holdout reap
/// fires) actually closes the client's QUIC connection promptly, not just the
/// relay's own internal roster bookkeeping. Before the fix, `run_slot_link`'s
/// `shutdown.notified()` arm broke its serve loop without ever calling
/// `connection.close()` (despite its own comment saying it would) — the
/// beacon and control-stream reader tasks it spawned each held their own
/// `connection.clone()`, so the connection lingered until QUIC's own idle
/// timeout instead of freeing promptly. This test builds its own minimal
/// relay directly (rather than through `start_relay`/`start_relay_with_mesh`,
/// which don't expose the `Sessions` handle `close_slots` needs) so it can
/// reach the same signal a real coordinator reap would send.
#[tokio::test]
async fn a_coordinator_reap_closes_the_connection_so_the_client_observes_it_end() {
    use rally_point_relay::routing::{self, SessionKey};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(12);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let (chain, key_der, ca) = self_signed();
    let server_cfg = server_config(chain, key_der).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let endpoint = quinn::Endpoint::server(server_cfg, bind).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let sessions = routing::Sessions::default();
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry_for(&[&tenant])),
        Arc::clone(&sessions),
        rally_point_relay::mesh::new_mesh_state(),
        None,
    ));
    let endpoint = client_endpoint(&ca);

    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let client_connection = slot0.connection().clone();
    // Let the relay finish registering the slot before reaping it.
    tokio::time::sleep(Duration::from_millis(80)).await;

    routing::close_slots(&sessions, &key, &[SlotId(0)]);

    match tokio::time::timeout(Duration::from_secs(5), client_connection.closed()).await {
        Ok(_reason) => {}
        Err(_) => panic!("the client never observed the connection end after a coordinator reap"),
    }
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
        if handshake(&connection, &token, &client_key, &[])
            .await
            .is_ok()
        {
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
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
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

    let frame = recv_meaningful(&mut ctrl1).await;
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
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
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

    let first = recv_meaningful(&mut ctrl1).await;
    assert!(matches!(first, ControlInbound::Leave(_)));

    // Let the slot's task finish tearing down (deregister, the post-loop
    // Trigger-A decide_leave, remove_slot, presence) well past when it would
    // have run, then confirm no second leave push ever follows. A clean leave
    // fans no connectivity(false) frame (that is the disconnect path only), so
    // the stream is silent from here — any frame at all would be a regression.
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
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
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
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
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
    // leave for slot 0 over its own control stream (past any connectivity frame).
    let pushed = recv_meaningful(&mut ctrl1).await;
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
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
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
async fn an_empty_result_report_is_dropped_without_closing_the_link() {
    // A zero-length result payload is the wire sentinel `SlotDeparted` uses for
    // "no result reported" (see wire.proto), never a genuine report, so the relay
    // must never record one: doing so would make a real empty result
    // indistinguishable from no result once the slot departs. The relay drops it
    // (no notice) but keeps the link, exactly like an oversize report.
    use rally_point_relay::consensus::{self, Authority, RelayNotice};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::send_control_game_result;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(205);
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
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );
    let (notice_tx, mut notice_rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;

    let (mut ctrl0_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_game_result(&mut ctrl0_send, Vec::new().into())
        .await
        .unwrap();

    // No result notice fires for the empty report.
    assert!(
        tokio::time::timeout(Duration::from_millis(400), notice_rx.recv())
            .await
            .is_err(),
        "an empty result payload must fire no notice",
    );
    assert!(
        consensus::result_for(&makers, &key, SlotId(0)).is_none(),
        "an empty result payload must never be retained",
    );

    // The link is still up: a real report on the same stream is still accepted
    // and fires its notice — the first record for the slot, since the empty one
    // was dropped rather than recorded.
    send_control_game_result(&mut ctrl0_send, vec![0x1u8, 0x2, 0x3].into())
        .await
        .unwrap();
    let notice = tokio::time::timeout(Duration::from_secs(5), notice_rx.recv())
        .await
        .expect("the real result never fired a notice — the link was torn down")
        .expect("the notice channel closed early");
    let RelayNotice::Result(result) = notice else {
        panic!("expected a result notice, got {notice:?}");
    };
    assert_eq!(result.slot, SlotId(0));
    assert_eq!(result.payload, vec![0x1, 0x2, 0x3]);

    // And the relay never closed the connection over the empty report.
    assert!(
        slot0.connection().close_reason().is_none(),
        "an empty result must not close the link",
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
async fn a_dead_control_stream_reader_closes_the_slot_link() {
    // The client's control stream is the only channel `RequestDrop` and a
    // clean leave-intent ever arrive on. If its reader task ends while the
    // connection is otherwise alive -- here a clean EOF, no reset -- the relay
    // must close the connection so the client's reconnect machinery takes
    // over with fresh streams, rather than just disarming and serving
    // datagrams forever while permanently losing both of those.
    //
    // Mirrors the private `routing::CONTROL_STREAM_LOST_CLOSE`, the same way
    // the decided-departure test below mirrors `server::SLOT_DEPARTED_CLOSE`
    // (that one is `pub` and imported directly; this one isn't, so the value
    // is hardcoded here).
    const CONTROL_STREAM_LOST_CLOSE: u32 = 0x07;

    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(206);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;

    // Open the client's outbound control stream -- the one the relay's
    // `control_rx` reads -- then immediately finish it: a clean EOF with the
    // connection itself left fully alive, exactly the "control stream dead,
    // link fine" split this bug is about.
    let (mut ctrl0_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    let _ = ctrl0_send.finish();

    // The relay closes the whole connection in response.
    expect_closed(&mut slot0).await;
    match slot0.connection().closed().await {
        quinn::ConnectionError::ApplicationClosed(app) => assert_eq!(
            u32::try_from(u64::from(app.error_code)).unwrap(),
            CONTROL_STREAM_LOST_CLOSE,
            "the relay closes with the control-stream-lost code",
        ),
        other => panic!("expected an application close, got {other:?}"),
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

/// Reads control frames until one is a `SlotConnectivity` naming `(slot, connected)`,
/// skipping every other frame kind. Panics on timeout. A reconnect test uses this
/// to synchronize on the relay having observed a drop (the disconnect fan-out) before
/// it acts further.
async fn wait_for_connectivity(
    reader: &mut tokio::sync::mpsc::Receiver<rally_point_transport::control::ControlInbound>,
    slot: SlotId,
    connected: bool,
) {
    use rally_point_transport::control::ControlInbound;
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("a connectivity frame arrives before the timeout")
            .expect("the control stream stays open");
        if let ControlInbound::Connectivity(change) = frame
            && change.slot == u32::from(slot.0)
            && change.connected == connected
        {
            return;
        }
    }
}

/// Collects the next `n` oversize-turn payloads pushed down a control stream,
/// skipping the session-start and connectivity frames that a register also fans.
/// Panics on timeout. A reconnect test uses this to read the turns the relay replays
/// from the ring.
async fn collect_oversize_turns(
    reader: &mut tokio::sync::mpsc::Receiver<rally_point_transport::control::ControlInbound>,
    n: usize,
) -> Vec<Payload> {
    use rally_point_transport::control::ControlInbound;
    let mut turns = Vec::new();
    while turns.len() < n {
        let frame = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("a replayed turn arrives before the timeout")
            .expect("the control stream stays open");
        if let ControlInbound::OversizeTurn(payload) = frame {
            turns.push(payload);
        }
    }
    turns
}

#[tokio::test]
async fn a_reconnect_while_the_drop_is_held_reinstates_the_slot_and_replays_missed_turns() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(300);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Seed this relay as the authority over an expected {0, 1} set: the session then
    // starts (turns are ring-buffered only once started). A dropped slot is never
    // auto-decided regardless of the unlock floor, so the floor here matters only to
    // bound how long the test waits before asserting no leave ever fired.
    let unlock = Duration::from_millis(1000);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_drop_unlock(unlock);
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
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut ctrl0 = spawn_control_reader(slot0.connection().clone());
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // Both connected, so the session started. Slot 0's first framed turn reaches
    // slot 1 live and gives the session a frame basis.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    let mut got = Vec::new();
    while got.is_empty() {
        got = slot1.recv().await.unwrap().fresh;
    }
    assert_eq!(got[0].seq, 0);

    // Slot 1's link dies. Wait until slot 0 hears the disconnect — proof the relay
    // has run the departure path and marked the drop hold for slot 1.
    drop(slot1);
    wait_for_connectivity(&mut ctrl0, SlotId(1), false).await;

    // While slot 1 is gone, slot 0 produces two more framed turns. They fan to no
    // peer (slot 1 is deregistered) but are recorded into the session's replay ring.
    for (seq, frame, byte) in [(1u64, 11u32, 2u8), (2, 12, 3)] {
        slot0
            .send(Some(Payload {
                seq,
                slot: 0,
                game_frame_count: Some(frame),
                commands: vec![0x0C, byte, 2, 3, 4, 5, 6, 7].into(),
                ..Default::default()
            }))
            .unwrap();
    }
    // Let the relay validate and record the two turns before the reconnect reads the
    // ring.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Slot 1 re-dials while its drop is still held, resuming from slot 0 seq 1 (it
    // already has seq 0). The relay accepts it (the hold is still pending), releases
    // the hold, and replays the two missed turns on the reliable control stream.
    let slot1b = connect_slot_resuming(
        &endpoint,
        addr,
        &tenant,
        session,
        SlotId(1),
        &[(SlotId(0), 1)],
    )
    .await;
    let mut ctrl1 = spawn_control_reader(slot1b.connection().clone());

    let replayed = collect_oversize_turns(&mut ctrl1, 2).await;
    assert_eq!(
        replayed.iter().map(|p| p.seq).collect::<Vec<_>>(),
        vec![1, 2],
        "exactly the missed turns, in seq order",
    );
    assert_eq!(&replayed[0].commands[..], &[0x0C, 2, 2, 3, 4, 5, 6, 7]);
    assert_eq!(&replayed[1].commands[..], &[0x0C, 3, 2, 3, 4, 5, 6, 7]);
    assert_eq!(replayed[0].slot, 0, "a replayed turn keeps its origin slot");

    // The hold was released and the slot reinstated: even well past the unlock floor
    // (past which a drop would only ever be honored on request, never automatically),
    // slot 0 never receives a synced leave for slot 1 (it only hears slot 1 reconnect).
    let deadline = tokio::time::Instant::now() + unlock + Duration::from_millis(500);
    loop {
        match tokio::time::timeout_at(deadline, ctrl0.recv()).await {
            Ok(Some(ControlInbound::Leave(leave))) => {
                panic!("a reinstated slot still had a leave decided: {leave:?}")
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("slot 0's control stream closed early"),
            Err(_) => break,
        }
    }
}

#[tokio::test]
async fn a_resumed_turn_past_the_window_on_a_nonzero_slot_is_forwarded_not_closed() {
    // The same-relay resume regression, end to end: a client authorized on a NONZERO
    // slot re-homes mid-game and resumes its own-slot seq stream well past the 4096
    // receive window. The real DLL leaves the wire slot at 0 on every turn, while the
    // resume anchor is keyed on the authorized slot — so a relay edge that keyed dedup
    // on the wire slot would anchor slot 1 yet dedup slot 0, reject the first resumed
    // turn as out-of-window, and fatally close the link. The ingress-slot rebind keeps
    // dedup and the anchor on the authorized slot, so the turn is accepted and fanned
    // out. (Presenting a high own-slot resume cursor reproduces the anchored,
    // past-window state without pushing 4096 real turns through the loopback first.)
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(320);

    // The peer that should receive slot 1's resumed turn. It is deep in the same
    // game, so its own fan-in dedup has already tracked slot 1's stream up to the
    // resume point — anchor it there so the past-window forwarded turn is in this
    // peer's window (exactly as a real re-home, where every peer resumes too).
    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    slot0.anchor_receive_window(SlotId(1), 8000);

    // Slot 1 (re)connects presenting a resume cursor for its OWN slot at a high
    // absolute seq — the oldest seq it will re-send after a re-home. The relay anchors
    // slot 1's receive window there.
    let mut slot1 = connect_slot_resuming(
        &endpoint,
        addr,
        &tenant,
        session,
        SlotId(1),
        &[(SlotId(1), 8000)],
    )
    .await;

    // Slot 1 re-sends its resumed turn, stamping wire slot 0 exactly as the DLL does,
    // at a seq far past the from-zero window. Keyed on the wire slot this trips
    // PayloadOutOfWindow and closes the link — the regression.
    slot1
        .send(Some(Payload {
            seq: 8000,
            slot: 0,
            game_frame_count: Some(9000),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();

    // The turn is forwarded to slot 0, bound to the authorized slot 1.
    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot0.recv().await.unwrap().fresh;
    }
    assert_eq!(
        delivered[0].slot, 1,
        "the resumed turn keeps its authorized slot"
    );
    assert_eq!(delivered[0].seq, 8000);
    assert_eq!(&delivered[0].commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);

    // And slot 1's link was not torn down over the past-window resumed turn.
    assert!(
        slot1.connection().close_reason().is_none(),
        "the resumed nonzero-slot link must survive its first past-window turn",
    );
}

/// A client presenting an absurd own-slot resume-cursor anchor (near the u64
/// ceiling) is refused outright rather than let that value become the dedup
/// window's base -- the real gate the transport-level saturating arithmetic
/// is only a backstop for. Task-isolated: only the presenting connection is
/// closed, never the relay itself.
#[tokio::test]
async fn an_absurd_resume_anchor_is_refused_not_applied() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(321);

    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(0), client_key.public);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    // The relay applies the anchor (and closes the connection over it) only
    // after the handshake ack -- but the close can race the ack's own
    // delivery, so this accepts either observable outcome: the handshake's
    // own read failing with the connection closed, or a successful handshake
    // followed by the closed connection on the first subsequent recv. Either
    // way, the load-bearing proof is the close code and reason below.
    let handshake_outcome =
        handshake(&connection, &token, &client_key, &[(SlotId(0), u64::MAX)]).await;

    if handshake_outcome.is_ok() {
        let mut link = Link::new(connection.clone());
        let _ = tokio::time::timeout(Duration::from_secs(2), link.recv()).await;
    }
    // `close_reason` reflects the local endpoint's own processed state, which
    // can lag slightly behind the read/write error already observed above;
    // poll briefly rather than risk a one-shot race.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let close = loop {
        if let Some(reason) = connection.close_reason() {
            break Some(reason);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    match close {
        Some(quinn::ConnectionError::ApplicationClosed(close)) => {
            assert_eq!(
                close.error_code,
                quinn::VarInt::from_u32(0x09),
                "closed with the dedicated resume-anchor-invalid code",
            );
        }
        other => panic!("expected the connection closed over the absurd anchor, got {other:?}"),
    }
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
        quinn::ConnectionError::ApplicationClosed(app) => assert_eq!(
            u32::try_from(u64::from(app.error_code)).unwrap(),
            SLOT_DEPARTED_CLOSE,
            "the re-register is refused with the terminal departed close code",
        ),
        other => panic!("expected the terminal departed application close, got {other:?}"),
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
        quinn::ConnectionError::ApplicationClosed(app) => assert_eq!(
            u32::try_from(u64::from(app.error_code)).unwrap(),
            SLOT_NOT_HOMED_CLOSE,
            "the misrouted slot is refused with the not-homed close code",
        ),
        other => panic!("expected the not-homed application close, got {other:?}"),
    }
}

/// A session admitted by a client dial with no applied descriptor is
/// provisional and bounded: left undescribed past its window, the relay's
/// sweep closes the connection (with a distinct, retryable-looking close
/// code) and drops the session's roster state, rather than trusting an
/// admit-first session indefinitely. This drives the real admission gate
/// (`server.rs`'s `serve_connection`) and the real sweep
/// (`provisional::run_sweep_with`), not a hand-simulated mark and reap.
#[tokio::test]
async fn a_provisional_session_with_no_descriptor_is_reaped_at_its_deadline() {
    use rally_point_relay::provisional::{self, ProvisionalSessions};
    use rally_point_relay::routing::{self, PROVISIONAL_EXPIRED_CLOSE, SessionKey};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(303);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let window = Duration::from_millis(150);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_provisional_window(window);
    let provisional: ProvisionalSessions = mesh.provisional.clone();
    let decision_makers = mesh.decision_makers.clone();
    let (chain, key_der, ca) = self_signed();
    let server_cfg = server_config(chain, key_der).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let endpoint = quinn::Endpoint::server(server_cfg, bind).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let sessions = routing::Sessions::default();
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry_for(&[&tenant])),
        Arc::clone(&sessions),
        mesh,
        None,
    ));

    // Armed from the start (standing in for an established control
    // connection), with a fast sweep cadence so the test doesn't wait a whole
    // production tick.
    let (_armed_tx, armed_rx) = tokio::sync::watch::channel(true);
    tokio::spawn(provisional::run_sweep_with(
        provisional,
        Arc::clone(&sessions),
        decision_makers,
        armed_rx,
        Duration::from_millis(20),
    ));

    let client_endpoint = client_endpoint(&ca);
    // No descriptor is ever applied for this session -- admission's
    // provisional mark stands until the sweep reaps it.
    let slot0 = connect_slot(&client_endpoint, addr, &tenant, session, SlotId(0)).await;
    let client_connection = slot0.connection().clone();

    match tokio::time::timeout(window * 5, client_connection.closed())
        .await
        .expect("the client observes the connection end within the deadline")
    {
        quinn::ConnectionError::ApplicationClosed(app) => assert_eq!(
            u32::try_from(u64::from(app.error_code)).unwrap(),
            PROVISIONAL_EXPIRED_CLOSE,
            "reaped with the provisional-expired close code",
        ),
        other => panic!("expected the provisional-expired application close, got {other:?}"),
    }

    // The session's roster state is gone too, not just the connection.
    wait_until(
        tokio::time::Instant::now() + Duration::from_secs(5),
        "the reaped session's roster entry never cleared",
        || sessions.lock().get(&key).is_none(),
    )
    .await;

    // A genuinely slow descriptor only delays, never bricks: the same slot
    // redials and is admitted fresh, with its own new provisional window
    // (not a leftover already-expired one), and is reaped again on its own
    // timer rather than being refused outright or reaped instantly.
    let redial_start = tokio::time::Instant::now();
    let slot0_again = connect_slot(&client_endpoint, addr, &tenant, session, SlotId(0)).await;
    let redialed_connection = slot0_again.connection().clone();
    match tokio::time::timeout(window * 5, redialed_connection.closed())
        .await
        .expect("the redialed connection also ends within a fresh deadline")
    {
        quinn::ConnectionError::ApplicationClosed(app) => assert_eq!(
            u32::try_from(u64::from(app.error_code)).unwrap(),
            PROVISIONAL_EXPIRED_CLOSE,
            "the redial is reaped with the same close code, on its own new window",
        ),
        other => panic!("expected the provisional-expired application close, got {other:?}"),
    }
    assert!(
        redial_start.elapsed() >= window,
        "the redial got a full fresh window rather than inheriting an already-expired deadline",
    );
}

/// A descriptor that arrives inside a provisional session's window clears its
/// mark, so the sweep leaves the connection alone past the original deadline
/// -- the intended common case: the coordinator's descriptor push usually
/// beats the window by a wide margin, and a legitimate session must never be
/// punished for winning the very create-response-to-dial race the
/// provisional window exists to bound.
#[tokio::test]
async fn a_descriptor_arriving_inside_the_window_saves_the_session_from_the_sweep() {
    use rally_point_proto::control::SessionDescriptor;
    use rally_point_proto::ids::RelayId;
    use rally_point_relay::mesh_control::MeshControl;
    use rally_point_relay::provisional::{self, ProvisionalSessions};
    use rally_point_relay::routing::{self, SessionKey};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(304);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let window = Duration::from_millis(150);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_provisional_window(window);
    let provisional: ProvisionalSessions = mesh.provisional.clone();
    let decision_makers = mesh.decision_makers.clone();
    // Points at the same decision-maker registry and provisional map the
    // relay serves this session with, so `apply_descriptor` here is
    // indistinguishable from one the coordinator subscriber would have
    // applied -- this test drives the real clearing path, not a hand call
    // into `ProvisionalSessions` directly.
    let control = MeshControl::new(RelayId(1), mesh.decision_makers.clone(), Arc::default())
        .with_provisional(provisional.clone());

    let (chain, key_der, ca) = self_signed();
    let server_cfg = server_config(chain, key_der).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let endpoint = quinn::Endpoint::server(server_cfg, bind).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let sessions = routing::Sessions::default();
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry_for(&[&tenant])),
        Arc::clone(&sessions),
        mesh,
        None,
    ));

    let (_armed_tx, armed_rx) = tokio::sync::watch::channel(true);
    tokio::spawn(provisional::run_sweep_with(
        provisional,
        Arc::clone(&sessions),
        decision_makers,
        armed_rx,
        Duration::from_millis(20),
    ));

    let client_endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&client_endpoint, addr, &tenant, session, SlotId(0)).await;
    let client_connection = slot0.connection().clone();

    // A descriptor arrives well inside the window.
    tokio::time::sleep(Duration::from_millis(30)).await;
    control.apply_descriptor(&SessionDescriptor {
        tenant: TenantId(TENANT.to_owned()),
        session,
        peers: vec![],
        bounds: rally_point_proto::control::BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
    });

    // Wait well past the original deadline: the sweep must have left the
    // connection alone.
    tokio::time::sleep(window * 3).await;
    assert!(
        client_connection.close_reason().is_none(),
        "a descriptor inside the window saves the session; the sweep must not have reaped it",
    );
    assert!(
        sessions.lock().get(&key).is_some(),
        "the slot is still registered",
    );
}

/// Dev/static mode (`--mesh-peer`, no `--coordinator-url`) never spawns the
/// provisional-admission sweep at all -- there is no separate "unarmed" flag
/// to fail closed on, the sweep task simply does not exist. This drives that
/// exact shape: a provisionally-admitted session on a relay with no sweep
/// running whatsoever survives indefinitely, however long its window would
/// otherwise have bounded it.
#[tokio::test]
async fn with_no_sweep_running_a_provisional_session_is_never_reaped() {
    use rally_point_relay::routing::{self, SessionKey};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(305);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // A window tiny enough that, were any sweep running, it would have reaped
    // this many times over by the time the test's own wait below elapses.
    let window = Duration::from_millis(20);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_provisional_window(window);
    let (chain, key_der, ca) = self_signed();
    let server_cfg = server_config(chain, key_der).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let endpoint = quinn::Endpoint::server(server_cfg, bind).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let sessions = routing::Sessions::default();
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry_for(&[&tenant])),
        Arc::clone(&sessions),
        mesh,
        None,
        // No `provisional::run_sweep`/`run_sweep_with` task spawned anywhere
        // for this relay -- exactly the dev/static (`--mesh-peer`, no
        // `--coordinator-url`) wiring in `main.rs`, which never constructs
        // one either.
    ));

    let client_endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&client_endpoint, addr, &tenant, session, SlotId(0)).await;
    let client_connection = slot0.connection().clone();

    tokio::time::sleep(window * 10).await;
    assert!(
        client_connection.close_reason().is_none(),
        "with no sweep running, the connection is never reaped no matter how long its window would have allowed",
    );
    assert!(
        sessions.lock().get(&key).is_some(),
        "the slot is still registered",
    );
}

/// Polls `condition` until it's true or `deadline` passes, sleeping briefly between
/// checks. Panics with `what` on timeout. Used to observe async server-side
/// teardown (a disconnect's `end_slot_link` running) that has no local peer to
/// signal it via a control frame.
async fn wait_until(
    deadline: tokio::time::Instant,
    what: &str,
    mut condition: impl FnMut() -> bool,
) {
    loop {
        if condition() {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("{what}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// `end_slot_link`'s session-emptied teardown must not sweep away a hold its
/// own disconnect just marked: the sweep may only discard *decided* holds, not
/// every hold for the session, or a client reconnecting into that same window
/// would find its drop hold already erased — with the departure record still
/// standing, that reads as an already-decided leave, so the admission gate
/// would wrongly refuse the very client the hold exists to let back in. On a
/// session split across relays, each relay's local roster holds only its own
/// slot(s), so **every** disconnect empties it and hits this teardown — a
/// single connected slot reproduces the exact condition without needing a
/// second relay.
///
/// Drives the real teardown (a genuine disconnect, not a hand-simulated
/// hold+release) and the real admission gate (`server.rs`'s `serve_connection`,
/// not a direct call into `routing`/`consensus`) end to end: the slot must be
/// reinstated, not refused.
#[tokio::test]
async fn a_last_local_slots_disconnect_still_reinstates_on_reconnect_through_the_real_gate() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(310);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // A single local slot: it is always "the last local slot" for this relay, so
    // its own disconnect always empties the roster and runs the session-emptied
    // teardown in the same breath that marks its hold.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let drop_holds = mesh.drop_holds.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;

    // Sever the connection -- a real disconnect, not a clean leave-intent -- so
    // `end_slot_link` runs its real session-emptied teardown.
    drop(slot0);

    // Wait for the relay's async teardown to actually finish: the departure
    // recorded and the hold marked. Polled on the shared registries (cloned before
    // the relay took ownership of `mesh`) since there is no local peer to observe
    // this through a control frame.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    wait_until(
        deadline,
        "the relay never recorded the disconnected slot's departure and hold",
        || {
            consensus::slot_departed(&makers, &key, SlotId(0))
                && drop_holds.is_pending(&key, SlotId(0))
        },
    )
    .await;

    // Re-dial through the REAL admission gate end to end -- this is exactly the bug
    // Finding 1 fixed: before the fix, the session-emptied teardown above had
    // already swept the hold this disconnect just marked, so this handshake would
    // be refused with `SLOT_DEPARTED_CLOSE` instead of admitted.
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(0), client_key.public);
    let redial = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    handshake(&redial, &token, &client_key, &[])
        .await
        .expect("the re-register must be admitted -- the hold must survive the roster-empty sweep");

    // And the slot is genuinely reinstated: no departure, no hold, either.
    assert!(
        !consensus::slot_departed(&makers, &key, SlotId(0)),
        "the reconnect reinstated the slot",
    );
    assert!(!drop_holds.is_pending(&key, SlotId(0)));
}

/// The structural companion to the hold-sweep case above: the same last-slot
/// disconnect that marks the hold also empties the local roster — and while
/// that hold promises a reconnect, the emptying must not report `SessionClosed`
/// (on a single-relay session the coordinator would retire the session on the
/// spot, refusing the promised reconnect) nor drop the session's serving state
/// (the lobby log and replay ring are what make the admitted resume whole).
/// End to end through the real gate: the close is deferred, the reconnected
/// client is replayed the lobby log, and the close then fires exactly once,
/// when the client later leaves cleanly.
#[tokio::test]
async fn a_held_last_slot_disconnect_defers_the_session_close_and_keeps_its_state() {
    use rally_point_relay::consensus::{self, Authority, RelayNotice};
    use rally_point_relay::presence::{self, Candidate};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{
        ControlInbound, send_control_leave_intent, spawn_control_reader,
    };

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(312);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // A single local slot over an expected {0} set, this relay the authority and
    // first in its own presence order: slot 0 arriving is full coverage, so the
    // session starts — the deferral applies only to a started session, whose
    // abandoned-session timer bounds it.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let drop_holds = mesh.drop_holds.clone();
    let lobby = mesh.lobby.clone();
    let (notice_tx, mut notice_rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );
    presence::set_order(&mesh.presence, &key, vec![Candidate::SelfRelay]);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    wait_until(deadline, "the session never started", || {
        consensus::session_started(&makers, &key)
    })
    .await;

    // A framed turn gives the session a frame basis (a clean leave's decide
    // schedules against it), and a lobby command goes into the replay log the
    // reconnect below must still find.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    // A peer-authored lobby command into the replay log (a member's own
    // commands are skipped on its replay, so the survivable content must be
    // authored by another slot — here injected as a mesh delivery would be).
    rally_point_relay::lobby::deliver(
        &lobby,
        &key,
        rally_point_proto::messages::LobbyCommand {
            slot: 1,
            payload: vec![0xAB, 0xCD].into(),
        },
    );
    // Let the relay validate the turn before the blip.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // The blip: a real disconnect of the relay's only local slot.
    drop(slot0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    wait_until(
        deadline,
        "the relay never recorded the disconnected slot's departure and hold",
        || {
            consensus::slot_departed(&makers, &key, SlotId(0))
                && drop_holds.is_pending(&key, SlotId(0))
        },
    )
    .await;

    // The emptying ran, the hold is pending — and no close was reported.
    while let Ok(notice) = notice_rx.try_recv() {
        assert!(
            !matches!(notice, RelayNotice::SessionClosed { .. }),
            "no close may be reported while the slot's drop is held",
        );
    }

    // Re-dial through the real gate: admitted (the hold), and the lobby log —
    // which the emptying must not have dropped — replays to the returning member.
    let slot0b = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut ctrl0b = spawn_control_reader(slot0b.connection().clone());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let frame = tokio::time::timeout_at(deadline, ctrl0b.recv())
            .await
            .expect("the lobby log was not replayed to the reconnected member")
            .expect("control stream closed early");
        if let ControlInbound::Lobby(command) = frame {
            assert_eq!(&command.payload[..], &[0xAB, 0xCD]);
            assert_eq!(command.slot, 1, "the replayed command keeps its author");
            break;
        }
    }

    // The client leaves cleanly: the emptying now has nothing held, so the
    // close runs — exactly once.
    let (mut leave_send, _unused_recv) = slot0b.connection().open_bi().await.unwrap();
    send_control_leave_intent(&mut leave_send).await.unwrap();

    let mut deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut closes = 0usize;
    loop {
        match tokio::time::timeout_at(deadline, notice_rx.recv()).await {
            Ok(Some(RelayNotice::SessionClosed { .. })) => {
                closes += 1;
                // A duplicate close would ride the same teardown, so a short
                // quiesce window after the first is enough to catch one.
                deadline = tokio::time::Instant::now() + Duration::from_millis(700);
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            // Quiesced: nothing more is coming within the window.
            Err(_) => break,
        }
    }
    assert_eq!(closes, 1, "the clean emptying reported exactly one close");
}

/// The mass-blip variant: every slot in a session drops together (a shared uplink
/// hiccup), arming the abandoned-session timer -- and then one of them reconnects
/// inside the window. The reconnect must be admitted through the real gate, the
/// timer must stand down (nothing gets force-decided while a reconnect is live),
/// and the *other*, still-disconnected slot's hold must still be exactly what it
/// was before the blip: alive, and honorable by a `RequestDrop` once its own
/// unlock floor passes.
#[tokio::test]
async fn a_reconnect_inside_the_abandon_window_cancels_it_and_the_other_holds_still_honor_a_request()
 {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::presence::{self, Candidate};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{
        ControlInbound, send_control_request_drop, spawn_control_reader,
    };

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(311);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Tiny unlock and abandon windows so the test doesn't wait the production 30s
    // / 45s. Authority over the full {0, 1} expected set so the session actually
    // starts (the abandon condition requires it) and set this relay first in its
    // own presence order so its own roster count drives the authority verdict.
    let unlock = Duration::from_millis(200);
    let abandon_timeout = Duration::from_millis(300);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_timings(unlock, abandon_timeout);
    let makers = mesh.decision_makers.clone();
    let presence_registry = mesh.presence.clone();
    let drop_holds = mesh.drop_holds.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );
    presence::set_order(&presence_registry, &key, vec![Candidate::SelfRelay]);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // Both slots produce a framed turn so their own departure records carry a last
    // frame -- a basis their eventual leave (however it's decided) can schedule
    // against.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    slot1
        .send(Some(Payload {
            seq: 0,
            slot: 1,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The shared uplink blip: both slots' links die. Slot 1 first (session stays
    // non-empty, ordinary disconnect path), then slot 0 -- whose disconnect empties
    // the local roster and arms the abandon timer.
    drop(slot1);
    drop(slot0);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    wait_until(
        deadline,
        "the relay never marked holds for both disconnected slots",
        || drop_holds.is_pending(&key, SlotId(0)) && drop_holds.is_pending(&key, SlotId(1)),
    )
    .await;
    wait_until(deadline, "the abandoned-session timer never armed", || {
        drop_holds.abandon_armed(&key)
    })
    .await;

    // Slot 0 re-dials inside the (short) abandon window, through the real gate.
    let slot0b = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut ctrl0 = spawn_control_reader(slot0b.connection().clone());

    // The reconnect must have cancelled the timer -- verify directly, and then
    // outlast the original window with nothing decided.
    wait_until(
        tokio::time::Instant::now() + Duration::from_secs(2),
        "the reconnect never cancelled the abandoned-session timer",
        || !drop_holds.abandon_armed(&key),
    )
    .await;
    assert!(
        !consensus::slot_departed(&makers, &key, SlotId(0)),
        "the reconnected slot is reinstated",
    );
    assert!(
        drop_holds.is_pending(&key, SlotId(1)),
        "the other slot's hold is untouched by the reconnect",
    );

    // Wait well past the original abandon window: nothing was force-decided while
    // the reconnect was in flight, so slot 0 (now live) sees no leave at all yet.
    let past_window = tokio::time::Instant::now() + abandon_timeout + Duration::from_millis(300);
    loop {
        match tokio::time::timeout_at(past_window, ctrl0.recv()).await {
            Ok(Some(ControlInbound::Leave(leave))) => {
                panic!("the cancelled abandon timer still decided a leave: {leave:?}")
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("slot 0's control stream closed early"),
            Err(_) => break,
        }
    }
    assert!(
        drop_holds.is_pending(&key, SlotId(1)),
        "slot 1's drop is still held, undecided, after the window that would have abandoned it",
    );

    // Slot 1's hold survived intact: reconnected slot 0 can still request its drop,
    // and past slot 1's own unlock floor (already well past, at this point) it is
    // honored -- proof the hold that outlived the blip is a fully live one, not a
    // stale leftover.
    let (mut req_send, _unused) = slot0b.connection().open_bi().await.unwrap();
    send_control_request_drop(&mut req_send, 1).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, ctrl0.recv()).await {
            Ok(Some(ControlInbound::Leave(leave))) => {
                assert_eq!(leave.slot, 1);
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("slot 0's control stream closed before the honored drop arrived"),
            Err(_) => panic!("the request-drop for the still-held slot 1 was never honored"),
        }
    }
}
