//! End-to-end coverage of the relay mesh: `C–S===S–C`.
//!
//! Two relays serve on one endpoint each (client + mesh ALPNs). A dials B on
//! the mesh ALPN; B's accept loop dispatches the connection to the mesh path
//! via `mesh_accept`. Both sides wrap as `MeshLink`, register a forward channel
//! for the session, and spawn the mesh-link driver. A client on relay A sends
//! a turn; a client on relay B receives it across the mesh. Asserts the turn
//! arrives exactly once — proving the full cross-relay delivery path through
//! the real ALPN dispatch + mesh fan-out.

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
use rally_point_relay::mesh;
use rally_point_relay::routing::{SessionKey, Sessions};
use rally_point_relay::server;
use rally_point_transport::quic::{client_config, mesh_client_config, server_config};
use rally_point_transport::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rally_point_transport::{Link, MeshLink, quinn, rustls};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use tokio::sync::mpsc;
const KID: &str = "staging-key-1";
const TENANT: &str = "sb-staging";

type AnyError = Box<dyn Error + Send + Sync>;

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

struct Tenant {
    kid: String,
    name: String,
    key: Keypair,
}

fn make_tenant() -> Tenant {
    Tenant {
        kid: KID.to_owned(),
        name: TENANT.to_owned(),
        key: keypair(),
    }
}

fn self_signed() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let der = cert.cert.der().clone();
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (vec![der.clone()], key, der)
}

fn registry_for(tenant: &Tenant) -> Registry {
    let mut registry = Registry::new();
    registry.insert(
        KeyId(tenant.kid.clone()),
        TenantId(tenant.name.clone()),
        tenant.key.public,
    );
    registry
}

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

/// A relay with its client edge, shared mesh state, and a mesh-accept channel.
struct Relay {
    addr: SocketAddr,
    ca: CertificateDer<'static>,
    sessions: Sessions,
    mesh: mesh::MeshState,
    mesh_rx: mpsc::Receiver<quinn::Connection>,
}

impl Relay {
    fn start(tenant: &Tenant) -> Self {
        let (chain, key, ca) = self_signed();
        let cfg = server_config(chain, key).unwrap();
        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let endpoint = quinn::Endpoint::server(cfg, bind).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let sessions: Sessions = Arc::default();
        let mesh = mesh::new_mesh_state();
        let (mesh_tx, mesh_rx) = mpsc::channel(8);

        tokio::spawn(server::serve(
            endpoint,
            Arc::new(registry_for(tenant)),
            Arc::clone(&sessions),
            mesh.clone(),
            Some(mesh_tx),
        ));

        Self {
            addr,
            ca,
            sessions,
            mesh,
            mesh_rx,
        }
    }
}

fn turn(slot: u8, seq: u64) -> Payload {
    Payload {
        seq,
        slot: u32::from(slot),
        game_frame_count: None,
        // Empty commands — a bare turn signal. validate_turn accepts this
        // (it yields an empty payload after stripping). A non-empty command
        // would need to be a valid SC:R opcode or validate_turn rejects it.
        commands: vec![].into(),
    }
}

/// Spawns a mesh-link driver on `link` and returns the command sender the test
/// uses to join and leave sessions. A thin wrapper over `run_mesh_link` so the
/// two-relay tests stay focused on the cross-relay path, not channel plumbing.
///
/// Uses the production [`mesh::IDLE_TIMEOUT`] (60s) so the multi-step cross-relay
/// tests below aren't torn down mid-run by the idle timer. The dedicated
/// idle-teardown test spawns its own driver with a short real duration.
fn spawn_mesh_link(
    link: MeshLink,
    sessions: Sessions,
    mesh: mesh::MeshState,
) -> mpsc::UnboundedSender<mesh::MeshCommand> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(mesh::run_mesh_link(
        link,
        rx,
        sessions,
        mesh,
        mesh::IDLE_TIMEOUT,
    ));
    tx
}
/// Like [`spawn_mesh_link`] but with a custom `idle_timeout` and returns the
/// driver's `JoinHandle` so the caller can await its [`mesh::MeshLinkExit`].
/// Used by the idle-teardown test, which needs a short real duration (not the
/// 60s production const) so the teardown is observable in well under a second.
fn spawn_mesh_link_timed(
    link: MeshLink,
    sessions: Sessions,
    mesh: mesh::MeshState,
    idle_timeout: Duration,
) -> (
    mpsc::UnboundedSender<mesh::MeshCommand>,
    tokio::task::JoinHandle<mesh::MeshLinkExit>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let handle = tokio::spawn(mesh::run_mesh_link(link, rx, sessions, mesh, idle_timeout));
    (tx, handle)
}

/// Brings up a loopback mesh connection pair (two `MeshLink`s over one real
/// quinn connection negotiated on `MESH_ALPN`), reusing the test's self-signed
/// cert helper. Both endpoints are returned so the caller keeps them alive.
async fn mesh_link_pair() -> (MeshLink, MeshLink, quinn::Endpoint, quinn::Endpoint) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let client_cfg = mesh_client_config(roots).unwrap();

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = quinn::Endpoint::server(server_cfg, bind).unwrap();
    let server_addr = server.local_addr().unwrap();
    let mut client = quinn::Endpoint::client(bind).unwrap();
    client.set_default_client_config(client_cfg);

    let accept = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
    };
    let client_conn = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let server_conn = accept.await.unwrap();

    (
        MeshLink::new(client_conn),
        MeshLink::new(server_conn),
        client,
        server,
    )
}

/// A link that served a session, went empty, and stayed empty past
/// `idle_timeout` tears down with [`mesh::MeshLinkExit::Idle`]. Joins a
/// session, leaves it, and waits past a short real-duration timeout — no
/// `tokio::time::pause`/`advance` (that would trip quinn's own 10s idle
/// timeout before the 200ms app-level one, surfacing `ConnectionFailed`
/// instead of `Idle`).
#[tokio::test]
async fn idle_link_tears_down_after_timeout_post_session() -> Result<(), AnyError> {
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let (mesh_a, mesh_b, _ep_a, _ep_b) = mesh_link_pair().await;
    let sessions: Sessions = Arc::default();
    let mesh = mesh::new_mesh_state();
    let idle_timeout = Duration::from_millis(200);

    let (cmds_a, handle_a) =
        spawn_mesh_link_timed(mesh_a, Arc::clone(&sessions), mesh.clone(), idle_timeout);
    // Keep mesh_b alive so the QUIC connection doesn't close — dropping the
    // peer's Connection handle closes it from the other side, and A's driver
    // would exit `ConnectionFailed` instead of `Idle`. mesh_b isn't driven
    // (no recv loop); quinn's endpoint processes keepalive ACKs internally.
    let _peer_alive = mesh_b;

    // Join, then leave — arming the idle timer on the transition to empty.
    cmds_a.send(mesh::MeshCommand::Join(key.clone()))?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    cmds_a.send(mesh::MeshCommand::Leave(key))?;

    // Wait past the idle timeout (200ms) plus a margin.
    tokio::time::sleep(Duration::from_millis(350)).await;

    let exit = handle_a.await.expect("driver task panicked");
    assert_eq!(exit, mesh::MeshLinkExit::Idle, "should tear down idle");
    Ok(())
}

/// A never-joined link stays parked: the idle timer is not armed until a link
/// has served at least one session, so a link that got no `Join` survives
/// well past `idle_timeout`. This is the custody contract the binary relies
/// on (it holds the command sender so drivers stay ready for the future Join
/// source) — tearing never-joined links down would strand the pair.
#[tokio::test]
async fn never_joined_link_survives_past_idle_timeout() -> Result<(), AnyError> {
    let (mesh_a, mesh_b, _ep_a, _ep_b) = mesh_link_pair().await;
    let sessions: Sessions = Arc::default();
    let mesh = mesh::new_mesh_state();
    let idle_timeout = Duration::from_millis(150);

    let (_cmds_a, handle_a) =
        spawn_mesh_link_timed(mesh_a, Arc::clone(&sessions), mesh.clone(), idle_timeout);
    let _peer_alive = mesh_b;

    // Wait well past the idle timeout without ever sending a Join.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // The driver must still be running — never armed, never fired.
    assert!(
        !handle_a.is_finished(),
        "never-joined link should stay parked, not tear down"
    );
    // Cancel the task so the test doesn't leak it.
    handle_a.abort();
    Ok(())
}

/// `C–S===S–C`: a client on relay A sends a turn; a client on relay B receives
/// it across the mesh. Asserts exactly-once delivery.
#[tokio::test]
async fn cross_relay_turn_delivery_is_exactly_once() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let relay_a = Relay::start(&tenant);
    let mut relay_b = Relay::start(&tenant);

    // A dials B on the mesh ALPN. B's accept loop dispatches to mesh_rx.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let mesh_cfg = mesh_client_config(roots).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut mesh_ep = quinn::Endpoint::client(bind).unwrap();
    mesh_ep.set_default_client_config(mesh_cfg);
    let conn_a = mesh_ep
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let conn_b = relay_b
        .mesh_rx
        .recv()
        .await
        .expect("B dispatched mesh conn");

    let mesh_a = MeshLink::new(conn_a);
    let mesh_b = MeshLink::new(conn_b);

    let cmds_a = spawn_mesh_link(mesh_a, Arc::clone(&relay_a.sessions), relay_a.mesh.clone());
    let cmds_b = spawn_mesh_link(mesh_b, Arc::clone(&relay_b.sessions), relay_b.mesh.clone());
    cmds_a.send(mesh::MeshCommand::Join(key.clone())).unwrap();
    cmds_b.send(mesh::MeshCommand::Join(key.clone())).unwrap();

    // Connect clients: slot 0 (sender) on A, slot 1 on B.
    let client_key_0 = keypair();
    let token_0 = mint_token(&tenant, session, SlotId(0), client_key_0.public);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_a.ca.clone()).unwrap();
    let client_cfg = client_config(roots).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut client_ep = quinn::Endpoint::client(bind).unwrap();
    client_ep.set_default_client_config(client_cfg);

    let conn_slot0 = client_ep
        .connect(relay_a.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot0, &token_0, &client_key_0).await?;
    let mut client_a = Link::new(conn_slot0);

    let client_key_1 = keypair();
    let token_1 = mint_token(&tenant, session, SlotId(1), client_key_1.public);
    let mut roots_b = rustls::RootCertStore::empty();
    roots_b.add(relay_b.ca.clone()).unwrap();
    let client_cfg_b = client_config(roots_b).unwrap();
    let mut client_ep_b = quinn::Endpoint::client(bind).unwrap();
    client_ep_b.set_default_client_config(client_cfg_b);
    let conn_slot1 = client_ep_b
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot1, &token_1, &client_key_1).await?;
    let mut client_b = Link::new(conn_slot1);

    // Let mesh drivers open their sessions on the MeshLinks.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client A (slot 0) sends a turn.
    client_a.send(Some(turn(0, 0))).unwrap();

    // Client B (slot 1) receives exactly one copy via the mesh.
    // This proves the full path: client A → relay A run_slot_link →
    // fan_out_to_mesh → mesh-link driver → MeshLink::send → relay B
    // MeshLink::recv → mesh-link driver → fan_out → client B.
    //
    // The client-side Dedup guarantees exactly-once delivery to each client
    // regardless of MeshSeen — MeshSeen is a relay-side forward-once
    // optimization (prevents O(N²) mesh amplification), not a client-visible
    // correctness guard. So this test proves cross-relay delivery, not
    // MeshSeen's dedup.
    let received_b = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .expect("client B did not receive the turn within 2s")
        .expect("client B link error");
    assert_eq!(received_b.fresh.len(), 1, "B: exactly one payload");
    assert_eq!(received_b.fresh[0].slot, 0);
    assert_eq!(received_b.fresh[0].seq, 0);
    assert!(
        received_b.fresh[0].commands.is_empty(),
        "empty commands preserved"
    );

    Ok(())
}

/// `C-S===S-C` with two games on one relay-pair: a client in game 1 on relay A
/// sends a turn; the client in game 1 on relay B receives it. The client in
/// game 2 on relay B does *not* receive it — turns don't leak across sessions
/// on the shared mesh connection. This is the load-bearing proof for the
/// multi-session driver: one `MeshLink` dispatches to N per-session states, and
/// the `SessionId -> SessionState` demux keeps the two games independent.
#[tokio::test]
async fn two_sessions_on_one_mesh_link_do_not_cross_wire() -> Result<(), AnyError> {
    let tenant = make_tenant();

    // Two games, same tenant, different session ids.
    let session_1 = SessionId(1);
    let session_2 = SessionId(2);
    let key_1 = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: session_1,
    };
    let key_2 = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: session_2,
    };

    let relay_a = Relay::start(&tenant);
    let mut relay_b = Relay::start(&tenant);

    // A dials B on the mesh ALPN. B's accept loop dispatches to mesh_rx.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let mesh_cfg = mesh_client_config(roots).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut mesh_ep = quinn::Endpoint::client(bind).unwrap();
    mesh_ep.set_default_client_config(mesh_cfg);
    let conn_a = mesh_ep
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let conn_b = relay_b
        .mesh_rx
        .recv()
        .await
        .expect("B dispatched mesh conn");

    let mesh_a = MeshLink::new(conn_a);
    let mesh_b = MeshLink::new(conn_b);

    // One mesh-link driver per relay, serving both sessions on the shared
    // connection. Both sessions join up front here; the dynamic-join test
    // below exercises joining after the link is already running.
    let cmds_a = spawn_mesh_link(mesh_a, Arc::clone(&relay_a.sessions), relay_a.mesh.clone());
    let cmds_b = spawn_mesh_link(mesh_b, Arc::clone(&relay_b.sessions), relay_b.mesh.clone());
    for k in [&key_1, &key_2] {
        cmds_a.send(mesh::MeshCommand::Join(k.clone())).unwrap();
        cmds_b.send(mesh::MeshCommand::Join(k.clone())).unwrap();
    }

    // Game 1: slot 0 on A, slot 1 on B.
    let client_key_0 = keypair();
    let token_0 = mint_token(&tenant, session_1, SlotId(0), client_key_0.public);
    let mut roots_a = rustls::RootCertStore::empty();
    roots_a.add(relay_a.ca.clone()).unwrap();
    let client_cfg_a = client_config(roots_a).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut client_ep_a = quinn::Endpoint::client(bind).unwrap();
    client_ep_a.set_default_client_config(client_cfg_a);
    let conn_slot0 = client_ep_a
        .connect(relay_a.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot0, &token_0, &client_key_0).await?;
    let mut client_a_game1 = Link::new(conn_slot0);

    let client_key_1 = keypair();
    let token_1 = mint_token(&tenant, session_1, SlotId(1), client_key_1.public);
    let mut roots_b1 = rustls::RootCertStore::empty();
    roots_b1.add(relay_b.ca.clone()).unwrap();
    let client_cfg_b1 = client_config(roots_b1).unwrap();
    let mut client_ep_b1 = quinn::Endpoint::client(bind).unwrap();
    client_ep_b1.set_default_client_config(client_cfg_b1);
    let conn_slot1 = client_ep_b1
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot1, &token_1, &client_key_1).await?;
    let mut client_b_game1 = Link::new(conn_slot1);

    // Game 2: slot 0 on B (a different game with its own session id).
    let client_key_2 = keypair();
    let token_2 = mint_token(&tenant, session_2, SlotId(0), client_key_2.public);
    let mut roots_b2 = rustls::RootCertStore::empty();
    roots_b2.add(relay_b.ca.clone()).unwrap();
    let client_cfg_b2 = client_config(roots_b2).unwrap();
    let mut client_ep_b2 = quinn::Endpoint::client(bind).unwrap();
    client_ep_b2.set_default_client_config(client_cfg_b2);
    let conn_slot0_game2 = client_ep_b2
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot0_game2, &token_2, &client_key_2).await?;
    let mut client_b_game2 = Link::new(conn_slot0_game2);

    // Let mesh drivers open their sessions on the MeshLinks.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client A in game 1 sends a turn.
    client_a_game1.send(Some(turn(0, 0))).unwrap();

    // Client B in game 1 receives exactly one copy via the mesh.
    let received_b1 = tokio::time::timeout(Duration::from_secs(2), client_b_game1.recv())
        .await
        .expect("client B game 1 did not receive the turn within 2s")
        .expect("client B game 1 link error");
    assert_eq!(received_b1.fresh.len(), 1, "B game 1: exactly one payload");
    assert_eq!(received_b1.fresh[0].slot, 0);
    assert_eq!(received_b1.fresh[0].seq, 0);

    // Client B in game 2 does NOT receive game 1's turn. The multi-session
    // driver's SessionId demux keeps the two games independent on the shared
    // mesh connection.
    let leaked = tokio::time::timeout(Duration::from_millis(200), client_b_game2.recv()).await;
    assert!(
        leaked.is_err(),
        "game 2 client must not receive game 1's turn — sessions are isolated"
    );

    Ok(())
}

/// Dynamic session join on a running mesh link: one session starts joined and
/// delivers a turn, then a *second* session joins the already-running driver and
/// delivers its own turn. This proves the command-channel join path — the core
/// of the dynamic-join/leave API — not just the upfront-list path the other two
/// tests exercise.
#[tokio::test]
async fn a_session_joined_after_the_link_is_running_delivers() -> Result<(), AnyError> {
    let tenant = make_tenant();

    let session_1 = SessionId(1);
    let session_2 = SessionId(2);
    let key_1 = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: session_1,
    };
    let key_2 = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: session_2,
    };

    let relay_a = Relay::start(&tenant);
    let mut relay_b = Relay::start(&tenant);

    // A dials B on the mesh ALPN. B's accept loop dispatches to mesh_rx.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let mesh_cfg = mesh_client_config(roots).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut mesh_ep = quinn::Endpoint::client(bind).unwrap();
    mesh_ep.set_default_client_config(mesh_cfg);
    let conn_a = mesh_ep
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let conn_b = relay_b
        .mesh_rx
        .recv()
        .await
        .expect("B dispatched mesh conn");

    let mesh_a = MeshLink::new(conn_a);
    let mesh_b = MeshLink::new(conn_b);

    // Spawn the drivers with no sessions joined yet — the links come up idle,
    // awaiting their first Join.
    let cmds_a = spawn_mesh_link(mesh_a, Arc::clone(&relay_a.sessions), relay_a.mesh.clone());
    let cmds_b = spawn_mesh_link(mesh_b, Arc::clone(&relay_b.sessions), relay_b.mesh.clone());

    // Session 1 joins first and exchanges a turn, proving the link is live.
    cmds_a.send(mesh::MeshCommand::Join(key_1.clone())).unwrap();
    cmds_b.send(mesh::MeshCommand::Join(key_1.clone())).unwrap();

    let client_key_1a = keypair();
    let token_1a = mint_token(&tenant, session_1, SlotId(0), client_key_1a.public);
    let mut roots_a = rustls::RootCertStore::empty();
    roots_a.add(relay_a.ca.clone()).unwrap();
    let client_cfg_a = client_config(roots_a).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut client_ep_a = quinn::Endpoint::client(bind).unwrap();
    client_ep_a.set_default_client_config(client_cfg_a);
    let conn_s1_a = client_ep_a
        .connect(relay_a.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_s1_a, &token_1a, &client_key_1a).await?;
    let mut client_s1_a = Link::new(conn_s1_a);

    let client_key_1b = keypair();
    let token_1b = mint_token(&tenant, session_1, SlotId(1), client_key_1b.public);
    let mut roots_b = rustls::RootCertStore::empty();
    roots_b.add(relay_b.ca.clone()).unwrap();
    let client_cfg_b = client_config(roots_b).unwrap();
    let mut client_ep_b = quinn::Endpoint::client(bind).unwrap();
    client_ep_b.set_default_client_config(client_cfg_b);
    let conn_s1_b = client_ep_b
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_s1_b, &token_1b, &client_key_1b).await?;
    let mut client_s1_b = Link::new(conn_s1_b);

    tokio::time::sleep(Duration::from_millis(50)).await;
    client_s1_a.send(Some(turn(0, 0))).unwrap();
    let received_s1 = tokio::time::timeout(Duration::from_secs(2), client_s1_b.recv())
        .await
        .expect("session 1 turn did not arrive within 2s")
        .expect("session 1 link error");
    assert_eq!(received_s1.fresh.len(), 1, "session 1: exactly one payload");

    // Now session 2 joins the already-running link — the dynamic-join path.
    cmds_a.send(mesh::MeshCommand::Join(key_2.clone())).unwrap();
    cmds_b.send(mesh::MeshCommand::Join(key_2.clone())).unwrap();

    let client_key_2a = keypair();
    let token_2a = mint_token(&tenant, session_2, SlotId(0), client_key_2a.public);
    let conn_s2_a = client_ep_a
        .connect(relay_a.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_s2_a, &token_2a, &client_key_2a).await?;
    let mut client_s2_a = Link::new(conn_s2_a);

    let client_key_2b = keypair();
    let token_2b = mint_token(&tenant, session_2, SlotId(1), client_key_2b.public);
    let conn_s2_b = client_ep_b
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_s2_b, &token_2b, &client_key_2b).await?;
    let mut client_s2_b = Link::new(conn_s2_b);

    tokio::time::sleep(Duration::from_millis(50)).await;
    client_s2_a.send(Some(turn(0, 0))).unwrap();
    let received_s2 = tokio::time::timeout(Duration::from_secs(2), client_s2_b.recv())
        .await
        .expect("session 2 turn did not arrive within 2s")
        .expect("session 2 link error");
    assert_eq!(received_s2.fresh.len(), 1, "session 2: exactly one payload");
    assert_eq!(received_s2.fresh[0].slot, 0);
    assert_eq!(received_s2.fresh[0].seq, 0);

    Ok(())
}

/// The per-Join collision guard on the live driver: two tenants that both
/// assigned session id 1 can't be told apart on the wire, so the second Join
/// is refused — not overwriting the first. The colliding tenant then *leaves*
/// the shared id; because the driver keys `joined` by the bare wire session id,
/// a Leave that matched on id alone would evict whatever holds it — tenant A.
/// A client in tenant A's session 1 still receives turns after both the
/// colliding Join and its Leave are attempted, proving the Leave matched the
/// full SessionKey and left the legitimate tenant's session intact.
#[tokio::test]
async fn a_colliding_join_across_tenants_is_refused_on_the_live_driver() -> Result<(), AnyError> {
    // tenant_b only needs to differ in name — the collision is on the mesh
    // driver's session-state map (bare session id can't disambiguate tenants),
    // not on the client edge, so no tenant_b client ever connects. Both relays
    // admit tenant_a's clients; tenant_b exists solely as a SessionKey.
    let tenant_a = make_tenant();
    let tenant_b_name = "sb-other".to_owned();

    let session = SessionId(1);
    let key_a = SessionKey {
        tenant: TenantId(tenant_a.name.clone()),
        session,
    };
    let key_b = SessionKey {
        tenant: TenantId(tenant_b_name),
        session,
    };

    let relay_a = Relay::start(&tenant_a);
    let mut relay_b = Relay::start(&tenant_a);

    // A dials B on the mesh ALPN. B's accept loop dispatches to mesh_rx.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let mesh_cfg = mesh_client_config(roots).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut mesh_ep = quinn::Endpoint::client(bind).unwrap();
    mesh_ep.set_default_client_config(mesh_cfg);
    let conn_a = mesh_ep
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let conn_b = relay_b
        .mesh_rx
        .recv()
        .await
        .expect("B dispatched mesh conn");

    let mesh_a = MeshLink::new(conn_a);
    let mesh_b = MeshLink::new(conn_b);

    let cmds_a = spawn_mesh_link(mesh_a, Arc::clone(&relay_a.sessions), relay_a.mesh.clone());
    let cmds_b = spawn_mesh_link(mesh_b, Arc::clone(&relay_b.sessions), relay_b.mesh.clone());

    // Tenant A joins session 1 first on both sides.
    cmds_a.send(mesh::MeshCommand::Join(key_a.clone())).unwrap();
    cmds_b.send(mesh::MeshCommand::Join(key_a.clone())).unwrap();

    // Tenant B attempts to join the same session id — must be refused, not
    // overwriting tenant A's session. The command is accepted by the channel
    // (the driver logs and drops it); there's no ack, so we prove refusal by
    // showing tenant A's session still works afterward.
    cmds_b.send(mesh::MeshCommand::Join(key_b.clone())).unwrap();
    cmds_a.send(mesh::MeshCommand::Join(key_b.clone())).unwrap();

    // Tenant B then leaves the colliding id. The driver keys `joined` by the
    // bare wire session id, so a Leave matching on id alone would evict tenant
    // A's session 1. The Leave must match the full SessionKey and be ignored
    // here, leaving tenant A's session intact — proven by the delivery below.
    cmds_b
        .send(mesh::MeshCommand::Leave(key_b.clone()))
        .unwrap();
    cmds_a
        .send(mesh::MeshCommand::Leave(key_b.clone()))
        .unwrap();

    // Connect tenant A's clients: slot 0 on A, slot 1 on B.
    let client_key_0 = keypair();
    let token_0 = mint_token(&tenant_a, session, SlotId(0), client_key_0.public);
    let mut roots_a = rustls::RootCertStore::empty();
    roots_a.add(relay_a.ca.clone()).unwrap();
    let client_cfg_a = client_config(roots_a).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut client_ep_a = quinn::Endpoint::client(bind).unwrap();
    client_ep_a.set_default_client_config(client_cfg_a);
    let conn_slot0 = client_ep_a
        .connect(relay_a.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot0, &token_0, &client_key_0).await?;
    let mut client_a = Link::new(conn_slot0);

    let client_key_1 = keypair();
    let token_1 = mint_token(&tenant_a, session, SlotId(1), client_key_1.public);
    let mut roots_b = rustls::RootCertStore::empty();
    roots_b.add(relay_b.ca.clone()).unwrap();
    let client_cfg_b = client_config(roots_b).unwrap();
    let mut client_ep_b = quinn::Endpoint::client(bind).unwrap();
    client_ep_b.set_default_client_config(client_cfg_b);
    let conn_slot1 = client_ep_b
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    handshake(&conn_slot1, &token_1, &client_key_1).await?;
    let mut client_b = Link::new(conn_slot1);

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Tenant A's turn still delivers across the mesh after the colliding Join
    // and its Leave were attempted — proving tenant A's session survived, tenant
    // B never overwrote it, and B's Leave on the shared id did not evict it.
    client_a.send(Some(turn(0, 0))).unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .expect("tenant A's turn did not arrive within 2s after colliding Join + Leave")
        .expect("client B link error");
    assert_eq!(received.fresh.len(), 1, "exactly one payload delivered");
    assert_eq!(received.fresh[0].slot, 0);
    assert_eq!(received.fresh[0].seq, 0);

    Ok(())
}
