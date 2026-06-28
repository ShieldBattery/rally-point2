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
        // Empty commands — a bare turn signal. validate_turn accepts this
        // (it yields an empty payload after stripping). A non-empty command
        // would need to be a valid SC:R opcode or validate_turn rejects it.
        commands: vec![].into(),
    }
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

    tokio::spawn(mesh::run_mesh_link(
        mesh_a,
        vec![key.clone()],
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
    ));
    tokio::spawn(mesh::run_mesh_link(
        mesh_b,
        vec![key.clone()],
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
    ));

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
    // connection.
    tokio::spawn(mesh::run_mesh_link(
        mesh_a,
        vec![key_1.clone(), key_2.clone()],
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
    ));
    tokio::spawn(mesh::run_mesh_link(
        mesh_b,
        vec![key_1.clone(), key_2.clone()],
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
    ));

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
