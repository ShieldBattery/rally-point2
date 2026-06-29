//! Integration coverage of the mesh-edge **connection half**
//! (`mesh_edge::run_mesh_accept` + `run_mesh_dial`): two real relays serve on
//! their own endpoints, the lower-id one dials the higher-id one through the
//! production dial path, the higher-id one accepts through the production
//! accept drain, and each established link's `MeshCommand` sender comes back on
//! the `links` channel. The test sends `Join` on both senders (exactly as the
//! coordinator's session-descriptor push will in Phase 3, and as `mesh_edge.rs`
//! sends it on the command channel directly), then proves a turn flows
//! cross-relay.
//!
//! This mirrors `mesh_edge.rs::cross_relay_turn_delivery_is_exactly_once` but
//! exercises the connection-establishment layer (`mesh_edge`) instead of
//! manually creating `MeshLink`s and spawning `run_mesh_link`. The per-link
//! driver, dedup, and fan-out are already proven by `mesh_edge.rs`; this test
//! proves the connection half wires them up correctly and the returned
//! command senders drive Join end-to-end.

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_proto::token::{
    CHALLENGE_LEN, CHANNEL_BINDING_EXPORTER_LABEL, CHANNEL_BINDING_LEN, ClientPublicKey,
    ConnectionChallenge, ExpiresAt, KeyId, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, SignedToken,
    TokenClaims,
};
use rally_point_relay::auth::HANDSHAKE_OK;
use rally_point_relay::mesh;
use rally_point_relay::mesh_edge;
use rally_point_relay::routing::{SessionKey, Sessions};
use rally_point_relay::server;
use rally_point_transport::quic::{client_config, server_config};
use rally_point_transport::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rally_point_transport::{Link, quinn, rustls};
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

fn registry_for(tenant: &Tenant) -> rally_point_relay::auth::Registry {
    let mut registry = rally_point_relay::auth::Registry::new();
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

/// A relay with its client edge serving, plus the mesh-accept channel and
/// shared mesh state. Mirrors `mesh_edge.rs`'s `Relay` but exposes
/// `mesh_accept_rx` for the production `run_mesh_accept` drain.
struct Relay {
    addr: SocketAddr,
    ca: CertificateDer<'static>,
    sessions: Sessions,
    mesh: mesh::MeshState,
    mesh_accept_rx: mpsc::Receiver<quinn::Connection>,
}

impl Relay {
    fn start(tenant: &Tenant, relay_id: u64) -> Self {
        let (chain, key, ca) = self_signed();
        let cfg = server_config(chain, key).unwrap();
        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let endpoint = quinn::Endpoint::server(cfg, bind).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let sessions: Sessions = Arc::default();
        let mesh = mesh::new_mesh_state();
        let (mesh_accept_tx, mesh_accept_rx) = mpsc::channel(8);

        tokio::spawn(server::serve(
            endpoint,
            Arc::new(registry_for(tenant)),
            Arc::clone(&sessions),
            mesh.clone(),
            Some(mesh_accept_tx),
        ));

        tracing::info!(relay_id, %addr, "relay started");
        Self {
            addr,
            ca,
            sessions,
            mesh,
            mesh_accept_rx,
        }
    }
}

fn turn(slot: u8, seq: u64) -> Payload {
    Payload {
        seq,
        slot: u32::from(slot),
        game_frame_count: None,
        commands: vec![].into(),
    }
}

/// Connects a client to `addr`, authorizes with a minted token, and returns
/// the `Link` for sending/receiving turns.
async fn connect_client(
    addr: SocketAddr,
    ca: &CertificateDer<'static>,
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
) -> Result<Link, AnyError> {
    let client_key = keypair();
    let token = mint_token(tenant, session, slot, client_key.public);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let cfg = client_config(roots).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut ep = quinn::Endpoint::client(bind).unwrap();
    ep.set_default_client_config(cfg);
    let conn = ep.connect(addr, "localhost").unwrap().await.unwrap();
    handshake(&conn, &token, &client_key).await?;
    Ok(Link::new(conn))
}

/// Two relays mesh via the production connection half (`run_mesh_dial` +
/// `run_mesh_accept`); the test sends `Join` on the returned command senders;
/// a turn flows cross-relay.
#[tokio::test]
async fn cross_relay_turn_through_production_mesh_connection_half() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Relay A is the lower id (1), so it dials. Relay B is the higher id (2),
    // so it accepts A's dial.
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    // B's accept drain: spawns a `run_mesh_link` driver for each peer relay
    // that dials in, returning the command sender on `links_b_rx`.
    let (links_b_tx, mut links_b_rx) = mpsc::channel::<mpsc::Sender<mesh::MeshCommand>>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
    ));

    // A dials B. The dial establishes the connection and spawns a
    // `run_mesh_link` driver, returning the command sender on `links_a_rx`.
    let (links_a_tx, mut links_a_rx) = mpsc::channel::<mpsc::Sender<mesh::MeshCommand>>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addr: relay_b.addr,
        server_name: "localhost".to_owned(),
        roots,
    };
    tokio::spawn(mesh_edge::run_mesh_dial(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
    ));

    // Collect the command senders from each side's `links` channel.
    let cmds_a = links_a_rx
        .recv()
        .await
        .ok_or("dial side did not produce a link")?;
    let cmds_b = links_b_rx
        .recv()
        .await
        .ok_or("accept side did not produce a link")?;

    // Send Join on both sides — the test drives this exactly as the
    // coordinator's session-descriptor push will in Phase 3.
    cmds_a.send(mesh::MeshCommand::Join(key.clone())).await?;
    cmds_b.send(mesh::MeshCommand::Join(key.clone())).await?;

    // Connect clients: slot 0 (sender) on relay A, slot 1 on relay B.
    let mut client_a =
        connect_client(relay_a.addr, &relay_a.ca, &tenant, session, SlotId(0)).await?;
    let mut client_b =
        connect_client(relay_b.addr, &relay_b.ca, &tenant, session, SlotId(1)).await?;

    // Let the mesh drivers open their sessions on the MeshLinks.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client A (slot 0) sends a turn.
    client_a.send(Some(turn(0, 0))).unwrap();

    // Client B (slot 1) receives exactly one copy via the mesh. This proves
    // the full production path: `run_mesh_dial` establishes the connection +
    // spawns the driver, `run_mesh_accept` accepts it + spawns the driver, the
    // returned command senders drive Join, and a turn flows cross-relay.
    let received_b = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .map_err(|_| "client B did not receive the turn within 2s")?
        .map_err(|e| format!("client B link error: {e}"))?;
    assert_eq!(received_b.fresh.len(), 1, "B: exactly one payload");
    assert_eq!(received_b.fresh[0].slot, 0);
    assert_eq!(received_b.fresh[0].seq, 0);

    // Consume relay_a: its mesh_accept_rx is unused (A dials, it doesn't
    // accept), so drop it to release the resources.
    drop(relay_a);
    Ok(())
}

/// `should_dial_mesh` returns false for equal ids, so neither relay dials —
/// `run_mesh_dial` is a no-op and the `links` channel receives nothing.
#[tokio::test]
async fn equal_relay_ids_do_not_dial() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 1);

    let (links_tx, mut links_rx) = mpsc::channel::<mpsc::Sender<mesh::MeshCommand>>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(1),
        peer_addr: relay_b.addr,
        server_name: "localhost".to_owned(),
        roots,
    };
    mesh_edge::run_mesh_dial(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_tx,
    )
    .await;

    // No link established — the dial was a no-op.
    assert!(
        links_rx.try_recv().is_err(),
        "equal ids should not produce a link"
    );
    Ok(())
}

/// A higher-id relay does not dial a lower-id peer — `run_mesh_dial` is a
/// no-op. The lower-id peer's dial arrives on the accept side instead.
#[tokio::test]
async fn higher_id_relay_does_not_dial_lower_id_peer() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_a = Relay::start(&tenant, 2); // higher id
    let relay_b = Relay::start(&tenant, 1); // lower id (would dial A)

    let (links_tx, mut links_rx) = mpsc::channel::<mpsc::Sender<mesh::MeshCommand>>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(2),
        peer_id: RelayId(1),
        peer_addr: relay_b.addr,
        server_name: "localhost".to_owned(),
        roots,
    };
    mesh_edge::run_mesh_dial(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_tx,
    )
    .await;

    assert!(
        links_rx.try_recv().is_err(),
        "higher-id relay should not dial a lower-id peer"
    );
    Ok(())
}
