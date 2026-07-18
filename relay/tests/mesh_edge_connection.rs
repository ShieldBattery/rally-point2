//! Integration coverage of the mesh-edge **connection half**
//! (`mesh_edge::run_mesh_accept` + `run_mesh_dial`): two real relays serve on
//! their own endpoints, the lower-id one dials the higher-id one through the
//! production dial path, the higher-id one accepts through the production
//! accept drain, and each established link comes back on the `links` channel as
//! `(peer id, MeshCommand sender)` — the dialer's id known from config, the
//! acceptor's learned from the identity hello. The first test sends `Join` on
//! both senders directly and proves a turn flows cross-relay; the second drives
//! the same turn through `MeshControl::apply_descriptor`, exactly as the
//! coordinator's session-descriptor push will once its control transport exists.
//!
//! This mirrors `mesh_edge.rs::cross_relay_turn_delivery_is_exactly_once` but
//! exercises the connection-establishment layer (`mesh_edge`) instead of
//! manually creating `MeshLink`s and spawning `run_mesh_link`. The per-link
//! driver, dedup, and fan-out are already proven by `mesh_edge.rs`; these tests
//! prove the connection half wires them up correctly, labels each link with its
//! peer, and that Join drives cross-relay delivery end-to-end.

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::{BufferBounds, RelayPeer, SessionDescriptor, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_proto::token::{
    CHALLENGE_LEN, CHANNEL_BINDING_EXPORTER_LABEL, CHANNEL_BINDING_LEN, ClientPublicKey,
    ConnectionChallenge, ExpiresAt, KeyId, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, SignedToken,
    TokenClaims,
};
use rally_point_relay::auth::HANDSHAKE_OK;
use rally_point_relay::coordinator_client::{FleetMeshPeers, FleetMeshPeersReader};
use rally_point_relay::mesh;
use rally_point_relay::mesh_control;
use rally_point_relay::mesh_dialer;
use rally_point_relay::mesh_edge;
use rally_point_relay::routing::{SessionKey, Sessions};
use rally_point_relay::server;
use rally_point_transport::quic::{client_config, server_config};
use rally_point_transport::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rally_point_transport::{Link, quinn, rustls};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use tokio::sync::{mpsc, watch};

const KID: &str = "staging-key-1";
const TENANT: &str = "sb-staging";

type AnyError = Box<dyn Error + Send + Sync>;

/// An empty fleet mesh-peer read handle for the accept side: these tests exercise
/// the connection half, not the coordinator's peer-auth push, so the acceptor's
/// fleet map is empty (its writer is dropped immediately, leaving only the handle).
fn empty_fleet_peers() -> FleetMeshPeersReader {
    FleetMeshPeers::new().reader()
}

/// What an established mesh link surfaces on the `links` channel: the peer's id and
/// the command sender that drives `Join`/`Leave` on that link.
type LinkHandle = (RelayId, mpsc::UnboundedSender<mesh::MeshCommand>);

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

    // A fresh dial presents no resume cursors: an empty (zero-count) frame.
    let cursor_frame = rally_point_proto::handshake::encode_resume_cursors(&[])?;
    send.write_all(&cursor_frame).await?;

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
        commands: vec![].into(),
        ..Default::default()
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

    // A's mesh-dial identity: a real certificate, separate from A's client-edge
    // serving cert, whose fingerprint is seeded into B's fleet-peer map below —
    // so this test (unlike most of this file's) runs with peer-identity
    // enforcement ACTIVE, proving the happy path still works when the fleet map
    // is non-empty and the dialer's certificate actually matches it.
    let (dial_chain, dial_key, dial_ca) = self_signed();
    let fleet = FleetMeshPeers::new();
    fleet.store(vec![rally_point_proto::control::MeshPeerIdentity {
        relay_id: RelayId(1),
        cert_sha256: rally_point_transport::quic::cert_fingerprint(dial_ca.as_ref()),
    }]);

    // B's accept drain: spawns a `run_mesh_link` driver for each peer relay
    // that dials in, returning `(peer id, command sender)` on `links_b_rx`.
    let (links_b_tx, mut links_b_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        fleet.reader(),
        false,
    ));

    // A dials B. The dial establishes the connection and spawns a
    // `run_mesh_link` driver, returning `(peer id, command sender)` on
    // `links_a_rx`.
    let (links_a_tx, mut links_a_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    tokio::spawn(mesh_edge::run_mesh_dial(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
    ));

    // Collect each side's link, labeled with the peer it reaches. A dialed B,
    // so A's link is labeled with B's id; B read the dialer's identity hello,
    // so B's link is labeled with A's id.
    let (peer_a, cmds_a) = links_a_rx
        .recv()
        .await
        .ok_or("dial side did not produce a link")?;
    let (peer_b, cmds_b) = links_b_rx
        .recv()
        .await
        .ok_or("accept side did not produce a link")?;
    assert_eq!(peer_a, RelayId(2), "A's link reaches B");
    assert_eq!(
        peer_b,
        RelayId(1),
        "B learned the dialer's id from the hello",
    );

    // Send Join on both sides — the test drives the command senders directly,
    // standing in for the coordinator-fed `MeshControl` Join source.
    cmds_a.send(mesh::MeshCommand::Join(key.clone()))?;
    cmds_b.send(mesh::MeshCommand::Join(key.clone()))?;

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

/// The same cross-relay turn, but driven by [`mesh_control::MeshControl`]
/// applying a coordinator [`SessionDescriptor`] instead of a hand-sent `Join`.
///
/// Proves the production Join path end to end: each established link registers
/// in the relay's `MeshControl` keyed by the peer id the hello carried, a
/// descriptor names that peer, `apply_descriptor` emits the targeted `Join` on
/// the right link, and a turn flows cross-relay. This is exactly what the
/// coordinator's session-descriptor push will drive once its control transport
/// to the relay exists.
#[tokio::test]
async fn descriptor_drives_cross_relay_turn_via_mesh_control() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(1);

    // Relay A (id 1) dials; relay B (id 2) accepts.
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    // Each relay's Join source.
    let control_a = mesh_control::MeshControl::new(RelayId(1), Arc::default(), Arc::default());
    let control_b = mesh_control::MeshControl::new(RelayId(2), Arc::default(), Arc::default());

    let (links_b_tx, mut links_b_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));

    let (links_a_tx, mut links_a_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    tokio::spawn(mesh_edge::run_mesh_dial(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
    ));

    // Register each established link in its relay's control, keyed by the peer
    // id the connection half labeled it with. Awaiting the link makes this
    // deterministic — no sleeping to hope the link came up.
    let (peer_a, cmds_a) = links_a_rx
        .recv()
        .await
        .ok_or("dial side did not produce a link")?;
    control_a.register_link(peer_a, cmds_a);
    let (peer_b, cmds_b) = links_b_rx
        .recv()
        .await
        .ok_or("accept side did not produce a link")?;
    control_b.register_link(peer_b, cmds_b);

    // The coordinator pushes each relay its descriptor: A's only peer is B, and
    // B's only peer is A. Applying it emits the targeted Join on the link the
    // peer id selects.
    control_a.apply_descriptor(&SessionDescriptor {
        tenant: TenantId(TENANT.to_owned()),
        session,
        peers: vec![RelayPeer {
            relay_id: RelayId(2),
            relay_addr: relay_b.addr,
            cert_der: relay_b.ca.to_vec(),
            relay_addrs: vec![],
        }],
        bounds: BufferBounds::new(1, 6).unwrap(),
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
    control_b.apply_descriptor(&SessionDescriptor {
        tenant: TenantId(TENANT.to_owned()),
        session,
        peers: vec![RelayPeer {
            relay_id: RelayId(1),
            relay_addr: relay_a.addr,
            cert_der: relay_a.ca.to_vec(),
            relay_addrs: vec![],
        }],
        bounds: BufferBounds::new(1, 6).unwrap(),
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

    // Connect clients: slot 0 (sender) on relay A, slot 1 on relay B.
    let mut client_a =
        connect_client(relay_a.addr, &relay_a.ca, &tenant, session, SlotId(0)).await?;
    let mut client_b =
        connect_client(relay_b.addr, &relay_b.ca, &tenant, session, SlotId(1)).await?;

    // Let the mesh drivers process the Join (open their sessions) before the turn.
    tokio::time::sleep(Duration::from_millis(50)).await;

    client_a.send(Some(turn(0, 0))).unwrap();

    let received_b = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .map_err(|_| "client B did not receive the turn within 2s")?
        .map_err(|e| format!("client B link error: {e}"))?;
    assert_eq!(received_b.fresh.len(), 1, "B: exactly one payload");
    assert_eq!(received_b.fresh[0].slot, 0);
    assert_eq!(received_b.fresh[0].seq, 0);

    drop(relay_a);
    Ok(())
}

/// Buffer authority hands off to the next relay in the coordinator-assigned
/// order when the deciding relay's players all leave — driven end to end over
/// the production mesh presence path, with no descriptor re-push.
///
/// Relay A heads the order and serves the session's first client, so it
/// decides. When that client disconnects, A's slot roster empties: A demotes
/// itself locally, its mesh driver pushes the zero over the presence stream,
/// and B — next in the order, still serving a player — promotes itself. The
/// assertions poll rather than sleep because presence propagates on the mesh
/// flush cadence.
#[tokio::test]
async fn authority_hands_off_over_mesh_presence_when_players_leave() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Relay A (id 1) dials; relay B (id 2) accepts. Each control shares its
    // relay's decision-maker and presence registries, as the binary wires it —
    // the descriptor's order must land where the turn-path reports do.
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);
    let control_a = mesh_control::MeshControl::new(
        RelayId(1),
        relay_a.mesh.decision_makers.clone(),
        relay_a.mesh.presence.clone(),
    );
    let control_b = mesh_control::MeshControl::new(
        RelayId(2),
        relay_b.mesh.decision_makers.clone(),
        relay_b.mesh.presence.clone(),
    );

    let (links_b_tx, mut links_b_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));
    let (links_a_tx, mut links_a_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    tokio::spawn(mesh_edge::run_mesh_dial(
        mesh_edge::MeshDial {
            our_id: RelayId(1),
            peer_id: RelayId(2),
            peer_addrs: vec![relay_b.addr],
            server_name: "localhost".to_owned(),
            roots,
            cert_chain: dial_chain,
            key: dial_key,
        },
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
    ));

    let (peer_a, cmds_a) = links_a_rx
        .recv()
        .await
        .ok_or("dial side did not produce a link")?;
    control_a.register_link(peer_a, cmds_a);
    let (peer_b, cmds_b) = links_b_rx
        .recv()
        .await
        .ok_or("accept side did not produce a link")?;
    control_b.register_link(peer_b, cmds_b);

    // The coordinator ranked A first (the session's home relay).
    let descriptor_for = |peers: Vec<RelayPeer>| SessionDescriptor {
        tenant: TenantId(TENANT.to_owned()),
        session,
        peers,
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![RelayId(1), RelayId(2)],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
    };
    control_a.apply_descriptor(&descriptor_for(vec![RelayPeer {
        relay_id: RelayId(2),
        relay_addr: relay_b.addr,
        cert_der: relay_b.ca.to_vec(),
        relay_addrs: vec![],
    }]));
    control_b.apply_descriptor(&descriptor_for(vec![RelayPeer {
        relay_id: RelayId(1),
        relay_addr: relay_a.addr,
        cert_der: relay_a.ca.to_vec(),
        relay_addrs: vec![],
    }]));

    // A player on each relay. A's client is the one whose departure hands off.
    let mut client_a =
        connect_client(relay_a.addr, &relay_a.ca, &tenant, session, SlotId(0)).await?;
    let mut client_b =
        connect_client(relay_b.addr, &relay_b.ca, &tenant, session, SlotId(1)).await?;

    let a_is_authority = || {
        relay_a
            .mesh
            .decision_makers
            .lock()
            .get(&key)
            .is_some_and(|m| m.is_authority())
    };
    let b_is_authority = || {
        relay_b
            .mesh
            .decision_makers
            .lock()
            .get(&key)
            .is_some_and(|m| m.is_authority())
    };

    // Steady state: A (first in order, serving a player) decides, B defers.
    // Polled, not asserted immediately: right after Join, A's roster was still
    // empty, so B may hold a transiently different view until A's first
    // nonzero presence report lands.
    wait_for("A to hold authority and B to defer", || {
        a_is_authority() && !b_is_authority()
    })
    .await?;

    // Prove the session actually carries turns while A decides.
    client_a.send(Some(turn(0, 0))).unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .map_err(|_| "client B did not receive the turn within 2s")?
        .map_err(|e| format!("client B link error: {e}"))?;
    assert_eq!(received.fresh.len(), 1);

    // A's only player leaves. No descriptor re-push follows — the handoff must
    // ride the relays' own presence exchange.
    drop(client_a);
    wait_for("authority to hand off from A to B", || {
        !a_is_authority() && b_is_authority()
    })
    .await?;

    drop(relay_a);
    Ok(())
}

/// Polls `cond` until it holds, failing after a few seconds. Presence and
/// authority propagate on the mesh flush cadence (~150ms), so tests observe
/// them by polling, never by a single fixed sleep.
async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) -> Result<(), AnyError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| format!("timed out waiting for {what}").into())
}

/// `should_dial_mesh` returns false for equal ids, so neither relay dials —
/// `run_mesh_dial` is a no-op and the `links` channel receives nothing.
#[tokio::test]
async fn equal_relay_ids_do_not_dial() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 1);

    let (links_tx, mut links_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(1),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
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

    let (links_tx, mut links_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(2),
        peer_id: RelayId(1),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
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

/// The dial is supervised: when an established link's connection fails, the dialer
/// redials and surfaces a fresh link, rather than the pair being stranded until
/// the process restarts.
///
/// The test drains relay B's accept channel directly (instead of handing it to
/// `run_mesh_accept`) so it can application-close the first connection — forcing
/// the dialer's link driver to exit `ConnectionFailed` — and then observe the
/// redial arrive as a second accepted connection and a second surfaced link.
#[tokio::test]
async fn dial_redials_after_the_link_connection_fails() -> Result<(), AnyError> {
    let tenant = make_tenant();

    // A (id 1) dials; B (id 2) accepts. B stays up throughout, so the redial can
    // reconnect to it.
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);

    let (links_a_tx, mut links_a_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    // A short redial delay so the test doesn't wait the production interval.
    tokio::spawn(mesh_edge::run_mesh_dial_with(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
        Duration::from_millis(50),
    ));

    // The first dial connects: B accepts a connection and A surfaces a link
    // labeled with B's id.
    let conn1 = tokio::time::timeout(Duration::from_secs(2), relay_b.mesh_accept_rx.recv())
        .await
        .map_err(|_| "B did not accept A's first dial within 2s")?
        .ok_or("B's accept channel closed")?;
    let (peer1, _cmds1) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "A did not surface its first link within 2s")?
        .ok_or("A's links channel closed")?;
    assert_eq!(peer1, RelayId(2), "A's first link reaches B");

    // The link's connection fails: B application-closes it, so A's driver exits
    // `ConnectionFailed` and the supervisor redials.
    conn1.close(0u32.into(), b"drop to force a redial");

    // A redials: B accepts a second connection, and A surfaces a fresh link — the
    // proof the dial is supervised, not fire-once.
    let _conn2 = tokio::time::timeout(Duration::from_secs(2), relay_b.mesh_accept_rx.recv())
        .await
        .map_err(|_| "A did not redial after the connection failed")?
        .ok_or("B's accept channel closed")?;
    let (peer2, _cmds2) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "A did not surface a link after redialing")?
        .ok_or("A's links channel closed")?;
    assert_eq!(peer2, RelayId(2), "A's redialed link reaches B");

    drop(relay_a);
    Ok(())
}

/// A peer's control-stream reader ending while the connection stays otherwise
/// alive must be treated as a link failure, not a degradation limped through —
/// otherwise the pair permanently loses
/// `SlotDeparted`/`LeaveDirective`/oversize-turn/delivery-cursor traffic between
/// them. Mirrors [`dial_redials_after_the_link_connection_fails`] exactly, but
/// kills the link by finishing the peer's control stream (a clean EOF, no reset,
/// no whole-connection close) instead of closing the connection outright — the
/// established link must still exit `ConnectionFailed` and the dial supervisor
/// must still redial.
#[tokio::test]
async fn dial_redials_after_the_peer_control_stream_dies() -> Result<(), AnyError> {
    let tenant = make_tenant();

    // A (id 1) dials; B (id 2) accepts. B stays up throughout, so the redial can
    // reconnect to it.
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);

    let (links_a_tx, mut links_a_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    // A short redial delay so the test doesn't wait the production interval.
    tokio::spawn(mesh_edge::run_mesh_dial_with(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
        Duration::from_millis(50),
    ));

    // The first dial connects: B accepts a connection and A surfaces a link
    // labeled with B's id. B's real driver never runs here (its accept channel
    // is drained directly), so nothing has yet accepted A's (the dialer's) mesh
    // control stream from B's side of the wire.
    let conn1 = tokio::time::timeout(Duration::from_secs(2), relay_b.mesh_accept_rx.recv())
        .await
        .map_err(|_| "B did not accept A's first dial within 2s")?
        .ok_or("B's accept channel closed")?;
    let (peer1, _cmds1) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "A did not surface its first link within 2s")?
        .ok_or("A's links channel closed")?;
    assert_eq!(peer1, RelayId(2), "A's first link reaches B");

    // The mesh control stream is one bidirectional stream the dialer (A) opens
    // and writes an establishing frame on right away — which is why B's
    // `accept_bi` below completes promptly even though B's real driver never
    // ran. Accept B's paired half of that same stream, then immediately finish
    // B's send direction: a clean EOF on the stream A's `peer_control_rx`
    // reads, with the connection itself left fully alive.
    let (mut b_control_send, _unused) = conn1.accept_bi().await?;
    b_control_send.finish()?;

    // A's driver must treat that as a link failure and redial, exactly like the
    // whole-connection-close case: B accepts a second connection, and A surfaces
    // a fresh link.
    let _conn2 = tokio::time::timeout(Duration::from_secs(2), relay_b.mesh_accept_rx.recv())
        .await
        .map_err(|_| "A did not redial after its peer's control stream died")?
        .ok_or("B's accept channel closed")?;
    let (peer2, _cmds2) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "A did not surface a link after redialing")?
        .ok_or("A's links channel closed")?;
    assert_eq!(peer2, RelayId(2), "A's redialed link reaches B");

    drop(relay_a);
    Ok(())
}

/// A congested link's shared forward queue filling must reset the link, not
/// silently drop the fresh turn — a dropped turn never enters the link's
/// `AckManager`, so its own redundancy has nothing to re-carry and the peer
/// relay's clients would stall on a permanent per-(slot, seq) gap forever. Mirrors
/// [`dial_redials_after_the_peer_control_stream_dies`], but forces the reset by
/// flooding `fan_out_to_mesh` past the shared queue's capacity instead of
/// severing the control stream — the established link must still exit
/// `ConnectionFailed` and the dial supervisor must still redial.
///
/// The flood loop below has no `.await` in it, and `#[tokio::test]` defaults to
/// the current-thread runtime: cooperative scheduling can't preempt A's driver
/// task mid-loop to drain the queue, so every send lands before the driver ever
/// gets a chance to empty it — the fill is deterministic, not a timing race.
#[tokio::test]
async fn dial_redials_after_the_forward_queue_fills() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(9);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // A (id 1) dials; B (id 2) accepts. B stays up throughout, so the redial can
    // reconnect to it. B's real driver never runs here (its accept channel is
    // drained directly), so nothing on B's side ever drains what A sends it —
    // irrelevant to this test, since the queue that fills is A's own outbound
    // `MeshLinkTx::forward`, drained only by A's driver.
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);

    let (links_a_tx, mut links_a_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    // A short redial delay so the test doesn't wait the production interval.
    tokio::spawn(mesh_edge::run_mesh_dial_with(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
        Duration::from_millis(50),
    ));

    // The first dial connects: B accepts a connection and A surfaces a link
    // labeled with B's id.
    let _conn1 = tokio::time::timeout(Duration::from_secs(2), relay_b.mesh_accept_rx.recv())
        .await
        .map_err(|_| "B did not accept A's first dial within 2s")?
        .ok_or("B's accept channel closed")?;
    let (peer1, cmds_a) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "A did not surface its first link within 2s")?
        .ok_or("A's links channel closed")?;
    assert_eq!(peer1, RelayId(2), "A's first link reaches B");

    // Join the session so `fan_out_to_mesh` finds a registered target, then let
    // A's driver actually process the command and register.
    cmds_a.send(mesh::MeshCommand::Join(key.clone()))?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Mirrors the private `routing::FORWARD_CAPACITY` (not visible to an
    // external integration test, like `CONTROL_STREAM_LOST_CLOSE` elsewhere in
    // this suite).
    const FORWARD_CAPACITY: usize = 1024;

    // Flood past the shared forward queue's capacity in one synchronous burst —
    // see the doc comment above for why this reliably fills it rather than
    // racing A's driver's own drain.
    for _ in 0..(FORWARD_CAPACITY + 8) {
        mesh::fan_out_to_mesh(
            &relay_a.mesh.links,
            &key,
            Payload {
                ..Default::default()
            },
        );
    }

    // A's driver must treat the full queue as a link failure and redial, exactly
    // like a dropped connection: B accepts a second connection, and A surfaces a
    // fresh link.
    let _conn2 = tokio::time::timeout(Duration::from_secs(2), relay_b.mesh_accept_rx.recv())
        .await
        .map_err(|_| "A did not redial after its forward queue filled")?
        .ok_or("B's accept channel closed")?;
    let (peer2, _cmds2) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "A did not surface a link after redialing")?
        .ok_or("A's links channel closed")?;
    assert_eq!(peer2, RelayId(2), "A's redialed link reaches B");

    drop(relay_a);
    Ok(())
}

/// A turn that never made it across the link before a full-queue reset is not
/// gone for good: once the link redials and both sides re-Join, the
/// resume-cursor exchange each Join now sends replays it, and it reaches the
/// peer's client. Upgrades [`dial_redials_after_the_forward_queue_fills`] to
/// prove recovery, not just the reset, and to prove it for the *exact* turn
/// that tripped the reset — the very case the reset alone left unrecovered.
///
/// Both relays run their real, production drivers (`run_mesh_accept` on B,
/// `run_mesh_dial_with` on A) so a redial and rejoin happen exactly as they
/// would in the field, including B's real `MeshCommand::Join` handling
/// re-sending its own resume cursors down the fresh link.
///
/// The fill is a burst of throwaway `fan_out_to_mesh` calls, exactly like the
/// mirrored test's own flood (see its doc for why a no-`.await` loop makes
/// the fill deterministic on this test's current-thread runtime) — none of
/// those are recorded into any replay ring, so their own fate is irrelevant.
/// The one turn this test actually tracks is forwarded through
/// `mesh::forward_turn` right after the fill: its own `fan_out_to_mesh` call
/// is the one that finds the queue full and fires the reset, so it is, by
/// construction, the exact turn that tripped it — and it was already
/// recorded into A's replay ring under [`TurnOrigin::Local`] before that
/// fan-out ever ran. Isolating the tracked turn from the filler this way
/// (rather than recording and replaying the whole flood) keeps the replay
/// this test waits on to a single small datagram — the flood volume needed
/// to reliably trip `Full` has no bearing on how much needs replaying to
/// prove recovery, and a large unpaced replay burst risks real datagram loss
/// under load with nothing left afterward to trigger the redundancy that
/// would normally recover it.
#[tokio::test]
async fn a_full_queue_reset_recovers_via_the_redialed_links_resume_cursor_exchange()
-> Result<(), AnyError> {
    use rally_point_proto::control::BufferBounds;
    use rally_point_relay::consensus;
    use rally_point_relay::delivery::DeliveryHome;

    let tenant = make_tenant();
    let session = SessionId(9);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // A (id 1) dials; B (id 2) runs the real accept loop, so a redial is
    // accepted and driven exactly as it would be in production.
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    let (links_b_tx, mut links_b_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));

    let (links_a_tx, mut links_a_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    // A short redial delay so the test doesn't wait the production interval.
    tokio::spawn(mesh_edge::run_mesh_dial_with(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
        Duration::from_millis(50),
    ));

    let (peer_a1, cmds_a1) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "A did not surface its first link within 2s")?
        .ok_or("A's links channel closed")?;
    let (peer_b1, cmds_b1) = tokio::time::timeout(Duration::from_secs(2), links_b_rx.recv())
        .await
        .map_err(|_| "B did not surface its first link within 2s")?
        .ok_or("B's links channel closed")?;
    assert_eq!(peer_a1, RelayId(2));
    assert_eq!(peer_b1, RelayId(1));

    // A's own decision-maker exists and is latched started, so the replay
    // ring actually records what's about to be flooded through it —
    // `deliver_turn_to_locals` only buffers into the ring once the session
    // has started (pre-start traffic has its own, separate replay log).
    let _ = consensus::sync_maker(
        &relay_a.mesh.decision_makers,
        &key,
        BufferBounds::new(1, 6).unwrap(),
        consensus::Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );
    consensus::mark_session_started(&relay_a.mesh.decision_makers, &key);

    cmds_a1.send(mesh::MeshCommand::Join(key.clone()))?;
    cmds_b1.send(mesh::MeshCommand::Join(key.clone()))?;

    let mut client_a =
        connect_client(relay_a.addr, &relay_a.ca, &tenant, session, SlotId(0)).await?;
    let mut client_b =
        connect_client(relay_b.addr, &relay_b.ca, &tenant, session, SlotId(1)).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // A real turn, sent and delivered through the full production path, so
    // B's forward-gate cursor for slot 0 genuinely advances to "next needed
    // = 1" before anything is lost.
    client_a.send(Some(turn(0, 0))).unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .map_err(|_| "client B did not receive the baseline turn within 2s")?
        .map_err(|e| format!("client B link error: {e}"))?;
    assert_eq!(received.fresh.len(), 1);
    assert_eq!(received.fresh[0].seq, 0, "the baseline turn arrived live");

    // Mirrors the private `routing::FORWARD_CAPACITY` (see the sibling flood
    // test's own comment on this).
    const FORWARD_CAPACITY: usize = 1024;
    let triggering_seq = 1u64;

    // Fill A's shared forward queue to exactly capacity with throwaway
    // garbage (never recorded into the replay ring -- these exist only to
    // occupy the queue, and whether any of them individually reach B before
    // the reset is irrelevant to this test). Then forward ONE real, ring-recorded
    // turn: its own `fan_out_to_mesh` call is what finds the queue full and
    // fires the reset, so it is, by construction, the exact turn that
    // triggered Full -- and `deliver_turn_to_locals` already recorded it into
    // A's ring before that fan-out ever ran, so its loss on this link is
    // exactly the case resume-from-cursor recovers. Both loops run with no
    // `.await` in between -- see the doc comment above for why that is what
    // makes the fill (and which call trips it) deterministic rather than a
    // race with A's driver's own drain.
    for _ in 0..FORWARD_CAPACITY {
        mesh::fan_out_to_mesh(&relay_a.mesh.links, &key, turn(0, 0));
    }
    mesh::forward_turn(
        &relay_a.sessions,
        &relay_a.mesh.links,
        &relay_a.mesh.seen,
        &relay_a.mesh.decision_makers,
        &relay_a.mesh.turn_ring,
        &key,
        SlotId(0),
        turn(0, triggering_seq),
        DeliveryHome::Local,
    );

    // A's driver resets on the full queue and redials; B's real accept loop
    // takes the fresh connection and surfaces a new link.
    let (peer_a2, cmds_a2) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "A did not surface a link after redialing")?
        .ok_or("A's links channel closed")?;
    let (peer_b2, cmds_b2) = tokio::time::timeout(Duration::from_secs(2), links_b_rx.recv())
        .await
        .map_err(|_| "B did not surface a link after A redialed")?
        .ok_or("B's links channel closed")?;
    assert_eq!(peer_a2, RelayId(2));
    assert_eq!(peer_b2, RelayId(1));

    // Re-Join both sides on the fresh link -- standing in for the
    // coordinator re-pushing the session descriptor after a reconnect, the
    // same way every other test in this file drives Join by hand. Each
    // Join's resume-cursor reconcile fires from here: B tells A it still
    // needs slot 0 from seq 1, and A replays its ring at or past that --
    // just the one triggering turn, since nothing else was ever recorded.
    cmds_a2.send(mesh::MeshCommand::Join(key.clone()))?;
    cmds_b2.send(mesh::MeshCommand::Join(key.clone()))?;

    // Collect fresh datagrams at B until the triggering seq arrives (or the
    // deadline lapses) -- the strongest available proof that recovery
    // reached all the way through, not just the reset alone.
    let mut seen = std::collections::HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !seen.contains(&triggering_seq) && tokio::time::Instant::now() < deadline {
        let Ok(Ok(received)) = tokio::time::timeout(Duration::from_secs(2), client_b.recv()).await
        else {
            break;
        };
        for payload in received.fresh {
            assert_eq!(payload.slot, 0, "only slot 0 is in play on this link");
            seen.insert(payload.seq);
        }
    }
    assert!(
        seen.contains(&triggering_seq),
        "the turn that triggered the full-queue reset did not arrive after resume; got seqs {seen:?}",
    );

    drop(relay_a);
    Ok(())
}

/// The on-demand dialer establishes a mesh link to a peer the coordinator's
/// descriptors name, and re-establishes it after the link ends — the production
/// path that closes the "idle teardown then a new session leaves the pair
/// unmeshed" gap.
///
/// The dialer is fed a desired-peer set over a `watch` (standing in for the Join
/// source's `desired_peers()`), against a real accepting relay. Dropping the
/// surfaced command sender stands in for the link winding down; because the peer is
/// still desired, the dialer redials.
#[tokio::test]
async fn dialer_establishes_and_reestablishes_a_desired_peer_link() -> Result<(), AnyError> {
    let tenant = make_tenant();

    // A (id 1) dials; B (id 2) accepts via the production accept drain.
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);
    let (links_b_tx, _links_b_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));

    // A's on-demand dialer, fed desired peers over a watch. Its configured
    // fallback roots are EMPTY: trust must come entirely from the pinned cert
    // the desired peer carries — the production two-relay shape, where each
    // relay self-signs at startup and only the coordinator-relayed cert links
    // them.
    let (links_a_tx, mut links_a_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    let (peers_tx, peers_rx) = watch::channel(Vec::<RelayPeer>::new());
    let (dial_chain, dial_key, _) = self_signed();
    let config = mesh_dialer::DialerConfig {
        our_id: RelayId(1),
        server_name: "localhost".to_owned(),
        roots: rustls::RootCertStore::empty(),
        cert_chain: dial_chain,
        key: dial_key,
        sessions: Arc::clone(&relay_a.sessions),
        mesh: relay_a.mesh.clone(),
        links: links_a_tx,
        redial_delay: Duration::from_millis(50),
    };
    tokio::spawn(mesh_dialer::run_mesh_dialer(config, peers_rx));

    // The coordinator's descriptors name B as a peer, carrying B's enrolled
    // cert → the dialer pins it and dials.
    peers_tx.send(vec![RelayPeer {
        relay_id: RelayId(2),
        relay_addr: relay_b.addr,
        cert_der: relay_b.ca.to_vec(),
        relay_addrs: vec![],
    }])?;
    let (peer1, cmds1) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "the dialer did not establish a link to the desired peer")?
        .ok_or("A's links channel closed")?;
    assert_eq!(peer1, RelayId(2), "the dialed link reaches B");

    // The link winds down (its command sender is dropped). B is still desired, so
    // the dialer re-establishes the link.
    drop(cmds1);
    let (peer2, _cmds2) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "the dialer did not re-establish the link after it ended")?
        .ok_or("A's links channel closed")?;
    assert_eq!(peer2, RelayId(2), "the re-established link reaches B");

    drop(relay_a);
    Ok(())
}

/// A dialer config for relay A (id 1) with `roots` trusting the given peer certs,
/// plus the desired-peer watch sender and the links receiver, wired to a short
/// redial delay. Factors out the boilerplate the dialer lifecycle tests share.
fn dialer_for_a(
    relay_a: &Relay,
    peer_cas: &[&CertificateDer<'static>],
) -> (watch::Sender<Vec<RelayPeer>>, mpsc::Receiver<LinkHandle>) {
    let (links_a_tx, links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    for ca in peer_cas {
        roots.add((*ca).clone()).unwrap();
    }
    let (peers_tx, peers_rx) = watch::channel(Vec::<RelayPeer>::new());
    let (dial_chain, dial_key, _) = self_signed();
    let config = mesh_dialer::DialerConfig {
        our_id: RelayId(1),
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
        sessions: Arc::clone(&relay_a.sessions),
        mesh: relay_a.mesh.clone(),
        links: links_a_tx,
        redial_delay: Duration::from_millis(50),
    };
    tokio::spawn(mesh_dialer::run_mesh_dialer(config, peers_rx));
    (peers_tx, links_a_rx)
}

/// A desired peer carrying no pinned cert: the dial falls back to the
/// configured roots `dialer_for_a` was given (the old-coordinator shape). The
/// pinned-cert path is exercised by
/// `dialer_establishes_and_reestablishes_a_desired_peer_link`, which runs with
/// empty fallback roots.
fn peer_at(id: u64, addr: SocketAddr) -> RelayPeer {
    RelayPeer {
        relay_id: RelayId(id),
        relay_addr: addr,
        cert_der: Vec::new(),
        relay_addrs: Vec::new(),
    }
}

/// Polls `cond` until it holds, up to a couple of seconds. Returns whether it
/// became true (for asserting async state settled without a fixed sleep).
async fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cond()
}

/// A peer that moves to a new address (a restart, same id) is retargeted: the
/// dialer cancels the dial to the old address and dials the new one. Without that,
/// the one-per-peer dedup would leave a supervisor dialing the stale address forever
/// and the pair would never mesh.
#[tokio::test]
async fn dialer_retargets_a_link_when_a_peer_moves_to_a_new_address() -> Result<(), AnyError> {
    let tenant = make_tenant();

    // Peer id 2 exists first at relay B's address, then at relay C's (same id, new
    // address — a restart).
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);
    let relay_c = Relay::start(&tenant, 2);
    let (peers_tx, mut links_a_rx) = dialer_for_a(&relay_a, &[&relay_b.ca, &relay_c.ca]);

    // Peer 2 at B's address: the dialer dials B. Waiting for the link before moving
    // the peer synchronizes on the dialer having applied the first address.
    peers_tx.send(vec![peer_at(2, relay_b.addr)])?;
    let (peer1, _cmds1) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "the dialer did not dial the peer at its first address")?
        .ok_or("A's links channel closed")?;
    assert_eq!(peer1, RelayId(2));

    // Peer 2 moves to C's address: the dialer retargets and a fresh link forms.
    peers_tx.send(vec![peer_at(2, relay_c.addr)])?;
    let (peer2, _cmds2) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "the dialer did not retarget to the peer's new address")?
        .ok_or("A's links channel closed")?;
    assert_eq!(peer2, RelayId(2));

    drop(relay_a);
    Ok(())
}

/// A supervisor stuck retrying an unreachable address never stops on its own, so a
/// later address for the same peer must still get dialed: the dialer cancels the
/// stuck supervisor and dials the new address. This is the "removal while connects
/// are failing" case — otherwise the stuck retrier would hold the peer's slot and
/// the pair would never mesh once the peer became reachable.
#[tokio::test]
async fn dialer_retargets_away_from_an_unreachable_address() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    // A free loopback port with nothing listening — a dial there never connects, so
    // the supervisor retries indefinitely and never reports a stop.
    let dead_addr = {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        addr
    };

    let (peers_tx, mut links_a_rx) = dialer_for_a(&relay_a, &[&relay_b.ca]);

    // Peer 2 first at the unreachable address: the dialer spawns a supervisor that
    // fails to connect and keeps retrying. Give it a moment to reach that state, and
    // confirm no link forms.
    peers_tx.send(vec![peer_at(2, dead_addr)])?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        links_a_rx.try_recv().is_err(),
        "no link forms to an unreachable address",
    );

    // Peer 2 reappears at B's live address: the stuck supervisor must be cancelled
    // and a fresh dial started, or the dedup keeps it stuck on the dead address.
    peers_tx.send(vec![peer_at(2, relay_b.addr)])?;
    let (peer, _cmds) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "the dialer stayed stuck on the dead address after the peer moved")?
        .ok_or("A's links channel closed")?;
    assert_eq!(peer, RelayId(2));

    drop(relay_a);
    Ok(())
}

/// Removing a peer while it is serving a session must clean up that session's mesh
/// forwarding state, even though the dialer cancels the link driver with a hard
/// abort. Otherwise `mesh.links` keeps a dead forward channel for the ended session
/// forever — session ids are never reused, so nothing later reclaims it.
#[tokio::test]
async fn removing_a_serving_peer_cleans_up_its_mesh_forwarding_state() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);
    let (peers_tx, mut links_a_rx) = dialer_for_a(&relay_a, &[&relay_b.ca]);

    // Dial B, then join a session on the established link (standing in for a
    // descriptor-driven Join); the join registers a mesh forward channel.
    peers_tx.send(vec![peer_at(2, relay_b.addr)])?;
    let (_peer, cmds) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "the dialer did not establish the link")?
        .ok_or("A's links channel closed")?;
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(1),
    };
    cmds.send(mesh::MeshCommand::Join(key.clone()))?;
    assert!(
        wait_until(|| relay_a.mesh.links.lock().contains_key(&key)).await,
        "the join should register a mesh forward channel",
    );

    // The peer is removed from the desired set: the dialer aborts the link driver.
    // The forward-channel registration must still be torn down despite the abort.
    peers_tx.send(vec![])?;
    assert!(
        wait_until(|| !relay_a.mesh.links.lock().contains_key(&key)).await,
        "the aborted link's mesh forwarding state was not cleaned up",
    );

    drop(relay_a);
    Ok(())
}

/// The accept side enforces protocol-version negotiation on the identity hello:
/// a dialer advertising a version this build cannot negotiate is refused — the
/// connection is application-closed with `MESH_CLOSE_PROTOCOL_MISMATCH` before
/// the link driver spawns, and nothing ever surfaces on the `links` channel.
#[tokio::test]
async fn acceptor_refuses_an_incompatible_mesh_hello() -> Result<(), AnyError> {
    use rally_point_proto::mesh::MeshHello;
    use rally_point_proto::version::{MESH_CLOSE_PROTOCOL_MISMATCH, ProtocolVersion};

    let tenant = make_tenant();
    let relay_b = Relay::start(&tenant, 2);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));

    // A stand-in dialer speaking only v1 (below MIN_SUPPORTED): connect on the
    // mesh ALPN and announce the incompatible version in the hello.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let cfg = rally_point_transport::quic::mesh_client_config(roots, dial_chain, dial_key)
        .map_err(|e| format!("building mesh client config: {e}"))?;
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut ep = quinn::Endpoint::client(bind)?;
    ep.set_default_client_config(cfg);
    let connection = ep.connect(relay_b.addr, "localhost")?.await?;

    let mut hello_stream = connection.open_uni().await?;
    // A version below the supported floor — one this build cannot negotiate.
    let incompatible = ProtocolVersion(ProtocolVersion::MIN_SUPPORTED.0 - 1);
    let hello = MeshHello::new(RelayId(1), incompatible);
    hello_stream.write_all(&hello.encode()).await?;

    // The acceptor refuses with the protocol-mismatch application close...
    let reason = connection.closed().await;
    match reason {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.error_code,
                quinn::VarInt::from_u32(MESH_CLOSE_PROTOCOL_MISMATCH),
                "the close carries the protocol-mismatch code",
            );
        }
        other => panic!("expected an application close refusing the version, got {other:?}"),
    }

    // ...and no link ever surfaces for the refused peer.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), links_b_rx.recv())
            .await
            .is_err(),
        "a refused peer must not surface on the links channel",
    );
    Ok(())
}

// --- Mesh-accept peer-identity enforcement ---

/// Connects to `addr` on the mesh ALPN using `cfg`, then sends the identity
/// hello claiming `relay_id` at the current protocol version — the shared setup
/// every peer-identity enforcement test below drives before checking how the
/// acceptor answers.
async fn dial_and_send_hello(
    addr: SocketAddr,
    cfg: quinn::ClientConfig,
    relay_id: RelayId,
) -> Result<quinn::Connection, AnyError> {
    use rally_point_proto::mesh::MeshHello;
    use rally_point_proto::version::ProtocolVersion;

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut ep = quinn::Endpoint::client(bind)?;
    ep.set_default_client_config(cfg);
    let connection = ep.connect(addr, "localhost")?.await?;
    let mut hello_stream = connection.open_uni().await?;
    let hello = MeshHello::new(relay_id, ProtocolVersion::CURRENT);
    hello_stream.write_all(&hello.encode()).await?;
    Ok(connection)
}

/// Asserts `connection` was application-closed with `expected_code`.
async fn expect_mesh_close(connection: &quinn::Connection, expected_code: u32) {
    let reason = connection.closed().await;
    match reason {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.error_code,
                quinn::VarInt::from_u32(expected_code),
                "unexpected close code (reason: {:?})",
                close.reason,
            );
        }
        other => panic!("expected an application close, got {other:?}"),
    }
}

/// Builds a mesh-ALPN client config that presents **no** TLS client
/// certificate — what a peer relay predating this leg would still do, and the
/// exact shape [`MESH_CLOSE_NO_CLIENT_CERT`](rally_point_proto::version::MESH_CLOSE_NO_CLIENT_CERT)
/// exists to refuse once enforcement is active. `mesh_client_config` cannot
/// express this any more (it always presents a certificate), so this builds the
/// TLS config by hand, mirroring `quic.rs`'s own stale-ALPN tests.
fn mesh_client_config_without_a_certificate(roots: rustls::RootCertStore) -> quinn::ClientConfig {
    let mut tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![rally_point_transport::quic::MESH_ALPN.to_vec()];
    let client =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("a valid TLS 1.3 config");
    quinn::ClientConfig::new(Arc::new(client))
}

/// With no coordinator ever having pushed a fleet-peer set (the dev/loopback
/// `--mesh-peer` posture), peer-identity enforcement stays off: a dialer
/// presenting a real certificate and a valid hello establishes a link exactly
/// as before this leg, with no fingerprint check at all.
#[tokio::test]
async fn an_empty_fleet_map_admits_any_peer_certificate() -> Result<(), AnyError> {
    // A full production dial (not the bare hello-only helper the refusal tests
    // below use): the acceptor's `accept_bi` for the mesh control stream is
    // bounded by the hello timeout, so reaching an established link needs the
    // dialer to actually open and establish that stream too, exactly as
    // `run_mesh_dial` does.
    let tenant = make_tenant();
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let (links_a_tx, _links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    tokio::spawn(mesh_edge::run_mesh_dial(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
    ));

    let (peer_id, _cmds) = tokio::time::timeout(Duration::from_secs(2), links_b_rx.recv())
        .await
        .map_err(|_| "the link should establish with enforcement off")?
        .ok_or("accept side did not produce a link")?;
    assert_eq!(peer_id, RelayId(1));
    drop(relay_a);
    Ok(())
}

/// `--require-mesh-peer-auth` fails closed even before the coordinator's first
/// push: every dial is refused while the fleet map is still empty, with the
/// same code an unrecognized claimed id draws (an empty map trivially has no
/// entry for any id).
#[tokio::test]
async fn require_peer_auth_refuses_every_dial_while_the_fleet_map_is_empty() -> Result<(), AnyError>
{
    let tenant = make_tenant();
    let relay_b = Relay::start(&tenant, 2);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        true, // --require-mesh-peer-auth
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let cfg = rally_point_transport::quic::mesh_client_config(roots, dial_chain, dial_key)?;
    let connection = dial_and_send_hello(relay_b.addr, cfg, RelayId(1)).await?;

    expect_mesh_close(
        &connection,
        rally_point_proto::version::MESH_CLOSE_UNKNOWN_PEER,
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), links_b_rx.recv())
            .await
            .is_err(),
        "a refused peer must not surface on the links channel",
    );
    Ok(())
}

/// A peer that completes the TLS handshake without presenting a client
/// certificate is refused once enforcement is active (a non-empty fleet map) —
/// there is nothing to pin against it.
#[tokio::test]
async fn acceptor_refuses_a_peer_presenting_no_client_certificate() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_b = Relay::start(&tenant, 2);

    // Enforcement is active: seed one (unrelated) fleet entry so the map is
    // non-empty. Which entry doesn't matter — this refusal fires before the
    // fleet map is even consulted for a specific id.
    let fleet = FleetMeshPeers::new();
    fleet.store(vec![rally_point_proto::control::MeshPeerIdentity {
        relay_id: RelayId(99),
        cert_sha256: [0xAA; 32],
    }]);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        fleet.reader(),
        false,
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let cfg = mesh_client_config_without_a_certificate(roots);
    let connection = dial_and_send_hello(relay_b.addr, cfg, RelayId(1)).await?;

    expect_mesh_close(
        &connection,
        rally_point_proto::version::MESH_CLOSE_NO_CLIENT_CERT,
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), links_b_rx.recv())
            .await
            .is_err(),
        "a refused peer must not surface on the links channel",
    );
    Ok(())
}

/// A peer presenting a real certificate but claiming a relay id the fleet map
/// does not name is refused — the coordinator never enrolled that id.
#[tokio::test]
async fn acceptor_refuses_a_peer_claiming_an_unenrolled_relay_id() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_b = Relay::start(&tenant, 2);

    // The fleet only knows relay 9; the dialer below claims relay 42.
    let fleet = FleetMeshPeers::new();
    fleet.store(vec![rally_point_proto::control::MeshPeerIdentity {
        relay_id: RelayId(9),
        cert_sha256: [0xAA; 32],
    }]);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        fleet.reader(),
        false,
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let cfg = rally_point_transport::quic::mesh_client_config(roots, dial_chain, dial_key)?;
    let connection = dial_and_send_hello(relay_b.addr, cfg, RelayId(42)).await?;

    expect_mesh_close(
        &connection,
        rally_point_proto::version::MESH_CLOSE_UNKNOWN_PEER,
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), links_b_rx.recv())
            .await
            .is_err(),
        "a refused peer must not surface on the links channel",
    );
    Ok(())
}

/// A peer whose claimed relay id is enrolled, but whose presented certificate's
/// fingerprint does not match what the coordinator recorded for that id, is
/// refused — the fleet-set pin caught an impostor (or a cert that rotated
/// without a fresh coordinator push).
#[tokio::test]
async fn acceptor_refuses_a_peer_whose_certificate_fingerprint_does_not_match()
-> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_b = Relay::start(&tenant, 2);

    // The fleet records relay 1 under a fingerprint that is NOT the dialer's
    // actual certificate below — a decoy cert's fingerprint.
    let (_decoy_chain, _decoy_key, decoy_ca) = self_signed();
    let fleet = FleetMeshPeers::new();
    fleet.store(vec![rally_point_proto::control::MeshPeerIdentity {
        relay_id: RelayId(1),
        cert_sha256: rally_point_transport::quic::cert_fingerprint(decoy_ca.as_ref()),
    }]);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        fleet.reader(),
        false,
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let cfg = rally_point_transport::quic::mesh_client_config(roots, dial_chain, dial_key)?;
    let connection = dial_and_send_hello(relay_b.addr, cfg, RelayId(1)).await?;

    expect_mesh_close(
        &connection,
        rally_point_proto::version::MESH_CLOSE_CERT_MISMATCH,
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), links_b_rx.recv())
            .await
            .is_err(),
        "a refused peer must not surface on the links channel",
    );
    Ok(())
}

/// The flight recorder captures a real client's lifecycle end to end: the
/// connect event and validated-turn counters accumulate while the client plays,
/// and its disconnect empties the session, whose close-time flush lands the
/// blob at the file sink's tenant-scoped path.
#[tokio::test]
async fn the_flight_recorder_captures_a_client_lifecycle_and_flushes_on_close()
-> Result<(), AnyError> {
    use rally_point_relay::flight_recorder::{FileSink, FlightBlob, FlightEvent};

    let tenant = make_tenant();
    let session = SessionId(1);
    let relay = Relay::start(&tenant, 1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let flight = relay.mesh.decision_makers.flight_recorder().clone();
    let dir = std::env::temp_dir().join(format!("rp2-flight-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    flight.set_sink(std::sync::Arc::new(FileSink::new(dir.clone())));

    // Two clients connect; slot 0 sends a couple of turns and slot 1 receives
    // them — the receive is what proves the relay validated and delivered both
    // before the disconnect below (dropping earlier could race the datagrams).
    let mut client_a = connect_client(relay.addr, &relay.ca, &tenant, session, SlotId(0)).await?;
    let mut client_b = connect_client(relay.addr, &relay.ca, &tenant, session, SlotId(1)).await?;
    client_a.send(Some(turn(0, 0)))?;
    client_a.send(Some(turn(0, 1)))?;
    let mut received = 0;
    while received < 2 {
        let got = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
            .await
            .map_err(|_| "client B did not receive the turns within 2s")?
            .map_err(|e| format!("client B link error: {e}"))?;
        received += got.fresh.len();
    }

    // The connect events landed when the link tasks started serving.
    let seen: Vec<FlightEvent> = flight.events(&key).into_iter().map(|r| r.event).collect();
    assert!(
        seen.contains(&FlightEvent::SlotConnected {
            slot: 0,
            resumed: false,
        }),
        "the connect event is recorded: {seen:?}",
    );

    // The clients disconnect: the session empties, the close-time flush writes
    // the blob to <dir>/<tenant>/<session>/<relay_id>.json (relay id 0 — this
    // dev relay never set one).
    drop(client_a);
    drop(client_b);
    let path = dir.join(TENANT).join("1").join("0.json");
    let mut blob: Option<FlightBlob> = None;
    for _ in 0..250 {
        if let Ok(json) = std::fs::read_to_string(&path) {
            blob = Some(serde_json::from_str(&json)?);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let blob = blob.expect("the close-time flush wrote the blob");

    let events: Vec<&FlightEvent> = blob.events.iter().map(|r| &r.event).collect();
    assert!(events.contains(&&FlightEvent::SlotConnected {
        slot: 0,
        resumed: false
    }));
    assert!(events.contains(&&FlightEvent::SlotDisconnected { slot: 0 }));
    assert!(events.contains(&&FlightEvent::SessionClosed));

    // The final counter snapshot carries the sender's validated turns and the
    // receiver's delivered ones.
    let last = blob.samples.last().expect("a final counter snapshot");
    let sender = last
        .slots
        .iter()
        .find(|s| s.slot == 0)
        .expect("slot 0's counters");
    assert!(
        sender.turns_validated >= 2,
        "both sent turns were validated: {sender:?}",
    );
    assert_eq!(sender.newest_seq, 1);
    let receiver = last
        .slots
        .iter()
        .find(|s| s.slot == 1)
        .expect("slot 1's counters");
    assert!(
        receiver.turns_forwarded >= 2,
        "both turns were delivered to slot 1: {receiver:?}",
    );

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// A dual-stack peer's dial walks the candidate list: the first advertised
/// address is unusable (rejected at connect — port 0), and the link still
/// establishes on the second candidate within the same attempt, no redial
/// delay spent.
#[tokio::test]
async fn a_mesh_dial_falls_back_to_the_next_advertised_candidate() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));

    let (links_a_tx, mut links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let unreachable: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        // The peer advertises an unusable candidate first; the walk must fall
        // through to the reachable one.
        peer_addrs: vec![unreachable, relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    tokio::spawn(mesh_edge::run_mesh_dial(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
    ));

    // The link establishes on the second candidate — well within one attempt
    // (the 2s bound is far under the supervisor's redial delay would allow for
    // a second attempt to even begin mattering here).
    let (peer_a, _cmds_a) = tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
        .await
        .map_err(|_| "the dial did not fall back to the reachable candidate")?
        .ok_or("A's links channel closed")?;
    assert_eq!(peer_a, RelayId(2));
    let (peer_b, _cmds_b) = tokio::time::timeout(Duration::from_secs(2), links_b_rx.recv())
        .await
        .map_err(|_| "the acceptor did not surface the link")?
        .ok_or("B's links channel closed")?;
    assert_eq!(peer_b, RelayId(1));

    drop(relay_a);
    Ok(())
}

/// End-to-end delivery tracking across the mesh: with cross-homed clients
/// exchanging turns and the destination's beacon advancing, the authority's
/// per-pair lag view converges near zero and the hop count reads 2; when the
/// destination's beacon stops while the origin keeps producing, that pair's
/// lag grows.
#[tokio::test]
async fn the_authority_folds_cross_relay_delivery_and_sees_a_parked_beacon_lag()
-> Result<(), AnyError> {
    use rally_point_relay::consensus;
    use std::collections::HashMap;

    let tenant = make_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Relay A (id 1) is the authority (id-order fallback); relay B (id 2)
    // accepts A's dial. Each Join source shares its relay's REAL registries, so
    // the makers the descriptors create are the ones the link tasks feed.
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);
    let control_a = mesh_control::MeshControl::new(
        RelayId(1),
        Arc::clone(&relay_a.mesh.decision_makers),
        Arc::clone(&relay_a.mesh.presence),
    )
    .with_broadcast(Arc::clone(&relay_a.sessions), relay_a.mesh.links.clone());
    let control_b = mesh_control::MeshControl::new(
        RelayId(2),
        Arc::clone(&relay_b.mesh.decision_makers),
        Arc::clone(&relay_b.mesh.presence),
    )
    .with_broadcast(Arc::clone(&relay_b.sessions), relay_b.mesh.links.clone());

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));
    let (links_a_tx, mut links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    tokio::spawn(mesh_edge::run_mesh_dial(
        mesh_edge::MeshDial {
            our_id: RelayId(1),
            peer_id: RelayId(2),
            peer_addrs: vec![relay_b.addr],
            server_name: "localhost".to_owned(),
            roots,
            cert_chain: dial_chain,
            key: dial_key,
        },
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
    ));
    let (peer_a, cmds_a) = links_a_rx.recv().await.ok_or("no dial-side link")?;
    control_a.register_link(peer_a, cmds_a);
    let (peer_b, cmds_b) = links_b_rx.recv().await.ok_or("no accept-side link")?;
    control_b.register_link(peer_b, cmds_b);

    // The coordinator's descriptors: each relay names the other as its peer,
    // with A ranked first (the authority).
    let delivery_descriptor = |peers: Vec<RelayPeer>| SessionDescriptor {
        tenant: TenantId(TENANT.to_owned()),
        session,
        peers,
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![RelayId(1), RelayId(2)],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
    };
    control_a.apply_descriptor(&delivery_descriptor(vec![RelayPeer {
        relay_id: RelayId(2),
        relay_addr: relay_b.addr,
        cert_der: relay_b.ca.to_vec(),
        relay_addrs: vec![],
    }]));
    control_b.apply_descriptor(&delivery_descriptor(vec![RelayPeer {
        relay_id: RelayId(1),
        relay_addr: relay_a.addr,
        cert_der: relay_a.ca.to_vec(),
        relay_addrs: vec![],
    }]));

    // Cross-homed clients: the origin (slot 0) on the authority, the
    // destination (slot 1) on relay B. The turns carry frames, as in-game turns
    // always do — the delivery fold deliberately keys on framed (in-game)
    // turns, like the consensus coordinate it sits beside.
    let framed_turn = |slot: u8, seq: u64| Payload {
        seq,
        slot: u32::from(slot),
        commands: vec![].into(),
        game_frame_count: Some(seq as u32 + 1),
        ..Default::default()
    };
    let mut client_a =
        connect_client(relay_a.addr, &relay_a.ca, &tenant, session, SlotId(0)).await?;
    let mut client_b =
        connect_client(relay_b.addr, &relay_b.ca, &tenant, session, SlotId(1)).await?;
    tokio::time::sleep(Duration::from_millis(50)).await; // let the mesh join settle

    // Slot 0 sends turns 0..=5; the destination receives them across the mesh.
    for seq in 0..=5u64 {
        client_a.send(Some(framed_turn(0, seq)))?;
    }
    let mut received = 0;
    while received < 6 {
        let got = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
            .await
            .map_err(|_| "client B did not receive the turns within 2s")?
            .map_err(|e| format!("client B link error: {e}"))?;
        received += got.fresh.len();
    }

    // The destination confirms final delivery up its ack-beacon stream, exactly
    // as the client driver does in production.
    let mut beacon_send = client_b.connection().open_uni().await?;
    let mut last_sent: HashMap<SlotId, u64> = HashMap::new();
    rally_point_transport::beacon::flush_beacon(
        &mut beacon_send,
        &mut last_sent,
        [(SlotId(0), 5u64)].into(),
    )
    .await;

    // The authority's fold converges: relay B taps the beacon, ships the
    // cursors over the mesh control stream, relay A folds them — lag near zero
    // (newest origin seq 5, delivered 5), and the cross-homed pair reads 2
    // relay hops.
    let mut view = (None, None);
    for _ in 0..150 {
        view = consensus::session_e2e(&relay_a.mesh.decision_makers, &key);
        if matches!(view, (Some(lag), Some(2)) if lag <= 1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        matches!(view, (Some(lag), Some(2)) if lag <= 1),
        "the authority's e2e view converges (lag ~0, hops 2): {view:?}",
    );

    // The destination's beacon parks (it confirms nothing further) while the
    // origin keeps producing: the pair's lag grows past what any healthy
    // in-flight window explains.
    for seq in 6..=30u64 {
        client_a.send(Some(framed_turn(0, seq)))?;
    }
    let mut lag = 0;
    for _ in 0..150 {
        if let (Some(l), _) = consensus::session_e2e(&relay_a.mesh.decision_makers, &key) {
            lag = l;
            if lag >= 20 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        lag >= 20,
        "a parked destination beacon shows as growing pair lag: {lag}",
    );

    drop(relay_a);
    Ok(())
}
