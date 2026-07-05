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

    // B's accept drain: spawns a `run_mesh_link` driver for each peer relay
    // that dials in, returning `(peer id, command sender)` on `links_b_rx`.
    let (links_b_tx, mut links_b_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    tokio::spawn(mesh_edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
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
    ));

    let (links_a_tx, mut links_a_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
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
        }],
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
    });
    control_b.apply_descriptor(&SessionDescriptor {
        tenant: TenantId(TENANT.to_owned()),
        session,
        peers: vec![RelayPeer {
            relay_id: RelayId(1),
            relay_addr: relay_a.addr,
            cert_der: relay_a.ca.to_vec(),
        }],
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
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
    ));
    let (links_a_tx, mut links_a_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    tokio::spawn(mesh_edge::run_mesh_dial(
        mesh_edge::MeshDial {
            our_id: RelayId(1),
            peer_id: RelayId(2),
            peer_addr: relay_b.addr,
            server_name: "localhost".to_owned(),
            roots,
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
    };
    control_a.apply_descriptor(&descriptor_for(vec![RelayPeer {
        relay_id: RelayId(2),
        relay_addr: relay_b.addr,
        cert_der: relay_b.ca.to_vec(),
    }]));
    control_b.apply_descriptor(&descriptor_for(vec![RelayPeer {
        relay_id: RelayId(1),
        relay_addr: relay_a.addr,
        cert_der: relay_a.ca.to_vec(),
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

    let (links_tx, mut links_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
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
    let dial = mesh_edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addr: relay_b.addr,
        server_name: "localhost".to_owned(),
        roots,
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
    ));

    // A's on-demand dialer, fed desired peers over a watch. Its configured
    // fallback roots are EMPTY: trust must come entirely from the pinned cert
    // the desired peer carries — the production two-relay shape, where each
    // relay self-signs at startup and only the coordinator-relayed cert links
    // them.
    let (links_a_tx, mut links_a_rx) =
        mpsc::channel::<(RelayId, mpsc::UnboundedSender<mesh::MeshCommand>)>(8);
    let (peers_tx, peers_rx) = watch::channel(Vec::<RelayPeer>::new());
    let config = mesh_dialer::DialerConfig {
        our_id: RelayId(1),
        server_name: "localhost".to_owned(),
        roots: rustls::RootCertStore::empty(),
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
    let config = mesh_dialer::DialerConfig {
        our_id: RelayId(1),
        server_name: "localhost".to_owned(),
        roots,
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
