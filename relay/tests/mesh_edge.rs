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
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::mesh::{MESH_PRESENCE_LEN, MeshPresence};
use rally_point_proto::messages::{GameChat, LobbyCommand, Payload, PlayerSkin};
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
        ..Default::default()
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
    let (tx, handle) = spawn_mesh_link_timed(link, sessions, mesh, mesh::IDLE_TIMEOUT);
    drop(handle);
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
    let attempt = mesh::new_mesh_link_attempt();
    let lease = mesh::claim_mesh_link(&mesh, RelayId(0), &attempt)
        .expect("raw test driver claims its peer lease");
    // These raw link pairs skip the hello exchange, so build the presence
    // streams the production edge would have set up: an outbound uni-stream
    // and a reader accepting the peer's. Presence isn't the subject here; the
    // driver just needs its I/O to exist.
    let handle = tokio::spawn(async move {
        let Ok(presence_tx) = link.connection().open_uni().await else {
            return mesh::MeshLinkExit::ConnectionFailed;
        };
        let presence_rx =
            rally_point_relay::presence::spawn_presence_reader_accepting(link.connection().clone());
        let presence_io = rally_point_relay::presence::PresenceIo {
            peer_id: RelayId(0),
            tx: presence_tx,
            rx: presence_rx,
        };
        // The raw link pairs skip the production dialer/acceptor hello dance, so
        // set up the mesh control stream symmetrically: each side opens its own
        // send stream (writing an establishing frame so the peer's accept
        // completes) and accepts the peer's for reading — two bidirectional
        // streams, each used one-directionally.
        let Ok((mut control_send, _unused_recv)) = link.connection().open_bi().await else {
            return mesh::MeshLinkExit::ConnectionFailed;
        };
        if rally_point_transport::mesh_control_stream::establish_mesh_control(&mut control_send)
            .await
            .is_err()
        {
            return mesh::MeshLinkExit::ConnectionFailed;
        }
        let control_rx =
            rally_point_transport::mesh_control_stream::spawn_mesh_control_reader_accepting(
                link.connection().clone(),
            );
        let control_io = mesh::MeshControlIo {
            tx: control_send,
            rx: control_rx,
        };
        mesh::run_mesh_link(
            link,
            mesh::MeshLinkIo {
                presence: presence_io,
                control: control_io,
                lease,
            },
            rx,
            sessions,
            mesh,
            idle_timeout,
        )
        .await
    });
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
    let (dial_chain, dial_key, _) = self_signed();
    let client_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();

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

/// Connects a client to `relay` for `slot`, runs the authorization handshake,
/// and returns the live connection plus the client endpoint (kept alive by the
/// caller so the connection is not torn down when the endpoint drops).
async fn connect_client(
    relay: &Relay,
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
) -> Result<(quinn::Connection, quinn::Endpoint), AnyError> {
    let client_key = keypair();
    let token = mint_token(tenant, session, slot, client_key.public);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay.ca.clone()).unwrap();
    let client_cfg = client_config(roots).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut endpoint = quinn::Endpoint::client(bind).unwrap();
    endpoint.set_default_client_config(client_cfg);
    let connection = endpoint.connect(relay.addr, "localhost")?.await?;
    handshake(&connection, &token, &client_key).await?;
    Ok((connection, endpoint))
}

/// Opens a client's reliable control-stream halves: the send half it writes its
/// own lobby commands on, and the reader that surfaces the frames the relay
/// pushes down (lobby commands from the other members). Mirrors what a real
/// `LinkDriver` sets up on the control stream.
async fn open_lobby_streams(
    connection: &quinn::Connection,
) -> (
    quinn::SendStream,
    mpsc::Receiver<rally_point_transport::control::ControlInbound>,
) {
    let (send, _our_recv) = connection.open_bi().await.unwrap();
    let rx = rally_point_transport::control::spawn_control_reader(connection.clone());
    (send, rx)
}

/// Reads the next lobby command off a client's control reader within a short
/// timeout, returning `(slot, payload_bytes)` — panicking on any other frame kind
/// or on timeout, so a test asserts against a clean tuple.
async fn next_lobby(
    rx: &mut mpsc::Receiver<rally_point_transport::control::ControlInbound>,
) -> (u32, Vec<u8>) {
    match next_non_connectivity(rx).await {
        rally_point_transport::control::ControlInbound::Lobby(command) => {
            (command.slot, command.payload.to_vec())
        }
        other => panic!("expected a lobby command, got {other:?}"),
    }
}

/// Reads the next control frame that isn't a `SlotConnectivity` change, skipping
/// the informational connectivity frames the relay fans on every register and
/// disconnect. Panics on timeout or a closed stream. The mesh tests read the
/// substantive frame their setup produced past those.
async fn next_non_connectivity(
    rx: &mut mpsc::Receiver<rally_point_transport::control::ControlInbound>,
) -> rally_point_transport::control::ControlInbound {
    use rally_point_transport::control::ControlInbound;
    loop {
        let inbound = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a control frame arrived within 2s")
            .expect("control reader ended early");
        if !matches!(inbound, ControlInbound::Connectivity(_)) {
            return inbound;
        }
    }
}

/// Reads one fixed-width presence frame from a raw mesh presence stream.
async fn next_mesh_presence(stream: &mut quinn::RecvStream) -> MeshPresence {
    let mut frame = [0; MESH_PRESENCE_LEN];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut frame))
        .await
        .expect("a mesh presence frame arrived within 2s")
        .expect("the mesh presence stream remained readable");
    MeshPresence::decode(frame)
}

/// Reads the next game-chat message off a client's control reader within a
/// short timeout, returning `(slot, target_kind, target_slot, text)` —
/// panicking on any other frame kind or on timeout. Mirrors [`next_lobby`].
async fn next_chat(
    rx: &mut mpsc::Receiver<rally_point_transport::control::ControlInbound>,
) -> (u32, u32, u32, String) {
    match next_non_connectivity(rx).await {
        rally_point_transport::control::ControlInbound::Chat(chat) => {
            (chat.slot, chat.target_kind, chat.target_slot, chat.text)
        }
        other => panic!("expected a chat message, got {other:?}"),
    }
}

/// Reads the next player-skin blob off a client's control reader within a short
/// timeout, returning `(slot, payload_bytes)` — panicking on any other frame kind
/// or on timeout. Mirrors [`next_lobby`] and [`next_chat`].
async fn next_skin(
    rx: &mut mpsc::Receiver<rally_point_transport::control::ControlInbound>,
) -> (u32, Vec<u8>) {
    match next_non_connectivity(rx).await {
        rally_point_transport::control::ControlInbound::Skin(skin) => {
            (skin.slot, skin.payload.to_vec())
        }
        other => panic!("expected a player-skin blob, got {other:?}"),
    }
}

/// Dials relay A → relay B on the mesh ALPN, spawns a mesh-link driver on each
/// side, joins `key` on both, and returns the two command senders plus the mesh
/// client endpoint (kept alive by the caller). Factors the two-relay mesh setup
/// the cross-relay tests share.
async fn mesh_two_relays(
    relay_a: &Relay,
    relay_b: &mut Relay,
    key: &SessionKey,
) -> (
    mpsc::UnboundedSender<mesh::MeshCommand>,
    mpsc::UnboundedSender<mesh::MeshCommand>,
    quinn::Endpoint,
) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let mesh_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();
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

    let cmds_a = spawn_mesh_link(
        MeshLink::new(conn_a),
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
    );
    let cmds_b = spawn_mesh_link(
        MeshLink::new(conn_b),
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
    );
    cmds_a.send(mesh::MeshCommand::Join(key.clone())).unwrap();
    cmds_b.send(mesh::MeshCommand::Join(key.clone())).unwrap();
    (cmds_a, cmds_b, mesh_ep)
}

/// A relay can apply a session descriptor (and therefore Join its side of the
/// shared mesh link) before its peer applies the same descriptor. Slot-presence
/// announcements sent during that gap used to be dropped by the unjoined peer,
/// leaving the eventual authority permanently short of the expected roster.
/// The first post-Join presence report is now a rendezvous barrier: it proves the
/// peer has installed its Join and triggers one current-roster replay.
#[tokio::test]
async fn asymmetric_mesh_joins_converge_slot_presence_and_start_the_session() -> Result<(), AnyError>
{
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_transport::control::ControlInbound;

    let tenant = make_tenant();
    let session = SessionId(41);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let relay_a = Relay::start(&tenant);
    let relay_b = Relay::start(&tenant);
    let expected: std::collections::HashSet<_> = [SlotId(0), SlotId(1)].into_iter().collect();
    let bounds = rally_point_proto::control::BufferBounds::new(0, 20).unwrap();

    // Relay B is the authority. That choice is load-bearing for the regression:
    // A joins first, so B must recover A's early slot announcement after B's own
    // later Join rather than starting from the announcement B sends to A.
    let _ = consensus::sync_maker(
        &relay_a.mesh.decision_makers,
        &key,
        bounds,
        Authority::Peer,
        std::collections::HashSet::new(),
        expected.clone(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
    );
    let _ = consensus::sync_maker(
        &relay_b.mesh.decision_makers,
        &key,
        bounds,
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        expected,
        [SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
    );

    // Both clients connect before either side joins the mesh session. Their live
    // SlotPresent frames therefore have no registered mesh channel to use; Join
    // reconciliation is the only way those already-live slots cross the link.
    let (client_a, _client_ep_a) = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let (client_b, _client_ep_b) = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;
    let (_send_a, mut control_a) = open_lobby_streams(&client_a).await;
    let (_send_b, mut control_b) = open_lobby_streams(&client_b).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(!consensus::session_started(
        &relay_b.mesh.decision_makers,
        &key
    ));

    let (mesh_a, mesh_b, _mesh_ep_a, _mesh_ep_b) = mesh_link_pair().await;
    let commands_a = spawn_mesh_link(mesh_a, Arc::clone(&relay_a.sessions), relay_a.mesh.clone());
    let commands_b = spawn_mesh_link(mesh_b, Arc::clone(&relay_b.sessions), relay_b.mesh.clone());

    // A's replay happens while B is still unjoined and is intentionally
    // discarded. Prove that this one-sided state alone cannot start B.
    commands_a.send(mesh::MeshCommand::Join(key.clone()))?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!consensus::session_started(
        &relay_b.mesh.decision_makers,
        &key
    ));

    // B now joins and sends its initial aggregate. A's one-shot rendezvous
    // response replays slot 0 after B is known joined, completing B's expected
    // roster. The authority starts both local and peer clients exactly once.
    commands_b.send(mesh::MeshCommand::Join(key.clone()))?;
    assert!(matches!(
        next_non_connectivity(&mut control_b).await,
        ControlInbound::SessionStart(_)
    ));
    assert!(matches!(
        next_non_connectivity(&mut control_a).await,
        ControlInbound::SessionStart(_)
    ));
    assert!(consensus::session_started(
        &relay_b.mesh.decision_makers,
        &key
    ));

    Ok(())
}

/// The first report received after both sides have joined is a rendezvous, not
/// an ordinary push-on-change exchange. It must force this relay's current
/// aggregate back to a peer that may have dropped the original pre-Join frame,
/// even when that value is unchanged in `presence_sent`. The forced reply is
/// one-shot so the peer's corresponding reply cannot start an echo loop.
#[tokio::test]
async fn first_peer_presence_forces_exactly_one_current_reply() -> Result<(), AnyError> {
    let sessions: Sessions = Arc::default();
    let mesh_state = mesh::new_mesh_state();
    let (local_link, peer_link, _local_endpoint, _peer_endpoint) = mesh_link_pair().await;
    let local_connection = local_link.connection().clone();
    let peer_connection = peer_link.connection().clone();

    // Feed peer reports directly so their ordering relative to command barriers
    // is deterministic, while retaining a real QUIC stream for outbound frames.
    let presence_send = local_connection.open_uni().await?;
    let (peer_presence_tx, peer_presence_rx) = mpsc::channel::<MeshPresence>(8);
    let (mut control_send, _unused_control_recv) = local_connection.open_bi().await?;
    rally_point_transport::mesh_control_stream::establish_mesh_control(&mut control_send).await?;
    let (peer_control_tx, peer_control_rx) =
        mpsc::channel::<rally_point_proto::messages::MeshControlFrame>(8);
    let attempt = mesh::new_mesh_link_attempt();
    let lease = mesh::claim_mesh_link(&mesh_state, RelayId(9), &attempt)
        .expect("the test driver claims its peer lease");
    let (commands_tx, commands_rx) = mpsc::unbounded_channel();
    let driver = tokio::spawn(mesh::run_mesh_link(
        local_link,
        mesh::MeshLinkIo {
            presence: rally_point_relay::presence::PresenceIo {
                peer_id: RelayId(9),
                tx: presence_send,
                rx: peer_presence_rx,
            },
            control: mesh::MeshControlIo {
                tx: control_send,
                rx: peer_control_rx,
            },
            lease,
        },
        commands_rx,
        Arc::clone(&sessions),
        mesh_state,
        mesh::IDLE_TIMEOUT,
    ));

    let key = |session| SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(session),
    };
    let rendezvous = key(42);
    commands_tx.send(mesh::MeshCommand::Join(rendezvous.clone()))?;
    let mut outbound_presence =
        tokio::time::timeout(Duration::from_secs(2), peer_connection.accept_uni())
            .await
            .map_err(|_| "the driver did not open its presence stream within 2s")??;
    assert_eq!(
        next_mesh_presence(&mut outbound_presence).await,
        MeshPresence {
            session: rendezvous.session,
            live_players: 0,
        },
        "Join sends the initial local aggregate",
    );

    // A same-session duplicate is documented as a no-op. The following fresh
    // Join is a stream-order barrier: if the duplicate wrote anything, that
    // unexpected session-42 frame would appear before session 43 here.
    commands_tx.send(mesh::MeshCommand::Join(rendezvous.clone()))?;
    let duplicate_barrier = key(43);
    commands_tx.send(mesh::MeshCommand::Join(duplicate_barrier.clone()))?;
    assert_eq!(
        next_mesh_presence(&mut outbound_presence).await.session,
        duplicate_barrier.session,
        "a duplicate Join emits no aggregate presence frame",
    );

    peer_presence_tx
        .send(MeshPresence {
            session: rendezvous.session,
            live_players: 7,
        })
        .await?;
    assert_eq!(
        next_mesh_presence(&mut outbound_presence).await,
        MeshPresence {
            session: rendezvous.session,
            live_players: 0,
        },
        "the first peer report forces the unchanged current aggregate",
    );

    // Enqueue the second report before its command barrier. The driver's biased
    // select handles ready presence before commands; if it echoed this report,
    // session 42 would therefore precede the barrier's session-44 frame.
    peer_presence_tx
        .send(MeshPresence {
            session: rendezvous.session,
            live_players: 8,
        })
        .await?;
    let repeat_barrier = key(44);
    commands_tx.send(mesh::MeshCommand::Join(repeat_barrier.clone()))?;
    assert_eq!(
        next_mesh_presence(&mut outbound_presence).await.session,
        repeat_barrier.session,
        "later peer reports do not trigger aggregate-presence echoes",
    );

    drop(commands_tx);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), driver).await??,
        mesh::MeshLinkExit::CommandChannelClosed,
    );
    drop(peer_presence_tx);
    drop(peer_control_tx);
    Ok(())
}

/// A lobby command a member authors on relay A reaches both a same-relay peer and
/// a cross-relay peer, in order and stamped with the author's slot; and a peer's
/// own lobby command reaches the author. The full pre-game fan-out path across
/// the mesh, driven by real relays and real client control streams.
#[tokio::test]
async fn lobby_commands_reach_same_relay_and_cross_relay_peers_in_order() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let relay_a = Relay::start(&tenant);
    let mut relay_b = Relay::start(&tenant);
    let (_cmds_a, _cmds_b, _mesh_ep) = mesh_two_relays(&relay_a, &mut relay_b, &key).await;

    // Host (slot 0) and a same-relay peer (slot 2) on A; a cross-relay peer
    // (slot 1) on B. All three are connected before any command flows, so each
    // receives its peers' commands live.
    let (host, _ep0) = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let (peer_a, _ep2) = connect_client(&relay_a, &tenant, session, SlotId(2)).await?;
    let (peer_b, _ep1) = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;

    let (mut host_send, mut host_rx) = open_lobby_streams(&host).await;
    let (_peer_a_send, mut peer_a_rx) = open_lobby_streams(&peer_a).await;
    let (mut peer_b_send, mut peer_b_rx) = open_lobby_streams(&peer_b).await;

    // Let the mesh drivers open their sessions and every slot link register.
    tokio::time::sleep(Duration::from_millis(80)).await;

    // The host authors three setup commands (the wire slot is ignored — the relay
    // stamps the authenticated slot 0).
    for byte in [0x01u8, 0x02, 0x03] {
        rally_point_transport::control::send_control_lobby(
            &mut host_send,
            LobbyCommand {
                slot: 99,
                payload: vec![byte].into(),
            },
        )
        .await?;
    }

    // The same-relay peer receives all three, in order, stamped with the host's
    // authoritative slot.
    assert_eq!(next_lobby(&mut peer_a_rx).await, (0, vec![0x01]));
    assert_eq!(next_lobby(&mut peer_a_rx).await, (0, vec![0x02]));
    assert_eq!(next_lobby(&mut peer_a_rx).await, (0, vec![0x03]));

    // The cross-relay peer receives all three across the mesh, in order, same
    // slot stamp.
    assert_eq!(next_lobby(&mut peer_b_rx).await, (0, vec![0x01]));
    assert_eq!(next_lobby(&mut peer_b_rx).await, (0, vec![0x02]));
    assert_eq!(next_lobby(&mut peer_b_rx).await, (0, vec![0x03]));

    // A peer authors its own command; it reaches the host stamped with the
    // peer's slot (1) — the relay never trusts the wire slot.
    rally_point_transport::control::send_control_lobby(
        &mut peer_b_send,
        LobbyCommand {
            slot: 42,
            payload: vec![0xAA].into(),
        },
    )
    .await?;
    assert_eq!(next_lobby(&mut host_rx).await, (1, vec![0xAA]));

    Ok(())
}

/// A member that dials in AFTER the host already sent its setup commands still
/// receives the whole sequence, in order — the per-session replay log catches it
/// up. Covers both a same-relay late dial (replayed from A's log) and a
/// cross-relay one (replayed from B's log, fed by the mesh).
#[tokio::test]
async fn a_late_dialing_peer_replays_the_full_lobby_sequence() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let relay_a = Relay::start(&tenant);
    let mut relay_b = Relay::start(&tenant);
    let (_cmds_a, _cmds_b, _mesh_ep) = mesh_two_relays(&relay_a, &mut relay_b, &key).await;

    // Only the host is connected. It sends its setup commands before any peer
    // exists — the relay logs them (and fans copies across the mesh, which relay
    // B logs too).
    let (host, _ep0) = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let (mut host_send, _host_rx) = open_lobby_streams(&host).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    for byte in [0x01u8, 0x02, 0x03] {
        rally_point_transport::control::send_control_lobby(
            &mut host_send,
            LobbyCommand {
                slot: 0,
                payload: vec![byte].into(),
            },
        )
        .await?;
    }
    // Give the commands time to reach and append to both relays' logs.
    tokio::time::sleep(Duration::from_millis(120)).await;

    // A same-relay peer dials late: it replays A's log in order.
    let (peer_a, _ep2) = connect_client(&relay_a, &tenant, session, SlotId(2)).await?;
    let (_peer_a_send, mut peer_a_rx) = open_lobby_streams(&peer_a).await;
    assert_eq!(next_lobby(&mut peer_a_rx).await, (0, vec![0x01]));
    assert_eq!(next_lobby(&mut peer_a_rx).await, (0, vec![0x02]));
    assert_eq!(next_lobby(&mut peer_a_rx).await, (0, vec![0x03]));

    // A cross-relay peer dials late: it replays B's log (fed by the mesh) in order.
    let (peer_b, _ep1) = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;
    let (_peer_b_send, mut peer_b_rx) = open_lobby_streams(&peer_b).await;
    assert_eq!(next_lobby(&mut peer_b_rx).await, (0, vec![0x01]));
    assert_eq!(next_lobby(&mut peer_b_rx).await, (0, vec![0x02]));
    assert_eq!(next_lobby(&mut peer_b_rx).await, (0, vec![0x03]));

    Ok(())
}

/// Reads control frames until one is a `SlotConnectivity` naming `(slot,
/// connected)`, skipping every other frame kind. Panics on timeout. Mirrors
/// `client_edge.rs`'s helper of the same name (a separate integration test
/// binary, so not shared).
async fn wait_for_connectivity(
    reader: &mut mpsc::Receiver<rally_point_transport::control::ControlInbound>,
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

/// A member spamming lobby commands past the relay's per-slot rate cap gets
/// only the admitted prefix relayed to a cross-relay peer — the over-cap
/// remainder never reaches the mesh control channel at all (not merely
/// delayed) — and a departure that follows right on the spam's heels still
/// reaches that peer promptly, proving the refused burst left nothing queued
/// ahead of it to back up behind. Mirrors
/// `lobby_commands_reach_same_relay_and_cross_relay_peers_in_order`'s
/// cross-relay setup.
#[tokio::test]
async fn lobby_spam_past_the_rate_cap_never_reaches_the_mesh_and_a_departure_still_gets_through()
-> Result<(), AnyError> {
    // Mirrors the private `lobby::LOBBY_RATE_BURST` (see the sibling flood
    // tests' own comments on this pattern, e.g. mesh.rs's
    // `routing::FORWARD_CAPACITY` mirror).
    const LOBBY_RATE_BURST: usize = 32;

    let tenant = make_tenant();
    let session = SessionId(3);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let relay_a = Relay::start(&tenant);
    let mut relay_b = Relay::start(&tenant);
    let (_cmds_a, _cmds_b, _mesh_ep) = mesh_two_relays(&relay_a, &mut relay_b, &key).await;

    // The spammer (slot 0) is on A; the observing peer (slot 1) is on B, so
    // the mesh control channel is genuinely exercised, not just local fan-out.
    let (host, _ep0) = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let (peer_b, _ep1) = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;

    let (mut host_send, _host_rx) = open_lobby_streams(&host).await;
    let (_peer_b_send, mut peer_b_rx) = open_lobby_streams(&peer_b).await;

    tokio::time::sleep(Duration::from_millis(80)).await;

    // Fire well past the burst, back to back with no pacing -- exactly the
    // shape a flooding or buggy client produces.
    for i in 0..(LOBBY_RATE_BURST + 20) {
        rally_point_transport::control::send_control_lobby(
            &mut host_send,
            LobbyCommand {
                slot: 99,
                payload: vec![i as u8].into(),
            },
        )
        .await?;
    }

    // The peer receives exactly the admitted prefix -- the refused remainder
    // was never handed to `fan_out_lobby_command` at all.
    let mut received = Vec::new();
    for _ in 0..LOBBY_RATE_BURST {
        received.push(next_lobby(&mut peer_b_rx).await.1[0]);
    }
    assert_eq!(
        received,
        (0..LOBBY_RATE_BURST as u8).collect::<Vec<_>>(),
        "exactly the admitted prefix, in order",
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), next_lobby(&mut peer_b_rx))
            .await
            .is_err(),
        "nothing past the burst ever reaches the mesh -- not delayed, dropped outright",
    );

    // The spammer's own link now dies. Explicitly closed (not just dropped):
    // `open_lobby_streams`'s reader task holds its own clone of the
    // connection, so a plain `drop(host)` would leave that clone alive and
    // the connection would linger rather than close promptly. If the refused
    // burst had queued anything ahead of this on the shared mesh control
    // channel, the departure would be stuck behind it; it arrives promptly
    // instead.
    host.close(0u32.into(), b"done");
    wait_for_connectivity(&mut peer_b_rx, SlotId(0), false).await;

    Ok(())
}

/// A game-chat message a member authors on relay A reaches a cross-relay peer on
/// relay B, in order, stamped with the author's slot and with its scope fields
/// (`target_kind`/`target_slot`) preserved verbatim across the mesh hop — the
/// relay never interprets them. The full mid-game chat fan-out path across the
/// mesh, driven by real relays and real client control streams, mirroring the
/// lobby-command cross-relay test.
#[tokio::test]
async fn game_chat_reaches_a_cross_relay_peer_through_the_mesh() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(2);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let relay_a = Relay::start(&tenant);
    let mut relay_b = Relay::start(&tenant);
    let (_cmds_a, _cmds_b, _mesh_ep) = mesh_two_relays(&relay_a, &mut relay_b, &key).await;

    // The sender (slot 0) is on A; the receiver (slot 1) is on B.
    let (host, _ep0) = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let (peer_b, _ep1) = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;

    let (mut host_send, _host_rx) = open_lobby_streams(&host).await;
    let (_peer_b_send, mut peer_b_rx) = open_lobby_streams(&peer_b).await;

    // Let the mesh drivers open their sessions and both slot links register.
    tokio::time::sleep(Duration::from_millis(80)).await;

    // The host authors a scoped chat message (the wire slot is ignored — the
    // relay stamps the authenticated slot 0).
    rally_point_transport::control::send_control_chat(
        &mut host_send,
        GameChat {
            slot: 99,
            target_kind: 1,
            target_slot: 4,
            text: "flanking from the north".to_owned(),
        },
    )
    .await?;

    // The cross-relay peer receives it across the mesh, stamped with the host's
    // authoritative slot, its scope fields intact.
    assert_eq!(
        next_chat(&mut peer_b_rx).await,
        (0, 1, 4, "flanking from the north".to_owned()),
    );

    Ok(())
}

/// A cosmetic-skin blob a member broadcasts on relay A reaches a cross-relay peer
/// on relay B, stamped with the author's slot — and, unlike chat, is stored in
/// relay B's per-session map, so a client that dials into B *after* the blob
/// arrived still replays it on register. The full skin fan-out-plus-replay path
/// across the mesh, mirroring the game-chat cross-relay test with the store its
/// latest-per-slot map adds.
#[tokio::test]
async fn player_skin_reaches_a_cross_relay_peer_and_replays_to_a_late_joiner()
-> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(3);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let relay_a = Relay::start(&tenant);
    let mut relay_b = Relay::start(&tenant);
    let (_cmds_a, _cmds_b, _mesh_ep) = mesh_two_relays(&relay_a, &mut relay_b, &key).await;

    // The sender (slot 0) is on A; the first receiver (slot 1) is on B.
    let (host, _ep0) = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let (peer_b, _ep1) = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;

    let (mut host_send, _host_rx) = open_lobby_streams(&host).await;
    let (_peer_b_send, mut peer_b_rx) = open_lobby_streams(&peer_b).await;

    // Let the mesh drivers open their sessions and both slot links register.
    tokio::time::sleep(Duration::from_millis(80)).await;

    // The host broadcasts its blob (the wire slot is ignored — the relay stamps
    // the authenticated slot 0).
    rally_point_transport::control::send_control_skin(
        &mut host_send,
        PlayerSkin {
            slot: 99,
            payload: vec![0xCA, 0xFE, 0xBA, 0xBE].into(),
        },
    )
    .await?;

    // The cross-relay peer receives it, stamped with the host's authoritative slot.
    assert_eq!(
        next_skin(&mut peer_b_rx).await,
        (0, vec![0xCA, 0xFE, 0xBA, 0xBE]),
    );

    // A client dialing into relay B after the blob already crossed the mesh still
    // gets it — proof relay B stored the mesh-received blob in its own map and
    // replays it on register.
    let (late_b, _ep2) = connect_client(&relay_b, &tenant, session, SlotId(2)).await?;
    let (_late_send, mut late_rx) = open_lobby_streams(&late_b).await;
    assert_eq!(
        next_skin(&mut late_rx).await,
        (0, vec![0xCA, 0xFE, 0xBA, 0xBE])
    );

    Ok(())
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
    let (dial_chain, dial_key, _) = self_signed();
    let mesh_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();
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
    // regardless of MeshSeen. MeshSeen is the relay's session-level gate for
    // reconnect/resume and re-home overlap, so this test proves direct
    // cross-relay delivery rather than that defensive duplicate path.
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

/// `C-S===S-C` for a turn too large for any datagram: relay A's mesh forward
/// path diverts it onto the mesh control stream (no datagram could carry it),
/// relay B's dispatch folds it back into its normal turn path, and relay B's
/// slot link diverts it again onto the receiving client's own control stream.
/// Without the mesh divert this turn silently never reached B's clients — a
/// permanent lockstep stall in any cross-relay game whose turn outgrew the
/// datagram budget.
#[tokio::test]
async fn cross_relay_oversize_turn_diverts_over_the_mesh_control_stream() -> Result<(), AnyError> {
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

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
    let (dial_chain, dial_key, _) = self_signed();
    let mesh_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();
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

    // The receiving client on relay B (slot 1), reading its control stream —
    // that's where B's slot link delivers a turn too large for the client path.
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
    let client_b = Link::new(conn_slot1);
    let mut ctrl_b = spawn_control_reader(client_b.connection().clone());

    // Let mesh drivers open their sessions on the MeshLinks.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Relay A forwards slot 0's turn, as its slot-link task would after
    // validating it — but this one is far past any datagram budget, so A's
    // mesh-link driver must divert it onto the mesh control stream.
    let oversize = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0xAB; 5000].into(),
        game_frame_count: Some(12),
        ..Default::default()
    };
    mesh::forward_client_turn(
        &relay_a.sessions,
        &relay_a.mesh.links,
        &relay_a.mesh.seen,
        &relay_a.mesh.decision_makers,
        &relay_a.mesh.turn_ring,
        &key,
        SlotId(0),
        oversize.clone(),
    );

    // Client B receives the turn on its control stream: two divert hops (mesh
    // control stream, then the client's own), one identical payload. Read past any
    // connectivity frame the client's own register fanned.
    let received = next_non_connectivity(&mut ctrl_b).await;
    let ControlInbound::OversizeTurn(delivered) = received else {
        panic!("expected an oversize turn, got {received:?}");
    };
    assert_eq!(delivered.slot, 0);
    assert_eq!(delivered.seq, 0);
    assert_eq!(delivered.game_frame_count, Some(12));
    assert_eq!(
        delivered.commands, oversize.commands,
        "the command bytes cross both divert hops verbatim",
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
    let (dial_chain, dial_key, _) = self_signed();
    let mesh_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();
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
    let (dial_chain, dial_key, _) = self_signed();
    let mesh_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();
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
    let (dial_chain, dial_key, _) = self_signed();
    let mesh_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();
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
