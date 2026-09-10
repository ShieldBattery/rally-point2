//! Fixtures only the mesh-driver suite uses: raw `MeshLink` pairs, the
//! `run_mesh_link` spawners the two-relay tests share, and the control-stream
//! readers that pull lobby, chat and skin frames off a client.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::mesh::{MESH_PRESENCE_LEN, MeshPresence};
use rally_point_proto::token::SignedToken;
use rally_point_relay::auth::Registry;
use rally_point_relay::mesh;
use rally_point_relay::routing::{SessionKey, Sessions};
use rally_point_relay::server;
use rally_point_transport::quic::{client_config, mesh_client_config, server_config};
use rally_point_transport::rustls::pki_types::CertificateDer;
use rally_point_transport::{MeshLink, noq, rustls};

use tokio::sync::mpsc;

pub use crate::common::{
    AnyError, KID, Keypair, TENANT, Tenant, keypair, mint_token, self_signed, turn,
    wait_for_connectivity,
};

/// The one tenant these tests trust, named by the suite's fixed key id.
pub fn make_tenant() -> Tenant {
    crate::common::make_tenant(KID, TENANT)
}

/// A registry trusting `tenant` alone.
pub fn registry_for(tenant: &Tenant) -> Registry {
    crate::common::registry_for(&[tenant])
}

/// Runs the client side of the handshake as a fresh dial, presenting no resume
/// cursors (an empty, zero-count frame) so the relay replays nothing.
pub async fn handshake(
    connection: &noq::Connection,
    token: &SignedToken,
    signing_key: &Keypair,
) -> Result<(), AnyError> {
    crate::common::handshake(connection, token, signing_key, &[]).await
}

/// A relay with its client edge, shared mesh state, and a mesh-accept channel.
pub struct Relay {
    pub addr: SocketAddr,
    pub ca: CertificateDer<'static>,
    pub sessions: Sessions,
    pub mesh: mesh::MeshState,
    pub mesh_rx: mpsc::Receiver<noq::Connection>,
}

impl Relay {
    pub fn start(tenant: &Tenant) -> Self {
        let (chain, key, ca) = self_signed();
        let cfg = server_config(chain, key).unwrap();
        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let endpoint = noq::Endpoint::server(cfg, bind).unwrap();
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

/// Spawns a mesh-link driver on `link` and returns the command sender the test
/// uses to join and leave sessions. A thin wrapper over `run_mesh_link` so the
/// two-relay tests stay focused on the cross-relay path, not channel plumbing.
///
/// Uses the production [`mesh::IDLE_TIMEOUT`] (60s) so the multi-step cross-relay
/// tests below aren't torn down mid-run by the idle timer. The dedicated
/// idle-teardown test spawns its own driver with a short real duration.
pub fn spawn_mesh_link(
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
pub fn spawn_mesh_link_timed(
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
        let presence_rx = rally_point_relay::session::presence::spawn_presence_reader_accepting(
            link.connection().clone(),
        );
        let presence_io = rally_point_relay::session::presence::PresenceIo {
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
/// noq connection negotiated on `MESH_ALPN`), reusing the test's self-signed
/// cert helper. Both endpoints are returned so the caller keeps them alive.
pub async fn mesh_link_pair() -> (MeshLink, MeshLink, noq::Endpoint, noq::Endpoint) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let client_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = noq::Endpoint::server(server_cfg, bind).unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = noq::Endpoint::client(bind).unwrap();
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

/// A loopback connection whose PEER advertises an under-floor datagram budget
/// (its `datagram_receive_buffer_size` caps what this side may send), for
/// exercising establishment-time floor refusals. Returns the dialing side's
/// connection plus both endpoints so the caller keeps them alive.
pub async fn connection_with_peer_datagram_limit(
    limit: usize,
) -> (noq::Connection, noq::Endpoint, noq::Endpoint) {
    let (chain, key, ca) = self_signed();
    let mut server_cfg = server_config(chain, key).unwrap();
    let mut transport = noq::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(limit));
    server_cfg.transport_config(std::sync::Arc::new(transport));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let client_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = noq::Endpoint::server(server_cfg, bind).unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = noq::Endpoint::client(bind).unwrap();
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
    let _server_conn = accept.await.unwrap();
    (client_conn, client, server)
}

/// Connects a client to `relay` for `slot`, runs the authorization handshake,
/// and returns the live connection plus the client endpoint (kept alive by the
/// caller so the connection is not torn down when the endpoint drops).
pub async fn connect_client(
    relay: &Relay,
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
) -> Result<(noq::Connection, noq::Endpoint), AnyError> {
    let client_key = keypair();
    let token = mint_token(tenant, session, slot, client_key.public);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay.ca.clone()).unwrap();
    let client_cfg = client_config(roots).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let endpoint = noq::Endpoint::client(bind).unwrap();
    endpoint.set_default_client_config(client_cfg);
    let connection = endpoint.connect(relay.addr, "localhost")?.await?;
    handshake(&connection, &token, &client_key).await?;
    Ok((connection, endpoint))
}

/// Opens a client's reliable control-stream halves: the send half it writes its
/// own lobby commands on, and the reader that surfaces the frames the relay
/// pushes down (lobby commands from the other members). Mirrors what a real
/// `LinkDriver` sets up on the control stream.
pub async fn open_lobby_streams(
    connection: &noq::Connection,
) -> (
    noq::SendStream,
    mpsc::Receiver<rally_point_transport::control::ControlInbound>,
) {
    let (send, _our_recv) = connection.open_bi().await.unwrap();
    let rx = rally_point_transport::control::spawn_control_reader(connection.clone());
    (send, rx)
}

/// Reads the next lobby command off a client's control reader within a short
/// timeout, returning `(slot, payload_bytes)` — panicking on any other frame kind
/// or on timeout, so a test asserts against a clean tuple.
pub async fn next_lobby(
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
pub async fn next_non_connectivity(
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
pub async fn next_mesh_presence(stream: &mut noq::RecvStream) -> MeshPresence {
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
pub async fn next_chat(
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
pub async fn next_skin(
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
pub async fn mesh_two_relays(
    relay_a: &Relay,
    relay_b: &mut Relay,
    key: &SessionKey,
) -> (
    mpsc::UnboundedSender<mesh::MeshCommand>,
    mpsc::UnboundedSender<mesh::MeshCommand>,
    noq::Endpoint,
) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let mesh_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mesh_ep = noq::Endpoint::client(bind).unwrap();
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
