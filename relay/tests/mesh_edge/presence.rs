//! Slot presence over the mesh: asymmetric joins converging on one roster, and
//! the single current-state reply a first peer presence forces.

use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::mesh::MeshPresence;
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh;
use rally_point_relay::routing::Sessions;

use crate::helpers::*;
use tokio::sync::mpsc;

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

    let tenant = make_default_tenant();
    let session = SessionId(41);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    // Relay B is the authority. That choice is load-bearing for the regression:
    // A joins first, so B must recover A's early slot announcement after B's own
    // later Join rather than starting from the announcement B sends to A.
    seed_authority(&relay_a.mesh.decision_makers, &key)
        .expecting([0, 1])
        .homed([0])
        .authority(Authority::Peer)
        .apply();
    seed_authority(&relay_b.mesh.decision_makers, &key)
        .expecting([0, 1])
        .homed([1])
        .apply();

    // Both clients connect before either side joins the mesh session. Their live
    // SlotPresent frames therefore have no registered mesh channel to use; Join
    // reconciliation is the only way those already-live slots cross the link.
    let client_a = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let client_b = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;
    let (_send_a, mut control_a) = open_lobby_streams(client_a.connection()).await;
    let (_send_b, mut control_b) = open_lobby_streams(client_b.connection()).await;
    wait_for_slots(&relay_a.sessions, &key, 1).await;
    wait_for_slots(&relay_b.sessions, &key, 1).await;
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
    wait_for_mesh_link(&relay_a.mesh, &key).await;
    // A's replay is on the wire by now; give B long enough to have acted on it
    // if it were going to. A negative claim needs some window, but a short one:
    // B is one loopback hop away.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!consensus::session_started(
        &relay_b.mesh.decision_makers,
        &key
    ));

    // B now joins and sends its initial aggregate. A's one-shot rendezvous
    // response replays slot 0 after B is known joined, completing B's expected
    // roster. The authority starts both local and peer clients exactly once.
    commands_b.send(mesh::MeshCommand::Join(key.clone()))?;
    assert!(matches!(
        recv_meaningful(&mut control_b).await,
        ControlInbound::SessionStart(_)
    ));
    assert!(matches!(
        recv_meaningful(&mut control_a).await,
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
            presence: rally_point_relay::session::presence::PresenceIo {
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
