//! Lobby commands across relays: every relay drops what it already accepted
//! from an author by origin seq, whether it accepted the original from the
//! author or from a peer relay, so a re-send after the author moves delivers
//! only the lost command; a mesh link's rejoin re-shares what a dead link
//! failed to carry; and a command one relay refused holds back nothing behind
//! it on any relay.

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::LobbyCommand;
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh::{MeshCommand, MeshLinkExit};
use rally_point_relay::routing::Sessions;
use rally_point_transport::control::send_control_lobby;
use rally_point_transport::noq;
use rally_point_transport::{Link, MeshLink};

use crate::helpers::*;

async fn send_all(send: &mut noq::SendStream, seqs: impl IntoIterator<Item = u64>) {
    for seq in seqs {
        send_control_lobby(
            send,
            LobbyCommand {
                slot: 0,
                payload: vec![0x10 + seq as u8].into(),
                seq: Some(seq),
            },
        )
        .await
        .unwrap();
    }
}

/// Ends the host's `link` and waits for `sessions` to drop slot 0, the way a
/// relay eventually lets go of a link whose path died.
async fn drop_host(link: &Link, sessions: &Sessions, key: &SessionKey) {
    link.connection().close(0u32.into(), b"path died");
    wait_until("the host's slot never deregistered", || {
        sessions
            .lock()
            .get(key)
            .is_some_and(|slots| !slots.contains_key(&SlotId(0)))
    })
    .await;
}

#[tokio::test]
async fn a_re_send_after_the_author_moves_relays_delivers_only_the_lost_command()
-> Result<(), AnyError> {
    let tenant = make_default_tenant();
    let session = SessionId(30);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);
    let (_cmds_a, _cmds_b, _mesh_ep) = mesh_two_relays(&relay_a, &mut relay_b, &key).await;

    // The host (slot 0) and one peer on A, another peer on B.
    let host = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let peer_a = connect_client(&relay_a, &tenant, session, SlotId(2)).await?;
    let peer_b = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;
    let (mut host_send, _host_rx) = open_lobby_streams(host.connection()).await;
    let (_peer_a_send, mut peer_a_rx) = open_lobby_streams(peer_a.connection()).await;
    let (_peer_b_send, mut peer_b_rx) = open_lobby_streams(peer_b.connection()).await;
    wait_for_slots(&relay_a.sessions, &key, 2).await;
    wait_for_slots(&relay_b.sessions, &key, 1).await;
    wait_for_mesh_link(&relay_a.mesh, &key).await;
    wait_for_mesh_link(&relay_b.mesh, &key).await;

    // Two commands through A: B holds them only as mesh copies.
    send_all(&mut host_send, [0, 1]).await;
    for rx in [&mut peer_a_rx, &mut peer_b_rx] {
        for seq in [0, 1] {
            assert_eq!(
                next_sequenced_lobby(rx).await,
                (0, Some(seq), 0x10 + seq as u8)
            );
        }
    }

    // The host's link to A dies with its third command lost, and it comes back
    // through B, re-sending everything. B already has 0 and 1 from the mesh and
    // forwards only 2, to its own peer and across the mesh to A's.
    drop_host(&host, &relay_a.sessions, &key).await;
    let host_on_b = connect_client(&relay_b, &tenant, session, SlotId(0)).await?;
    let (mut on_b_send, _on_b_rx) = open_lobby_streams(host_on_b.connection()).await;
    send_all(&mut on_b_send, [0, 1, 2]).await;
    for rx in [&mut peer_b_rx, &mut peer_a_rx] {
        assert_eq!(next_sequenced_lobby(rx).await, (0, Some(2), 0x12));
    }
    assert_no_lobby(&mut peer_b_rx, "B forwarded a command its log already had").await;
    assert_no_lobby(&mut peer_a_rx, "A delivered a mesh copy twice").await;

    // And back through A: A accepted 0 and 1 from the host and 2 from the mesh,
    // so the whole re-send is dropped there and no peer on either relay sees
    // any of it again.
    drop_host(&host_on_b, &relay_b.sessions, &key).await;
    let host_on_a = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let (mut on_a_send, _on_a_rx) = open_lobby_streams(host_on_a.connection()).await;
    send_all(&mut on_a_send, [0, 1, 2]).await;
    assert_no_lobby(&mut peer_a_rx, "A forwarded a command its log already had").await;
    assert_no_lobby(&mut peer_b_rx, "a re-send crossed the mesh twice").await;

    Ok(())
}

/// One raw mesh link from relay A to relay B, joined to a session on both
/// sides. The drivers run while their command senders live; the test ends the
/// link by closing `conn_a`, and awaits the exits before dialing again.
struct JoinedLink {
    conn_a: noq::Connection,
    _cmds: [tokio::sync::mpsc::UnboundedSender<MeshCommand>; 2],
    exits: [tokio::task::JoinHandle<MeshLinkExit>; 2],
}

/// Dials A → B and joins `key` on both ends: the dialing half of
/// [`mesh_two_relays`], with B's accept channel held by the caller so the pair
/// can be dialed again after the link dies.
async fn join_mesh_link(
    relay_a: &Relay,
    relay_b: &Relay,
    mesh_accept: &mut tokio::sync::mpsc::Receiver<noq::Connection>,
    mesh_ep: &noq::Endpoint,
    key: &SessionKey,
) -> JoinedLink {
    let conn_a = mesh_ep
        .connect(relay_b.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let conn_b = mesh_accept.recv().await.expect("B dispatched mesh conn");
    let idle = rally_point_relay::mesh::IDLE_TIMEOUT;
    let (cmds_a, exit_a) = spawn_mesh_link_timed(
        MeshLink::new(conn_a.clone()),
        std::sync::Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        idle,
    );
    let (cmds_b, exit_b) = spawn_mesh_link_timed(
        MeshLink::new(conn_b),
        std::sync::Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        idle,
    );
    cmds_a.send(MeshCommand::Join(key.clone())).unwrap();
    cmds_b.send(MeshCommand::Join(key.clone())).unwrap();
    JoinedLink {
        conn_a,
        _cmds: [cmds_a, cmds_b],
        exits: [exit_a, exit_b],
    }
}

#[tokio::test]
async fn a_command_logged_while_the_mesh_link_was_down_reaches_the_peer_on_rejoin()
-> Result<(), AnyError> {
    let tenant = make_default_tenant();
    let session = SessionId(31);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);
    let mut mesh_accept = relay_b.mesh_accept_rx();
    let mut roots = rally_point_transport::rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let mesh_ep = noq::Endpoint::client((std::net::Ipv4Addr::LOCALHOST, 0).into())?;
    mesh_ep.set_default_client_config(rally_point_transport::quic::mesh_client_config(
        roots, dial_chain, dial_key,
    )?);

    let first = join_mesh_link(&relay_a, &relay_b, &mut mesh_accept, &mesh_ep, &key).await;
    let host = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let peer_b = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;
    let (mut host_send, _host_rx) = open_lobby_streams(host.connection()).await;
    let (_peer_b_send, mut peer_b_rx) = open_lobby_streams(peer_b.connection()).await;
    wait_for_slots(&relay_a.sessions, &key, 1).await;
    wait_for_slots(&relay_b.sessions, &key, 1).await;
    wait_for_mesh_link(&relay_a.mesh, &key).await;
    wait_for_mesh_link(&relay_b.mesh, &key).await;

    send_all(&mut host_send, [0]).await;
    assert_eq!(
        next_sequenced_lobby(&mut peer_b_rx).await,
        (0, Some(0), 0x10)
    );

    // The mesh link dies, and the host's next command is logged on A with no
    // link to cross. The one after it crosses live once the link is back; the
    // re-share brings the one B missed, before or after it.
    first.conn_a.close(0u32.into(), b"mesh path died");
    for exit in first.exits {
        let _ = exit.await;
    }
    wait_until("A never unregistered the dead mesh link", || {
        !relay_a.mesh.links.lock().contains_key(&key)
    })
    .await;
    send_all(&mut host_send, [1]).await;
    wait_until("A never logged the command", || {
        relay_a.mesh.session.side_channels.lobby.is_repeat(
            &key,
            &LobbyCommand {
                slot: 0,
                payload: vec![0x11].into(),
                seq: Some(1),
            },
        )
    })
    .await;

    let _rejoined = join_mesh_link(&relay_a, &relay_b, &mut mesh_accept, &mesh_ep, &key).await;
    wait_for_mesh_link(&relay_a.mesh, &key).await;
    wait_for_mesh_link(&relay_b.mesh, &key).await;
    send_all(&mut host_send, [2]).await;
    let mut got = vec![
        next_sequenced_lobby(&mut peer_b_rx).await,
        next_sequenced_lobby(&mut peer_b_rx).await,
    ];
    got.sort();
    assert_eq!(
        got,
        vec![(0, Some(1), 0x11), (0, Some(2), 0x12)],
        "the rejoined link re-shares what B missed, and the live one crosses too",
    );
    assert_no_lobby(&mut peer_b_rx, "the re-share delivered a command twice").await;

    Ok(())
}

#[tokio::test]
async fn a_policy_refused_command_never_holds_back_the_authors_later_ones_on_any_relay()
-> Result<(), AnyError> {
    // The host's home relay accepts seq 0, refuses seq 1 by policy (the slot
    // has started, so the refusal only drops it), and accepts seq 2. Every
    // relay delivers 0 and 2, and neither a mesh rejoin's re-share nor the
    // author's own re-send changes what anyone delivers.
    use rally_point_proto::control::{AllowedLobbyCommand, BufferBounds, LobbyPolicy};
    use rally_point_relay::consensus::{Authority, MakerSync};

    let tenant = make_default_tenant();
    let session = SessionId(32);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);
    let _ = relay_a.mesh.session.decision_makers.sync_maker(
        &key,
        MakerSync {
            lobby_policy: Some(LobbyPolicy {
                allowed: [0x10u8, 0x12]
                    .into_iter()
                    .map(|byte| AllowedLobbyCommand {
                        slot: SlotId(0),
                        payload: vec![byte],
                    })
                    .collect(),
            }),
            ..MakerSync::new(BufferBounds::new(0, 20).unwrap(), Authority::SelfRelay)
        },
    );
    let mut mesh_accept = relay_b.mesh_accept_rx();
    let mut roots = rally_point_transport::rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let mesh_ep = noq::Endpoint::client((std::net::Ipv4Addr::LOCALHOST, 0).into())?;
    mesh_ep.set_default_client_config(rally_point_transport::quic::mesh_client_config(
        roots, dial_chain, dial_key,
    )?);
    let first = join_mesh_link(&relay_a, &relay_b, &mut mesh_accept, &mesh_ep, &key).await;

    let host = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let peer_a = connect_client(&relay_a, &tenant, session, SlotId(2)).await?;
    let peer_b = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;
    let (mut host_send, _host_rx) = open_lobby_streams(host.connection()).await;
    let (_peer_a_send, mut peer_a_rx) = open_lobby_streams(peer_a.connection()).await;
    let (_peer_b_send, mut peer_b_rx) = open_lobby_streams(peer_b.connection()).await;
    wait_for_slots(&relay_a.sessions, &key, 2).await;
    wait_for_slots(&relay_b.sessions, &key, 1).await;
    wait_for_mesh_link(&relay_a.mesh, &key).await;
    wait_for_mesh_link(&relay_b.mesh, &key).await;

    send_all(&mut host_send, [0]).await;
    for rx in [&mut peer_a_rx, &mut peer_b_rx] {
        assert_eq!(next_sequenced_lobby(rx).await, (0, Some(0), 0x10));
    }
    rally_point_transport::control::send_control_game_started(&mut host_send).await?;
    wait_until("A never recorded the host's start", || {
        relay_a
            .mesh
            .session
            .decision_makers
            .has_started(&key, SlotId(0))
    })
    .await;
    send_all(&mut host_send, [1, 2]).await;
    for rx in [&mut peer_a_rx, &mut peer_b_rx] {
        assert_eq!(
            next_sequenced_lobby(rx).await,
            (0, Some(2), 0x12),
            "the refused seq 1 holds nothing back",
        );
    }

    // The mesh link dies and rejoins: each side re-shares its log, and both
    // already hold everything in it.
    first.conn_a.close(0u32.into(), b"mesh path died");
    for exit in first.exits {
        let _ = exit.await;
    }
    wait_until("A never unregistered the dead mesh link", || {
        !relay_a.mesh.links.lock().contains_key(&key)
    })
    .await;
    let _rejoined = join_mesh_link(&relay_a, &relay_b, &mut mesh_accept, &mesh_ep, &key).await;
    wait_for_mesh_link(&relay_a.mesh, &key).await;
    wait_for_mesh_link(&relay_b.mesh, &key).await;

    // And the host re-dials and re-sends its whole history: 0 and 2 are
    // repeats, and 1 is refused again.
    drop_host(&host, &relay_a.sessions, &key).await;
    let host_again = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let (mut again_send, _again_rx) = open_lobby_streams(host_again.connection()).await;
    rally_point_transport::control::send_control_game_started(&mut again_send).await?;
    send_all(&mut again_send, [0, 1, 2]).await;
    assert_no_lobby(&mut peer_a_rx, "A delivered a command again").await;
    assert_no_lobby(&mut peer_b_rx, "B delivered a command again").await;

    Ok(())
}
