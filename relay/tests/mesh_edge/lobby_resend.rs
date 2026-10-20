//! A lobby author re-sending its commands after its link moved: every relay
//! drops what it already accepted from that author by origin seq, whether it
//! accepted the original from the author or from a peer relay, so the re-send
//! delivers only the lost command and nothing crosses the mesh twice.

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::LobbyCommand;
use rally_point_relay::key::SessionKey;
use rally_point_relay::routing::Sessions;
use rally_point_transport::Link;
use rally_point_transport::control::send_control_lobby;
use rally_point_transport::noq;

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
