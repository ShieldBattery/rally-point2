//! A client re-sending its lobby commands on a fresh control stream: the relay
//! forwards only what it never accepted, by the author's origin seq, and keeps
//! forwarding an older client's unsequenced commands exactly as before.

use crate::helpers::*;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::LobbyCommand;
use rally_point_relay::key::SessionKey;
use rally_point_relay::routing::Sessions;
use rally_point_relay::session::side_channel::LOBBY;
use rally_point_transport::control::{send_control_lobby, spawn_control_reader};
use rally_point_transport::noq;

fn command(seq: Option<u64>, byte: u8) -> LobbyCommand {
    LobbyCommand {
        slot: 0,
        payload: vec![byte].into(),
        seq,
    }
}

async fn send_all(send: &mut noq::SendStream, commands: impl IntoIterator<Item = LobbyCommand>) {
    for command in commands {
        send_control_lobby(send, command).await.unwrap();
    }
}

/// Ends `link` the way a dead path eventually does on the relay's side, and
/// waits for the relay to drop the slot: until then a re-dial is refused as a
/// slot already connected.
async fn drop_link(link: &rally_point_transport::Link, sessions: &Sessions, key: &SessionKey) {
    link.connection().close(0u32.into(), b"path died");
    wait_until("the dead link's slot never deregistered", || {
        sessions
            .lock()
            .get(key)
            .is_some_and(|slots| !slots.contains_key(&SlotId(0)))
    })
    .await;
}

#[tokio::test]
async fn a_re_sent_lobby_command_reaches_a_peer_once_and_the_lost_one_gets_through() {
    // The host wrote three commands; the relay saw only the first two (the
    // third went onto a path that died, so the relay only dropped the link
    // once it idled out). The host's next connection re-sends all three: the
    // peer gets the third, and nothing twice.
    let tenant = make_default_tenant();
    let session = SessionId(420);
    let key = SessionKey {
        tenant: rally_point_proto::control::TenantId(TENANT.to_owned()),
        session,
    };
    let TestRelay {
        addr, ca, sessions, ..
    } = start_relay(registry_for_one(&tenant));
    let endpoint = client_endpoint(&ca);

    let peer = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut peer_rx = spawn_control_reader(peer.connection().clone());
    let host = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let (mut host_send, _) = host.connection().open_bi().await.unwrap();
    wait_for_slots(&sessions, &key, 2).await;

    send_all(
        &mut host_send,
        [command(Some(0), 0x01), command(Some(1), 0x02)],
    )
    .await;
    assert_eq!(next_sequenced_lobby(&mut peer_rx).await, (0, Some(0), 0x01));
    assert_eq!(next_sequenced_lobby(&mut peer_rx).await, (0, Some(1), 0x02));

    drop_link(&host, &sessions, &key).await;
    let host_again = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let (mut again_send, _) = host_again.connection().open_bi().await.unwrap();
    send_all(
        &mut again_send,
        [
            command(Some(0), 0x01),
            command(Some(1), 0x02),
            command(Some(2), 0x03),
        ],
    )
    .await;
    assert_eq!(
        next_sequenced_lobby(&mut peer_rx).await,
        (0, Some(2), 0x03),
        "the re-send delivers exactly the command the relay never accepted",
    );
    assert_no_lobby(&mut peer_rx, "a re-sent command was delivered twice").await;

    // A member that dials in afterwards replays each command once.
    let late = connect_slot(&endpoint, addr, &tenant, session, SlotId(2)).await;
    let mut late_rx = spawn_control_reader(late.connection().clone());
    for (seq, byte) in [(0, 0x01), (1, 0x02), (2, 0x03)] {
        assert_eq!(
            next_sequenced_lobby(&mut late_rx).await,
            (0, Some(seq), byte)
        );
    }
    assert_no_lobby(&mut late_rx, "the replay carried a re-sent command twice").await;
}

#[tokio::test]
async fn a_re_send_spends_no_rate_budget_on_commands_already_delivered() {
    // The host is one command short of its burst when its link dies with that
    // command unaccepted. Its re-send repeats everything first; were the
    // repeats charged, they would spend the last token and the one command the
    // re-send exists for would be rate-dropped.
    let tenant = make_default_tenant();
    let session = SessionId(421);
    let key = SessionKey {
        tenant: rally_point_proto::control::TenantId(TENANT.to_owned()),
        session,
    };
    let TestRelay {
        addr, ca, sessions, ..
    } = start_relay(registry_for_one(&tenant));
    let endpoint = client_endpoint(&ca);

    let peer = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut peer_rx = spawn_control_reader(peer.connection().clone());
    let host = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let (mut host_send, _) = host.connection().open_bi().await.unwrap();
    wait_for_slots(&sessions, &key, 2).await;

    let delivered = u64::from(LOBBY.rate_burst - 1);
    send_all(
        &mut host_send,
        (0..delivered).map(|seq| command(Some(seq), seq as u8)),
    )
    .await;
    for seq in 0..delivered {
        assert_eq!(
            next_sequenced_lobby(&mut peer_rx).await,
            (0, Some(seq), seq as u8)
        );
    }

    drop_link(&host, &sessions, &key).await;
    let host_again = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let (mut again_send, _) = host_again.connection().open_bi().await.unwrap();
    send_all(
        &mut again_send,
        (0..=delivered).map(|seq| command(Some(seq), seq as u8)),
    )
    .await;
    assert_eq!(
        next_sequenced_lobby(&mut peer_rx).await,
        (0, Some(delivered), delivered as u8)
    );
    assert_no_lobby(&mut peer_rx, "a re-sent command was delivered twice").await;
}

#[tokio::test]
async fn an_older_clients_unsequenced_commands_are_all_forwarded() {
    // No seq, no identity: two byte-identical commands are two commands, as
    // they were before the seq existed.
    let tenant = make_default_tenant();
    let session = SessionId(422);
    let key = SessionKey {
        tenant: rally_point_proto::control::TenantId(TENANT.to_owned()),
        session,
    };
    let TestRelay {
        addr, ca, sessions, ..
    } = start_relay(registry_for_one(&tenant));
    let endpoint = client_endpoint(&ca);

    let peer = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut peer_rx = spawn_control_reader(peer.connection().clone());
    let host = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let (mut host_send, _) = host.connection().open_bi().await.unwrap();
    wait_for_slots(&sessions, &key, 2).await;

    send_all(&mut host_send, [command(None, 0x07), command(None, 0x07)]).await;
    assert_eq!(next_sequenced_lobby(&mut peer_rx).await, (0, None, 0x07));
    assert_eq!(next_sequenced_lobby(&mut peer_rx).await, (0, None, 0x07));
}
