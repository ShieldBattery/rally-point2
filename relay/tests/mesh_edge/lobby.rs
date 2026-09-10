//! Reliable control-stream traffic across the mesh: lobby commands in order, the
//! replay a late-dialing peer gets, the per-slot rate cap, chat, and skins.

use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::{GameChat, LobbyCommand, PlayerSkin};
use rally_point_relay::routing::SessionKey;

use crate::helpers::*;

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
