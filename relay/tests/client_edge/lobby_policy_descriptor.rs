//! Lobby commands that arrive before a coordinator-managed relay has its descriptor.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::close_codes;
use rally_point_proto::control::{AllowedLobbyCommand, LobbyPolicy, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::LobbyCommand;
use rally_point_relay::consensus::RelayNotice;
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh::control::MeshControl;
use rally_point_relay::routing;
use rally_point_transport::control::{
    ControlInbound, send_control_game_started, send_control_leave_intent, send_control_lobby,
    spawn_control_reader,
};
use rally_point_transport::noq::ConnectionError;

fn key(session: SessionId) -> SessionKey {
    SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    }
}

fn install_policy(control: &MeshControl, key: &SessionKey, allowed: Option<&[u8]>) {
    let mut desc = descriptor(TENANT, key.session);
    desc.expected_slots = (0..4).map(SlotId).collect();
    desc.lobby_policy = allowed.map(|payload| LobbyPolicy {
        allowed: vec![AllowedLobbyCommand {
            slot: SlotId(0),
            payload: payload.to_vec(),
        }],
    });
    control.apply_descriptor(&desc);
}

async fn send_lobby(send: &mut rally_point_transport::noq::SendStream, payload: &[u8]) {
    send_control_lobby(
        send,
        LobbyCommand {
            slot: 99,
            payload: payload.to_vec().into(),
        },
    )
    .await
    .unwrap();
}

async fn next_lobby(reader: &mut tokio::sync::mpsc::Receiver<ControlInbound>) -> Vec<u8> {
    match recv_meaningful(reader).await {
        ControlInbound::Lobby(command) => {
            assert_eq!(command.slot, 0, "the author is the authenticated slot");
            command.payload.to_vec()
        }
        other => panic!("expected lobby command, got {other:?}"),
    }
}

#[tokio::test]
async fn invalid_pre_descriptor_command_waits_then_evicts_without_delivery_or_replay() {
    let tenant = make_default_tenant();
    let session = SessionId(901);
    let key = key(session);
    let mesh = rally_point_relay::mesh::MeshState::default();
    mesh.session.provisional_turns.arm();
    let makers = mesh.session.decision_makers.clone();
    let (notice_tx, mut notices) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);
    let TestRelay {
        addr,
        ca,
        sessions,
        mesh: relay_mesh,
    } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let control = MeshControl::new(RelayId(1), &relay_mesh, sessions.clone());
    let endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_lobby(&mut send0, b"forbidden").await;
    send_lobby(&mut send0, b"allowed").await;
    send_control_game_started(&mut send0).await.unwrap();

    assert!(
        tokio::time::timeout(Duration::from_millis(250), next_lobby(&mut reader1))
            .await
            .is_err(),
        "an unvalidated command must not reach another local member",
    );
    assert!(slot0.connection().close_reason().is_none());
    assert_no_event_notice(
        &mut notices,
        Duration::from_millis(50),
        "no violation is reported before the policy is known",
    )
    .await;

    install_policy(&control, &key, Some(b"allowed"));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), slot0.connection().closed())
            .await
            .expect("the pending command is reconsidered"),
        ConnectionError::ApplicationClosed(ref close)
            if close.error_code == close_codes::LOBBY_VIOLATION.into()
    ));
    let notice = recv_event_notice(&mut notices).await;
    assert!(
        matches!(notice, RelayNotice::LobbyViolation(ref violation) if violation.slot == SlotId(0))
    );
    assert_no_event_notice(
        &mut notices,
        Duration::from_millis(100),
        "the command reports exactly one violation",
    )
    .await;
    let slot2 = connect_slot(&endpoint, addr, &tenant, session, SlotId(2)).await;
    let mut reader2 = spawn_control_reader(slot2.connection().clone());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next_lobby(&mut reader1))
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next_lobby(&mut reader2))
            .await
            .is_err()
    );

    wait_until("the evicted slot leaves the roster", || {
        !routing::live_slots(&sessions)
            .iter()
            .any(|(live_key, slots)| live_key == &key && slots.contains(&SlotId(0)))
    })
    .await;
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(0), client_key.public);
    let redial = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let _ = handshake(&redial, &token, &client_key, &[]).await;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), redial.closed())
            .await
            .expect("the evicted slot's redial is refused"),
        ConnectionError::ApplicationClosed(ref close)
            if close.error_code == close_codes::SLOT_DEPARTED.into()
    ));
}

#[tokio::test]
async fn honest_pre_descriptor_init_releases_once_before_later_game_started() {
    let tenant = make_default_tenant();
    let session = SessionId(902);
    let key = key(session);
    let mesh = rally_point_relay::mesh::MeshState::default();
    mesh.session.provisional_turns.arm();
    let makers = mesh.session.decision_makers.clone();
    let (notice_tx, mut notices) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);
    let TestRelay {
        addr,
        ca,
        sessions,
        mesh: relay_mesh,
    } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let control = MeshControl::new(RelayId(1), &relay_mesh, sessions);
    let endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_lobby(&mut send0, b"init").await;
    send_control_game_started(&mut send0).await.unwrap();

    assert!(
        tokio::time::timeout(Duration::from_millis(250), next_lobby(&mut reader1))
            .await
            .is_err()
    );
    assert_no_event_notice(
        &mut notices,
        Duration::from_millis(50),
        "a later game-start report cannot overtake the held init",
    )
    .await;
    install_policy(&control, &key, Some(b"init"));
    assert_eq!(next_lobby(&mut reader1).await, b"init".to_vec());
    assert!(matches!(
        recv_event_notice(&mut notices).await,
        RelayNotice::SlotStarted(_)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next_lobby(&mut reader1))
            .await
            .is_err()
    );
    let slot2 = connect_slot(&endpoint, addr, &tenant, session, SlotId(2)).await;
    let mut reader2 = spawn_control_reader(slot2.connection().clone());
    assert_eq!(next_lobby(&mut reader2).await, b"init".to_vec());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next_lobby(&mut reader2))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn pre_descriptor_init_releases_under_a_descriptor_without_a_policy() {
    let tenant = make_default_tenant();
    let session = SessionId(903);
    let key = key(session);
    let mesh = rally_point_relay::mesh::MeshState::default();
    mesh.session.provisional_turns.arm();
    let TestRelay {
        addr,
        ca,
        sessions,
        mesh: relay_mesh,
    } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let control = MeshControl::new(RelayId(1), &relay_mesh, sessions);
    let endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_lobby(&mut send0, b"ordinary-init").await;
    assert!(
        tokio::time::timeout(Duration::from_millis(250), next_lobby(&mut reader1))
            .await
            .is_err()
    );
    install_policy(&control, &key, None);
    assert_eq!(next_lobby(&mut reader1).await, b"ordinary-init".to_vec());
}

#[tokio::test]
async fn game_started_before_pre_descriptor_mismatch_drops_without_penalty() {
    let tenant = make_default_tenant();
    let session = SessionId(904);
    let key = key(session);
    let mesh = rally_point_relay::mesh::MeshState::default();
    mesh.session.provisional_turns.arm();
    let makers = mesh.session.decision_makers.clone();
    let (notice_tx, mut notices) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);
    let TestRelay {
        addr,
        ca,
        sessions,
        mesh: relay_mesh,
    } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let control = MeshControl::new(RelayId(1), &relay_mesh, sessions);
    let endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_control_game_started(&mut send0).await.unwrap();
    assert_no_event_notice(
        &mut notices,
        Duration::from_millis(50),
        "the start report awaits the descriptor",
    )
    .await;
    send_lobby(&mut send0, b"wrong-after-start").await;
    assert!(
        tokio::time::timeout(Duration::from_millis(250), next_lobby(&mut reader1))
            .await
            .is_err()
    );
    install_policy(&control, &key, Some(b"allowed"));
    assert!(matches!(
        recv_event_notice(&mut notices).await,
        RelayNotice::SlotStarted(_)
    ));
    send_lobby(&mut send0, b"allowed").await;
    assert_eq!(next_lobby(&mut reader1).await, b"allowed".to_vec());
    assert!(slot0.connection().close_reason().is_none());
    assert_no_event_notice(
        &mut notices,
        Duration::from_millis(100),
        "a command after GameStarted must not be reported as a violation",
    )
    .await;
}

#[tokio::test]
async fn disconnected_honest_init_is_delivered_when_descriptor_arrives() {
    let tenant = make_default_tenant();
    let session = SessionId(905);
    let key = key(session);
    let mesh = rally_point_relay::mesh::MeshState::default();
    mesh.session.provisional_turns.arm();
    let TestRelay {
        addr,
        ca,
        sessions,
        mesh: relay_mesh,
    } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let control = MeshControl::new(RelayId(1), &relay_mesh, sessions);
    let endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_lobby(&mut send0, b"init").await;
    send0.finish().unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), slot0.connection().closed()).await.unwrap(),
        ConnectionError::ApplicationClosed(ref close)
            if close.error_code == close_codes::CONTROL_STREAM_LOST.into()
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next_lobby(&mut reader1))
            .await
            .is_err()
    );
    install_policy(&control, &key, Some(b"init"));
    assert_eq!(next_lobby(&mut reader1).await, b"init".to_vec());
    let slot2 = connect_slot(&endpoint, addr, &tenant, session, SlotId(2)).await;
    let mut reader2 = spawn_control_reader(slot2.connection().clone());
    assert_eq!(next_lobby(&mut reader2).await, b"init".to_vec());
}

#[tokio::test]
async fn disconnected_bad_init_is_reported_and_evicted_on_descriptor() {
    let tenant = make_default_tenant();
    let session = SessionId(906);
    let key = key(session);
    let mesh = rally_point_relay::mesh::MeshState::default();
    mesh.session.provisional_turns.arm();
    let makers = mesh.session.decision_makers.clone();
    let (notice_tx, mut notices) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);
    let TestRelay {
        addr,
        ca,
        sessions,
        mesh: relay_mesh,
    } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let control = MeshControl::new(RelayId(1), &relay_mesh, sessions.clone());
    let endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_lobby(&mut send0, b"bad").await;
    send0.finish().unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), slot0.connection().closed()).await.unwrap(),
        ConnectionError::ApplicationClosed(ref close)
            if close.error_code == close_codes::CONTROL_STREAM_LOST.into()
    ));
    wait_until("the only slot leaves the roster", || {
        !routing::live_slots(&sessions)
            .iter()
            .any(|(live_key, slots)| live_key == &key && slots.contains(&SlotId(0)))
    })
    .await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next_lobby(&mut reader1))
            .await
            .is_err()
    );
    install_policy(&control, &key, Some(b"init"));
    let mut violation_seen = false;
    for _ in 0..3 {
        let notice = recv_event_notice(&mut notices).await;
        if matches!(notice, RelayNotice::LobbyViolation(ref violation) if violation.slot == SlotId(0))
        {
            violation_seen = true;
            break;
        }
    }
    assert!(violation_seen, "the disconnected offender is attributed");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next_lobby(&mut reader1))
            .await
            .is_err()
    );
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(0), client_key.public);
    let redial = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let _ = handshake(&redial, &token, &client_key, &[]).await;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), redial.closed()).await.unwrap(),
        ConnectionError::ApplicationClosed(ref close)
            if close.error_code == close_codes::SLOT_DEPARTED.into()
    ));
}

#[tokio::test]
async fn standalone_relay_without_descriptor_forwards_lobby_commands() {
    let tenant = make_default_tenant();
    let session = SessionId(907);
    let TestRelay { addr, ca, .. } = start_relay(registry_for_one(&tenant));
    let endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_lobby(&mut send0, b"standalone").await;
    assert_eq!(next_lobby(&mut reader1).await, b"standalone".to_vec());
    send_lobby(&mut send0, b"still-open").await;
    assert_eq!(next_lobby(&mut reader1).await, b"still-open".to_vec());
    assert!(slot0.connection().close_reason().is_none());
}

#[tokio::test]
async fn start_before_bad_lobby_then_clean_leave_is_not_a_violation() {
    let tenant = make_default_tenant();
    let session = SessionId(908);
    let key = key(session);
    let mesh = rally_point_relay::mesh::MeshState::default();
    mesh.session.provisional_turns.arm();
    let makers = mesh.session.decision_makers.clone();
    let (notice_tx, mut notices) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);
    let TestRelay {
        addr,
        ca,
        sessions,
        mesh: relay_mesh,
    } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let control = MeshControl::new(RelayId(1), &relay_mesh, sessions);
    let endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_control_game_started(&mut send0).await.unwrap();
    send_lobby(&mut send0, b"wrong-after-start").await;
    send_control_leave_intent(&mut send0).await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), slot0.connection().closed()).await.unwrap(),
        ConnectionError::ApplicationClosed(ref close)
            if close.error_code == close_codes::LEAVE_PROCESSED.into()
    ));
    install_policy(&control, &key, Some(b"init"));
    assert!(matches!(
        recv_event_notice(&mut notices).await,
        RelayNotice::SlotStarted(_)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next_lobby(&mut reader1))
            .await
            .is_err()
    );
    assert_no_event_notice(
        &mut notices,
        Duration::from_millis(100),
        "a lobby after GameStarted is not a violation",
    )
    .await;
}

#[tokio::test]
async fn pre_descriptor_flood_cannot_consume_another_slots_lobby_quota() {
    use rally_point_relay::observability::events::FlightEvent;

    let tenant = make_default_tenant();
    let session = SessionId(909);
    let key = key(session);
    let mesh = rally_point_relay::mesh::MeshState::default();
    mesh.session.provisional_turns.arm();
    let makers = mesh.session.decision_makers.clone();
    let (notice_tx, mut notices) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);
    let TestRelay {
        addr,
        ca,
        sessions,
        mesh: relay_mesh,
    } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let control = MeshControl::new(RelayId(1), &relay_mesh, sessions);
    let endpoint = client_endpoint(&ca);
    let host = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let attacker = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let witness = connect_slot(&endpoint, addr, &tenant, session, SlotId(2)).await;
    let mut reader = spawn_control_reader(witness.connection().clone());
    let (mut attack_send, _) = attacker.connection().open_bi().await.unwrap();
    // Five frames fit the transport cap and rate burst while filling 256 KiB.
    // The wire slot is forged by send_lobby; quotas must use the authenticated slot.
    for size in [60 * 1024, 60 * 1024, 60 * 1024, 60 * 1024, 16 * 1024] {
        send_lobby(&mut attack_send, &vec![0x44; size]).await;
    }
    send_control_game_started(&mut attack_send).await.unwrap();
    let start_received = |slot| {
        makers.flight_recorder().events(&key).iter().any(|record| {
            matches!(record.event, FlightEvent::SlotGameStarted { slot: author } if author == slot)
        })
    };
    // This marker follows the flood on the same stream, so the relay has
    // journaled every preceding command before the host sends its init.
    wait_until("attacker flood was journaled", || start_received(1)).await;
    let init = [0x48, 1, 2, 3, 4, 8, 8, 8, 8, 8, 8, 8, 8];
    let (mut host_send, _) = host.connection().open_bi().await.unwrap();
    send_lobby(&mut host_send, &init).await;
    send_control_game_started(&mut host_send).await.unwrap();
    wait_until("host init was handled", || {
        start_received(0)
            || relay_mesh
                .session
                .provisional_turns
                .slot_sealed(&key, SlotId(0))
    })
    .await;
    assert!(
        !relay_mesh
            .session
            .provisional_turns
            .slot_sealed(&key, SlotId(0)),
        "a peer's flood must not seal the honest host",
    );
    assert!(host.connection().close_reason().is_none());
    // No unvalidated bytes may reach the witness before the descriptor arrives.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next_lobby(&mut reader))
            .await
            .is_err()
    );

    install_policy(&control, &key, Some(&init));
    assert_eq!(next_lobby(&mut reader).await, init.to_vec());
    assert!(matches!(
        recv_event_notice(&mut notices).await,
        RelayNotice::LobbyViolation(ref violation) if violation.slot == SlotId(1)
    ));
    assert!(matches!(
        recv_event_notice(&mut notices).await,
        RelayNotice::SlotStarted(ref started) if started.slot == SlotId(0)
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), attacker.connection().closed()).await.unwrap(),
        ConnectionError::ApplicationClosed(ref close)
            if close.error_code == close_codes::LOBBY_VIOLATION.into()
    ));
    assert!(host.connection().close_reason().is_none());
    let late = connect_slot(&endpoint, addr, &tenant, session, SlotId(3)).await;
    let mut late_reader = spawn_control_reader(late.connection().clone());
    assert_eq!(next_lobby(&mut late_reader).await, init.to_vec());
    assert_no_event_notice(
        &mut notices,
        Duration::from_millis(100),
        "only the flooder is blamed",
    )
    .await;
}
