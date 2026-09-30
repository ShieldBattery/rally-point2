//! The descriptor lobby policy at the actual authenticated client edge.

use std::collections::HashMap;
use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::close_codes;
use rally_point_proto::control::{AllowedLobbyCommand, LobbyPolicy, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::LobbyCommand;
use rally_point_relay::consensus::{Authority, MakerSync, RelayNotice};
use rally_point_relay::key::SessionKey;
use rally_point_transport::control::{ControlInbound, send_control_lobby, spawn_control_reader};
use rally_point_transport::noq::ConnectionError;

fn policy(entries: &[(u8, &[u8])]) -> LobbyPolicy {
    LobbyPolicy {
        allowed: entries
            .iter()
            .map(|(slot, payload)| AllowedLobbyCommand {
                slot: SlotId(*slot),
                payload: payload.to_vec(),
            })
            .collect(),
    }
}

fn configure_policy(
    makers: &rally_point_relay::consensus::DecisionMakers,
    key: &SessionKey,
    allowed: &[(u8, &[u8])],
) {
    let _ = makers.sync_maker(
        key,
        MakerSync {
            lobby_policy: Some(policy(allowed)),
            ..MakerSync::new(
                rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
                Authority::SelfRelay,
            )
        },
    );
}

async fn next_lobby(reader: &mut tokio::sync::mpsc::Receiver<ControlInbound>) -> (u32, Vec<u8>) {
    match recv_meaningful(reader).await {
        ControlInbound::Lobby(command) => (command.slot, command.payload.to_vec()),
        other => panic!("expected lobby command, got {other:?}"),
    }
}

#[tokio::test]
async fn allowed_lobby_command_forwards_and_replays_from_the_authenticated_slot() {
    let tenant = make_default_tenant();
    let session = SessionId(401);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let mesh = rally_point_relay::mesh::MeshState::default();
    configure_policy(&mesh.session.decision_makers, &key, &[(0, b"allow")]);
    let TestRelay { addr, ca, .. } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let endpoint = client_endpoint(&ca);

    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_control_lobby(
        &mut send0,
        LobbyCommand {
            slot: 99,
            payload: b"allow".to_vec().into(),
        },
    )
    .await
    .unwrap();

    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    assert_eq!(next_lobby(&mut reader1).await, (0, b"allow".to_vec()));
}

#[tokio::test]
async fn pre_start_lobby_mismatch_is_not_delivered_reports_and_refuses_redial() {
    let tenant = make_default_tenant();
    let session = SessionId(402);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let mesh = rally_point_relay::mesh::MeshState::default();
    let makers = mesh.session.decision_makers.clone();
    configure_policy(&makers, &key, &[(1, b"wrong-slot"), (0, b"allowed")]);
    makers.set_session_refs(
        &key,
        Some("game-402".to_owned()),
        HashMap::from([(SlotId(0), "user-0".to_owned())]),
    );
    let (notice_tx, mut notices) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);
    let TestRelay { addr, ca, .. } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let endpoint = client_endpoint(&ca);

    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_control_lobby(
        &mut send0,
        LobbyCommand {
            slot: 0,
            payload: b"wrong-slot".to_vec().into(),
        },
    )
    .await
    .unwrap();

    match slot0.connection().closed().await {
        ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code, close_codes::LOBBY_VIOLATION.into())
        }
        other => panic!("expected lobby-policy close, got {other:?}"),
    }
    let notice = recv_event_notice(&mut notices).await;
    let RelayNotice::LobbyViolation(notice) = notice else {
        panic!("expected lobby violation, got {notice:?}")
    };
    assert_eq!(notice.slot, SlotId(0));
    assert!(
        tokio::time::timeout(Duration::from_millis(150), next_lobby(&mut reader1))
            .await
            .is_err(),
        "wrong authenticated slot must not reach local fan-out or the replay log",
    );
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(0), client_key.public);
    let redial = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let _ = handshake(&redial, &token, &client_key, &[]).await;
    assert!(
        matches!(redial.closed().await, ConnectionError::ApplicationClosed(_)),
        "eviction refuses a redial"
    );
}

#[tokio::test]
async fn post_start_mismatch_is_dropped_and_no_policy_still_forwards() {
    let tenant = make_default_tenant();
    let session = SessionId(403);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let mesh = rally_point_relay::mesh::MeshState::default();
    let makers = mesh.session.decision_makers.clone();
    configure_policy(&makers, &key, &[(0, b"allowed")]);
    makers.note_slot_started(&key, SlotId(0));
    let TestRelay { addr, ca, .. } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_control_lobby(
        &mut send0,
        LobbyCommand {
            slot: 0,
            payload: b"wrong".to_vec().into(),
        },
    )
    .await
    .unwrap();
    assert!(
        slot0.connection().close_reason().is_none(),
        "post-start mismatch must not evict"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(150), next_lobby(&mut reader1))
            .await
            .is_err()
    );

    let session = SessionId(404);
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_control_lobby(
        &mut send0,
        LobbyCommand {
            slot: 99,
            payload: b"legacy".to_vec().into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(next_lobby(&mut reader1).await, (0, b"legacy".to_vec()));
}

#[tokio::test]
async fn wrong_lobby_bytes_are_blocked_before_delivery_or_replay() {
    let tenant = make_default_tenant();
    let session = SessionId(405);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let mesh = rally_point_relay::mesh::MeshState::default();
    configure_policy(&mesh.session.decision_makers, &key, &[(0, b"allowed")]);
    let TestRelay { addr, ca, .. } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let endpoint = client_endpoint(&ca);
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    let (mut send0, _) = slot0.connection().open_bi().await.unwrap();
    send_control_lobby(
        &mut send0,
        LobbyCommand {
            slot: 0,
            payload: b"wrong-bytes".to_vec().into(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        slot0.connection().closed().await,
        ConnectionError::ApplicationClosed(ref close) if close.error_code == close_codes::LOBBY_VIOLATION.into()
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(150), next_lobby(&mut reader1))
            .await
            .is_err(),
        "bad bytes must not reach a recipient or become replay state",
    );
}
