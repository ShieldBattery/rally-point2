//! Lobby-violation webhooks use coordinator-owned correlation ids because they
//! attribute a deliberate policy breach to one player.

use rally_point_proto::control::LobbyViolationNotice;

use super::*;

fn notice(session: SessionId) -> LobbyViolationNotice {
    LobbyViolationNotice {
        tenant: TenantId(TEST_TENANT.to_owned()),
        session,
        slot: SlotId(0),
        arrival_ms: 1_700_000_000_123,
    }
}

#[tokio::test]
async fn a_lobby_violation_uses_authoritative_identity_and_dedups_retries() {
    let (url, mut rx) = WebhookReceiver::default().spawn().await;
    let (setup, session) = setup_with_session(Some("game-99"), Some("sb-user-7"));
    tenant::set_notify(
        setup.tenants(),
        &TenantId(TEST_TENANT.to_owned()),
        Some(NotifyConfig { url }),
    );
    let lifecycle = Lifecycle::new(setup.clone());

    report(&lifecycle, SessionNotice::LobbyViolation(notice(session)));
    report(&lifecycle, SessionNotice::LobbyViolation(notice(session)));

    let got = signed_webhook(&setup, &mut rx).await;
    assert_eq!(
        got.body,
        serde_json::json!({
            "event": "lobbyViolation",
            "tenant": TEST_TENANT,
            "session": session.0,
            "externalId": "game-99",
            "slot": 0,
            "externalRef": "sb-user-7",
            "arrivalMs": 1_700_000_000_123u64,
        }),
        "webhook identity comes from the coordinator session roster",
    );
    no_further_webhook(&mut rx, "a resent lobby violation posts exactly once").await;
}

#[tokio::test]
async fn a_serving_peer_cannot_report_another_homes_lobby_violation() {
    let (url, mut rx) = WebhookReceiver::default().spawn().await;
    let (setup, session) = SessionFixture {
        relays: vec![
            RelaySpec {
                id: 1,
                region: None,
            },
            RelaySpec {
                id: 2,
                region: Some("region-b"),
            },
        ],
        players: vec![
            PlayerSpec {
                slot: 0,
                external_ref: Some("sb-user-0"),
                region: None,
            },
            PlayerSpec {
                slot: 1,
                external_ref: Some("sb-user-1"),
                region: Some("region-b"),
            },
        ],
        external_id: Some("game-99"),
        notify_url: Some(url),
    }
    .build();
    let lifecycle = Lifecycle::new(setup.clone());

    lifecycle.ingest_notice(RelayId(2), SessionNotice::LobbyViolation(notice(session)));
    no_further_webhook(
        &mut rx,
        "a serving peer cannot attribute a violation to a slot it does not home",
    )
    .await;

    report(&lifecycle, SessionNotice::LobbyViolation(notice(session)));
    let got = signed_webhook(&setup, &mut rx).await;
    assert_eq!(got.body["externalRef"], "sb-user-0");
}
