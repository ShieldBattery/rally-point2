//! Every notice kind, one table: each is reported through the single ingest
//! entry point and must webhook exactly once per event, however many times the
//! relay resends it.
//!
//! The kinds differ here only in their payload — the dedup key shape, the
//! resolution, the ordering and the delivery are all one implementation — so
//! this is the one place that asserts the shared behavior for all six. What is
//! genuinely per kind (the body a consumer parses, and the correlation-id
//! fallbacks) lives in the topic files beside this one.

use rally_point_proto::control::{
    DepartureNotice, DesyncNotice, DivergedSlot, ResultNotice, SessionStartedNotice,
    SlotConnectedNotice, SlotStartedNotice,
};

use super::*;

/// One self-describing notice per kind for `session`, paired with the `event`
/// discriminator its webhook body must carry. Each carries its own gameId, so
/// none of them depends on the coordinator holding a session record.
fn every_kind(session: SessionId) -> Vec<(&'static str, SessionNotice)> {
    let tenant = TenantId(TEST_TENANT.to_owned());
    vec![
        (
            "departure",
            SessionNotice::Departure(DepartureNotice {
                finalized: false,
                tenant: tenant.clone(),
                session,
                slot: SlotId(0),
                kind: DepartureKind::Dropped,
                reason: 0x4000_0006,
                leave_seq: 1,
                external_id: Some("game-1".to_owned()),
                external_ref: Some("sb-user-0".to_owned()),
                result: None,
                final_turn_count: None,
            }),
        ),
        (
            "desync",
            SessionNotice::Desync(DesyncNotice {
                tenant: tenant.clone(),
                session,
                sync_ordinal: 91,
                game_frame: Some(4242),
                detected_at_ms: 1_700_000_000_000,
                no_majority: false,
                diverged: vec![DivergedSlot {
                    slot: SlotId(2),
                    external_ref: Some("sb-user-diverged".to_owned()),
                }],
                external_id: Some("game-1".to_owned()),
            }),
        ),
        (
            "result",
            SessionNotice::Result(ResultNotice {
                tenant: tenant.clone(),
                session,
                slot: SlotId(1),
                external_id: Some("game-1".to_owned()),
                external_ref: Some("sb-user-1".to_owned()),
                payload: vec![0x01, 0x02, 0x03, 0x04],
                arrival_ms: 1_700_000_000_123,
                session_frame: Some(4200),
                slot_frame: Some(4242),
            }),
        ),
        (
            "slotConnected",
            SessionNotice::SlotConnected(SlotConnectedNotice {
                tenant: tenant.clone(),
                session,
                slot: SlotId(0),
                external_id: Some("game-1".to_owned()),
                external_ref: Some("sb-user-0".to_owned()),
                resumed: false,
                connected_at_ms: 1_700_000_000_000,
            }),
        ),
        (
            "sessionStarted",
            SessionNotice::SessionStarted(SessionStartedNotice {
                tenant: tenant.clone(),
                session,
                external_id: Some("game-1".to_owned()),
                started_at_ms: 1_700_000_000_000,
                initial_buffer_turns: Some(6),
            }),
        ),
        (
            "slotStarted",
            SessionNotice::SlotStarted(SlotStartedNotice {
                tenant,
                session,
                slot: SlotId(0),
                external_id: Some("game-1".to_owned()),
                external_ref: Some("sb-user-0".to_owned()),
                arrival_ms: 1_700_000_000_123,
                session_frame: Some(1),
                slot_frame: Some(1),
            }),
        ),
    ]
}

#[tokio::test]
async fn every_notice_kind_webhooks_once_per_event() {
    // A relay resends an unacked notice across a reconnect, and for a departure
    // every serving relay reports the same leave independently — either way the
    // tenant must see the event once. A fresh receiver and lifecycle per kind, so
    // one kind's delivery can never be read as another's.
    for (event, notice) in every_kind(SessionId(7)) {
        let (url, mut rx) = WebhookReceiver::default().spawn().await;
        let setup = setup_without_session(url);
        let lifecycle = Lifecycle::new(setup.clone());

        report(&lifecycle, notice.clone());
        report(&lifecycle, notice);

        let got = signed_webhook(&setup, &mut rx).await;
        assert_eq!(
            got.body["event"], event,
            "the delivered webhook names its own kind",
        );
        no_further_webhook(&mut rx, &format!("a resent {event} webhooks exactly once")).await;
    }
}

#[tokio::test]
async fn a_notice_from_a_relay_outside_the_serving_set_reaches_nothing() {
    // The reporter authorization runs inside the same entry point, ahead of
    // everything else: a relay that does not serve the session claims no dedup
    // entry and enqueues nothing, so the tenant's key never signs its bytes.
    let (url, mut rx) = WebhookReceiver::default().spawn().await;
    let (setup, session) = SessionFixture {
        players: vec![PlayerSpec {
            slot: 0,
            external_ref: Some("sb-user-0"),
            region: None,
        }],
        external_id: Some("game-1"),
        notify_url: Some(url),
        ..Default::default()
    }
    .build();
    let lifecycle = Lifecycle::new(setup.clone());

    for (event, notice) in every_kind(session) {
        // Relay 2 never served this session; relay 1 is its only serving relay.
        lifecycle.ingest_notice(RelayId(2), notice);
        no_further_webhook(
            &mut rx,
            &format!("a {event} from outside the serving set posts nothing"),
        )
        .await;
    }
}
