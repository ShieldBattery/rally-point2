//! Desync- and result-webhook tests, combined: both are per-slot or
//! per-session facts a relay reports once, deduped by their own key shape
//! (`(tenant, session, sync_ordinal)` for desyncs, `(tenant, session, slot)`
//! for results), with the same notice-first correlation-id resolution as
//! departures. Desyncs additionally exercise the desync mark that pins a
//! session's flight-recorder retention class independent of webhook delivery.

use rally_point_proto::control::{DesyncNotice, ResultNotice};

use super::*;
use crate::lifecycle::Lifecycle;

// -- Desync webhooks --

/// A desync notice carrying its own gameId and a diverged slot with a ref, so
/// a webhook delivers without depending on the coordinator's stored session.
fn desync(session: SessionId, sync_ordinal: u64, no_majority: bool) -> DesyncNotice {
    DesyncNotice {
        tenant: TenantId("sb-test".to_owned()),
        session,
        sync_ordinal,
        game_frame: Some(4242),
        detected_at_ms: 1_700_000_000_000,
        no_majority,
        diverged: if no_majority {
            vec![]
        } else {
            vec![DivergedSlot {
                slot: SlotId(2),
                external_ref: Some("sb-user-diverged".to_owned()),
            }]
        },
        external_id: Some("game-desync".to_owned()),
    }
}

#[tokio::test]
async fn a_desync_posts_one_signed_webhook_and_dedups_by_sync_ordinal() {
    let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
    // A tenant enrolled (for the signing key) but no session created this
    // lifetime: the notice's self-stamped refs carry the webhook.
    let reg = registry::new_registry();
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = SessionSetup::new(reg, tenants);
    tenant::set_notify(
        setup.tenants(),
        &TenantId("sb-test".to_owned()),
        Some(NotifyConfig { url }),
    );
    let dedup = new_dedup();
    let lifecycle = Lifecycle::new(setup.clone());

    // Two at-least-once redeliveries of the same event webhook once.
    handle_desync(
        &setup,
        &dedup.desyncs,
        &dedup.desync_marks,
        &lifecycle,
        desync(SessionId(7), 91, false),
    );
    handle_desync(
        &setup,
        &dedup.desyncs,
        &dedup.desync_marks,
        &lifecycle,
        desync(SessionId(7), 91, false),
    );

    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("a desync webhook is delivered")
        .expect("the receiver got it");
    assert_signed(&setup, "sb-test", &got);
    assert_eq!(got.body["event"], "desync");
    assert_eq!(got.body["tenant"], "sb-test");
    assert_eq!(got.body["session"], 7);
    assert_eq!(got.body["externalId"], "game-desync");
    assert_eq!(got.body["syncOrdinal"], 91);
    assert_eq!(got.body["gameFrame"], 4242);
    assert_eq!(got.body["detectedAtMs"], 1_700_000_000_000u64);
    assert_eq!(got.body["noMajority"], false);
    assert_eq!(got.body["diverged"][0]["slot"], 2);
    assert_eq!(got.body["diverged"][0]["externalRef"], "sb-user-diverged");

    assert!(
        timeout(Duration::from_millis(400), rx.recv())
            .await
            .is_err(),
        "a redelivery of the same (tenant, session, sync_ordinal) webhooks once",
    );
}

#[tokio::test]
async fn a_no_majority_desync_omits_absent_optionals_and_carries_an_empty_diverged() {
    let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
    let reg = registry::new_registry();
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = SessionSetup::new(reg, tenants);
    tenant::set_notify(
        setup.tenants(),
        &TenantId("sb-test".to_owned()),
        Some(NotifyConfig { url }),
    );
    let dedup = new_dedup();
    let lifecycle = Lifecycle::new(setup.clone());

    // A no-majority desync with no game frame — gameFrame must be omitted, not
    // null, and diverged is an empty array.
    let mut notice = desync(SessionId(8), 5, true);
    notice.game_frame = None;
    handle_desync(
        &setup,
        &dedup.desyncs,
        &dedup.desync_marks,
        &lifecycle,
        notice,
    );

    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("a desync webhook is delivered")
        .unwrap();
    assert_eq!(got.body["event"], "desync");
    assert_eq!(got.body["noMajority"], true);
    assert_eq!(got.body["diverged"].as_array().unwrap().len(), 0);
    assert!(
        got.body.get("gameFrame").is_none(),
        "an absent game frame is omitted, not sent as null",
    );
}

#[tokio::test]
async fn a_desync_with_no_gameid_from_any_source_is_a_silent_no_op() {
    let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
    let (setup, session) = setup_with_session(None, None);
    tenant::set_notify(
        setup.tenants(),
        &TenantId("sb-test".to_owned()),
        Some(NotifyConfig { url }),
    );
    let dedup = new_dedup();
    let lifecycle = Lifecycle::new(setup.clone());

    // Neither the notice nor the stored session has a gameId.
    let mut notice = desync(session, 1, false);
    notice.external_id = None;
    let tenant = notice.tenant.clone();
    handle_desync(
        &setup,
        &dedup.desyncs,
        &dedup.desync_marks,
        &lifecycle,
        notice,
    );

    assert!(
        timeout(Duration::from_millis(400), rx.recv())
            .await
            .is_err(),
        "no gameId from the notice or the stored session -> dropped",
    );

    // Dropped, but not orphaned: the dedup entry this call inserted has a
    // lifecycle state to eventually retire it, even though no webhook was
    // ever enqueued for this session.
    assert!(
        dedup.desyncs.lock().contains(&(tenant.clone(), session, 1)),
        "the dedup entry was recorded",
    );
    assert!(
        lifecycle.contains_state(&tenant, session),
        "a lifecycle state exists to eventually retire the dedup entry above -- \
         without it, an unresolvable desync notice would leak its dedup entry \
         for the life of the process",
    );
    // The desync mark is recorded regardless of the dropped webhook: the flight
    // sink still pins this session's recordings.
    assert!(
        is_session_desynced(
            &dedup.desync_marks,
            &tenant,
            session,
            std::time::Instant::now(),
        ),
        "the desync fact is marked even when no webhook was delivered",
    );
}

#[test]
fn a_desync_mark_is_read_back_and_expires_after_its_ttl() {
    let marks: DesyncMarks = Arc::new(Mutex::new(HashMap::new()));
    let tenant = TenantId("sb-test".to_owned());
    let session = SessionId(7);
    // Explicitly std's clock: the desync marks are stamped with it, not tokio's
    // test clock, which this module's other tests bring into scope as `Instant`.
    let now = std::time::Instant::now();

    // Unmarked reads as not desynced; a mark reads back true.
    assert!(!is_session_desynced(&marks, &tenant, session, now));
    mark_session_desynced(&marks, tenant.clone(), session, now);
    assert!(is_session_desynced(&marks, &tenant, session, now));

    // A read past the TTL treats the mark as absent and prunes it in the pass.
    let later = now + DESYNC_MARK_TTL + Duration::from_secs(1);
    assert!(!is_session_desynced(&marks, &tenant, session, later));
    assert!(
        marks.lock().is_empty(),
        "an expired mark is pruned, not merely read as absent",
    );
}

// -- Result webhooks --

/// A result notice carrying its own gameId and player ref plus opaque bytes,
/// so a webhook delivers without depending on the coordinator's stored
/// session. `refs_from_notice` controls whether the correlation ids ride the
/// notice (self-describing) or are left to the stored-session fallback.
fn result(session: SessionId, slot: u8, refs_from_notice: bool) -> ResultNotice {
    ResultNotice {
        tenant: TenantId("sb-test".to_owned()),
        session,
        slot: SlotId(slot),
        external_id: refs_from_notice.then(|| "game-result".to_owned()),
        external_ref: refs_from_notice.then(|| "sb-user-result".to_owned()),
        payload: vec![0x01, 0x02, 0x03, 0x04],
        arrival_ms: 1_700_000_000_123,
        session_frame: Some(4200),
        slot_frame: Some(4242),
    }
}

#[tokio::test]
async fn a_result_posts_one_signed_webhook_with_base64_payload_and_dedups_by_slot() {
    let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
    // A tenant enrolled (for the signing key) but no session created this
    // lifetime: the notice's self-stamped refs carry the webhook.
    let reg = registry::new_registry();
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = SessionSetup::new(reg, tenants);
    tenant::set_notify(
        setup.tenants(),
        &TenantId("sb-test".to_owned()),
        Some(NotifyConfig { url }),
    );
    let dedup = new_dedup();
    let lifecycle = Lifecycle::new(setup.clone());

    // Two at-least-once redeliveries of the same slot's report webhook once.
    handle_result(
        &setup,
        &dedup.results,
        &lifecycle,
        result(SessionId(7), 1, true),
    );
    handle_result(
        &setup,
        &dedup.results,
        &lifecycle,
        result(SessionId(7), 1, true),
    );

    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("a result webhook is delivered")
        .expect("the receiver got it");
    assert_signed(&setup, "sb-test", &got);
    assert_eq!(got.body["event"], "result");
    assert_eq!(got.body["tenant"], "sb-test");
    assert_eq!(got.body["session"], 7);
    assert_eq!(got.body["externalId"], "game-result");
    assert_eq!(got.body["slot"], 1);
    assert_eq!(got.body["externalRef"], "sb-user-result");
    // The opaque payload rides as standard base64 of the raw bytes.
    assert_eq!(
        got.body["payload"],
        base64::engine::general_purpose::STANDARD.encode([0x01, 0x02, 0x03, 0x04]),
    );
    assert_eq!(got.body["arrivalMs"], 1_700_000_000_123u64);
    assert_eq!(got.body["sessionFrame"], 4200);
    assert_eq!(got.body["slotFrame"], 4242);

    assert!(
        timeout(Duration::from_millis(400), rx.recv())
            .await
            .is_err(),
        "a redelivery of the same (tenant, session, slot) webhooks once",
    );
}

#[tokio::test]
async fn a_result_with_no_notice_refs_falls_back_to_the_stored_session() {
    // The notice carries no correlation ids of its own; the coordinator's
    // stored session (from create_session) supplies both the gameId and the
    // player ref — the refs-fallback path.
    let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
    let (setup, session) = setup_with_session(Some("game-stored"), Some("sb-user-stored"));
    tenant::set_notify(
        setup.tenants(),
        &TenantId("sb-test".to_owned()),
        Some(NotifyConfig { url }),
    );
    let dedup = new_dedup();
    let lifecycle = Lifecycle::new(setup.clone());

    handle_result(
        &setup,
        &dedup.results,
        &lifecycle,
        result(session, 0, false),
    );

    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("a result webhook is delivered from the stored session refs")
        .unwrap();
    assert_eq!(got.body["externalId"], "game-stored");
    assert_eq!(got.body["externalRef"], "sb-user-stored");
}

#[tokio::test]
async fn a_result_with_no_gameid_from_any_source_is_a_silent_no_op() {
    let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
    let (setup, session) = setup_with_session(None, None);
    tenant::set_notify(
        setup.tenants(),
        &TenantId("sb-test".to_owned()),
        Some(NotifyConfig { url }),
    );
    let dedup = new_dedup();
    let lifecycle = Lifecycle::new(setup.clone());

    // Neither the notice nor the stored session has a gameId.
    handle_result(
        &setup,
        &dedup.results,
        &lifecycle,
        result(session, 0, false),
    );

    assert!(
        timeout(Duration::from_millis(400), rx.recv())
            .await
            .is_err(),
        "no gameId from the notice or the stored session -> dropped",
    );
}
