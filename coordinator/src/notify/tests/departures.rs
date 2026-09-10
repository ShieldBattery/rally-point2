//! Departure-webhook tests: one webhook per `(tenant, session, slot)` leave,
//! deduped across redundant relay reports, with correlation ids resolved
//! notice-first then falling back to the stored session.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rally_point_proto::control::DepartureNotice;

use super::*;
use crate::lifecycle::Lifecycle;

/// A departure notice with no correlation ids of its own — the relay-predates-
/// the-field case, which relies entirely on the coordinator's stored session.
fn notice(session: SessionId, slot: u8, kind: DepartureKind, reason: u32) -> DepartureNotice {
    DepartureNotice {
        finalized: false,
        tenant: TenantId("sb-test".to_owned()),
        session,
        slot: SlotId(slot),
        kind,
        reason,
        leave_seq: 1,
        external_id: None,
        external_ref: None,
        result: None,
        final_turn_count: None,
    }
}

#[tokio::test]
async fn a_departure_posts_one_webhook_with_body_and_signature_and_dedups_relays() {
    let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
    let (setup, session) = setup_with_session(Some("game-99"), Some("sb-user-7"));
    tenant::set_notify(
        setup.tenants(),
        &TenantId("sb-test".to_owned()),
        Some(NotifyConfig { url }),
    );
    let dedup = new_dedup();
    let lifecycle = Lifecycle::new(setup.clone());

    // Two relays report the same departure; the coordinator must webhook once.
    handle_departure(
        &setup,
        &dedup.departures,
        &lifecycle,
        notice(session, 0, DepartureKind::Dropped, 0x4000_0006),
    );
    handle_departure(
        &setup,
        &dedup.departures,
        &lifecycle,
        notice(session, 0, DepartureKind::Dropped, 0x4000_0006),
    );

    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("a webhook is delivered")
        .expect("the receiver got it");

    assert_signed(&setup, "sb-test", &got);
    assert_eq!(got.body["event"], "departure");
    assert_eq!(got.body["tenant"], "sb-test");
    assert_eq!(got.body["session"], session.0);
    assert_eq!(got.body["externalId"], "game-99");
    assert_eq!(got.body["slot"], 0);
    assert_eq!(got.body["externalRef"], "sb-user-7");
    assert_eq!(got.body["kind"], "dropped");
    assert_eq!(got.body["reason"], 0x4000_0006u32);
    assert_eq!(got.body["leaveSeq"], 1);
    // This departure carried no embedded result, so the field is omitted.
    assert!(
        got.body.get("result").is_none(),
        "a departure with no embedded result omits the field, not null",
    );

    // No second webhook: the duplicate relay report was deduped.
    assert!(
        timeout(Duration::from_millis(400), rx.recv())
            .await
            .is_err(),
        "duplicate departures from multiple relays webhook exactly once",
    );
}

#[tokio::test]
async fn a_departure_embeds_a_base64_result_when_the_slot_reported_one() {
    // A departure that carries the slot's end-of-game result: the webhook
    // embeds it as a base64 payload plus the relay's arrival/frame stamps, so
    // one delivery is atomic terminal truth.
    let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
    let (setup, session) = setup_with_session(Some("game-99"), Some("sb-user-7"));
    tenant::set_notify(
        setup.tenants(),
        &TenantId("sb-test".to_owned()),
        Some(NotifyConfig { url }),
    );
    let dedup = new_dedup();
    let lifecycle = Lifecycle::new(setup.clone());

    let mut with_result = notice(session, 0, DepartureKind::Left, 3);
    with_result.result = Some(rally_point_proto::control::ResultEcho {
        payload: vec![0x01, 0x02, 0x03, 0x04],
        arrival_ms: 1_700_000_000_123,
        session_frame: Some(4200),
        slot_frame: Some(4242),
    });
    handle_departure(&setup, &dedup.departures, &lifecycle, with_result);

    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("a webhook is delivered")
        .unwrap();
    assert_signed(&setup, "sb-test", &got);
    assert_eq!(
        got.body["result"]["payload"],
        BASE64_STANDARD.encode([0x01, 0x02, 0x03, 0x04]),
    );
    assert_eq!(got.body["result"]["arrivalMs"], 1_700_000_000_123u64);
    assert_eq!(got.body["result"]["sessionFrame"], 4200);
    assert_eq!(got.body["result"]["slotFrame"], 4242);
}

#[tokio::test]
async fn a_clean_leave_is_classified_left_in_the_webhook() {
    let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
    // A gameId is present (so the departure isn't dropped for lacking one),
    // but no per-slot player ref — the webhook must still deliver, just
    // omitting `externalRef`.
    let (setup, session) = setup_with_session(Some("game-42"), None);
    tenant::set_notify(
        setup.tenants(),
        &TenantId("sb-test".to_owned()),
        Some(NotifyConfig { url }),
    );
    let dedup = new_dedup();
    let lifecycle = Lifecycle::new(setup.clone());

    handle_departure(
        &setup,
        &dedup.departures,
        &lifecycle,
        notice(session, 0, DepartureKind::Left, 3),
    );

    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("a webhook is delivered")
        .unwrap();
    assert_eq!(got.body["kind"], "left");
    assert_signed(&setup, "sb-test", &got);
    assert_eq!(got.body["externalId"], "game-42");
    // Absent correlation ids are omitted entirely, not sent as `null` — the
    // consumer validates them as optional *strings*, and a literal `null`
    // would fail that validation. `Value::index` on a missing key also
    // returns `Null`, so `.get(..).is_none()` is the check that actually
    // proves omission rather than passing either way.
    assert!(
        got.body.get("externalRef").is_none(),
        "no per-slot ref was stored, so it's omitted rather than sent as null",
    );
}

#[tokio::test]
async fn a_notice_carrying_its_own_refs_delivers_even_with_no_stored_session() {
    // The coordinator-restart scenario this fallback exists to fix: the
    // tenant's signing key is (re-)enrolled (it can be persisted, e.g. via
    // --tenant-key), but the in-memory session-refs map is empty because
    // create_session was never called this coordinator lifetime for this
    // session. A notice that carries its own refs (the relay stamped them
    // from its own stored descriptor, independent of the coordinator's
    // process lifetime) must still deliver a correct webhook.
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

    // No `create_session` call at all — the session store has nothing for
    // this (or any) session id.
    let mut restart_notice = notice(SessionId(777), 0, DepartureKind::Dropped, 0x4000_0006);
    restart_notice.external_id = Some("game-restart".to_owned());
    restart_notice.external_ref = Some("sb-user-restart".to_owned());

    handle_departure(&setup, &dedup.departures, &lifecycle, restart_notice);

    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("a webhook is delivered even with no stored session for it")
        .unwrap();
    assert_eq!(got.body["externalId"], "game-restart");
    assert_eq!(got.body["externalRef"], "sb-user-restart");
    assert_eq!(got.body["kind"], "dropped");
}

#[tokio::test]
async fn no_gameid_ref_from_either_source_is_a_silent_no_op() {
    // Neither the notice nor the stored session (which itself was created
    // with no external_id) has a gameId ref — a webhook with no game to
    // attach to is useless to the consumer, so this stays a drop.
    let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
    let (setup, session) = setup_with_session(None, None);
    tenant::set_notify(
        setup.tenants(),
        &TenantId("sb-test".to_owned()),
        Some(NotifyConfig { url }),
    );
    let dedup = new_dedup();
    let lifecycle = Lifecycle::new(setup.clone());

    handle_departure(
        &setup,
        &dedup.departures,
        &lifecycle,
        notice(session, 0, DepartureKind::Dropped, 0x4000_0006),
    );

    assert!(
        timeout(Duration::from_millis(400), rx.recv())
            .await
            .is_err(),
        "no gameId ref from the notice or the stored session -> dropped",
    );
}

#[tokio::test]
async fn no_notify_config_is_a_silent_no_op() {
    // A receiver exists, but the tenant has no notify config, so nothing is
    // ever sent to it.
    let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
    let (setup, session) = setup_with_session(Some("game-1"), Some("sb-user-1"));
    // Deliberately do NOT point the tenant's notify config at `url`.
    let _ = url;
    let dedup = new_dedup();
    let lifecycle = Lifecycle::new(setup.clone());

    handle_departure(
        &setup,
        &dedup.departures,
        &lifecycle,
        notice(session, 0, DepartureKind::Dropped, 0x4000_0006),
    );

    assert!(
        timeout(Duration::from_millis(400), rx.recv())
            .await
            .is_err(),
        "a tenant with no notify config sends no webhook",
    );
}

#[tokio::test]
async fn an_unknown_session_is_a_silent_no_op() {
    let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
    let (setup, _session) = setup_with_session(Some("game-1"), Some("sb-user-1"));
    tenant::set_notify(
        setup.tenants(),
        &TenantId("sb-test".to_owned()),
        Some(NotifyConfig { url }),
    );
    let dedup = new_dedup();
    let lifecycle = Lifecycle::new(setup.clone());

    // A session the coordinator never created has no stored refs, and the
    // (refless) notice carries none either -> no gameId from any source,
    // so this still drops even though the "no session record" branch
    // itself is no longer a hard stop.
    handle_departure(
        &setup,
        &dedup.departures,
        &lifecycle,
        notice(SessionId(999_999), 0, DepartureKind::Dropped, 0x4000_0006),
    );

    assert!(
        timeout(Duration::from_millis(400), rx.recv())
            .await
            .is_err(),
        "a departure for an unknown session, with no notice-carried refs, sends no webhook",
    );
}
