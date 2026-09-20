//! Departure-webhook tests: the body a consumer parses, and correlation ids
//! resolved notice-first then falling back to the stored session. That one
//! event webhooks exactly once however often it is reported is tabled for every
//! kind in `ingest`. The drop branches every notice kind shares are tabled
//! here, since they are decided in one place.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rally_point_proto::control::{DepartureNotice, ResultNotice};

use super::*;

/// A departure notice with no correlation ids of its own — the relay-predates-
/// the-field case, which relies entirely on the coordinator's stored session.
fn notice(session: SessionId, slot: u8, kind: DepartureKind, reason: u32) -> DepartureNotice {
    DepartureNotice {
        finalized: false,
        tenant: TenantId(TEST_TENANT.to_owned()),
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

/// Points the test tenant's webhook at `url`.
fn notify_at(setup: &SessionSetup, url: String) {
    tenant::set_notify(
        setup.tenants(),
        &TenantId(TEST_TENANT.to_owned()),
        Some(NotifyConfig { url }),
    );
}

#[tokio::test]
async fn a_departure_webhook_carries_the_shape_the_tenant_parses() {
    let (url, mut rx) = WebhookReceiver::default().spawn().await;
    let (setup, session) = setup_with_session(Some("game-99"), Some("sb-user-7"));
    notify_at(&setup, url);
    let lifecycle = Lifecycle::new(setup.clone());

    report(
        &lifecycle,
        SessionNotice::Departure(notice(session, 0, DepartureKind::Dropped, 0x4000_0006)),
    );

    let got = signed_webhook(&setup, &mut rx).await;
    assert_eq!(got.body["event"], "departure");
    assert_eq!(got.body["tenant"], TEST_TENANT);
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
}

#[tokio::test]
async fn a_clean_leave_is_classified_left_and_omits_an_unstored_slot_ref() {
    // A gameId is present (so the departure isn't dropped for lacking one),
    // but no per-slot player ref — the webhook must still deliver, just
    // omitting `externalRef`.
    let (url, mut rx) = WebhookReceiver::default().spawn().await;
    let (setup, session) = setup_with_session(Some("game-42"), None);
    notify_at(&setup, url);
    let lifecycle = Lifecycle::new(setup.clone());

    report(
        &lifecycle,
        SessionNotice::Departure(notice(session, 0, DepartureKind::Left, 3)),
    );

    let got = signed_webhook(&setup, &mut rx).await;
    assert_eq!(got.body["kind"], "left");
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
async fn a_departure_embeds_a_base64_result_when_the_slot_reported_one() {
    // A departure that carries the slot's end-of-game result: the webhook
    // embeds it as a base64 payload plus the relay's arrival/frame stamps, so
    // one delivery is atomic terminal truth.
    let (url, mut rx) = WebhookReceiver::default().spawn().await;
    let (setup, session) = setup_with_session(Some("game-99"), Some("sb-user-7"));
    notify_at(&setup, url);
    let lifecycle = Lifecycle::new(setup.clone());

    let mut with_result = notice(session, 0, DepartureKind::Left, 3);
    with_result.result = Some(rally_point_proto::control::ResultEcho {
        payload: vec![0x01, 0x02, 0x03, 0x04],
        arrival_ms: 1_700_000_000_123,
        session_frame: Some(4200),
        slot_frame: Some(4242),
    });
    report(&lifecycle, SessionNotice::Departure(with_result));

    let got = signed_webhook(&setup, &mut rx).await;
    assert_eq!(
        got.body["result"]["payload"],
        BASE64_STANDARD.encode([0x01, 0x02, 0x03, 0x04]),
    );
    assert_eq!(got.body["result"]["arrivalMs"], 1_700_000_000_123u64);
    assert_eq!(got.body["result"]["sessionFrame"], 4200);
    assert_eq!(got.body["result"]["slotFrame"], 4242);
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
    let (url, mut rx) = WebhookReceiver::default().spawn().await;
    let setup = setup_without_session(url);
    let lifecycle = Lifecycle::new(setup.clone());

    let mut restart_notice = notice(SessionId(777), 0, DepartureKind::Dropped, 0x4000_0006);
    restart_notice.external_id = Some("game-restart".to_owned());
    restart_notice.external_ref = Some("sb-user-restart".to_owned());

    report(&lifecycle, SessionNotice::Departure(restart_notice));

    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("a webhook is delivered even with no stored session for it")
        .unwrap();
    assert_eq!(got.body["externalId"], "game-restart");
    assert_eq!(got.body["externalRef"], "sb-user-restart");
    assert_eq!(got.body["kind"], "dropped");
}

/// A result notice with no correlation ids of its own, for the shared
/// drop-branch table below.
fn refless_result(session: SessionId) -> ResultNotice {
    ResultNotice {
        tenant: TenantId(TEST_TENANT.to_owned()),
        session,
        slot: SlotId(0),
        external_id: None,
        external_ref: None,
        payload: vec![0x01, 0x02],
        arrival_ms: 1_700_000_000_123,
        session_frame: None,
        slot_frame: None,
    }
}

/// The reasons a notice resolves to nothing to send. All four are decided in
/// the prefix every handler resolves first, so they are proven once here rather
/// than per notice kind.
///
/// These drive the webhook path directly rather than through `report`: the
/// verdict below is read off the absence of lifecycle state, and ingest's
/// accounting step (which is not the webhook path) creates that state for a
/// departure or a result before the webhook path ever runs.
#[derive(Debug)]
enum Dropped {
    /// Neither the notice nor the stored session (itself created with no
    /// `external_id`) carries a gameId ref, and a webhook naming no game is
    /// useless to the consumer.
    NoGameIdRef,
    /// The tenant has a session and refs, but no notify config to post to.
    NoNotifyConfig,
    /// A session this coordinator never created, reported by a refless notice:
    /// the same no-gameId branch, reached from the post-restart tail rather
    /// than from a refless create.
    UnknownSessionAndReflessNotice,
    /// The same decision reached through the result handler — the per-kind
    /// wrapper adds nothing the positive result test does not already cover.
    ResultWithNoGameIdRef,
}

#[tokio::test]
async fn the_shared_drop_branches_are_silent_no_ops() {
    // Read off the lifecycle rather than out of a timeout: a resolved notice is
    // enqueued onto the session's ordered dispatch queue synchronously, and that
    // enqueue is what lazily creates the session's lifecycle state. No state
    // means nothing was ever going to be posted — exact, and free.
    for branch in [
        Dropped::NoGameIdRef,
        Dropped::NoNotifyConfig,
        Dropped::UnknownSessionAndReflessNotice,
        Dropped::ResultWithNoGameIdRef,
    ] {
        let (setup, session) = match branch {
            Dropped::NoNotifyConfig => setup_with_session(Some("game-1"), Some("sb-user-1")),
            _ => setup_with_session(None, None),
        };
        if !matches!(branch, Dropped::NoNotifyConfig) {
            // Nothing listens here: a resolved notice would be enqueued whether
            // or not the endpoint answers, and the enqueue is what is asserted.
            notify_at(&setup, "http://127.0.0.1:1/hook".to_owned());
        }
        let dedup = NoticeDedup::new();
        let lifecycle = Lifecycle::new(setup.clone());

        let target = match branch {
            Dropped::UnknownSessionAndReflessNotice => SessionId(999_999),
            _ => session,
        };
        match branch {
            Dropped::ResultWithNoGameIdRef => {
                handle_result(&setup, &dedup.results, &lifecycle, refless_result(target));
            }
            _ => handle_departure(
                &setup,
                &dedup.departures,
                &lifecycle,
                notice(target, 0, DepartureKind::Dropped, 0x4000_0006),
            ),
        }

        assert!(
            !lifecycle.contains_state(&TenantId(TEST_TENANT.to_owned()), target),
            "{branch:?}: a dropped notice enqueues nothing, so it leaves behind              no lifecycle state and no drain task either",
        );
    }
}
