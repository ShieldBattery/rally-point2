//! Flight-upload grant bookkeeping and the tenant-facing recording reads.

use super::*;

// --- Flight upload grant bookkeeping ---

fn outstanding_grant(session: u64, pinned: bool, minted_at: Instant) -> OutstandingGrant {
    OutstandingGrant {
        tenant: tenant_id(),
        session: SessionId(session),
        pinned,
        bytes: 100,
        minted_at,
    }
}

#[test]
fn a_done_takes_its_grant_and_ignores_an_unknown_duplicate_or_expired_one() {
    let now = Instant::now();
    let mut outstanding = std::collections::HashMap::new();
    outstanding.insert(7, outstanding_grant(42, true, now));

    // A done for a request the connection never granted is ignored.
    assert!(take_outstanding_grant(&mut outstanding, 9, now).is_none());

    // The matching done removes and returns its grant (carrying the pinned flag the
    // sweep keys on).
    let grant = take_outstanding_grant(&mut outstanding, 7, now).expect("the grant is found");
    assert_eq!(grant.session, SessionId(42));
    assert!(grant.pinned);

    // A duplicate done for the same request is now ignored — the entry is gone.
    assert!(take_outstanding_grant(&mut outstanding, 7, now).is_none());

    // Past a grant's expiry, a done for it reads as unknown, and the expired
    // entry is swept in the same pass.
    outstanding.insert(3, outstanding_grant(1, false, now));
    let later = now + flight_store::PRESIGNED_PUT_EXPIRY + Duration::from_secs(1);
    assert!(
        take_outstanding_grant(&mut outstanding, 3, later).is_none(),
        "an expired grant's done is ignored",
    );
    assert!(outstanding.is_empty(), "the expired entry was pruned");
}

// --- Flight recording read endpoints ---

#[tokio::test]
async fn flight_reads_answer_nothing_stored_with_no_store_configured() {
    // With no --flight-store, the read endpoints still authenticate and answer
    // "nothing stored" rather than erroring: an empty list from the listing,
    // a 404 from the fetch.
    let app = router(state_with_relay_and_tenant());

    let list_body =
        serde_json::to_vec(&serde_json::json!({"tenant": TEST_TENANT, "session": 7})).unwrap();
    let resp = signed_post(app.clone(), "/flight/blobs", &list_body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await["blobs"].as_array().unwrap().len(),
        0,
        "the listing is empty rather than an error",
    );

    let fetch_body = serde_json::to_vec(
        &serde_json::json!({"tenant": TEST_TENANT, "session": 7, "relay_id": 3}),
    )
    .unwrap();
    let resp = signed_post(app, "/flight/blob", &fetch_body, &TEST_CLIENT_SEED).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
