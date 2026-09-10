//! Hold-until-ready create: a request naming a region with no live relay warms
//! the region and is held until a relay enrolls or the per-create hold cap
//! elapses.

use super::*;

#[test]
fn a_cold_region_create_warms_and_holds_without_minting() {
    let (setup, warm) = provisioning_setup(Duration::from_secs(60));
    let outcome = create_or_provision_session_at(
        &setup,
        region_a_request(Some("g1")),
        ExpiresAt(u64::MAX),
        1_000,
    )
    .unwrap();
    match outcome {
        CreateOutcome::Provisioning { regions } => {
            assert_eq!(regions, vec![region_a()], "the unlit region is reported");
        }
        CreateOutcome::Created(_) => panic!("a cold requested region must hold, not place"),
    }
    // A held create mints nothing: no session membership, no idempotency entry.
    assert!(
        setup.session_relays.lock().is_empty(),
        "no session membership recorded while pending",
    );
    assert!(
        setup.create_idempotency.lock().is_empty(),
        "no idempotency entry cached while pending",
    );
    // The hold is anchored, and warm demand for the region was raised.
    assert_eq!(
        setup.pending_creates.lock().len(),
        1,
        "the hold is anchored"
    );
    assert_eq!(
        warm.target_at(&region_a(), 0),
        1,
        "the cold region was warmed so the loop provisions a relay there",
    );
}

#[test]
fn a_retry_within_the_cap_keeps_holding() {
    let (setup, _warm) = provisioning_setup(Duration::from_secs(60));
    let req = region_a_request(Some("g1"));
    assert!(matches!(
        create_or_provision_session_at(&setup, req.clone(), ExpiresAt(u64::MAX), 1_000).unwrap(),
        CreateOutcome::Provisioning { .. }
    ));
    // A retry at t=1_030, still inside the 60s cap, holds again on one anchor.
    assert!(matches!(
        create_or_provision_session_at(&setup, req, ExpiresAt(u64::MAX), 1_030).unwrap(),
        CreateOutcome::Provisioning { .. }
    ));
    assert_eq!(
        setup.pending_creates.lock().len(),
        1,
        "one anchor tracks the hold across retries",
    );
}

#[test]
fn the_cap_elapsing_falls_back_to_placement_and_clears_the_hold() {
    let (setup, _warm) = provisioning_setup(Duration::from_secs(60));
    let req = region_a_request(Some("g1"));
    assert!(matches!(
        create_or_provision_session_at(&setup, req.clone(), ExpiresAt(u64::MAX), 1_000).unwrap(),
        CreateOutcome::Provisioning { .. }
    ));
    // At t=1_060 the cap has elapsed: the create falls through to region-blind
    // placement (relay 1), exactly as an unlit-region create does with no gate.
    let resp =
        match create_or_provision_session_at(&setup, req, ExpiresAt(u64::MAX), 1_060).unwrap() {
            CreateOutcome::Created(created) => created.response,
            CreateOutcome::Provisioning { .. } => panic!("the cap elapsed; placement must proceed"),
        };
    assert_eq!(
        resp.home_relay.relay_id,
        RelayId(1),
        "the cold region fell back to the region-blind relay",
    );
    assert!(
        setup.pending_creates.lock().is_empty(),
        "the hold anchor is cleared once the create places",
    );
}

#[test]
fn a_relay_enrolling_while_pending_places_in_region_and_clears_the_hold() {
    let (setup, _warm) = provisioning_setup(Duration::from_secs(60));
    let req = region_a_request(Some("g1"));
    assert!(matches!(
        create_or_provision_session_at(&setup, req.clone(), ExpiresAt(u64::MAX), 1_000).unwrap(),
        CreateOutcome::Provisioning { .. }
    ));
    // A relay for region-a enrolls while the create is held.
    enroll_relay_in_region(setup.registry(), 2, 14901, Some("region-a"));
    // The next identical retry, still inside the cap, places in-region on relay 2
    // rather than falling back to the region-blind relay 1.
    let resp =
        match create_or_provision_session_at(&setup, req, ExpiresAt(u64::MAX), 1_005).unwrap() {
            CreateOutcome::Created(created) => created.response,
            CreateOutcome::Provisioning { .. } => {
                panic!("the region's relay enrolled; placement must proceed")
            }
        };
    assert_eq!(
        resp.home_relay.relay_id,
        RelayId(2),
        "the slot placed on the region's relay, not the fallback",
    );
    assert!(
        setup.pending_creates.lock().is_empty(),
        "the hold anchor is cleared once the create places",
    );
}

#[test]
fn a_create_without_an_external_id_never_holds() {
    let (setup, _warm) = provisioning_setup(Duration::from_secs(60));
    // The same cold region, but no external_id to anchor a hold: it places at
    // once via region-blind fallback rather than holding.
    let outcome =
        create_or_provision_session_at(&setup, region_a_request(None), ExpiresAt(u64::MAX), 1_000)
            .unwrap();
    assert!(
        matches!(outcome, CreateOutcome::Created(_)),
        "a create with no external_id falls back immediately",
    );
    assert!(
        setup.pending_creates.lock().is_empty(),
        "nothing is anchored for a create that cannot be held",
    );
}

#[test]
fn an_unusable_clock_never_holds() {
    let (setup, _warm) = provisioning_setup(Duration::from_secs(60));
    // `u64::MAX` marks an unusable clock: the create must fall back rather than
    // wedge, even though the region is cold.
    let outcome = create_or_provision_session_at(
        &setup,
        region_a_request(Some("g1")),
        ExpiresAt(u64::MAX),
        u64::MAX,
    )
    .unwrap();
    assert!(
        matches!(outcome, CreateOutcome::Created(_)),
        "a broken clock releases the create to fallback",
    );
    assert!(
        setup.pending_creates.lock().is_empty(),
        "no hold is anchored on a broken clock",
    );
}

#[test]
fn provisioning_off_never_holds() {
    // A setup with the dormant gate (no provisioning loop): a cold-region create
    // with an external_id still falls back immediately — no hold path exists.
    let setup = setup_with_two_relays_and_tenant();
    let outcome = create_or_provision_session_at(
        &setup,
        region_a_request(Some("g1")),
        ExpiresAt(u64::MAX),
        1_000,
    )
    .unwrap();
    assert!(
        matches!(outcome, CreateOutcome::Created(_)),
        "with no provisioning loop, create never holds",
    );
    assert!(setup.pending_creates.lock().is_empty());
}

#[test]
fn a_pending_sibling_roster_under_one_external_id_does_not_panic() {
    // Two different rosters share one external_id while the region is cold. The
    // pending map is keyed by external_id, so the second roster shares the first's
    // anchor and also holds — no session or cache exists yet, so nothing conflicts
    // and nothing panics.
    let (setup, _warm) = provisioning_setup(Duration::from_secs(60));
    let roster_a = region_a_request(Some("g1"));
    let mut roster_b = region_a_request(Some("g1"));
    roster_b.players[0].client_pubkey = ClientPublicKey([0x99; 32]);
    assert!(matches!(
        create_or_provision_session_at(&setup, roster_a, ExpiresAt(u64::MAX), 1_000).unwrap(),
        CreateOutcome::Provisioning { .. }
    ));
    assert!(matches!(
        create_or_provision_session_at(&setup, roster_b, ExpiresAt(u64::MAX), 1_010).unwrap(),
        CreateOutcome::Provisioning { .. }
    ));
    assert_eq!(
        setup.pending_creates.lock().len(),
        1,
        "both rosters share one external_id-keyed anchor",
    );
}
