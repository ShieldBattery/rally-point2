//! Region-aware placement: each slot homes in its own region, the primary home
//! is the plurality pick with ties rotating by session id, and each serving
//! relay's region is recorded and republished in every descriptor.

use super::*;

#[test]
fn region_placement_homes_each_slot_in_its_region() {
    // Two relays in two regions, one slot each: each slot homes on its region's
    // relay, producing the meshed cross-region shape.
    let setup =
        setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
    let resp = create_region_session(
        &setup,
        vec![
            player_in_region(0, Some("region-a")),
            player_in_region(1, Some("region-b")),
        ],
    );

    // One slot each is a tie, so either relay may be the rotated primary. The
    // response's primary-plus-override representation must still resolve each
    // slot to its requested region and carry both pinned certificates.
    assert_eq!(response_home_for_slot(&resp, SlotId(0)), RelayId(1));
    assert_eq!(response_home_for_slot(&resp, SlotId(1)), RelayId(2));
    assert_eq!(resp.slot_homes.len(), 1);
    assert_eq!(
        response_endpoint_for_relay(&resp, RelayId(1)).cert_der,
        fake_cert(1),
    );
    assert_eq!(
        response_endpoint_for_relay(&resp, RelayId(2)).cert_der,
        fake_cert(2),
    );
    // Both relays serve the meshed session.
    let serving: std::collections::HashSet<_> = setup
        .serving_relays(&tid(), resp.session)
        .into_iter()
        .collect();
    assert_eq!(
        serving,
        std::collections::HashSet::from([RelayId(1), RelayId(2)]),
    );
}

#[test]
fn tied_home_relays_rotate_and_every_descriptor_matches_the_response_home() {
    let setup =
        setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
    let players = || {
        vec![
            player_in_region(0, Some("region-a")),
            player_in_region(1, Some("region-b")),
        ]
    };

    let responses: Vec<SessionResponse> = (0..4)
        .map(|_| create_region_session(&setup, players()))
        .collect();

    for pair in responses.windows(2) {
        assert_ne!(
            pair[0].home_relay.relay_id, pair[1].home_relay.relay_id,
            "consecutive balanced sessions alternate their primary home",
        );
    }

    for response in &responses {
        let expected_home = if response.session.0 % 2 == 0 {
            RelayId(1)
        } else {
            RelayId(2)
        };
        assert_eq!(response.home_relay.relay_id, expected_home);
        assert_eq!(response_home_for_slot(response, SlotId(0)), RelayId(1));
        assert_eq!(response_home_for_slot(response, SlotId(1)), RelayId(2));

        let authority_order = setup.serving_relays(&tid(), response.session);
        assert_eq!(authority_order[0], response.home_relay.relay_id);
        for relay_id in [RelayId(1), RelayId(2)] {
            let descriptor = descriptor_for(&setup, &tid(), response.session, relay_id).unwrap();
            assert_eq!(descriptor.authority_order, authority_order);
        }
    }
}

#[test]
fn replaying_a_balanced_create_keeps_its_exact_rotated_home() {
    let setup =
        setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
    let request = |external_id: &str| SessionRequest {
        tenant: tid(),
        players: vec![
            player_in_region(0, Some("region-a")),
            player_in_region(1, Some("region-b")),
        ],
        external_id: Some(external_id.to_owned()),
        latency_estimate_ms: None,
    };

    let first = create_session(&setup, request("game-1"), ExpiresAt(u64::MAX)).unwrap();
    let candidate_after_first = candidate_session_id(&setup);
    let replay = create_session(&setup, request("game-1"), ExpiresAt(u64::MAX)).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.response, first.response);
    assert_eq!(
        candidate_session_id(&setup),
        candidate_after_first,
        "a replay neither re-places nor consumes a session id",
    );

    let next = create_session(&setup, request("game-2"), ExpiresAt(u64::MAX)).unwrap();
    assert_ne!(
        next.response.home_relay.relay_id, first.response.home_relay.relay_id,
        "the next fresh balanced session receives the next rotation",
    );
}

#[test]
fn a_slot_whose_region_has_no_relay_falls_back_to_the_global_pick() {
    // Only region-a has relays; a slot asking for region-b falls back to the
    // lowest-id available relay overall — today's region-blind pick.
    let setup =
        setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-a"))]);
    let resp = create_region_session(
        &setup,
        vec![
            player_in_region(0, Some("region-a")),
            player_in_region(1, Some("region-b")),
        ],
    );

    // region-a's lowest-id relay is 1; the unlit region-b slot falls back to the
    // global lowest-id pick, which is also relay 1 — so a single-relay session.
    assert_eq!(resp.home_relay.relay_id, RelayId(1));
    assert!(
        resp.slot_homes.is_empty(),
        "both slots land on relay 1, so there are no overrides",
    );
    assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(1)]);
}

#[test]
fn the_home_relay_is_the_plurality_pick_not_merely_the_lowest_id() {
    // relay 2 (region-b) is assigned two slots, relay 1 (region-a) one: the home
    // is the plurality relay 2, even though relay 1 has the lower id.
    let setup =
        setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
    let resp = create_region_session(
        &setup,
        vec![
            player_in_region(0, Some("region-b")),
            player_in_region(1, Some("region-b")),
            player_in_region(2, Some("region-a")),
        ],
    );

    assert_eq!(
        resp.home_relay.relay_id,
        RelayId(2),
        "the plurality relay is the home even though it is not the lowest id",
    );
    // Only the region-a slot (2) is overridden, onto relay 1.
    assert_eq!(resp.slot_homes.len(), 1);
    assert_eq!(resp.slot_homes[0].slot, SlotId(2));
    assert_eq!(resp.slot_homes[0].relay.relay_id, RelayId(1));

    let expected_order = vec![RelayId(2), RelayId(1)];
    assert_eq!(setup.serving_relays(&tid(), resp.session), expected_order);
    for relay_id in [RelayId(1), RelayId(2)] {
        let descriptor = descriptor_for(&setup, &tid(), resp.session, relay_id).unwrap();
        assert_eq!(
            descriptor.authority_order,
            vec![RelayId(2), RelayId(1)],
            "the unique plurality remains first in every descriptor",
        );
    }
}

#[test]
fn placement_records_each_serving_relays_region() {
    // The serving relays' regions are recorded so a later re-home can prefer the
    // dead relay's region.
    let setup =
        setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
    let resp = create_region_session(
        &setup,
        vec![
            player_in_region(0, Some("region-a")),
            player_in_region(1, Some("region-b")),
        ],
    );
    let refs = session_refs(&setup, &tid(), resp.session).unwrap();
    assert_eq!(
        refs.relay_regions.get(&RelayId(1)),
        Some(&Some(RegionId("region-a".to_owned()))),
    );
    assert_eq!(
        refs.relay_regions.get(&RelayId(2)),
        Some(&Some(RegionId("region-b".to_owned()))),
    );
}

#[test]
fn every_descriptor_carries_the_whole_sessions_region_labels() {
    // A relay releases the *session's* map to its clients, not just its own
    // entry, so both relays' descriptors carry both labels.
    let setup =
        setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
    let resp = create_region_session(
        &setup,
        vec![
            player_in_region(0, Some("region-a")),
            player_in_region(1, Some("region-b")),
        ],
    );

    let expected = vec![
        RelayRegionLabel {
            relay_id: RelayId(1),
            region: RegionId("region-a".to_owned()),
        },
        RelayRegionLabel {
            relay_id: RelayId(2),
            region: RegionId("region-b".to_owned()),
        },
    ];
    for relay_id in [RelayId(1), RelayId(2)] {
        let descriptor = descriptor_for(&setup, &tid(), resp.session, relay_id).unwrap();
        assert_eq!(
            descriptor.relay_regions, expected,
            "relay {relay_id:?}'s descriptor carries every serving relay's label, in relay-id order",
        );
    }
    assert_eq!(
        resp.relay_regions, expected,
        "the session-create response mirrors the same labels to the app server",
    );
}

#[test]
fn an_untagged_relay_is_omitted_from_the_descriptors_region_labels() {
    // A relay the coordinator never tagged has no label to release. It is left
    // out of the map entirely rather than carried with an empty region, so a
    // client can tell "no region recorded" from "recorded as nothing".
    let setup = setup_with_region_relays(&[(1, 14900, None), (2, 14901, Some("region-b"))]);
    let resp = create_region_session(
        &setup,
        vec![
            player_in_region(0, None),
            player_in_region(1, Some("region-b")),
        ],
    );

    // Both relays serve the session, but only the tagged one has a region.
    let refs = session_refs(&setup, &tid(), resp.session).unwrap();
    assert_eq!(refs.relay_regions.get(&RelayId(1)), Some(&None));
    let descriptor = descriptor_for(&setup, &tid(), resp.session, RelayId(1)).unwrap();
    let expected = vec![RelayRegionLabel {
        relay_id: RelayId(2),
        region: RegionId("region-b".to_owned()),
    }];
    assert_eq!(descriptor.relay_regions, expected);
    assert_eq!(
        resp.relay_regions, expected,
        "the response also omits the untagged relay's entry",
    );
}

#[test]
fn a_conflicting_create_differing_only_in_a_players_region_is_refused() {
    // Region selects a slot's home relay, so the same external_id reused with a
    // different per-slot region is a genuine roster mismatch (409), not a replay.
    let setup =
        setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
    let original = SessionRequest {
        tenant: tid(),
        players: vec![
            player_in_region(0, Some("region-a")),
            player_in_region(1, Some("region-a")),
        ],
        external_id: Some("game-1".to_owned()),
        latency_estimate_ms: None,
    };
    create_session(&setup, original.clone(), ExpiresAt(u64::MAX)).unwrap();

    let mut changed = original.clone();
    changed.players[1].region = Some(RegionId("region-b".to_owned()));
    assert_eq!(
        create_session(&setup, changed, ExpiresAt(u64::MAX)).unwrap_err(),
        SessionSetupError::IdempotentCreateMismatch,
    );

    // The original roster still replays, so the conflict left the cache intact.
    assert!(
        create_session(&setup, original, ExpiresAt(u64::MAX))
            .unwrap()
            .replayed,
    );
}

#[test]
fn rehome_prefers_a_replacement_in_the_dead_relays_region() {
    // relay 2 (region-b) homes the single-slot session; the spares are relay 1
    // (region-a) and relay 3 (region-b). When relay 2 dies and no serving relay
    // is left to take over, the replacement is the region-b spare (relay 3), not
    // the lower-id region-a relay 1.
    let setup = setup_with_region_relays(&[
        (1, 14900, Some("region-a")),
        (2, 14901, Some("region-b")),
        (3, 14902, Some("region-b")),
    ]);
    let resp = create_region_session(&setup, vec![player_in_region(0, Some("region-b"))]);
    assert_eq!(resp.home_relay.relay_id, RelayId(2));

    registry::remove(setup.registry(), RelayId(2));
    match rehome(&setup, &tid(), resp.session, RelayId(2), vec![]) {
        RehomeOutcome::NewTarget(ep) => assert_eq!(
            ep.relay_id,
            RelayId(3),
            "the replacement is the region-b spare, not the lower-id region-a relay",
        ),
        other => panic!("expected NewTarget(relay 3), got {other:?}"),
    }
}

#[test]
fn rehome_falls_back_to_any_relay_when_the_dead_region_has_no_live_relay() {
    // relay 2 (region-b) homes the session; the only spare is relay 1 (region-a).
    // When relay 2 dies, region-b has no live relay, so the replacement is the
    // region-blind fallback (relay 1).
    let setup =
        setup_with_region_relays(&[(1, 14900, Some("region-a")), (2, 14901, Some("region-b"))]);
    let resp = create_region_session(&setup, vec![player_in_region(0, Some("region-b"))]);
    assert_eq!(resp.home_relay.relay_id, RelayId(2));

    registry::remove(setup.registry(), RelayId(2));
    match rehome(&setup, &tid(), resp.session, RelayId(2), vec![]) {
        RehomeOutcome::NewTarget(ep) => assert_eq!(
            ep.relay_id,
            RelayId(1),
            "with no live relay in the dead region, any available relay takes over",
        ),
        other => panic!("expected NewTarget(relay 1), got {other:?}"),
    }
}
