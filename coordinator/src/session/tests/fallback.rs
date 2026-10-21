//! Cross-region fallback: a slot (or a re-homed group) whose region has no
//! available relay homes in the nearest region by backbone round-trip, reusing a
//! relay already serving the session when it is nearly as close, and takes the
//! lowest-id relay only when there is nothing to rank by.

use super::*;

/// Expects `outcome` to be a re-home onto a new target and returns its id.
fn new_target(outcome: RehomeOutcome) -> RelayId {
    match outcome {
        RehomeOutcome::NewTarget(endpoint) => endpoint.relay_id,
        other => panic!("expected a NewTarget re-home decision, got {other:?}"),
    }
}

#[test]
fn a_cold_region_falls_back_to_the_nearest_lit_region() {
    // mx has no relay. The lowest id (relay 1) is across an ocean; the nearest
    // region with a relay is us-west (relay 3), so both mx slots home there.
    let setup = region_fleet(&[
        (1, 14900, Some("eu-north")),
        (2, 14901, Some("us-east")),
        (3, 14902, Some("us-west")),
    ]);
    record_rtts(
        &setup,
        &[
            ("eu-north", "mx", 160),
            ("us-east", "mx", 55),
            ("us-west", "mx", 40),
        ],
    );

    let resp = create_region_session(
        &setup,
        vec![
            player_in_region(0, Some("mx")),
            player_in_region(1, Some("mx")),
        ],
    );
    assert_eq!(resp.home_relay.relay_id, RelayId(3));
    assert!(resp.slot_homes.is_empty(), "both mx slots share one relay");
    assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(3)]);
}

#[test]
fn a_cold_region_reuses_a_serving_relay_within_the_margin() {
    // The us-east slot homes on relay 2. For the mx slot, us-central (relay 3)
    // is nearest at 30 ms, but relay 2 already serves the session and is only
    // 10 ms farther, so the mx slot joins it rather than adding a relay. The mx
    // player is listed first: the lit region still resolves before the cold one
    // is ranked, so roster order does not change the pick.
    let setup = region_fleet(&[
        (1, 14900, Some("eu-north")),
        (2, 14901, Some("us-east")),
        (3, 14902, Some("us-central")),
    ]);
    record_rtts(
        &setup,
        &[
            ("eu-north", "mx", 160),
            ("us-east", "mx", 40),
            ("us-central", "mx", 30),
        ],
    );

    let resp = create_region_session(
        &setup,
        vec![
            player_in_region(0, Some("mx")),
            player_in_region(1, Some("us-east")),
        ],
    );
    assert_eq!(response_home_for_slot(&resp, SlotId(0)), RelayId(2));
    assert_eq!(response_home_for_slot(&resp, SlotId(1)), RelayId(2));
    assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(2)]);
}

#[test]
fn a_serving_relay_beyond_the_margin_loses_to_the_nearest_region() {
    // Same shape, but us-central is 20 ms closer to mx than the serving us-east
    // relay — a real geographic gap — so the mx slot homes on us-central and the
    // session meshes two relays.
    let setup = region_fleet(&[
        (1, 14900, Some("eu-north")),
        (2, 14901, Some("us-east")),
        (3, 14902, Some("us-central")),
    ]);
    record_rtts(
        &setup,
        &[
            ("eu-north", "mx", 160),
            ("us-east", "mx", 40),
            ("us-central", "mx", 20),
        ],
    );

    let resp = create_region_session(
        &setup,
        vec![
            player_in_region(0, Some("mx")),
            player_in_region(1, Some("us-east")),
        ],
    );
    assert_eq!(response_home_for_slot(&resp, SlotId(0)), RelayId(3));
    assert_eq!(response_home_for_slot(&resp, SlotId(1)), RelayId(2));
}

#[test]
fn a_cold_region_with_no_pair_data_falls_back_to_the_lowest_id() {
    // The table only knows a pair that does not involve mx, so nothing can be
    // ranked against it and the mx slot takes the region-blind lowest-id pick.
    let setup = region_fleet(&[(1, 14900, Some("eu-north")), (2, 14901, Some("us-west"))]);
    record_rtts(&setup, &[("us-west", "eu-north", 150)]);

    let resp = create_region_session(&setup, vec![player_in_region(0, Some("mx"))]);
    assert_eq!(resp.home_relay.relay_id, RelayId(1));
}

#[test]
fn a_region_with_no_pair_is_left_unranked_rather_than_assumed_near() {
    // mx's pair with us-west is known but its pair with eu-north is not: the
    // unmeasured region is not ranked at all, so the known-near relay wins even
    // though the other has the lower id.
    let setup = region_fleet(&[(1, 14900, Some("eu-north")), (2, 14901, Some("us-west"))]);
    record_rtts(&setup, &[("us-west", "mx", 45)]);

    let resp = create_region_session(&setup, vec![player_in_region(0, Some("mx"))]);
    assert_eq!(resp.home_relay.relay_id, RelayId(2));
}

#[test]
fn a_region_lit_only_outside_the_cohort_places_on_the_nearest_cohort_relay_without_holding() {
    // sg is lit only by an incapable relay, so the capable cohort has no sg
    // relay: the sg slot goes to the nearest capable region (us-west), not the
    // lowest-id capable relay (eu-north). The hold check still reads sg as lit,
    // because warming sg could not launch a relay its incapable one already
    // satisfies the demand for.
    let setup = fleet(&[
        (1, 14900, Some("eu-north"), true),
        (2, 14901, Some("us-west"), true),
        (3, 14902, Some("sg"), false),
    ])
    .0;
    record_rtts(&setup, &[("eu-north", "sg", 200), ("us-west", "sg", 170)]);
    let req = request(vec![player_in_region(0, Some("sg"))]);

    assert!(super::super::placement::unlit_requested_regions(&setup.registry, &req).is_empty());
    let resp = create_session(&setup, req, ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    assert_eq!(resp.home_relay.relay_id, RelayId(2));
}

#[test]
fn rehome_from_a_region_with_no_spare_moves_to_the_nearest_region() {
    // The au relay (2) homes the session and dies with no other au relay live.
    // sg (relay 3) is far nearer to au than the lower-id eu-north relay 1.
    let setup = region_fleet(&[
        (1, 14900, Some("eu-north")),
        (2, 14901, Some("au")),
        (3, 14902, Some("sg")),
    ]);
    record_rtts(&setup, &[("au", "eu-north", 280), ("au", "sg", 95)]);
    let resp = create_region_session(&setup, vec![player_in_region(0, Some("au"))]);
    assert_eq!(resp.home_relay.relay_id, RelayId(2));

    registry::remove(setup.registry(), RelayId(2));
    assert_eq!(
        new_target(rehome(&setup, &tid(), resp.session, RelayId(2), vec![])),
        RelayId(3),
    );
    assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(3)]);
}

#[test]
fn rehome_reuses_a_serving_relay_only_within_the_margin() {
    // An mx relay (4) homes slot 0 beside a us-east relay (2) homing slot 1, and
    // mx dies. With us-central (3) 10 ms nearer than the serving us-east relay,
    // the group joins relay 2; with us-central 20 ms nearer, it moves there.
    for (central_rtt, expected) in [(30, RelayId(2)), (20, RelayId(3))] {
        let setup = region_fleet(&[
            (1, 14900, Some("eu-north")),
            (2, 14901, Some("us-east")),
            (3, 14902, Some("us-central")),
            (4, 14903, Some("mx")),
        ]);
        record_rtts(
            &setup,
            &[
                ("mx", "eu-north", 160),
                ("mx", "us-east", 40),
                ("mx", "us-central", central_rtt),
            ],
        );
        let resp = create_region_session(
            &setup,
            vec![
                player_in_region(0, Some("mx")),
                player_in_region(1, Some("us-east")),
            ],
        );
        assert_eq!(response_home_for_slot(&resp, SlotId(0)), RelayId(4));

        registry::remove(setup.registry(), RelayId(4));
        assert_eq!(
            new_target(rehome(&setup, &tid(), resp.session, RelayId(4), vec![])),
            expected,
            "us-central at {central_rtt} ms against the serving us-east relay at 40 ms",
        );
    }
}

#[test]
fn rehome_prefers_a_spare_in_the_dead_region_over_a_distant_serving_relay() {
    // sg relay 1 homes slot 0 and us-west relay 2 homes slot 1. When relay 1
    // dies, the sg spare (relay 3) keeps the sg group in sg rather than sending it
    // across the Pacific to the serving us-west relay.
    let setup = region_fleet(&[
        (1, 14900, Some("sg")),
        (2, 14901, Some("us-west")),
        (3, 14902, Some("sg")),
    ]);
    record_rtts(&setup, &[("sg", "us-west", 170)]);
    let resp = create_region_session(
        &setup,
        vec![
            player_in_region(0, Some("sg")),
            player_in_region(1, Some("us-west")),
        ],
    );
    assert_eq!(response_home_for_slot(&resp, SlotId(0)), RelayId(1));

    registry::remove(setup.registry(), RelayId(1));
    assert_eq!(
        new_target(rehome(&setup, &tid(), resp.session, RelayId(1), vec![])),
        RelayId(3),
    );
}

#[test]
fn rehome_with_no_pair_data_keeps_preferring_a_serving_relay() {
    // The dead relay's region-a has no spare and no pair data to rank the others
    // by, so the re-home takes the region-blind rule: the relay already serving
    // the session (3), not the lower-id idle relay 2.
    let setup = region_fleet(&[
        (1, 14900, Some("region-a")),
        (2, 14901, Some("region-c")),
        (3, 14902, Some("region-b")),
    ]);
    let resp = create_region_session(
        &setup,
        vec![
            player_in_region(0, Some("region-a")),
            player_in_region(1, Some("region-b")),
        ],
    );

    registry::remove(setup.registry(), RelayId(1));
    assert_eq!(
        new_target(rehome(&setup, &tid(), resp.session, RelayId(1), vec![])),
        RelayId(3),
    );
}
