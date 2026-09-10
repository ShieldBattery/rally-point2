//! Coordinator-mediated re-home: the stay/move decision, the replacement pick,
//! its idempotency, the cert-pin check that catches a restart in place, and the
//! resumed descriptors a move (or a late departure) stages.

use super::*;

#[test]
fn rehome_stays_when_the_named_relay_is_still_live() {
    // The coordinator authoritatively knows the relay's liveness from its
    // registry: a client that believes a still-enrolled relay is dead is told to
    // stay rather than move.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup);
    assert_eq!(
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
        RehomeOutcome::Stay,
    );
}

#[test]
fn a_departure_recorded_mid_rehome_still_seeds_the_resumed_descriptors() {
    // Models a departure notice landing while the rehome is already inside
    // its assignment-locked body: the departed accounting gains an entry
    // after the request began (a caller-side snapshot taken up front would
    // miss it) but before the resumed descriptors are built. The reader is
    // invoked at build time, so the entry still rides every descriptor —
    // otherwise a fresh relay would wait forever on a slot that
    // permanently left, with no surviving mesh peer to re-announce it
    // after a single-relay death.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup);
    registry::remove(setup.registry(), RelayId(1));

    let departed: std::cell::RefCell<Vec<DepartedSlot>> = std::cell::RefCell::new(vec![]);
    let outcome = rehome_inner(
        &setup,
        &(tid(), resp.session),
        RelayId(1),
        true,
        || departed.borrow().clone(),
        || {
            // The mid-rehome departure notice (the seam runs after the
            // assignment lock is held, before the descriptor build).
            departed.borrow_mut().push(DepartedSlot {
                finalized: false,
                slot: SlotId(1),
                kind: DepartureKind::Dropped,
                final_turn_count: None,
            });
        },
        |_| {},
    );
    assert!(matches!(outcome, RehomeOutcome::NewTarget(_)));

    let staged = setup.descriptors().current_for(RelayId(2));
    assert_eq!(staged.len(), 1);
    assert_eq!(
        staged[0].departed_slots,
        vec![DepartedSlot {
            finalized: false,
            slot: SlotId(1),
            kind: DepartureKind::Dropped,
            final_turn_count: None,
        }],
        "the mid-rehome departure rides the resumed descriptor",
    );
}

#[test]
fn a_departure_after_the_rehome_refreshes_the_staged_resumed_descriptors() {
    // A departure notice landing after the rehome committed (and whose
    // reporting relay may die before ever mesh-reconciling with the new
    // relay) must still reach the rehomed relay: the refresh folds it into
    // the staged resumed descriptors, whose idempotent replay seeds it.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup);
    registry::remove(setup.registry(), RelayId(1));
    let RehomeOutcome::NewTarget(_) = rehome(&setup, &tid(), resp.session, RelayId(1), vec![])
    else {
        panic!("expected a NewTarget re-home decision");
    };
    assert_eq!(
        setup.descriptors().current_for(RelayId(2))[0].departed_slots,
        vec![],
        "the rehome staged no departures yet",
    );

    let late = DepartedSlot {
        finalized: false,
        slot: SlotId(1),
        kind: DepartureKind::Left,
        final_turn_count: Some(88),
    };
    refresh_resumed_descriptors(&setup, &tid(), resp.session, || vec![late.clone()]);

    let staged = setup.descriptors().current_for(RelayId(2));
    assert_eq!(staged.len(), 1);
    assert!(staged[0].resumed, "the refreshed descriptor stays resumed");
    assert_eq!(
        staged[0].departed_slots,
        vec![late],
        "the late departure rides the refreshed resumed descriptor",
    );
}

#[test]
fn a_departure_on_a_never_rehomed_session_restages_nothing() {
    // Without a rehome, every serving relay learns departures over the
    // mesh as they happen; the original descriptors carry no departure
    // seeds by design, and the refresh must leave them untouched.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup);

    refresh_resumed_descriptors(&setup, &tid(), resp.session, || {
        vec![DepartedSlot {
            finalized: false,
            slot: SlotId(1),
            kind: DepartureKind::Left,
            final_turn_count: Some(3),
        }]
    });

    for relay_id in setup.serving_relays(&tid(), resp.session) {
        let staged = setup.descriptors().current_for(relay_id);
        assert_eq!(staged.len(), 1);
        assert!(!staged[0].resumed, "an original descriptor stays unresumed");
        assert_eq!(
            staged[0].departed_slots,
            vec![],
            "no departure seeds are staged onto a never-rehomed session",
        );
    }
}

#[test]
fn rehome_moves_the_group_to_a_live_relay_when_the_home_died() {
    // The home relay (1) drops out of the registry; the session's whole group
    // moves to the lowest-id live relay (2), and the rebuilt descriptor is a
    // resumed one carrying the seeded departure and ranking the new relay in the
    // dead one's place.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup);
    registry::remove(setup.registry(), RelayId(1));

    let departed = vec![DepartedSlot {
        finalized: false,
        slot: SlotId(0),
        kind: DepartureKind::Dropped,
        final_turn_count: None,
    }];
    let RehomeOutcome::NewTarget(endpoint) =
        rehome(&setup, &tid(), resp.session, RelayId(1), departed.clone())
    else {
        panic!("expected a NewTarget re-home decision");
    };
    assert_eq!(
        endpoint.relay_id,
        RelayId(2),
        "the lowest-id live relay takes over"
    );
    assert_eq!(
        setup.serving_relays(&tid(), resp.session),
        vec![RelayId(2)],
        "the dead relay is replaced in place in the serving set",
    );

    let staged = setup.descriptors().current_for(RelayId(2));
    assert_eq!(staged.len(), 1);
    assert!(staged[0].resumed, "a rehome descriptor resumes the session");
    assert_eq!(
        staged[0].departed_slots, departed,
        "the seeded departure rides it"
    );
    assert_eq!(staged[0].authority_order, vec![RelayId(2)]);
    assert_eq!(
        staged[0].homed_slots,
        vec![SlotId(0), SlotId(1)],
        "both slots homed on the dead relay move onto R_new's descriptor",
    );
}

#[test]
fn rehome_commit_hook_precedes_resumed_descriptor_publication() {
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup);
    registry::remove(setup.registry(), RelayId(1));
    let committed = std::cell::Cell::new(false);

    let RehomeOutcome::NewTarget(endpoint) = rehome_with_assignment_commit(
        &setup,
        &tid(),
        resp.session,
        RelayId(1),
        Vec::new,
        |replacement| {
            assert_eq!(replacement, RelayId(2));
            assert_eq!(
                setup.serving_relays(&tid(), resp.session),
                vec![RelayId(2)],
                "authoritative membership is committed before the hook",
            );
            assert!(
                setup
                    .descriptors()
                    .current_for(RelayId(2))
                    .iter()
                    .all(|descriptor| descriptor.session != resp.session),
                "the target cannot observe its resumed descriptor before lifecycle commits",
            );
            committed.set(true);
        },
    ) else {
        panic!("expected a NewTarget re-home decision");
    };

    assert_eq!(endpoint.relay_id, RelayId(2));
    assert!(committed.get());
    assert!(
        setup
            .descriptors()
            .current_for(RelayId(2))
            .iter()
            .any(|descriptor| descriptor.session == resp.session),
        "descriptor publication follows the commit hook",
    );
}

#[test]
fn rehome_prefers_a_relay_already_serving_the_session() {
    // Relays 1 (home), 2 (region-b, already serving), and 3 (live but idle).
    // The home dies; the replacement must be relay 2 — already serving the
    // session — not the idle relay 3, even though 3 is a lower id than any
    // non-serving pick would otherwise use.
    let reg = registry::new_registry();
    enroll_relay(&reg, 1, 14900);
    enroll_relay_in_region(&reg, 2, 14901, Some("region-b"));
    enroll_relay(&reg, 3, 14902);
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        tid(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = SessionSetup::new(reg, tenants);
    let resp = create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: two_players_slot_1_in_region_b(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    // serving == {1, 2}; kill serving relay 1.
    registry::remove(setup.registry(), RelayId(1));

    let RehomeOutcome::NewTarget(endpoint) =
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![])
    else {
        panic!("expected a NewTarget re-home decision");
    };
    assert_eq!(
        endpoint.relay_id,
        RelayId(2),
        "a live relay already serving the session is preferred over an idle one",
    );

    // Relay 2's rebuilt descriptor gains slot 0 (moved off the dead relay
    // 1) in addition to its own original slot 1 -- the homed-slot set must
    // follow a rehome, not just freeze at a session's original
    // assignment, or R_new's own admission check would refuse the very
    // slot it was just handed.
    let staged = setup.descriptors().current_for(RelayId(2));
    assert_eq!(staged.len(), 1);
    assert_eq!(
        staged[0].homed_slots,
        vec![SlotId(0), SlotId(1)],
        "the moved slot (0) and R_new's original slot (1) are both homed there now",
    );
}

#[test]
fn rehome_is_idempotent_for_the_same_dead_relay() {
    // A concurrent/repeated re-home naming the same dead relay returns the same
    // target and does not re-mutate the serving set.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup);
    registry::remove(setup.registry(), RelayId(1));

    let first = rehome(&setup, &tid(), resp.session, RelayId(1), vec![]);
    let second = rehome(&setup, &tid(), resp.session, RelayId(1), vec![]);
    assert_eq!(first, second, "a repeat rehome returns the same target");
    assert!(matches!(first, RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(2)));
    assert_eq!(
        setup.serving_relays(&tid(), resp.session),
        vec![RelayId(2)],
        "a repeat rehome did not further mutate the serving set",
    );
}

#[test]
fn rehome_returns_the_recorded_target_after_the_dead_relay_re_enrolls() {
    // A dead relay can restart and re-enroll under a fresh cert after a session
    // has already re-homed off it. A straggler client still pinned to the OLD
    // cert then asks to re-home the same dead relay id. It must get the recorded
    // replacement (relay 2), not `Stay` — a `Stay` would pin it to relay 1's new
    // cert, which its old pin can never accept, wedging it forever.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup);

    // The home relay 1 dies; the first client re-homes the group onto relay 2.
    registry::remove(setup.registry(), RelayId(1));
    let first = rehome(&setup, &tid(), resp.session, RelayId(1), vec![]);
    assert!(
        matches!(first, RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(2)),
        "the first re-home moves the group to relay 2",
    );
    assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(2)]);

    // Relay 1 restarts and re-enrolls under a fresh cert.
    enroll_relay(setup.registry(), 1, 14900);

    // The straggler names the same dead relay 1. Even though relay 1 is enrolled
    // again, the recorded re-home wins: it gets relay 2, not Stay.
    assert_eq!(
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
        RehomeOutcome::NewTarget(RelayEndpoint::from(
            &registry::entry(setup.registry(), RelayId(2)).unwrap()
        )),
        "the recorded replacement overrules the re-enrolled dead relay's liveness",
    );
}

#[test]
fn a_chained_rehome_repoints_earlier_recorded_aliases() {
    // R1 → R2, then R2 → R3, then R2 restarts (live in the registry but
    // serving nothing of this session). A straggler still asking about R1
    // must be sent to R3: the recorded-rehome lookup validates only
    // registry liveness, so a stale R1 → R2 alias would misroute it
    // permanently onto a relay the session no longer uses.
    let setup = setup_with_two_relays_and_tenant();
    enroll_relay(setup.registry(), 3, 14902);
    let resp = create_default_session(&setup);

    registry::remove(setup.registry(), RelayId(1));
    let first = rehome(&setup, &tid(), resp.session, RelayId(1), vec![]);
    assert!(matches!(first, RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(2)));

    registry::remove(setup.registry(), RelayId(2));
    let second = rehome(&setup, &tid(), resp.session, RelayId(2), vec![]);
    assert!(matches!(second, RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(3)));

    // Relay 2 restarts: live again, but no longer serving this session.
    enroll_relay(setup.registry(), 2, 14901);

    assert_eq!(
        recorded_rehome(&setup, &tid(), resp.session, RelayId(1))
            .expect("the straggler's re-ask finds a recorded target")
            .relay_id,
        RelayId(3),
        "the R1 alias follows the chain to the current target, not to the restarted R2",
    );
    assert!(
        matches!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(3)
        ),
        "the in-lock idempotency lookup answers the re-pointed alias too",
    );
}

#[test]
fn rehome_replaces_a_same_id_relay_that_restarted_with_a_new_cert() {
    // The home relay restarts in place: same id, but a fresh self-signed cert
    // from the new process. Every client's pin was to the old cert, which it
    // can never match, so even though the id is still enrolled and still
    // serving, the coordinator must treat this as a mismatch and hand back the
    // same id under its new cert rather than Stay.
    // Relays 5 and 6 (rather than the usual 1 and 2) so a lower-id relay can
    // enroll later without becoming the session's original home -- proving the
    // replacement pick reaches for the restarted relay's own id rather than
    // drifting to whichever live relay happens to sort lowest.
    let reg = registry::new_registry();
    enroll_relay(&reg, 5, 14900);
    enroll_relay(&reg, 6, 14901);
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        tid(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = SessionSetup::new(reg, tenants);
    let resp = create_default_session(&setup);
    assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(5)]);

    // A new, lower-id relay enrolls after the session was created. It must not
    // steal the replacement pick away from the restarted relay's own id.
    enroll_relay(setup.registry(), 1, 14899);
    enroll_relay_with_cert(setup.registry(), 5, 14900, vec![0xEE; 4]);

    let departed = vec![DepartedSlot {
        finalized: false,
        slot: SlotId(0),
        kind: DepartureKind::Dropped,
        final_turn_count: None,
    }];
    let RehomeOutcome::NewTarget(endpoint) =
        rehome(&setup, &tid(), resp.session, RelayId(5), departed.clone())
    else {
        panic!("expected a NewTarget re-home decision");
    };
    assert_eq!(
        endpoint.relay_id,
        RelayId(5),
        "the restarted relay is its own valid replacement, not the newly-idle lower-id relay 1"
    );
    assert_eq!(
        endpoint.cert_der,
        vec![0xEE; 4],
        "the response carries the relay's fresh cert"
    );
    assert_eq!(
        setup.serving_relays(&tid(), resp.session),
        vec![RelayId(5)],
        "membership is unchanged -- the id never left the serving set",
    );

    let staged = setup.descriptors().current_for(RelayId(5));
    assert_eq!(staged.len(), 1);
    assert!(
        staged[0].resumed,
        "a resumed descriptor is re-pushed to the restarted relay"
    );
    assert_eq!(staged[0].departed_slots, departed);
    assert_eq!(
        staged[0].homed_slots,
        vec![SlotId(0), SlotId(1)],
        "both slots stay homed on the relay under its unchanged id",
    );

    let refs = session_refs(&setup, &tid(), resp.session).unwrap();
    assert_eq!(
        refs.relay_certs.get(&RelayId(5)),
        Some(&cert_fingerprint(&[0xEE; 4])),
        "the recorded pin is updated to the relay's fresh cert",
    );
}

#[test]
fn rehome_stays_when_a_relay_reconnects_under_an_unchanged_cert() {
    // A benign control-WS reconnect re-enrolls the same id under a NEW
    // generation but the SAME cert -- a connection blip, not a restart. The
    // enroll generation is deliberately not the signal for a cert change, so
    // this must still answer Stay.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup);

    enroll_relay(setup.registry(), 1, 14900); // same id, same fake_cert(1)

    assert_eq!(
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
        RehomeOutcome::Stay,
    );
    assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(1)]);
}

#[test]
fn create_session_records_each_serving_relays_cert_for_a_cross_relay_session() {
    let setup = setup_with_two_relays_region_b_and_tenant();
    let resp = create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: two_players_slot_1_in_region_b(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;

    let refs = session_refs(&setup, &tid(), resp.session).unwrap();
    assert_eq!(
        refs.relay_certs.get(&RelayId(1)),
        Some(&cert_fingerprint(&fake_cert(1))),
        "relay 1's client-pinned cert is recorded",
    );
    assert_eq!(
        refs.relay_certs.get(&RelayId(2)),
        Some(&cert_fingerprint(&fake_cert(2))),
        "the region-b relay's cert is recorded too",
    );
}
