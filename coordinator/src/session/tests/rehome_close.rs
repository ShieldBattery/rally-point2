//! Where a re-home refuses to act, and how it interleaves with a session close:
//! unknown sessions, a mis-named relay, retired membership, and the descriptor /
//! record clean-up on either ordering of a close and a completed re-home.

use super::*;

#[test]
fn rehome_unavailable_for_an_unknown_session() {
    // The dead relay is gone (else the stay-guard short-circuits); an unknown
    // session has no serving set to move.
    let setup = setup_with_two_relays_and_tenant();
    registry::remove(setup.registry(), RelayId(1));
    assert_eq!(
        rehome(&setup, &tid(), SessionId(999_999), RelayId(1), vec![]),
        RehomeOutcome::Unavailable,
    );
}

#[test]
fn rehome_unavailable_when_no_relay_can_take_over() {
    // Every relay has left the registry, so there is nobody to move the session
    // to.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup);
    registry::remove(setup.registry(), RelayId(1));
    registry::remove(setup.registry(), RelayId(2));
    assert_eq!(
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
        RehomeOutcome::Unavailable,
    );
}

#[test]
fn rehome_unavailable_when_the_named_relay_does_not_serve_the_session() {
    // `dead_relay` comes from the request body. A client that names a relay that
    // is neither still enrolled (so the stay-guard doesn't fire) nor a member of
    // the session's serving set must get Unavailable — with no mutation, no
    // resumed-descriptor push, and no idempotency entry recorded, so a bogus name
    // can't disturb an otherwise-healthy session.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup);

    // The session serves only its home relay 1. Relay 99 was never enrolled and
    // never served it, so it passes the stay-guard yet is not a serving member.
    let before_serving = setup.serving_relays(&tid(), resp.session);
    assert_eq!(before_serving, vec![RelayId(1)]);
    let baseline_descriptor = setup.descriptors().current_for(RelayId(1));

    assert_eq!(
        rehome(
            &setup,
            &tid(),
            resp.session,
            RelayId(99),
            vec![DepartedSlot {
                finalized: false,
                slot: SlotId(0),
                kind: DepartureKind::Dropped,
                final_turn_count: None,
            }],
        ),
        RehomeOutcome::Unavailable,
    );

    // The serving set is untouched, and no resumed descriptor was pushed to the
    // healthy relay (its outbox still holds exactly the create_session baseline).
    assert_eq!(setup.serving_relays(&tid(), resp.session), before_serving);
    assert_eq!(
        setup.descriptors().current_for(RelayId(1)),
        baseline_descriptor,
        "a non-serving dead-relay name must not re-push descriptors",
    );

    // Re-asking about the same unrelated relay is still Unavailable — no
    // idempotency entry was recorded that would echo a spurious target.
    assert_eq!(
        rehome(&setup, &tid(), resp.session, RelayId(99), vec![]),
        RehomeOutcome::Unavailable,
    );

    // And the session is otherwise unharmed: when its real home relay dies, a
    // correctly-named rehome still moves the group to the live relay 2.
    registry::remove(setup.registry(), RelayId(1));
    assert!(matches!(
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
        RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(2),
    ));
}

#[test]
fn forget_session_membership_retires_maps_and_refuses_rehome() {
    // Retiring a closed session's membership must empty both `session_relays`
    // and `session_refs`, and — with no serving set left — turn any further
    // re-home ask into `Unavailable`, so a straggler cannot resurrect the game.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: two_players(),
            external_id: Some("game-42".to_owned()),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    assert!(!setup.serving_relays(&tid(), resp.session).is_empty());
    assert!(session_refs(&setup, &tid(), resp.session).is_some());

    // Record a rehome first, so we can also prove the recorded fast path stops
    // matching once membership is retired (its rehomes are cleared elsewhere,
    // but even the standalone lookup must not resurrect a closed session).
    registry::remove(setup.registry(), RelayId(1));
    assert!(matches!(
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
        RehomeOutcome::NewTarget(_),
    ));

    setup.forget_session_membership(&tid(), resp.session);
    setup.forget_rehomes(&tid(), resp.session);

    assert!(
        setup.serving_relays(&tid(), resp.session).is_empty(),
        "membership retirement empties the serving set",
    );
    assert!(
        session_refs(&setup, &tid(), resp.session).is_none(),
        "membership retirement drops the correlation ids",
    );
    assert_eq!(
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
        RehomeOutcome::Unavailable,
        "a session with no membership refuses re-home",
    );
    assert!(
        recorded_rehome(&setup, &tid(), resp.session, RelayId(1)).is_none(),
        "no recorded target survives to resurrect the closed session",
    );
}

#[test]
fn rehome_removes_the_dead_relays_descriptor_so_a_re_enroll_is_not_re_synced() {
    // When the group moves off a dead relay, that relay's descriptor outbox entry
    // for the session must be removed — else a re-enrolling dead relay would be
    // re-synced a descriptor for a session it no longer serves and rejoin it.
    let setup = setup_with_two_relays_region_b_and_tenant();
    let resp = create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            // Slot 1 names region-b so both relays serve (and each has a
            // descriptor staged).
            players: two_players_slot_1_in_region_b(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    assert!(
        setup
            .descriptors()
            .current_for(RelayId(1))
            .iter()
            .any(|d| d.session == resp.session),
        "the serving relay has a descriptor before it dies",
    );

    // Serving relay 1 dies; its group re-homes onto already-serving relay 2.
    registry::remove(setup.registry(), RelayId(1));
    assert!(matches!(
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
        RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(2),
    ));

    // The dead relay's outbox no longer carries the moved-off session, so a
    // re-enrolling relay 1 subscribing afresh is not told to serve it.
    assert!(
        setup
            .descriptors()
            .current_for(RelayId(1))
            .iter()
            .all(|d| d.session != resp.session),
        "the dead relay's descriptor for the moved-off session was removed",
    );
    let rx = setup.descriptors().subscribe(RelayId(1));
    assert!(!rx.borrow().iter().any(|d| d.session == resp.session));
}

#[test]
fn a_rehome_racing_a_full_close_bails_without_recording_or_pushing() {
    // A rehome that has already passed the early serving-set snapshot, then has a
    // full close land before its mutation, must re-validate under the mutation
    // lock and return Unavailable — recording no rehome (which recorded_rehome
    // would otherwise serve token-free) and pushing no descriptor (which could
    // resurrect the dead session on a live relay). The `before_mutation` seam
    // simulates the close landing in exactly that window.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup); // serving == {1}
    registry::remove(setup.registry(), RelayId(1)); // the home died, so not Stay

    let baseline_relay2 = setup.descriptors().current_for(RelayId(2));

    let outcome = rehome_inner(
        &setup,
        &(tid(), resp.session),
        RelayId(1),
        true,
        Vec::new,
        || {
            // The concurrent full close clears the session's membership between the
            // snapshot and the mutation (its forget_rehomes would block on the
            // rehomes lock this rehome holds, so only membership is cleared here —
            // faithfully modeling the race window).
            setup.forget_session_membership(&tid(), resp.session);
        },
        |_| {},
    );

    assert_eq!(
        outcome,
        RehomeOutcome::Unavailable,
        "a rehome that raced a close bails instead of resurrecting the session",
    );
    assert!(
        recorded_rehome(&setup, &tid(), resp.session, RelayId(1)).is_none(),
        "the raced rehome recorded no idempotency entry to serve token-free",
    );
    assert_eq!(
        setup.descriptors().current_for(RelayId(2)),
        baseline_relay2,
        "the raced rehome pushed no resumed descriptor to a live relay",
    );
}

#[test]
fn a_full_close_after_a_completed_rehome_clears_the_new_relays_descriptor_and_record() {
    // The complement of the racing-rehome test: when a rehome completes FULLY —
    // recording its idempotency entry and pushing a resumed descriptor to the new
    // relay — BEFORE a full close, the close must still clean up after it. The
    // close takes the session's membership atomically, and that snapshot now
    // includes the new relay the completed rehome added, so the close removes the
    // new relay's descriptor too and its forget_rehomes clears the recorded entry.
    let setup = setup_with_two_relays_and_tenant();
    let resp = create_default_session(&setup); // serving == {1}
    registry::remove(setup.registry(), RelayId(1)); // the home died, so not Stay

    // A full rehome moves the group onto relay 2: it records the idempotency entry
    // and pushes a resumed descriptor to relay 2.
    assert!(matches!(
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
        RehomeOutcome::NewTarget(ref e) if e.relay_id == RelayId(2),
    ));
    assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(2)]);
    assert!(
        setup
            .descriptors()
            .current_for(RelayId(2))
            .iter()
            .any(|d| d.session == resp.session),
        "the completed rehome staged a resumed descriptor on the new relay",
    );
    assert!(
        recorded_rehome(&setup, &tid(), resp.session, RelayId(1)).is_some(),
        "the completed rehome recorded an idempotency entry",
    );

    // A full close, in the coordinator's take-first order: take the membership
    // snapshot (it now includes relay 2), remove each taken relay's descriptor,
    // then forget the recorded rehomes.
    let taken = setup.take_session_membership(&tid(), resp.session);
    assert_eq!(
        taken,
        vec![RelayId(2)],
        "the taken snapshot includes the relay the completed rehome added",
    );
    for relay_id in taken {
        setup.descriptors().remove(relay_id, &tid(), resp.session);
    }
    setup.forget_rehomes(&tid(), resp.session);

    // The new relay's descriptor for the closed session is gone from its outbox,
    // and a relay resubscribing after the close is not re-synced it.
    assert!(
        setup
            .descriptors()
            .current_for(RelayId(2))
            .iter()
            .all(|d| d.session != resp.session),
        "the close removed the new relay's descriptor for the closed session",
    );
    let rx = setup.descriptors().subscribe(RelayId(2));
    assert!(
        !rx.borrow().iter().any(|d| d.session == resp.session),
        "a fresh subscribe for the new relay lacks the closed session",
    );

    // No recorded rehome survives to be served token-free after the close.
    assert!(
        recorded_rehome(&setup, &tid(), resp.session, RelayId(1)).is_none(),
        "the close cleared the recorded rehome",
    );
}
