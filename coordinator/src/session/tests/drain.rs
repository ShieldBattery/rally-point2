//! Coordinated drain: a draining relay is ineligible for assignment, and a drain
//! mark linearizes against an in-flight create's pick-to-commit span.

use super::*;

#[test]
fn create_session_skips_a_draining_relay() {
    // Relay 1 (the default primary) drains; a create homes on the still-available
    // relay 2 and never names relay 1 in its outbox.
    let (setup, g1, _g2) = two_relay_fleet_with_generations();
    assert!(registry::mark_draining(setup.registry(), RelayId(1), g1));

    let resp = create_default_session(&setup);
    assert_eq!(
        resp.home_relay.relay_id,
        RelayId(2),
        "a create skips the draining relay and homes on the available one",
    );
    assert!(
        setup.descriptors().current_for(RelayId(1)).is_empty(),
        "the drained relay's outbox gains no session from a post-mark create",
    );
}

#[test]
fn all_relays_draining_yields_no_relays_available() {
    let (setup, g1) = one_relay_fleet_with_generation();
    registry::mark_draining(setup.registry(), RelayId(1), g1);

    let err = create_session(&setup, request(two_players()), ExpiresAt(u64::MAX)).unwrap_err();
    assert_eq!(err, SessionSetupError::NoRelaysAvailable);
}

#[test]
fn rehome_replacement_pick_never_selects_a_draining_relay() {
    // Home relay 1 dies; the only other live relay (2) is draining, so the
    // replacement pick refuses it (there is no other live relay) — Unavailable
    // rather than re-homing the whole group onto a relay that asked to stop.
    let (setup, _g1, g2) = two_relay_fleet_with_generations();
    let resp = create_default_session(&setup); // serving == {1}
    registry::remove(setup.registry(), RelayId(1));
    registry::mark_draining(setup.registry(), RelayId(2), g2);

    assert_eq!(
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
        RehomeOutcome::Unavailable,
        "a draining relay is never chosen as a re-home target",
    );
}

#[test]
fn rehome_for_a_serving_but_draining_relay_returns_stay() {
    // The dead-named relay is enrolled AND still serving, only draining. Drain
    // blocks NEW assignments; a draining relay still serving is alive, so the
    // stay-check (unchanged — it reads registry liveness, not availability)
    // correctly overrules the client's belief that it died.
    let (setup, g1, _g2) = two_relay_fleet_with_generations();
    let resp = create_default_session(&setup); // serving == {1}
    registry::mark_draining(setup.registry(), RelayId(1), g1);

    assert_eq!(
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
        RehomeOutcome::Stay,
        "a draining relay still serving its session is alive: Stay, not a move",
    );
}

#[test]
fn a_drain_mark_racing_create_session_is_linearized_after_the_commit() {
    // The deterministic interleaving: thread A enters create_session's critical
    // section and pauses at the seam (holding the assignment lock); thread B's
    // drain mark must block on that lock until A commits, so B's post-mark view of
    // the relay's descriptor outbox already includes A's just-created session.
    let (setup, g1) = one_relay_fleet_with_generation();

    let (seam_tx, seam_rx) = std::sync::mpsc::channel();
    let setup_a = setup.clone();
    let a = std::thread::spawn(move || {
        create_session_inner(
            &setup_a,
            request(two_players()),
            ExpiresAt(u64::MAX),
            || {
                // Reached the seam (past the pick, before the commit). Signal, then
                // linger so B has time to contend on the assignment lock A holds.
                seam_tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(50));
            },
        )
        .unwrap()
    });

    seam_rx.recv().unwrap(); // A is in its critical section, holding the lock
    {
        // B's drain mark blocks on the assignment lock until A commits and releases.
        let _assign = setup.lock_assignment();
        assert!(registry::mark_draining(setup.registry(), RelayId(1), g1));
    }
    let resp = a.join().unwrap();

    assert!(
        setup
            .descriptors()
            .current_for(RelayId(1))
            .iter()
            .any(|d| d.session == resp.response.session),
        "A committed before B could mark, so A's session is staged in the outbox",
    );
    assert!(
        !registry::is_available(setup.registry(), RelayId(1)),
        "the relay is now draining",
    );
}
