//! Coordinated drain: a draining relay is ineligible for assignment, and a drain
//! mark linearizes against an in-flight create's pick-to-commit span.

use super::*;

#[test]
fn create_session_skips_a_draining_relay() {
    // Relay 1 (the default primary) drains; a create homes on the still-available
    // relay 2 and never names relay 1 in its outbox.
    let (setup, g1, _g2) = two_relay_setup();
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
    let (setup, g1) = one_relay_setup();
    registry::mark_draining(setup.registry(), RelayId(1), g1);

    let err = create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap_err();
    assert_eq!(err, SessionSetupError::NoRelaysAvailable);
}

#[test]
fn rehome_replacement_pick_never_selects_a_draining_relay() {
    // Home relay 1 dies; the only other live relay (2) is draining, so the
    // replacement pick refuses it (there is no other live relay) — Unavailable
    // rather than re-homing the whole group onto a relay that asked to stop.
    let (setup, _g1, g2) = two_relay_setup();
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
    let (setup, g1, _g2) = two_relay_setup();
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
    let (setup, g1) = one_relay_setup();

    let (seam_tx, seam_rx) = std::sync::mpsc::channel();
    let setup_a = setup.clone();
    let a = std::thread::spawn(move || {
        create_session_inner(
            &setup_a,
            SessionRequest {
                tenant: tid(),
                players: two_players(),
                external_id: None,
                latency_estimate_ms: None,
            },
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

#[test]
fn concurrent_creates_and_a_drain_never_name_the_relay_without_staging_it() {
    // The stochastic form of the invariant: N threads hammer create_session on a
    // single relay while one thread marks it draining. Every session a create
    // returned Ok for necessarily committed before the mark (a post-mark create
    // sees the relay draining and fails NoRelaysAvailable), so it must be staged in
    // the relay's descriptor outbox as observed at the mark point — "set before
    // ack: an empty set at ack means provably unassigned", proven at coordinator
    // state level with no sockets.
    let (setup, g1) = one_relay_setup();

    let created: Arc<Mutex<Vec<SessionId>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let setup = setup.clone();
        let created = Arc::clone(&created);
        handles.push(std::thread::spawn(move || {
            for _ in 0..25 {
                if let Ok(resp) = create_session(
                    &setup,
                    SessionRequest {
                        tenant: tid(),
                        players: two_players(),
                        external_id: None,
                        latency_estimate_ms: None,
                    },
                    ExpiresAt(u64::MAX),
                ) {
                    created.lock().push(resp.response.session);
                }
            }
        }));
    }

    // Mark the relay draining partway through, then snapshot its outbox — the
    // coordinator-side ack point. After the mark, no further create can stage a
    // descriptor for the relay, so this snapshot is the complete set of sessions
    // that will ever name it.
    std::thread::sleep(std::time::Duration::from_millis(2));
    {
        let _assign = setup.lock_assignment();
        registry::mark_draining(setup.registry(), RelayId(1), g1);
    }
    let staged: std::collections::HashSet<SessionId> = setup
        .descriptors()
        .current_for(RelayId(1))
        .into_iter()
        .map(|d| d.session)
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    let created = created.lock();
    assert!(
        !created.is_empty(),
        "some creates committed before the drain"
    );
    for session in created.iter() {
        assert!(
            staged.contains(session),
            "every Ok session is staged in the relay's outbox at the drain point",
        );
    }
}
