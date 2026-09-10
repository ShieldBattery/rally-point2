//! Re-home and membership interactions with the all-relays-closed condition:
//! swapped-out relays, late closes, unassigned closes, and the webhook-only
//! state's membership retirement.

use super::*;

/// A two-relay setup — both enrolled, only relay 1 serving (the session's
/// default, unsplit assignment) — with the tenant's notify URL wired to
/// `url`, so a test can observe the final `sessionClosed` webhook.
fn setup_with_two_relays_and_session(url: String) -> (SessionSetup, SessionId) {
    use rally_point_proto::control::{PlayerHandoff, RelayHello, SessionRequest};
    use rally_point_proto::token::{ClientPublicKey, ExpiresAt};
    use rally_point_proto::version::ProtocolVersion;

    let reg = registry::new_registry();
    for (id, port) in [(1u64, 14900u16), (2, 14901)] {
        registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(id),
                std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                ProtocolVersion::CURRENT,
                vec![id as u8; 4],
            ),
        );
    }
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("k1".to_owned()),
        tid(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    tenant::set_notify(&tenants, &tid(), Some(NotifyConfig { url }));
    let setup = SessionSetup::new(reg, tenants);
    let resp = crate::session::create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: vec![
                PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([0xAA; 32]),
                    external_ref: None,
                    observer: false,
                    region: None,
                },
                PlayerHandoff {
                    slot: SlotId(1),
                    client_pubkey: ClientPublicKey([0xBB; 32]),
                    external_ref: None,
                    observer: false,
                    region: None,
                },
            ],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    (setup, resp.session)
}

#[tokio::test]
async fn rehome_then_the_replacements_close_satisfies_all_relays_closed_and_reaps_the_state() {
    // A rehome must keep the lifecycle's cached serving set in step with the
    // mutation `session::rehome` applies to the session's real membership --
    // otherwise the relay it swapped onto is never recognized as needing to
    // report closed, `all_relays_closed` can never be satisfied, and the
    // session's state (and its drain queue task) leaks for the process
    // lifetime instead of being reaped here.
    use crate::session::{self, RehomeOutcome};

    let (url, mut rx) = spawn_receiver(None).await;
    let (setup, s) = setup_with_two_relays_and_session(url);
    let lc = Lifecycle::with_graces(setup.clone(), HOUR, HOUR, HOUR);
    lc.register_session(
        tid(),
        s,
        setup.serving_relays(&tid(), s),
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    assert_eq!(setup.serving_relays(&tid(), s), vec![RelayId(1)]);

    registry::remove(setup.registry(), RelayId(1));
    let RehomeOutcome::NewTarget(endpoint) = session::rehome(&setup, &tid(), s, RelayId(1), vec![])
    else {
        panic!("expected a NewTarget re-home decision");
    };
    assert_eq!(endpoint.relay_id, RelayId(2));
    lc.on_rehome(&tid(), s, RelayId(1), RelayId(2));

    // The replacement's own close satisfies all-relays-closed (the cached set
    // now names only relay 2) and reaps the state: the final webhook fires, and
    // the session is no longer alive or tracked at all.
    close(&lc, tid(), s, RelayId(2));
    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("sessionClosed is delivered once the swapped-in relay closes")
        .unwrap();
    assert_eq!(got.event, "sessionClosed");
    assert!(
        !lc.is_alive(&tid(), s),
        "a fully-closed session is not alive"
    );
    assert!(
        !lc.contains_state(&tid(), s),
        "the session's lifecycle state and drain queue are reaped, not left immortal",
    );
}

#[tokio::test]
async fn a_late_close_from_the_swapped_out_dead_relay_is_ignored() {
    // A dead relay can briefly reconnect after a partition and flush a stale
    // SessionClosed for a session a rehome already swapped it out of. That
    // late report must not satisfy all-relays-closed on its own, and must not
    // disturb the real serving relay's own close finishing the session
    // normally afterward.
    use crate::session::{self, RehomeOutcome};

    let (url, mut rx) = spawn_receiver(None).await;
    let (setup, s) = setup_with_two_relays_and_session(url);
    let lc = Lifecycle::with_graces(setup.clone(), HOUR, HOUR, HOUR);
    lc.register_session(
        tid(),
        s,
        setup.serving_relays(&tid(), s),
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );

    registry::remove(setup.registry(), RelayId(1));
    let RehomeOutcome::NewTarget(endpoint) = session::rehome(&setup, &tid(), s, RelayId(1), vec![])
    else {
        panic!("expected a NewTarget re-home decision");
    };
    assert_eq!(endpoint.relay_id, RelayId(2));
    lc.on_rehome(&tid(), s, RelayId(1), RelayId(2));

    close(&lc, tid(), s, RelayId(1)); // the swapped-out dead relay's late report
    assert!(
        lc.is_alive(&tid(), s),
        "a close from a relay no longer in the cached serving set does not finish the session",
    );
    assert!(
        timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "no sessionClosed fires from the stale close alone",
    );

    close(&lc, tid(), s, RelayId(2));
    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the real serving relay's close still finishes the session")
        .unwrap();
    assert_eq!(got.event, "sessionClosed");
}

#[tokio::test]
async fn rehome_swap_composes_with_a_surviving_relay_that_was_already_serving() {
    // A balanced cross-region session on relays 1 (region-a) and 2 (region-b).
    // Relay 2 asks to drain -- still a serving member, but excluded from the
    // replacement pick -- so when relay 1 dies its group moves onto the idle
    // relay 3 instead, leaving BOTH 3 (the replacement) and 2 (the
    // drained-but-still-serving survivor) in the cached set. Both must report
    // closed before the session finishes.
    use crate::session::{self, RehomeOutcome};
    use rally_point_proto::control::{PlayerHandoff, RegionId, RelayHello, SessionRequest};
    use rally_point_proto::token::{ClientPublicKey, ExpiresAt};
    use rally_point_proto::version::ProtocolVersion;

    let (url, mut rx) = spawn_receiver(None).await;
    let reg = registry::new_registry();
    registry::enroll(
        &reg,
        RelayHello::new(
            RelayId(1),
            std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
            vec![1u8; 4],
        )
        .with_region(RegionId("region-a".to_owned())),
    );
    let gen2 = registry::enroll(
        &reg,
        RelayHello::new(
            RelayId(2),
            std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
            ProtocolVersion::CURRENT,
            vec![2u8; 4],
        )
        .with_region(RegionId("region-b".to_owned())),
    );
    registry::enroll(
        &reg,
        RelayHello::new(
            RelayId(3),
            std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 14902)),
            ProtocolVersion::CURRENT,
            vec![3u8; 4],
        ),
    );
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("k1".to_owned()),
        tid(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    tenant::set_notify(&tenants, &tid(), Some(NotifyConfig { url }));
    let setup = SessionSetup::new(reg, tenants);

    let resp = crate::session::create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: vec![
                PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([0xAA; 32]),
                    external_ref: None,
                    observer: false,
                    region: Some(RegionId("region-a".to_owned())),
                },
                PlayerHandoff {
                    slot: SlotId(1),
                    client_pubkey: ClientPublicKey([0xBB; 32]),
                    external_ref: None,
                    observer: false,
                    region: Some(RegionId("region-b".to_owned())),
                },
            ],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    let s = resp.session;
    let original_order = setup.serving_relays(&tid(), s);
    assert_eq!(original_order[0], resp.home_relay.relay_id);
    assert_eq!(
        original_order.iter().copied().collect::<HashSet<_>>(),
        HashSet::from([RelayId(1), RelayId(2)]),
    );

    let lc = Lifecycle::with_graces(setup.clone(), HOUR, HOUR, HOUR);
    lc.register_session(
        tid(),
        s,
        original_order.clone(),
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );

    assert!(registry::mark_draining(setup.registry(), RelayId(2), gen2));
    registry::remove(setup.registry(), RelayId(1));

    let RehomeOutcome::NewTarget(endpoint) = session::rehome(&setup, &tid(), s, RelayId(1), vec![])
    else {
        panic!("expected a NewTarget re-home decision");
    };
    assert_eq!(
        endpoint.relay_id,
        RelayId(3),
        "the draining relay 2 is skipped for the idle live relay 3",
    );
    let expected_order: Vec<RelayId> = original_order
        .into_iter()
        .map(|relay| {
            if relay == RelayId(1) {
                RelayId(3)
            } else {
                relay
            }
        })
        .collect();
    assert_eq!(setup.serving_relays(&tid(), s), expected_order);
    lc.on_rehome(&tid(), s, RelayId(1), RelayId(3));

    close(&lc, tid(), s, RelayId(3));
    assert!(lc.is_alive(&tid(), s), "relay 2 hasn't closed yet");

    close(&lc, tid(), s, RelayId(2));
    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("sessionClosed fires once both the replacement and the surviving relay close")
        .unwrap();
    assert_eq!(got.event, "sessionClosed");
}

#[tokio::test]
async fn an_unassigned_close_cannot_seed_a_future_assignment() {
    // A relay id may have served this session in an earlier topology or may be
    // selected by a future re-home. A terminal notice while it is not in the
    // cached assignment must not be retained and reused later.
    let (url, mut rx) = spawn_receiver(None).await;
    let setup = setup_with_notify(url);
    let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
    let s = SessionId(1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );

    // R2 is not assigned yet, so its close is ignored.
    close(&lc, tid(), s, RelayId(2));
    assert!(
        lc.is_alive(&tid(), s),
        "a close from a not-yet-swapped-in relay does not finish the session on its own",
    );

    // The later swap cannot inherit that unassigned mark.
    lc.inner
        .setup
        .set_session_membership_for_test(&tid(), s, vec![RelayId(2)]);
    lc.on_rehome(&tid(), s, RelayId(1), RelayId(2));
    assert!(lc.is_alive(&tid(), s));
    assert!(rx.try_recv().is_err());

    // A post-swap close is scoped to the installed assignment and retires it.
    close(&lc, tid(), s, RelayId(2));
    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the replacement's post-swap close delivers sessionClosed")
        .unwrap();
    assert_eq!(got.event, "sessionClosed");
    assert!(
        !lc.is_alive(&tid(), s),
        "a fully-closed session is not alive"
    );
    assert!(
        !lc.contains_state(&tid(), s),
        "the session's lifecycle state and drain queue are reaped, not stranded",
    );
}

#[tokio::test]
async fn session_closed_requires_matching_authoritative_membership() {
    let setup = bare_setup();
    let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
    let s = SessionId(101);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );
    lc.on_relay_enrolled(RelayId(1), 1);

    // Cached lifecycle membership alone is insufficient. This is the state
    // after authoritative membership has already been retired.
    lc.on_session_closed(tid(), s, RelayId(1), 1);
    assert!(lc.contains_state(&tid(), s));

    // A nonempty authoritative set assigning the session elsewhere rejects
    // the same unassigned close as well.
    lc.inner
        .setup
        .set_session_membership_for_test(&tid(), s, vec![RelayId(2)]);
    lc.on_session_closed(tid(), s, RelayId(1), 1);
    assert!(lc.contains_state(&tid(), s));

    // Both the authoritative and cached assignment now name the current
    // connection, so its terminal notice is accepted and retires the state.
    lc.inner
        .setup
        .set_session_membership_for_test(&tid(), s, vec![RelayId(1)]);
    lc.on_session_closed(tid(), s, RelayId(1), 1);
    assert!(!lc.contains_state(&tid(), s));
}

#[tokio::test]
async fn rehome_reopens_a_target_that_already_served_and_previously_closed() {
    // A resumed descriptor can give an already-serving target a newly homed
    // group. Its earlier close therefore belongs to the old assignment and
    // must not retire the resumed one immediately.
    let (url, mut rx) = spawn_receiver(None).await;
    let setup = setup_with_notify(url);
    let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
    let s = SessionId(1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );

    close(&lc, tid(), s, RelayId(2));
    assert!(lc.is_alive(&tid(), s), "R1 has not closed yet");

    // Re-home R1 onto the already-serving R2. Its earlier mark is reopened.
    lc.on_rehome(&tid(), s, RelayId(1), RelayId(2));
    assert!(lc.is_alive(&tid(), s));
    assert!(rx.try_recv().is_err());

    close(&lc, tid(), s, RelayId(2));
    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the target's post-rehome close finishes the session")
        .unwrap();
    assert_eq!(got.event, "sessionClosed");
    assert!(
        !lc.is_alive(&tid(), s),
        "a fully-closed session is not alive"
    );
}

#[tokio::test]
async fn a_rehome_preflight_without_a_commit_preserves_terminal_evidence() {
    // Stay and Unavailable outcomes run the preflight reset but have no new
    // assignment. A close recorded on the unchanged set must remain valid.
    let setup = bare_setup();
    let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
    let s = SessionId(2);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );

    close(&lc, tid(), s, RelayId(1));
    lc.prepare_rehome(&tid(), s);
    close(&lc, tid(), s, RelayId(2));

    assert!(
        !lc.contains_state(&tid(), s),
        "a failed/no-op rehome cannot discard an unchanged assignment's close",
    );
}

#[tokio::test]
async fn on_rehome_is_a_no_op_for_a_same_id_swap() {
    // A same-id restart's `NewTarget` names the relay's own id as both dead
    // and replacement. The cached serving set never dropped the id in the
    // first place, so composing `on_rehome` with it must leave the set
    // untouched rather than dropping the relay entirely.
    let setup = bare_setup();
    let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
    let s = SessionId(1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );

    // A close can land after the preflight reset but before rehome acquires
    // the assignment lock. The under-lock same-id commit must reopen it even
    // though the serving vector itself does not change.
    lc.prepare_rehome(&tid(), s);
    close(&lc, tid(), s, RelayId(1));
    lc.on_rehome(&tid(), s, RelayId(1), RelayId(1));

    // Close ONLY relay 2. If the same-id swap had wrongly dropped relay 1, or
    // retained its pre-commit close, this alone would finish the session.
    close(&lc, tid(), s, RelayId(2));
    assert!(
        lc.is_alive(&tid(), s),
        "relay 1 hasn't closed yet -- the same-id swap did not drop it from the set",
    );

    close(&lc, tid(), s, RelayId(1));
    assert!(
        !lc.is_alive(&tid(), s),
        "both original members closing finishes it"
    );
}

#[tokio::test]
async fn webhook_only_reap_retires_membership_harmlessly() {
    // A webhook-only state (restart amnesia) has no membership to begin with, so
    // its idle reap runs the same retirement as a no-op. It must not panic, and
    // the session stays unavailable to re-home afterward.
    use crate::session::{self, RehomeOutcome};

    let (url, mut rx) = spawn_receiver(None).await;
    let setup = setup_with_notify(url.clone());
    let lc = Lifecycle::with_graces(setup.clone(), HOUR, HOUR, SHORT);
    let s = SessionId(1);

    lc.enqueue_webhook(
        tid(),
        s,
        NotifyConfig { url },
        Bytes::from_static(br#"{"event":"departure"}"#),
        "departure",
    );
    assert!(
        setup.serving_relays(&tid(), s).is_empty(),
        "a webhook-only session never had membership",
    );

    // Let its queued webhook deliver, then wait for the idle reap to remove it.
    let _ = timeout(Duration::from_secs(2), rx.recv()).await;
    timeout(SHORT * 20, async {
        loop {
            if !lc.contains_state(&tid(), s) {
                break;
            }
            tokio::time::sleep(SHORT / 4).await;
        }
    })
    .await
    .expect("the webhook-only state is reaped after its idle grace");

    assert!(setup.serving_relays(&tid(), s).is_empty());
    assert_eq!(
        session::rehome(&setup, &tid(), s, RelayId(1), vec![]),
        RehomeOutcome::Unavailable,
        "still unavailable after the no-op membership retirement",
    );
}
