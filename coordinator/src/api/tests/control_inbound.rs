//! Inbound control frames: heartbeat ingest (presence, load state, backbone
//! RTTs), the generation fences, and the per-beat wire-shape caps.

use super::*;

/// A `Heartbeat` framed as an inbound control message, carrying the given
/// `(region, rtt_ms)` backbone measurements and an empty session roster.
fn heartbeat_with_rtts(rtts: &[(&str, u32)]) -> Message {
    let region_rtts = rtts
        .iter()
        .map(|(region, rtt_ms)| RegionRttReport {
            region: RegionId((*region).to_owned()),
            rtt_ms: *rtt_ms,
        })
        .collect();
    let heartbeat = RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: vec![],
        region_rtts,
    };
    Message::Text(serde_json::to_string(&heartbeat).unwrap().into())
}

/// A `Heartbeat` framed as an inbound control message, carrying the given
/// session roster and no RTT reports.
fn heartbeat_with_sessions(sessions: Vec<rally_point_proto::control::SessionPresence>) -> Message {
    let heartbeat = RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions,
        region_rtts: vec![],
    };
    Message::Text(serde_json::to_string(&heartbeat).unwrap().into())
}

#[test]
fn a_current_heartbeat_folds_region_rtts_and_a_stale_one_does_not() {
    // A relay enrolled in region-a reports a round-trip to region-b. The reports
    // fold into the pair store — but only from the relay's CURRENT connection: a
    // superseded (stale-generation) beat is dropped whole, the same fence presence
    // is under.
    let reg = registry::new_registry();
    let hello = RelayHello::new(
        RelayId(1),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion::CURRENT,
        vec![0xC1; 4],
    )
    .with_region(RegionId("region-a".to_owned()));
    // Enroll twice: the second connection supersedes the first, so the first
    // generation is no longer current.
    let stale_generation = registry::enroll(&reg, hello.clone());
    let current_generation = registry::enroll(&reg, hello);
    let setup = crate::session::SessionSetup::new(reg, crate::tenant::new_store());
    let lifecycle = Lifecycle::new(setup.clone());
    let notices = notify::new_dedup();
    let regions = regions_config(&["region-a", "region-b"]);
    let relay_region = RegionId("region-a".to_owned());
    let store = pair_rtts::new_store();
    let rtt = RegionRttIngest {
        relay_region: Some(&relay_region),
        regions: &regions,
        store: &store,
        ledger: None,
    };
    let beat = heartbeat_with_rtts(&[("region-b", 87)]);

    // The stale connection's beat writes nothing.
    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        stale_generation,
        &beat,
        &rtt,
    );
    assert!(
        store.snapshot().is_empty(),
        "a superseded connection's heartbeat writes no backbone RTTs",
    );

    // The current connection's beat folds the pair in.
    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        current_generation,
        &beat,
        &rtt,
    );
    let snap = store.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].a, RegionId("region-a".to_owned()));
    assert_eq!(snap[0].b, RegionId("region-b".to_owned()));
    assert_eq!(snap[0].rtt_ms, 87);

    // A report for a region the coordinator does not configure is dropped, leaving
    // the known pair untouched.
    let unknown = heartbeat_with_rtts(&[("region-z", 42)]);
    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        current_generation,
        &unknown,
        &rtt,
    );
    assert_eq!(
        store.snapshot().len(),
        1,
        "a report for an unconfigured region is dropped",
    );

    // The reverse direction, measured from region-b, lands in the OTHER slot rather
    // than overwriting region-a's reading: the served value becomes their average,
    // and the pair stays a single served row.
    let relay_region_b = RegionId("region-b".to_owned());
    let rtt_from_b = RegionRttIngest {
        relay_region: Some(&relay_region_b),
        regions: &regions,
        store: &store,
        ledger: None,
    };
    ingest_region_rtts(
        &rtt_from_b,
        RelayId(2),
        &[RegionRttReport {
            region: RegionId("region-a".to_owned()),
            rtt_ms: 93,
        }],
    );
    let snap = store.snapshot();
    assert_eq!(snap.len(), 1, "the two directions serve one pair");
    assert_eq!(
        snap[0].rtt_ms, 90,
        "both directions fold in and average: (87 + 93) / 2 = 90",
    );
}

#[tokio::test]
async fn a_heartbeats_load_state_reaches_the_lifecycle_without_notifying_the_tenant() {
    // The durability half of load reporting: the beat restates the relay's
    // whole retained state, so the load-state read is right even if every
    // notice was lost. It must stay silent to the tenant, though — these facts
    // were already notified, and re-firing them every beat would flood the
    // feed.
    let (setup, notices, lifecycle, session) =
        setup_with_session_and_notify("http://127.0.0.1:1/hook".to_owned());
    let tenant = TenantId("sb-test".to_owned());
    lifecycle.register_session(
        tenant.clone(),
        session,
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0), SlotId(1)]),
        std::collections::HashSet::new(),
    );
    let hello = RelayHello::new(
        RelayId(1),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion::CURRENT,
        vec![0xC1; 4],
    );
    let stale_generation = registry::enroll(setup.registry(), hello.clone());
    let generation = registry::enroll(setup.registry(), hello);
    lifecycle.on_relay_enrolled(RelayId(1), generation);

    let regions = RegionsConfig::default();
    let store = pair_rtts::new_store();
    let rtt = idle_rtt_ingest(&regions, &store);
    let beat = heartbeat_with_sessions(vec![rally_point_proto::control::SessionPresence {
        tenant: tenant.clone(),
        session,
        // Slot 0 arrived and dropped again; slot 1 is here and running.
        slots: vec![SlotId(1)],
        ever_connected: vec![SlotId(0), SlotId(1)],
        started: vec![SlotId(1)],
        started_at_ms: Some(1_700_000_000_000),
    }]);

    // A beat from a superseded connection describes a stale view and is
    // dropped whole — load state included.
    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        stale_generation,
        &beat,
        &rtt,
    );
    assert_eq!(
        lifecycle.load_state(&tenant, session),
        Some(crate::lifecycle::SessionLoadState {
            created_here: true,
            attestable: true,
            serving_relays: vec![RelayId(1)],
            started_at_ms: None,
            connected_slots: vec![],
            started_slots: vec![],
        }),
        "a stale connection's beat records nothing at all",
    );

    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        generation,
        &beat,
        &rtt,
    );
    let load = lifecycle
        .load_state(&tenant, session)
        .expect("the session was created here");
    assert_eq!(
        (load.started_at_ms, load.connected_slots, load.started_slots),
        (
            Some(1_700_000_000_000),
            vec![SlotId(0), SlotId(1)],
            vec![SlotId(1)],
        ),
    );
    assert!(
        notices.slot_connects.lock().is_empty()
            && notices.session_starts.lock().is_empty()
            && notices.slot_starts.lock().is_empty(),
        "the beat is the durable record, never a notification source",
    );
}

#[tokio::test]
async fn session_closed_from_a_superseded_connection_cannot_close_the_live_epoch() {
    let (setup, notices, lifecycle, session) =
        setup_with_session_and_notify("http://127.0.0.1:1/hook".to_owned());
    let tenant = TenantId("sb-test".to_owned());
    lifecycle.register_session(
        tenant.clone(),
        session,
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0)]),
        std::collections::HashSet::new(),
    );
    let hello = RelayHello::new(
        RelayId(1),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion::CURRENT,
        vec![0xC1; 4],
    );
    let stale_generation = registry::enroll(setup.registry(), hello.clone());
    let current_generation = registry::enroll(setup.registry(), hello);
    lifecycle.on_relay_enrolled(RelayId(1), current_generation);

    let regions = RegionsConfig::default();
    let store = pair_rtts::new_store();
    let rtt = idle_rtt_ingest(&regions, &store);
    let occupied = heartbeat_with_sessions(vec![session_presence(tenant.clone(), session)]);
    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        current_generation,
        &occupied,
        &rtt,
    );

    let closed = Message::Text(
        serde_json::to_string(&RelayToCoordinator::SessionClosed {
            tenant: tenant.clone(),
            session,
        })
        .unwrap()
        .into(),
    );
    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        stale_generation,
        &closed,
        &rtt,
    );
    assert!(
        lifecycle.is_alive(&tenant, session),
        "a late close from the predecessor cannot close the replacement",
    );

    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        current_generation,
        &closed,
        &rtt,
    );
    assert!(
        !lifecycle.is_alive(&tenant, session),
        "the current connection's close still retires the session",
    );
}

#[test]
fn relay_serves_session_enforces_membership_only_when_a_serving_set_exists() {
    let (setup, _notices, _lifecycle, session) =
        setup_with_session_and_notify("http://127.0.0.1:1/hook".to_owned());
    let tenant = TenantId("sb-test".to_owned());
    // The session's serving set is [RelayId(1)].
    assert!(
        relay_serves_session(&setup, RelayId(1), &tenant, session),
        "the session's serving relay may report",
    );
    assert!(
        !relay_serves_session(&setup, RelayId(2), &tenant, session),
        "a relay outside the serving set may not report",
    );
    // A session the coordinator never recorded a serving set for: unverifiable
    // (the post-restart tail case), so the reporter is allowed through.
    assert!(
        relay_serves_session(&setup, RelayId(2), &tenant, SessionId(999_999)),
        "with no serving record there is nothing to check against, so allow",
    );
}

#[test]
fn heartbeat_presence_from_a_relay_not_serving_the_session_is_rejected() {
    // Relay 1 serves the session; relay 2 is enrolled but was never assigned
    // it -- a compromised relay 2 heartbeats the session's slot anyway.
    let (setup, _notices, _lifecycle, session) =
        setup_with_session_and_notify("http://127.0.0.1:1/hook".to_owned());
    let relay_2_generation = registry::enroll(
        setup.registry(),
        RelayHello::new(
            RelayId(2),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14902)),
            ProtocolVersion::CURRENT,
            vec![0xC2; 4],
        ),
    );
    let lifecycle = Lifecycle::new(setup.clone());
    let notices = notify::new_dedup();
    let regions = RegionsConfig::default();
    let store = pair_rtts::new_store();
    let rtt = idle_rtt_ingest(&regions, &store);
    let tenant = TenantId("sb-test".to_owned());

    let beat = heartbeat_with_sessions(vec![session_presence(tenant.clone(), session)]);
    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(2),
        relay_2_generation,
        &beat,
        &rtt,
    );

    assert!(
        presence::fresh_slots(setup.presence(), &tenant, std::time::Instant::now()).is_empty(),
        "a relay outside the session's serving set cannot forge its presence",
    );
}

#[tokio::test]
async fn heartbeat_rejects_only_the_session_a_relay_does_not_serve() {
    // Relay 1 (untagged) serves session_a; relay 2 (region-b) serves
    // session_b. Relay 2's beat legitimately reports session_b and also
    // forges session_a's slot -- only the forged entry is dropped.
    let reg = registry::new_registry();
    registry::enroll(
        &reg,
        RelayHello::new(
            RelayId(1),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
            ProtocolVersion::CURRENT,
            vec![0xC1; 4],
        ),
    );
    let relay_2_generation = registry::enroll(
        &reg,
        RelayHello::new(
            RelayId(2),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14902)),
            ProtocolVersion::CURRENT,
            vec![0xC2; 4],
        )
        .with_region(RegionId("region-b".to_owned())),
    );
    let tenants = crate::tenant::new_store();
    crate::tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = session::SessionSetup::new(reg, tenants);
    let tenant = TenantId("sb-test".to_owned());

    let session_a = session::create_session(
        &setup,
        SessionRequest {
            tenant: tenant.clone(),
            players: vec![PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xAA; 32]),
                external_ref: None,
                observer: false,
                region: None,
            }],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response
    .session;
    let session_b = session::create_session(
        &setup,
        SessionRequest {
            tenant: tenant.clone(),
            players: vec![PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xBB; 32]),
                external_ref: None,
                observer: false,
                region: Some(RegionId("region-b".to_owned())),
            }],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response
    .session;
    assert_eq!(
        setup.serving_relays(&tenant, session_a),
        vec![RelayId(1)],
        "test setup sanity: session_a homes on relay 1",
    );
    assert_eq!(
        setup.serving_relays(&tenant, session_b),
        vec![RelayId(2)],
        "test setup sanity: session_b homes on relay 2",
    );

    let lifecycle = Lifecycle::new(setup.clone());
    let notices = notify::new_dedup();
    let regions = RegionsConfig::default();
    let store = pair_rtts::new_store();
    let rtt = idle_rtt_ingest(&regions, &store);

    let beat = heartbeat_with_sessions(vec![
        session_presence(tenant.clone(), session_b),
        session_presence(tenant.clone(), session_a),
    ]);
    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(2),
        relay_2_generation,
        &beat,
        &rtt,
    );

    let mut present = presence::fresh_slots(setup.presence(), &tenant, std::time::Instant::now());
    present.sort_by_key(|(s, _)| s.0);
    assert_eq!(
        present,
        vec![(session_b, SlotId(0))],
        "the relay's own session lands; the forged one does not, and the rest of the beat still applies",
    );
}

#[tokio::test]
async fn heartbeat_session_roster_beyond_the_cap_is_truncated() {
    let reg = registry::new_registry();
    let generation = registry::enroll(
        &reg,
        RelayHello::new(
            RelayId(1),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
            vec![0xC1; 4],
        ),
    );
    let setup = session::SessionSetup::new(reg, crate::tenant::new_store());
    let lifecycle = Lifecycle::new(setup.clone());
    let notices = notify::new_dedup();
    let regions = RegionsConfig::default();
    let store = pair_rtts::new_store();
    let rtt = idle_rtt_ingest(&regions, &store);
    let tenant = TenantId("sb-test".to_owned());

    // No serving-relay record exists for any of these sessions (the
    // fail-open tail), so the roster's own size is the only thing that
    // could cap how many entries land.
    let overshoot = MAX_HEARTBEAT_SESSIONS + 5;
    let sessions: Vec<_> = (0..overshoot as u64)
        .map(|id| session_presence(tenant.clone(), SessionId(id)))
        .collect();
    let beat = heartbeat_with_sessions(sessions);

    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        generation,
        &beat,
        &rtt,
    );

    assert_eq!(
        presence::fresh_slots(setup.presence(), &tenant, std::time::Instant::now()).len(),
        MAX_HEARTBEAT_SESSIONS,
        "a roster past the cap is truncated, not rejected whole or applied whole",
    );
}

#[tokio::test]
async fn heartbeat_session_slot_list_beyond_the_cap_is_truncated() {
    let reg = registry::new_registry();
    let generation = registry::enroll(
        &reg,
        RelayHello::new(
            RelayId(1),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
            vec![0xC1; 4],
        ),
    );
    let setup = session::SessionSetup::new(reg, crate::tenant::new_store());
    let lifecycle = Lifecycle::new(setup.clone());
    let notices = notify::new_dedup();
    let regions = RegionsConfig::default();
    let store = pair_rtts::new_store();
    let rtt = idle_rtt_ingest(&regions, &store);
    let tenant = TenantId("sb-test".to_owned());

    let overshoot = MAX_HEARTBEAT_SESSION_SLOTS + 5;
    let slots: Vec<SlotId> = (0..overshoot as u8).map(SlotId).collect();
    let beat = heartbeat_with_sessions(vec![rally_point_proto::control::SessionPresence {
        tenant: tenant.clone(),
        session: SessionId(1),
        slots,
        ever_connected: vec![],
        started: vec![],
        started_at_ms: None,
    }]);

    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        generation,
        &beat,
        &rtt,
    );

    assert_eq!(
        presence::fresh_slots(setup.presence(), &tenant, std::time::Instant::now()).len(),
        MAX_HEARTBEAT_SESSION_SLOTS,
        "a session's slot list past the cap is truncated, not applied whole",
    );
}

#[test]
fn heartbeat_region_rtt_reports_beyond_the_cap_are_truncated() {
    let reg = registry::new_registry();
    let generation = registry::enroll(
        &reg,
        RelayHello::new(
            RelayId(1),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
            vec![0xC1; 4],
        )
        .with_region(RegionId("origin".to_owned())),
    );
    let setup = session::SessionSetup::new(reg, crate::tenant::new_store());
    let lifecycle = Lifecycle::new(setup.clone());
    let notices = notify::new_dedup();

    let overshoot = MAX_HEARTBEAT_REGION_RTTS + 5;
    let region_ids: Vec<String> = (0..overshoot).map(|i| format!("region-{i}")).collect();
    let region_id_strs: Vec<&str> = region_ids.iter().map(String::as_str).collect();
    let regions = regions_config(&region_id_strs);
    let store = pair_rtts::new_store();
    let relay_region = RegionId("origin".to_owned());
    let rtt = RegionRttIngest {
        relay_region: Some(&relay_region),
        regions: &regions,
        store: &store,
        ledger: None,
    };

    let rtts: Vec<(&str, u32)> = region_id_strs.iter().map(|&r| (r, 10u32)).collect();
    let beat = heartbeat_with_rtts(&rtts);
    note_inbound_frame(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        generation,
        &beat,
        &rtt,
    );

    assert_eq!(
        store.snapshot().len(),
        MAX_HEARTBEAT_REGION_RTTS,
        "a region-RTT report list past the cap is truncated, not applied whole",
    );
}
