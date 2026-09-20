//! Heartbeat ingest: the generation fence, the serving-relay filter, the
//! per-beat wire-shape caps and the completeness downgrade they force, and what
//! each surviving beat fans out to.

use rally_point_proto::control::{PlayerHandoff, RegionId, RegionRttReport, SessionRequest};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt};

use super::*;
use crate::pair_rtts::PairRttStore;
use crate::presence;
use crate::regions::RegionsConfig;
use crate::session;

/// A beat carrying the given `(region, rtt_ms)` backbone measurements and an
/// empty session roster.
fn beat_with_rtts(rtts: &[(&str, u32)]) -> RelayHeartbeat {
    RelayHeartbeat {
        roster_complete: true,
        sessions: vec![],
        region_rtts: rtts
            .iter()
            .map(|(region, rtt_ms)| RegionRttReport {
                region: RegionId((*region).to_owned()),
                rtt_ms: *rtt_ms,
            })
            .collect(),
    }
}

/// A beat carrying the given session roster, marked complete, and no RTT
/// reports.
fn beat_with_sessions(sessions: Vec<SessionPresence>) -> RelayHeartbeat {
    RelayHeartbeat {
        roster_complete: true,
        sessions,
        region_rtts: vec![],
    }
}

/// A backbone-RTT ingest that records nothing: the reporting relay has no
/// region, so a beat's reports are dropped before they reach the store. Borrows
/// caller-owned temporaries so the returned view lives as long as they do.
fn idle_rtt_ingest<'a>(regions: &'a RegionsConfig, store: &'a PairRttStore) -> RegionRttIngest<'a> {
    RegionRttIngest {
        relay_region: None,
        regions,
        store,
        ledger: None,
    }
}

/// The inputs an ingest needs with nothing staged: a registry holding relay 1 at
/// `generation`, an empty tenant store, a fresh lifecycle, no region config, and
/// an idle RTT store. Returned as owned values the caller keeps alive, since the
/// ingest view borrows the last two.
struct HeartbeatFixture {
    setup: SessionSetup,
    lifecycle: Lifecycle,
    generation: u64,
    regions: RegionsConfig,
    store: PairRttStore,
}

impl HeartbeatFixture {
    /// Ingests one beat from relay 1's current connection.
    fn beat(&self, beat: RelayHeartbeat) {
        self.lifecycle.ingest_heartbeat(
            RelayId(1),
            self.generation,
            beat,
            &idle_rtt_ingest(&self.regions, &self.store),
        );
    }
}

fn bare_heartbeat_fixture() -> HeartbeatFixture {
    let reg = registry::RelayRegistry::new();
    let generation = registry::enroll(
        &reg,
        (RelaySpec {
            id: 1,
            region: None,
        })
        .hello(),
    );
    let setup = SessionSetup::new(reg, crate::tenant::TenantStore::new());
    let lifecycle = Lifecycle::new(setup.clone());
    HeartbeatFixture {
        setup,
        lifecycle,
        generation,
        regions: RegionsConfig::default(),
        store: PairRttStore::new(),
    }
}

#[test]
fn a_current_heartbeat_folds_region_rtts_and_a_stale_one_does_not() {
    // A relay enrolled in region-a reports a round-trip to region-b. The reports
    // fold into the pair store — but only from the relay's CURRENT connection: a
    // superseded (stale-generation) beat is dropped whole, the same fence presence
    // is under.
    let reg = registry::RelayRegistry::new();
    let hello = (RelaySpec {
        id: 1,
        region: Some("region-a"),
    })
    .hello();
    // Enroll twice: the second connection supersedes the first, so the first
    // generation is no longer current.
    let stale_generation = registry::enroll(&reg, hello.clone());
    let current_generation = registry::enroll(&reg, hello);
    let setup = SessionSetup::new(reg, crate::tenant::TenantStore::new());
    let lifecycle = Lifecycle::new(setup);
    let regions = regions_config(&["region-a", "region-b"]);
    let relay_region = RegionId("region-a".to_owned());
    let store = PairRttStore::new();
    let rtt = RegionRttIngest {
        relay_region: Some(&relay_region),
        regions: &regions,
        store: &store,
        ledger: None,
    };

    // The stale connection's beat writes nothing.
    lifecycle.ingest_heartbeat(
        RelayId(1),
        stale_generation,
        beat_with_rtts(&[("region-b", 87)]),
        &rtt,
    );
    assert!(
        store.snapshot().is_empty(),
        "a superseded connection's heartbeat writes no backbone RTTs",
    );

    // The current connection's beat folds the pair in.
    lifecycle.ingest_heartbeat(
        RelayId(1),
        current_generation,
        beat_with_rtts(&[("region-b", 87)]),
        &rtt,
    );
    let snap = store.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].a, RegionId("region-a".to_owned()));
    assert_eq!(snap[0].b, RegionId("region-b".to_owned()));
    assert_eq!(snap[0].rtt_ms, 87);

    // A report for a region the coordinator does not configure is dropped, leaving
    // the known pair untouched.
    lifecycle.ingest_heartbeat(
        RelayId(1),
        current_generation,
        beat_with_rtts(&[("region-z", 42)]),
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
    rtt_from_b.ingest(
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
    let (setup, session) = SessionFixture {
        players: vec![PlayerSpec {
            slot: 0,
            external_ref: Some("sb-user-0"),
            region: None,
        }],
        external_id: Some("game-1"),
        notify_url: Some("http://127.0.0.1:1/hook".to_owned()),
        ..Default::default()
    }
    .build();
    let lifecycle = Lifecycle::new(setup.clone());
    lifecycle.register_session(
        tid(),
        session,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    let hello = (RelaySpec {
        id: 1,
        region: None,
    })
    .hello();
    let stale_generation = registry::enroll(setup.registry(), hello.clone());
    let generation = registry::enroll(setup.registry(), hello);
    lifecycle.on_relay_enrolled(RelayId(1), generation);

    let regions = RegionsConfig::default();
    let store = PairRttStore::new();
    let rtt = idle_rtt_ingest(&regions, &store);
    // Slot 0 arrived and dropped again; slot 1 is here and running.
    let load_beat = || {
        beat_with_sessions(vec![SessionPresence {
            ever_connected: slots(&[0, 1]),
            started: slots(&[1]),
            started_at_ms: Some(1_700_000_000_000),
            ..presence_entry(&tid(), session, &[1])
        }])
    };

    // A beat from a superseded connection describes a stale view and is
    // dropped whole — load state included.
    lifecycle.ingest_heartbeat(RelayId(1), stale_generation, load_beat(), &rtt);
    assert_eq!(
        lifecycle.load_state(&tid(), session),
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

    lifecycle.ingest_heartbeat(RelayId(1), generation, load_beat(), &rtt);
    let load = lifecycle
        .load_state(&tid(), session)
        .expect("the session was created here");
    assert_eq!(
        (load.started_at_ms, load.connected_slots, load.started_slots),
        (
            Some(1_700_000_000_000),
            vec![SlotId(0), SlotId(1)],
            vec![SlotId(1)],
        ),
    );
    let dedup = lifecycle.notice_dedup();
    assert!(
        dedup.slot_connects.lock().is_empty()
            && dedup.session_starts.lock().is_empty()
            && dedup.slot_starts.lock().is_empty(),
        "the beat is the durable record, never a notification source",
    );
}

#[tokio::test]
async fn heartbeat_rejects_only_the_session_a_relay_does_not_serve() {
    // Relay 1 (untagged) serves session_a; relay 2 (region-b) serves
    // session_b. Relay 2's beat legitimately reports session_b and also
    // forges session_a's slot -- only the forged entry is dropped, and the
    // legitimate rest of the beat still applies.
    let setup = SessionFixture {
        relays: vec![
            RelaySpec {
                id: 1,
                region: None,
            },
            RelaySpec {
                id: 2,
                region: Some("region-b"),
            },
        ],
        ..Default::default()
    }
    .setup_only();
    let relay_2_generation = registry::enrolled_relays(setup.registry())
        .into_iter()
        .find(|relay| relay.relay_id == RelayId(2))
        .expect("relay 2 is enrolled")
        .generation;

    let create = |region: Option<&str>, key: u8| {
        session::create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: vec![PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([key; 32]),
                    external_ref: None,
                    observer: false,
                    region: region.map(|r| RegionId(r.to_owned())),
                }],
                external_id: None,
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap()
        .response
        .session
    };
    let session_a = create(None, 0xAA);
    let session_b = create(Some("region-b"), 0xBB);
    assert_eq!(
        setup.serving_relays(&tid(), session_a),
        vec![RelayId(1)],
        "test setup sanity: session_a homes on relay 1",
    );
    assert_eq!(
        setup.serving_relays(&tid(), session_b),
        vec![RelayId(2)],
        "test setup sanity: session_b homes on relay 2",
    );

    let lifecycle = Lifecycle::new(setup.clone());
    let regions = RegionsConfig::default();
    let store = PairRttStore::new();
    lifecycle.ingest_heartbeat(
        RelayId(2),
        relay_2_generation,
        beat_with_sessions(vec![
            presence_entry(&tid(), session_b, &[0]),
            presence_entry(&tid(), session_a, &[0]),
        ]),
        &idle_rtt_ingest(&regions, &store),
    );

    let mut present = presence::fresh_slots(setup.presence(), &tid(), Instant::now());
    present.sort_by_key(|(s, _)| s.0);
    assert_eq!(
        present,
        vec![(session_b, SlotId(0))],
        "the relay's own session lands; the forged one does not, and the rest of the beat still applies",
    );
}

#[tokio::test]
async fn heartbeat_session_roster_beyond_the_cap_is_truncated_and_stops_being_authoritative() {
    // Truncation drops a suffix the relay actually reported, so the beat stops
    // being an authoritative statement about who is absent: a session the
    // coordinator dropped from the roster looks exactly like one the relay
    // omitted because it is empty. The `complete` flag the lifecycle receives
    // must therefore be cleared, or a truncated beat would start an
    // empty-session grace against sessions it never really spoke about.
    let fixture = bare_heartbeat_fixture();
    let watched = SessionId(9_999_999);
    fixture.lifecycle.register_session(
        tid(),
        watched,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );
    stage_assignments(&fixture.setup, watched, &[RelayId(1)]);
    fixture
        .lifecycle
        .on_relay_enrolled(RelayId(1), fixture.generation);
    // An occupied beat first, so the session counts as started and a later
    // omission is the transition the empty-session grace watches for.
    fixture.beat(beat_with_sessions(vec![presence_entry(
        &tid(),
        watched,
        &[0],
    )]));

    // No serving-relay record exists for any of the filler sessions (the
    // fail-open tail), so the roster's own size is the only thing that could
    // cap how many entries land.
    let overshoot = MAX_HEARTBEAT_SESSIONS + 5;
    let filler: Vec<_> = (0..overshoot as u64)
        .map(|id| presence_entry(&tid(), SessionId(id), &[0]))
        .collect();
    fixture.beat(beat_with_sessions(filler));

    assert_eq!(
        presence::fresh_slots(fixture.setup.presence(), &tid(), Instant::now()).len(),
        MAX_HEARTBEAT_SESSIONS,
        "a roster past the cap is truncated, not rejected whole or applied whole",
    );
    assert_eq!(
        fixture.lifecycle.metrics_census().sessions[&tid()].empty_grace,
        0,
        "the watched session's absence from a truncated beat proves nothing",
    );

    // The same omission from a beat the coordinator did not truncate does start
    // the grace — so the assertion above is about the truncation, not about
    // omission being ignored generally.
    fixture.beat(beat_with_sessions(vec![]));
    assert_eq!(
        fixture.lifecycle.metrics_census().sessions[&tid()].empty_grace,
        1,
        "an un-truncated complete roster's omission is authoritative absence",
    );
}

#[tokio::test]
async fn heartbeat_session_slot_list_beyond_the_cap_is_truncated() {
    let fixture = bare_heartbeat_fixture();

    let overshoot = MAX_HEARTBEAT_SESSION_SLOTS + 5;
    let over_cap: Vec<u8> = (0..overshoot as u8).collect();
    fixture.beat(beat_with_sessions(vec![presence_entry(
        &tid(),
        SessionId(1),
        &over_cap,
    )]));

    assert_eq!(
        presence::fresh_slots(fixture.setup.presence(), &tid(), Instant::now()).len(),
        MAX_HEARTBEAT_SESSION_SLOTS,
        "a session's slot list past the cap is truncated, not applied whole",
    );
}

#[test]
fn heartbeat_region_rtt_reports_beyond_the_cap_are_truncated() {
    let reg = registry::RelayRegistry::new();
    let generation = registry::enroll(
        &reg,
        (RelaySpec {
            id: 1,
            region: Some("origin"),
        })
        .hello(),
    );
    let setup = SessionSetup::new(reg, crate::tenant::TenantStore::new());
    let lifecycle = Lifecycle::new(setup);

    let overshoot = MAX_HEARTBEAT_REGION_RTTS + 5;
    let region_ids: Vec<String> = (0..overshoot).map(|i| format!("region-{i}")).collect();
    let region_id_strs: Vec<&str> = region_ids.iter().map(String::as_str).collect();
    let regions = regions_config(&region_id_strs);
    let store = PairRttStore::new();
    let relay_region = RegionId("origin".to_owned());
    let rtt = RegionRttIngest {
        relay_region: Some(&relay_region),
        regions: &regions,
        store: &store,
        ledger: None,
    };

    let rtts: Vec<(&str, u32)> = region_id_strs.iter().map(|&r| (r, 10u32)).collect();
    lifecycle.ingest_heartbeat(RelayId(1), generation, beat_with_rtts(&rtts), &rtt);

    assert_eq!(
        store.snapshot().len(),
        MAX_HEARTBEAT_REGION_RTTS,
        "a region-RTT report list past the cap is truncated, not applied whole",
    );
}
