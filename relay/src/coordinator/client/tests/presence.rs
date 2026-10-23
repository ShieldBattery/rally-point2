//! What the relay reports about the sessions it holds: the heartbeat's roster
//! entries, requested snapshots with retained connection observations, and the
//! measured region round-trips a beat carries.

use super::*;

#[tokio::test]
async fn a_heartbeat_carries_the_live_roster_as_presence() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frame_tx, frame_rx) = tokio::sync::oneshot::channel();

    // Stand-in coordinator: complete the enroll handshake, then read the first
    // heartbeat.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let hello = accept_enroll(&mut ws).await;
        let Message::Text(hello) = hello else {
            panic!("first frame is the Hello");
        };
        assert!(hello.contains("\"type\":\"hello\""));
        let beat = ws.next().await.unwrap().unwrap();
        let _ = frame_tx.send(beat);
    });

    // A slot registered in the roster before the subscriber starts, so the
    // first beat already carries it. The guard is disarmed and the inbox held
    // so the slot stays registered for the test's duration.
    let (sessions, decision_makers) = fence_fixture();
    let (mut guard, _inbox) =
        crate::routing::register(&sessions, &key(7), rally_point_proto::ids::SlotId(3), 1)
            .expect("slot 3 registers");
    guard.disarm();

    // The session's decision-maker holds the load state the beat restates:
    // slot 2 arrived and dropped again (so it is off the live roster but
    // still ever-connected), slot 3 arrived and reported its game loop.
    decision_makers.note_slot_connected(&key(7), rally_point_proto::ids::SlotId(2), false, None);
    decision_makers.note_slot_connected(&key(7), rally_point_proto::ids::SlotId(3), false, None);
    decision_makers.note_slot_started(&key(7), rally_point_proto::ids::SlotId(3));

    SubscriberFixture {
        heartbeat: HeartbeatConfig {
            sources: HeartbeatSources {
                session_gates: crate::session::gate::SessionGates::default(),
                provisional_turns: crate::session::provisional_turns::ProvisionalTurnPen::default(),
                sessions: Arc::clone(&sessions),
                decision_makers,
                region_rtt_cache: RegionRttCache::default(),
                load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
            },
            interval: Duration::from_millis(50), // beat quickly so the test observes one
        },
        ..Default::default()
    }
    .spawn(addr);

    let beat = tokio::time::timeout(Duration::from_secs(5), frame_rx)
        .await
        .expect("a heartbeat arrives")
        .unwrap();
    let Message::Text(text) = beat else {
        panic!("the heartbeat is a text frame");
    };
    let decoded: RelayToCoordinator = serde_json::from_str(&text).unwrap();
    assert_eq!(
        decoded,
        RelayToCoordinator::Heartbeat {
            roster_complete: true,
            sessions: vec![SessionPresence {
                periodic_evidence: Vec::new(),
                tenant: TenantId(TENANT.to_owned()),
                session: SessionId(7),
                slots: vec![rally_point_proto::ids::SlotId(3)],
                ever_connected: vec![
                    rally_point_proto::ids::SlotId(2),
                    rally_point_proto::ids::SlotId(3),
                ],
                started: vec![rally_point_proto::ids::SlotId(3)],
                forwarded: vec![],
                // The session never started on this relay — neither its own
                // coverage latch nor an adopted directive — so it has no
                // instant to restate.
                started_at_ms: None,
                lobby_violations: vec![],
                evidence: vec![],
            }],
            region_rtts: vec![],
        },
        "the beat names the registered (tenant, session, slot) and the \
         session's retained load state",
    );
}

#[test]
fn a_beat_restates_the_load_state_of_a_session_whose_last_slot_left() {
    // A relay's makers, not its live roster, decide which sessions a beat
    // names. The roster drops a session the moment its last local slot leaves,
    // while the game runs on elsewhere — so keying the beat on the roster
    // would stop restating exactly the facts (who arrived here, who started)
    // the coordinator has no other durable source for.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let (registration, _inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), 1).expect("slot 0 registers");
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None);
    decision_makers.note_slot_started(&key(7), SlotId(0));

    // The slot's link ends: the routing group goes with it, the maker stays.
    drop(registration);
    assert!(crate::routing::live_slots(&sessions).is_empty());

    let sources = HeartbeatSources {
        session_gates: crate::session::gate::SessionGates::default(),

        provisional_turns: crate::session::provisional_turns::ProvisionalTurnPen::default(),
        sessions: Arc::clone(&sessions),
        decision_makers: Arc::clone(&decision_makers),
        region_rtt_cache: RegionRttCache::default(),
        load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
    };
    assert_eq!(
        heartbeat_presence(&sources),
        vec![SessionPresence {
            periodic_evidence: Vec::new(),
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(7),
            slots: vec![],
            ever_connected: vec![SlotId(0)],
            started: vec![SlotId(0)],
            forwarded: vec![],
            started_at_ms: None,
            lobby_violations: vec![],
            evidence: vec![],
        }],
        "the session is still named, with no connected slot and its retained sets",
    );

    // A session with a connected slot but no maker (a provisional admission no
    // descriptor ever claimed) is named too, with nothing retained.
    let (mut unclaimed, _unclaimed_inbox) =
        crate::routing::register(&sessions, &key(8), SlotId(1), 1).expect("slot 1 registers");
    unclaimed.disarm();
    let roster = heartbeat_presence(&sources);
    assert_eq!(roster.len(), 2);
    let unclaimed = roster
        .iter()
        .find(|entry| entry.session == SessionId(8))
        .expect("the maker-less session is on the beat");
    assert_eq!(unclaimed.slots, vec![SlotId(1)]);
    assert!(unclaimed.ever_connected.is_empty() && unclaimed.started.is_empty());
}

#[tokio::test]
async fn a_load_state_request_is_answered_on_the_control_connection() {
    // The exchange the coordinator's completeness claim rests on: the relay
    // answers the question it was asked, from the state it holds, echoing the
    // correlation id back so the answer belongs to that request and no other.
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frame_tx, frame_rx) = tokio::sync::oneshot::channel();

    // Stand-in coordinator: enroll the relay, push a load-state request, then
    // read frames until the snapshot arrives (a heartbeat may precede it).
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;
        let request = serde_json::to_string(&CoordinatorToRelay::LoadStateRequest {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(7),
            request_id: 99,
            settle_lobby: false,
        })
        .unwrap();
        ws.send(Message::Text(request.into())).await.unwrap();
        while let Some(Ok(Message::Text(text))) = ws.next().await {
            if text.contains("\"type\":\"load_state_snapshot\"") {
                let _ = frame_tx.send(text.to_string());
                return;
            }
        }
    });

    // What this relay holds for the session: slot 2 arrived, sent its pipe seed,
    // and dropped; slot 3 is here and running, its loop's turns flowing.
    let (sessions, decision_makers) = fence_fixture();
    let (mut guard, _inbox) =
        crate::routing::register(&sessions, &key(7), rally_point_proto::ids::SlotId(3), 1)
            .expect("slot 3 registers");
    guard.disarm();
    for slot in [2u8, 3] {
        decision_makers.note_slot_connected(
            &key(7),
            rally_point_proto::ids::SlotId(slot),
            false,
            None,
        );
    }
    decision_makers.note_slot_started(&key(7), rally_point_proto::ids::SlotId(3));
    decision_makers.note_unframed_home_turn(&key(7), rally_point_proto::ids::SlotId(2));
    decision_makers.observe_turn_frame(
        &key(7),
        rally_point_proto::ids::SlotId(3),
        4,
        rally_point_proto::ids::GameFrameCount(0),
        crate::consensus::delivery::DeliveryHome::Local,
    );

    SubscriberFixture {
        heartbeat: HeartbeatConfig {
            sources: HeartbeatSources {
                session_gates: crate::session::gate::SessionGates::default(),
                provisional_turns: crate::session::provisional_turns::ProvisionalTurnPen::default(),
                sessions: Arc::clone(&sessions),
                decision_makers,
                region_rtt_cache: RegionRttCache::default(),
                load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
            },
            // Long enough that the snapshot is not merely a beat in disguise.
            interval: Duration::from_secs(3600),
        },
        ..Default::default()
    }
    .spawn(addr);

    let text = tokio::time::timeout(Duration::from_secs(5), frame_rx)
        .await
        .expect("the relay answers promptly")
        .expect("the stand-in coordinator forwards the snapshot");
    assert_eq!(
        serde_json::from_str::<RelayToCoordinator>(&text).unwrap(),
        RelayToCoordinator::LoadStateSnapshot {
            request_id: 99,
            state: SessionPresence {
                periodic_evidence: Vec::new(),
                tenant: TenantId(TENANT.to_owned()),
                session: SessionId(7),
                slots: vec![rally_point_proto::ids::SlotId(3)],
                ever_connected: vec![
                    rally_point_proto::ids::SlotId(2),
                    rally_point_proto::ids::SlotId(3),
                ],
                started: vec![rally_point_proto::ids::SlotId(3)],
                forwarded: vec![
                    rally_point_proto::ids::SlotId(2),
                    rally_point_proto::ids::SlotId(3),
                ],
                started_at_ms: None,
                lobby_violations: vec![],
                evidence: vec![],
            },
            // Slot 2 arrived here and is gone: no stream to probe, and its
            // client may be holding a report for the stream it opens next, so
            // this answer's absences carry no proof.
            fenced: false,
            setup_settled: false,
            // The turn set needs no fence, and this build always carries it.
            reports_turns: true,
        },
    );
}

#[test]
fn a_load_state_snapshot_reports_the_same_session_a_beat_would() {
    // An attested snapshot and a heartbeat's roster entry describe a session
    // identically — they read the same live roster and the same retained maker
    // state. What differs is only what the reader may assume about ordering.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let (_registration, _inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), 1).expect("slot 0 registers");
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None);
    decision_makers.note_slot_started(&key(7), SlotId(0));

    let sources = HeartbeatSources {
        session_gates: crate::session::gate::SessionGates::default(),

        provisional_turns: crate::session::provisional_turns::ProvisionalTurnPen::default(),
        sessions: Arc::clone(&sessions),
        decision_makers: Arc::clone(&decision_makers),
        region_rtt_cache: RegionRttCache::default(),
        load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
    };
    assert_eq!(
        session_load_snapshot(&sources.sessions, &sources.decision_makers, key(7)).0,
        heartbeat_presence(&sources)
            .into_iter()
            .find(|entry| entry.session == SessionId(7))
            .expect("the session is on the beat"),
    );
}

#[test]
fn a_session_this_relay_does_not_hold_snapshots_to_empty_rather_than_nothing() {
    // Empty is a real answer — "I know of no arrival here" — and is exactly
    // what a relay that never held the session has to say. The coordinator's
    // completeness claim rests on the difference between this and silence, and
    // silence is never produced here: every question gets an answer.
    let sources = HeartbeatSources {
        session_gates: crate::session::gate::SessionGates::default(),
        provisional_turns: crate::session::provisional_turns::ProvisionalTurnPen::default(),
        sessions: Arc::default(),
        decision_makers: Arc::new(crate::consensus::new_decision_makers()),
        region_rtt_cache: RegionRttCache::default(),
        load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
    };
    assert_eq!(
        session_load_snapshot(&sources.sessions, &sources.decision_makers, key(7)).0,
        SessionPresence {
            periodic_evidence: Vec::new(),
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(7),
            slots: vec![],
            ever_connected: vec![],
            started: vec![],
            forwarded: vec![],
            started_at_ms: None,
            lobby_violations: vec![],
            evidence: vec![],
        },
    );
}

#[test]
fn heartbeat_region_rtts_snapshots_the_cache_sorted_by_region() {
    let cache = RegionRttCache::new();
    // An empty cache reports no RTTs — the beat's field stays off the wire.
    assert!(heartbeat_region_rtts(&cache).is_empty());

    // Insert out of region order; the snapshot is sorted by region id, so the
    // beat's wire output is deterministic regardless of map iteration order.
    cache.record(RegionId("us-east".to_owned()), 87);
    cache.record(RegionId("ap-southeast".to_owned()), 210);
    cache.record(RegionId("eu-central".to_owned()), 42);
    assert_eq!(
        heartbeat_region_rtts(&cache),
        vec![
            RegionRttReport {
                region: RegionId("ap-southeast".to_owned()),
                rtt_ms: 210,
            },
            RegionRttReport {
                region: RegionId("eu-central".to_owned()),
                rtt_ms: 42,
            },
            RegionRttReport {
                region: RegionId("us-east".to_owned()),
                rtt_ms: 87,
            },
        ],
    );
}

#[test]
fn heartbeat_roster_stays_compact_while_requested_snapshots_retain_full_observations() {
    use rally_point_proto::control::{EvidenceObservation, EvidenceVerdict};
    use rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN;
    use rally_point_proto::ids::SlotId;

    let sessions: Sessions = Arc::default();
    let decision_makers = Arc::new(crate::consensus::new_decision_makers());
    let mut registrations = Vec::new();
    let mut inboxes = Vec::new();
    for session in 0..256 {
        let key = key(session);
        let _ = decision_makers.sync_maker(
            &key,
            crate::consensus::MakerSync::new(
                BufferBounds { min: 1, max: 6 },
                crate::consensus::Authority::SelfRelay,
            ),
        );
        for slot in [SlotId(0), SlotId(1)] {
            let (registration, inbox) = crate::routing::register(&sessions, &key, slot, 1).unwrap();
            registrations.push(registration);
            inboxes.push(inbox);
            assert!(decision_makers.note_slot_connected(
                &key,
                slot,
                false,
                Some(EvidenceObservation {
                    sample_id: 0,
                    connection_id: [255; 32],
                    sequence: 1,
                    assignment_revision: 0,
                    verdict: EvidenceVerdict::Valid,
                    key_id: Some(7),
                    body: vec![255; MAX_EVIDENCE_BODY_LEN],
                })
            ));
        }
    }
    let sources = HeartbeatSources {
        session_gates: crate::session::gate::SessionGates::default(),
        provisional_turns: crate::session::provisional_turns::ProvisionalTurnPen::default(),
        sessions: Arc::clone(&sessions),
        decision_makers: Arc::clone(&decision_makers),
        region_rtt_cache: RegionRttCache::default(),
        load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
    };
    let roster = heartbeat_presence(&sources);
    assert_eq!(roster.len(), 256);
    for entry in &roster {
        assert_eq!(entry.slots, vec![SlotId(0), SlotId(1)]);
        assert_eq!(entry.ever_connected, entry.slots);
        assert!(entry.evidence.is_empty());
    }
    let frame = serde_json::to_vec(&RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: roster,
        region_rtts: vec![],
    })
    .unwrap();
    assert!(
        frame.len() < 128 * 1024,
        "the complete roster stays comfortably below the control-message cap"
    );

    let (snapshot, _) = session_load_snapshot(&sessions, &decision_makers, key(0));
    assert_eq!(snapshot.slots, vec![SlotId(0), SlotId(1)]);
    assert_eq!(snapshot.evidence.len(), 2);
    for entry in &snapshot.evidence {
        assert_eq!(entry.observation.body, vec![255; MAX_EVIDENCE_BODY_LEN]);
        assert_eq!(entry.observation.verdict, EvidenceVerdict::Valid);
    }
    let snapshot_bytes = serde_json::to_vec(&snapshot).unwrap();
    assert!(snapshot_bytes.len() < 2 * 1024 * 1024);
    assert!(
        snapshot_bytes.len() * 256 > 2 * 1024 * 1024,
        "repeating these bodies in the roster would exceed the control cap"
    );
}

#[test]
fn periodic_heartbeat_attachment_budget_rotates_without_truncating_the_roster() {
    use rally_point_proto::control::{EvidenceObservation, EvidenceVerdict, SlotEvidence};
    use rally_point_proto::ids::SlotId;
    let base: Vec<_> = (0..256)
        .map(|session| {
            let evidence: Vec<_> = (0..2)
                .map(|slot| SlotEvidence {
                    slot: SlotId(slot),
                    observation: EvidenceObservation {
                        sample_id: 0,
                        connection_id: [255; 32],
                        sequence: 1,
                        assignment_revision: 1,
                        verdict: EvidenceVerdict::Valid,
                        key_id: Some(7),
                        body: vec![255; rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN],
                    },
                })
                .collect();
            rally_point_proto::control::SessionPresence {
                tenant: TenantId(TENANT.to_owned()),
                session: SessionId(session),
                periodic_evidence: evidence
                    .iter()
                    .cloned()
                    .map(|mut entry| {
                        entry.observation.sample_id = 1;
                        entry.observation.sequence = 2;
                        entry
                    })
                    .collect(),
                evidence,
                slots: vec![],
                ever_connected: vec![],
                started: vec![],
                forwarded: vec![],
                lobby_violations: vec![],
                started_at_ms: None,
            }
        })
        .collect();
    let mut cursor = 0;
    let mut seen = std::collections::HashSet::new();
    for _ in 0..40 {
        let mut roster = base.clone();
        let candidates: Vec<_> = roster
            .iter()
            .flat_map(|session| {
                session.periodic_evidence.iter().map(|entry| {
                    (
                        SessionKey {
                            tenant: session.tenant.clone(),
                            session: session.session,
                        },
                        entry.slot,
                    )
                })
            })
            .collect();
        for session in &mut roster {
            session.evidence.clear();
            session.periodic_evidence.clear();
        }
        super::super::heartbeat::attach_heartbeat_evidence(
            &mut roster,
            &mut cursor,
            &[],
            candidates,
            |key, slot, remaining| {
                let session = &base[key.session.0 as usize];
                let admission = &session.evidence[slot.0 as usize];
                let periodic = &session.periodic_evidence[slot.0 as usize];
                let cost = serde_json::to_vec(&(admission, periodic)).unwrap().len() + 256;
                if cost > *remaining {
                    return None;
                }
                *remaining -= cost;
                Some((admission.clone(), periodic.clone()))
            },
        );
        assert_eq!(roster.len(), 256);
        let mut attachments = 0;
        for session in &roster {
            assert_eq!(session.evidence.len(), session.periodic_evidence.len());
            for (admission, periodic) in session.evidence.iter().zip(&session.periodic_evidence) {
                assert_eq!(admission.slot, periodic.slot);
                attachments += serde_json::to_vec(&(admission, periodic)).unwrap().len() + 128;
                seen.insert((session.session, periodic.slot));
            }
        }
        assert!(attachments <= 512 * 1024);
        let bytes = serde_json::to_vec(&RelayToCoordinator::Heartbeat {
            roster_complete: true,
            sessions: roster,
            region_rtts: vec![],
        })
        .unwrap();
        assert!(bytes.len() < 2 * 1024 * 1024);
    }
    assert_eq!(seen.len(), 512);
}

#[test]
fn near_full_roster_reserves_frame_space_before_cloning_observations() {
    use rally_point_proto::control::{EvidenceObservation, EvidenceVerdict, SlotEvidence};
    use rally_point_proto::ids::SlotId;
    let slots: Vec<_> = (0..16).map(SlotId).collect();
    let mut roster: Vec<_> = (0..4096)
        .map(|session| rally_point_proto::control::SessionPresence {
            tenant: TenantId("t".repeat(160)),
            session: SessionId(session),
            slots: slots.clone(),
            ever_connected: slots.clone(),
            started: slots.clone(),
            forwarded: slots.clone(),
            lobby_violations: vec![],
            evidence: vec![],
            periodic_evidence: vec![],
            started_at_ms: Some(1792700000000),
        })
        .collect();
    let candidates = roster
        .iter()
        .flat_map(|session| {
            slots.iter().map(|slot| {
                (
                    SessionKey {
                        tenant: session.tenant.clone(),
                        session: session.session,
                    },
                    *slot,
                )
            })
        })
        .collect();
    let sample = SlotEvidence {
        slot: SlotId(0),
        observation: EvidenceObservation {
            sample_id: 1,
            connection_id: [255; 32],
            sequence: 2,
            assignment_revision: 1,
            verdict: EvidenceVerdict::Valid,
            key_id: Some(7),
            body: vec![255; rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN],
        },
    };
    let cost = serde_json::to_vec(&(&sample, &sample)).unwrap().len() + 256;
    let mut copied = 0;
    super::super::heartbeat::attach_heartbeat_evidence(
        &mut roster,
        &mut 0,
        &[],
        candidates,
        |_, slot, remaining| {
            if cost > *remaining {
                return None;
            }
            *remaining -= cost;
            copied += 1;
            let mut periodic = sample.clone();
            periodic.slot = slot;
            let mut admission = periodic.clone();
            admission.observation.sample_id = 0;
            Some((admission, periodic))
        },
    );
    assert!(
        copied > 0 && copied < 40,
        "only fitting pairs get cloned: {copied}"
    );
    assert_eq!(roster.len(), 4096);
    let bytes = serde_json::to_vec(&RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: roster,
        region_rtts: vec![],
    })
    .unwrap();
    assert!(bytes.len() < 2 * 1024 * 1024, "{}", bytes.len());
}

#[test]
fn oversized_first_pair_does_not_pin_heartbeat_rotation() {
    let mut roster = vec![SessionPresence {
        tenant: key(7).tenant,
        session: SessionId(7),
        slots: vec![],
        ever_connected: vec![],
        started: vec![],
        forwarded: vec![],
        lobby_violations: vec![],
        evidence: vec![],
        periodic_evidence: vec![],
        started_at_ms: None,
    }];
    let candidates = vec![
        (key(7), rally_point_proto::ids::SlotId(0)),
        (key(7), rally_point_proto::ids::SlotId(1)),
    ];
    let mut cursor = 0;
    let mut attempts = Vec::new();
    for _ in 0..2 {
        super::super::heartbeat::attach_heartbeat_evidence(
            &mut roster,
            &mut cursor,
            &[],
            candidates.clone(),
            |_, slot, _| {
                attempts.push(slot);
                None
            },
        );
    }
    assert_eq!(
        attempts,
        vec![
            rally_point_proto::ids::SlotId(0),
            rally_point_proto::ids::SlotId(1)
        ]
    );
}
