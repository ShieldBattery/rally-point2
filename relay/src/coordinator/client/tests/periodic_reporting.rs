//! Paired recovery and separate sample notices on the actual control writer.
use super::*;
use crate::consensus::{Authority, EvidenceConfig, MakerSync};
use rally_point_proto::control::{EvidenceKey, EvidenceObservation, EvidenceVerdict};
use rally_point_proto::ids::SlotId;
use rally_point_proto::token::ClientPublicKey;

#[tokio::test]
async fn periodic_pair_is_sent_once_per_control_connection() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (sources, admission, expected) = reporting_fixture();
    let makers = sources.decision_makers.clone();
    let slot = SlotId(0);
    SubscriberFixture {
        heartbeat: HeartbeatConfig {
            sources,
            interval: Duration::from_millis(50),
        },
        ..Default::default()
    }
    .spawn(addr);
    tokio::time::timeout(Duration::from_secs(5), async {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        accept_enroll(&mut ws).await;
        let RelayToCoordinator::SlotEvidence(notice) = decode(ws.next().await.unwrap().unwrap())
        else {
            panic!("sample is sent immediately with its admission context")
        };
        assert_eq!(notice.evidence, expected);
        assert_eq!(notice.admission, Some(admission.clone()));
        for beat in 0..2 {
            let RelayToCoordinator::Heartbeat { sessions, .. } =
                decode(ws.next().await.unwrap().unwrap())
            else {
                panic!("unchanged samples must not emit another notice")
            };
            assert_eq!(sessions[0].slots, vec![slot]);
            if beat == 0 {
                assert_eq!(sessions[0].evidence[0].observation, admission);
                assert_eq!(sessions[0].periodic_evidence[0].observation, expected);
            } else {
                assert!(sessions[0].evidence.is_empty());
                assert!(sessions[0].periodic_evidence.is_empty());
            }
        }
        // Sent state belongs to this writer, not the retained session. A new
        // control connection must recover the same pair without a new sample.
        ws.close(None).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        accept_enroll(&mut ws).await;
        let RelayToCoordinator::SlotEvidence(notice) = decode(ws.next().await.unwrap().unwrap())
        else {
            panic!("reconnected writer resends the sample notice")
        };
        assert_eq!(notice.admission, Some(admission.clone()));
        assert_eq!(notice.evidence, expected);
        let RelayToCoordinator::Heartbeat { sessions, .. } =
            decode(ws.next().await.unwrap().unwrap())
        else {
            panic!("reconnected writer also refreshes heartbeat recovery")
        };
        assert_eq!(sessions[0].evidence[0].observation, admission);
        assert_eq!(sessions[0].periodic_evidence[0].observation, expected);
    })
    .await
    .unwrap();
    assert_eq!(
        makers.retained_load_state(&key(7)).evidence[0].observation,
        admission
    );
}

fn collect_sample(
    makers: &crate::consensus::DecisionMakers,
    key: &SessionKey,
    slot: SlotId,
    epoch: u64,
    observation: EvidenceObservation,
) -> bool {
    assert!(makers.begin_periodic_evidence(key, slot, epoch, observation.clone()));
    makers.record_periodic_evidence(key, slot, epoch, observation)
}

fn reporting_fixture() -> (HeartbeatSources, EvidenceObservation, EvidenceObservation) {
    let sessions: Sessions = Arc::default();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let slot = SlotId(0);
    let _ = makers.sync_maker(
        &key(7),
        MakerSync {
            evidence: EvidenceConfig {
                periodic: true,
                keys: vec![EvidenceKey {
                    key_id: 7,
                    public_key: ClientPublicKey([7; 32]),
                }],
                assignments: [(slot, 1)].into_iter().collect(),
                ..Default::default()
            },
            expected_slots: [slot].into_iter().collect(),
            homed_slots: [slot].into_iter().collect(),
            ..MakerSync::new(BufferBounds { min: 1, max: 6 }, Authority::SelfRelay)
        },
    );
    let (mut registration, _inbox) = crate::routing::register(&sessions, &key(7), slot, 1).unwrap();
    registration.disarm();
    let _ = makers.activate_connection_epoch(&key(7), slot, 1);
    let admission = EvidenceObservation {
        sample_id: 0,
        connection_id: [1; 32],
        sequence: crate::consensus::next_evidence_sequence().unwrap(),
        assignment_revision: 1,
        verdict: EvidenceVerdict::Valid,
        key_id: Some(7),
        body: vec![1],
    };
    assert!(makers.note_slot_connected(&key(7), slot, false, Some(admission.clone())));
    assert!(collect_sample(
        &makers,
        &key(7),
        slot,
        1,
        EvidenceObservation {
            sample_id: 1,
            body: vec![2],
            ..admission.clone()
        }
    ));
    let expected = makers.retained_load_state(&key(7)).periodic_evidence[0]
        .observation
        .clone();
    (
        HeartbeatSources {
            session_gates: Default::default(),
            provisional_turns: Default::default(),
            sessions,
            decision_makers: makers,
            region_rtt_cache: Default::default(),
            load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
        },
        admission,
        expected,
    )
}

#[tokio::test]
async fn periodic_collection_wakes_writer_without_waiting_for_heartbeat() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let (sources, admission, _) = reporting_fixture();
    let makers = sources.decision_makers.clone();
    SubscriberFixture {
        heartbeat: HeartbeatConfig {
            sources,
            interval: Duration::from_secs(3600),
        },
        ..Default::default()
    }
    .spawn(listener.local_addr().unwrap());
    tokio::time::timeout(Duration::from_secs(5), async {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        accept_enroll(&mut ws).await;
        assert!(matches!(
            decode(ws.next().await.unwrap().unwrap()),
            RelayToCoordinator::SlotEvidence(_)
        ));
        assert!(collect_sample(
            &makers,
            &key(7),
            SlotId(0),
            1,
            EvidenceObservation {
                sample_id: 2,
                body: vec![3],
                ..admission
            }
        ));
        let RelayToCoordinator::SlotEvidence(notice) = decode(ws.next().await.unwrap().unwrap())
        else {
            panic!("collector change sends a notice without a heartbeat")
        };
        assert_eq!(notice.evidence.sample_id, 2);
        assert_eq!(notice.evidence.body, vec![3]);
    })
    .await
    .unwrap();
}

#[test]
fn omitted_descriptor_policy_cannot_enable_periodic_reporting() {
    let mut wire = serde_json::to_value(descriptor(7, &[])).unwrap();
    wire.as_object_mut().unwrap().remove("periodicEvidence");
    let descriptor: SessionDescriptor = serde_json::from_value(wire).unwrap();
    assert!(!descriptor.periodic_evidence);
}

#[test]
fn stale_heartbeat_candidates_do_not_stop_later_reports() {
    use rally_point_proto::control::SlotEvidence;
    let mut roster = vec![SessionPresence {
        tenant: key(7).tenant,
        session: key(7).session,
        slots: vec![],
        ever_connected: vec![],
        started: vec![],
        forwarded: vec![],
        lobby_violations: vec![],
        evidence: vec![],
        evidence_history: vec![],
        periodic_evidence: vec![],
        started_at_ms: None,
    }];
    let mut attempted = Vec::new();
    super::super::heartbeat::attach_heartbeat_evidence(
        &mut roster,
        &mut 0,
        &[],
        (0..5).map(|slot| (key(7), SlotId(slot), 1)).collect(),
        |_, slot, _, remaining| {
            attempted.push(slot);
            if slot.0 != 4 {
                return Ok(None);
            }
            *remaining -= 1024;
            let admission = SlotEvidence {
                slot,
                observation: EvidenceObservation {
                    sample_id: 0,
                    connection_id: [1; 32],
                    sequence: 1,
                    assignment_revision: 1,
                    verdict: EvidenceVerdict::Valid,
                    key_id: Some(7),
                    body: vec![1],
                },
            };
            let mut sample = admission.clone();
            sample.observation.sample_id = 1;
            Ok(Some(crate::consensus::PeriodicEvidencePair {
                admission,
                sample,
                historical: false,
                observed_at_ms: 1,
            }))
        },
    );
    assert_eq!(attempted, (0..5).map(SlotId).collect::<Vec<_>>());
    assert_eq!(roster[0].periodic_evidence.len(), 1);
    assert_eq!(roster[0].periodic_evidence[0].slot, SlotId(4));
}

#[test]
fn heartbeat_bounds_periodic_attachments_even_with_excess_candidates() {
    use rally_point_proto::control::SlotEvidence;
    let mut roster = vec![SessionPresence {
        tenant: key(7).tenant,
        session: key(7).session,
        slots: vec![],
        ever_connected: vec![],
        started: vec![],
        forwarded: vec![],
        lobby_violations: vec![],
        evidence: vec![],
        evidence_history: vec![],
        periodic_evidence: vec![],
        started_at_ms: None,
    }];
    let mut copied = 0;
    super::super::heartbeat::attach_heartbeat_evidence(
        &mut roster,
        &mut 0,
        &[],
        (0..17).map(|slot| (key(7), SlotId(slot), 1)).collect(),
        |_, slot, _, remaining| {
            copied += 1;
            *remaining -= 1024;
            let admission = SlotEvidence {
                slot,
                observation: EvidenceObservation {
                    sample_id: 0,
                    connection_id: [1; 32],
                    sequence: 1,
                    assignment_revision: 1,
                    verdict: EvidenceVerdict::Valid,
                    key_id: Some(7),
                    body: vec![1],
                },
            };
            let mut sample = admission.clone();
            sample.observation.sample_id = 1;
            Ok(Some(crate::consensus::PeriodicEvidencePair {
                admission,
                sample,
                historical: false,
                observed_at_ms: 1,
            }))
        },
    );
    assert_eq!(copied, 16);
    assert_eq!(roster[0].periodic_evidence.len(), 16);
    serde_json::to_vec(&RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: roster,
        region_rtts: vec![],
    })
    .unwrap();
}

#[tokio::test]
async fn periodic_notices_yield_to_load_state_asks_and_ready_answers() {
    let (sources, admission, _) = reporting_fixture();
    let makers = sources.decision_makers.clone();
    let (asks, load_state_rx) = mpsc::channel(LOAD_STATE_ASK_CAPACITY);
    asks.try_send(LoadStateAsk {
        request_id: 99,
        key: key(999),
        settle_lobby: false,
    })
    .unwrap();
    let (frames_tx, mut frames_rx) = mpsc::unbounded_channel();
    let sink = Box::pin(futures_util::sink::unfold((), move |(), frame: Message| {
        let frames_tx = frames_tx.clone();
        let asks = asks.clone();
        let makers = makers.clone();
        let admission = admission.clone();
        async move {
            let message = decode(frame);
            if matches!(&message, RelayToCoordinator::SlotEvidence(notice) if notice.evidence.sample_id == 1)
            {
                assert_eq!(
                    asks.capacity(),
                    LOAD_STATE_ASK_CAPACITY,
                    "the pending load-state ask was consumed first"
                );
                assert!(collect_sample(
                    &makers,
                    &key(7),
                    SlotId(0),
                    1,
                    EvidenceObservation {
                        sample_id: 2,
                        body: vec![3],
                        ..admission
                    }
                ));
                // Let the already-started empty-session fence finish while this
                // send is in flight. Its ready answer must precede sample two.
                tokio::task::yield_now().await;
            }
            frames_tx.send(message).unwrap();
            Ok::<(), tokio_tungstenite::tungstenite::Error>(())
        }
    }));
    let mut outbound = OutboundQueues::new(
        mpsc::unbounded_channel().1,
        no_flight(),
        ControlConnStats::new(),
    );
    let mut drain = watch::channel(false).1;
    let config = HeartbeatConfig {
        sources,
        interval: Duration::from_secs(3600),
    };
    let identity = throwaway_identity_key();
    let writer = write_control_frames(
        sink,
        &mut outbound,
        &mut drain,
        &config,
        &identity,
        RelayId(1),
        WriterRoutes {
            challenge_rx: mpsc::unbounded_channel().1,
            flight_grant_rx: mpsc::unbounded_channel().1,
            load_state_rx,
            descriptor_ack_rx: watch::channel(None).1,
        },
    );
    let verify = async {
        let mut answered = false;
        loop {
            match frames_rx.recv().await.unwrap() {
                RelayToCoordinator::LoadStateSnapshot { request_id: 99, .. } => answered = true,
                RelayToCoordinator::SlotEvidence(notice) if notice.evidence.sample_id == 2 => {
                    assert!(
                        answered,
                        "a ready load-state answer outranks the next sample"
                    );
                    break;
                }
                RelayToCoordinator::SlotEvidence(_) => {}
                _ => panic!("unexpected writer frame"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! { _ = writer => panic!("writer ended unexpectedly"), () = verify => {} }
    })
    .await
    .unwrap();
}

#[test]
fn older_sticky_failure_is_reported_after_a_newer_sample_was_sent() {
    use super::super::heartbeat::{heartbeat_presence_with_evidence, unsent_periodic_candidates};

    let (sources, admission, _) = reporting_fixture();
    let makers = &sources.decision_makers;
    let slot = SlotId(0);
    assert!(collect_sample(
        makers,
        &key(7),
        slot,
        1,
        EvidenceObservation {
            sample_id: 2,
            verdict: EvidenceVerdict::Missing,
            ..admission.clone()
        }
    ));
    assert!(collect_sample(
        makers,
        &key(7),
        slot,
        1,
        EvidenceObservation {
            sample_id: 3,
            body: vec![3],
            ..admission.clone()
        }
    ));
    let retained = makers.retained_load_state(&key(7));
    let history = &retained.evidence_history[0].history;
    let current = &retained.periodic_evidence[0].observation;
    assert!(history.sample.sequence < current.sequence);
    let historical_id = (key(7), slot, history.sample.sequence);
    let current_id = (key(7), slot, current.sequence);

    // Notice and heartbeat delivery have separate ledgers. Receiving a newer
    // sample through either path is not proof that its older history arrived.
    let mut notice_sent = HashSet::from([current_id.clone()]);
    assert_eq!(
        unsent_periodic_candidates(&sources, &mut notice_sent),
        vec![historical_id.clone()]
    );
    let notice = makers
        .periodic_evidence_notice(&key(7), slot, history.sample.sequence)
        .unwrap();
    assert_eq!(notice.evidence, history.sample);
    assert_eq!(notice.historical_admission, Some(admission.clone()));
    assert!(notice.admission.is_none());
    notice_sent.insert(historical_id.clone());
    assert!(unsent_periodic_candidates(&sources, &mut notice_sent).is_empty());

    let mut heartbeat_sent = HashSet::from([current_id.clone()]);
    let roster = heartbeat_presence_with_evidence(&sources, &mut 0, &[], &mut heartbeat_sent);
    assert_eq!(roster.len(), 1);
    assert!(roster[0].evidence.is_empty());
    assert!(roster[0].periodic_evidence.is_empty());
    assert_eq!(roster[0].evidence_history, retained.evidence_history);
    heartbeat_sent.insert(historical_id.clone());
    let unchanged = heartbeat_presence_with_evidence(&sources, &mut 0, &[], &mut heartbeat_sent);
    assert!(unchanged[0].evidence.is_empty());
    assert!(unchanged[0].periodic_evidence.is_empty());
    assert!(unchanged[0].evidence_history.is_empty());

    // A fresh control connection recovers both distinct shapes exactly once,
    // even though they concern the same slot and admission identity.
    let mut fresh_sent = HashSet::new();
    let roster = heartbeat_presence_with_evidence(&sources, &mut 0, &[], &mut fresh_sent);
    assert_eq!(roster[0].evidence.len(), 1);
    assert_eq!(roster[0].periodic_evidence.len(), 1);
    assert_eq!(roster[0].evidence_history.len(), 1);
    assert_eq!(roster[0].evidence[0].observation, admission);
    assert_eq!(&roster[0].periodic_evidence[0].observation, current);
    assert_eq!(&roster[0].evidence_history[0].history, history);
    let frame = RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: roster,
        region_rtts: vec![],
    };
    let wire = serde_json::to_vec(&frame).unwrap();
    assert_eq!(
        serde_json::from_slice::<RelayToCoordinator>(&wire).unwrap(),
        frame
    );
    fresh_sent.extend([current_id, historical_id]);
    let unchanged = heartbeat_presence_with_evidence(&sources, &mut 0, &[], &mut fresh_sent);
    assert!(unchanged[0].evidence.is_empty());
    assert!(unchanged[0].periodic_evidence.is_empty());
    assert!(unchanged[0].evidence_history.is_empty());
}
