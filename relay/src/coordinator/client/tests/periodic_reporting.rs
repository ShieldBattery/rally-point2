//! Paired recovery and separate sample notices on the actual control writer.
use super::*;
use crate::consensus::{Authority, EvidenceConfig, MakerSync};
use rally_point_proto::control::{EvidenceKey, EvidenceObservation, EvidenceVerdict};
use rally_point_proto::ids::SlotId;
use rally_point_proto::token::ClientPublicKey;

#[tokio::test]
async fn periodic_heartbeat_precedes_notice_and_unchanged_sample_is_not_renotified() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
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
    assert!(makers.record_periodic_evidence(
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
    SubscriberFixture {
        heartbeat: HeartbeatConfig {
            sources: HeartbeatSources {
                session_gates: Default::default(),
                provisional_turns: Default::default(),
                sessions,
                decision_makers: makers.clone(),
                region_rtt_cache: Default::default(),
                load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
            },
            interval: Duration::from_millis(50),
        },
        ..Default::default()
    }
    .spawn(addr);
    tokio::time::timeout(Duration::from_secs(5), async {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        accept_enroll(&mut ws).await;
        let RelayToCoordinator::Heartbeat { sessions, .. } =
            decode(ws.next().await.unwrap().unwrap())
        else {
            panic!("paired heartbeat must arrive first")
        };
        assert_eq!(sessions[0].evidence[0].observation, admission);
        assert_eq!(sessions[0].periodic_evidence[0].observation, expected);
        let RelayToCoordinator::SlotEvidence(notice) = decode(ws.next().await.unwrap().unwrap())
        else {
            panic!("separate sample notice follows")
        };
        assert_eq!(notice.evidence, expected);
        for _ in 0..2 {
            assert!(matches!(
                decode(ws.next().await.unwrap().unwrap()),
                RelayToCoordinator::Heartbeat { .. }
            ));
        }
    })
    .await
    .unwrap();
    assert_eq!(
        makers.retained_load_state(&key(7)).evidence[0].observation,
        admission
    );
}

#[test]
fn omitted_descriptor_policy_cannot_enable_periodic_reporting() {
    let mut wire = serde_json::to_value(descriptor(7, &[])).unwrap();
    wire.as_object_mut().unwrap().remove("periodicEvidence");
    let descriptor: SessionDescriptor = serde_json::from_value(wire).unwrap();
    assert!(!descriptor.periodic_evidence);
}
