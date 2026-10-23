//! Inbound control frames: what the reader's dispatch does with a decoded
//! frame, the `SessionClosed` generation fence, and the drain mark's.
//!
//! What a *heartbeat* then means — the ceilings, the generation fence, the
//! serving-relay filter and the fan-out — is the lifecycle's, and is tested
//! there (`lifecycle::tests::heartbeat`); the one beat here is about this
//! layer's decode-and-hand-off.

use super::*;

/// A `Heartbeat` framed as an inbound control message, carrying the given
/// session roster (marked complete) and no RTT reports.
fn heartbeat_with_sessions(sessions: Vec<rally_point_proto::control::SessionPresence>) -> Message {
    let heartbeat = RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions,
        region_rtts: vec![],
    };
    Message::Text(serde_json::to_string(&heartbeat).unwrap().into())
}

#[tokio::test]
async fn a_decoded_heartbeat_frame_reaches_the_lifecycles_ingest() {
    // This layer's whole share of a heartbeat: decode the frame and hand it to
    // the owner once. The roster it carries lands, so the hand-off is real and
    // carries the beat's contents — everything the ingest then decides is
    // asserted against `Lifecycle::ingest_heartbeat` directly.
    let fixture = bare_inbound_fixture();
    let tenant = tenant_id();
    let session = SessionId(77);
    fixture.note(&heartbeat_with_sessions(vec![presence_entry(
        &tenant,
        session,
        &[0],
    )]));

    assert_eq!(
        presence::fresh_slots(fixture.setup.presence(), &tenant, std::time::Instant::now()),
        vec![(session, SlotId(0))],
        "the frame's roster reached the ingest and was applied",
    );
}

#[tokio::test]
async fn session_closed_from_a_superseded_connection_cannot_close_the_live_epoch() {
    let (setup, lifecycle, session) =
        setup_with_session_and_notify("http://127.0.0.1:1/hook".to_owned());
    let tenant = tenant_id();
    lifecycle.register_session(
        tenant.clone(),
        session,
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0)]),
        std::collections::HashSet::new(),
    );
    let hello = (RelaySpec {
        id: 1,
        region: None,
    })
    .hello();
    let stale_generation = registry::enroll(setup.registry(), hello.clone());
    let current_generation = registry::enroll(setup.registry(), hello);
    lifecycle.on_relay_enrolled(RelayId(1), current_generation);

    let regions = RegionsConfig::default();
    let store = pair_rtts::PairRttStore::new();
    let rtt = idle_rtt_ingest(&regions, &store);
    let occupied = heartbeat_with_sessions(vec![presence_entry(&tenant, session, &[0])]);
    note_inbound_frame(
        &setup,
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
fn a_drain_mark_from_a_superseded_connection_cannot_mark_its_live_successor() {
    // A relay's stale connection can flush a `Draining` after the relay already
    // reconnected. The successor's enroll cleared the draining flag, and the
    // stale mark must not set it again: that would exclude a live, idle relay
    // from every new assignment until it re-enrolled once more. The live
    // connection runs its own drain exchange when its own `Draining` arrives.
    let reg = registry::RelayRegistry::new();
    let hello = (RelaySpec {
        id: 1,
        region: None,
    })
    .hello();
    let stale_generation = registry::enroll(&reg, hello.clone());
    let current_generation = registry::enroll(&reg, hello);
    let setup = session::SessionSetup::new(reg, crate::tenant::TenantStore::new());

    let draining = || {
        registry::enrolled_relays(setup.registry())
            .into_iter()
            .find(|relay| relay.relay_id == RelayId(1))
            .expect("relay 1 is enrolled")
            .draining
    };

    assert!(
        !apply_drain_mark(&setup, RelayId(1), stale_generation),
        "a Draining from the superseded connection draws no ack",
    );
    assert!(
        !draining(),
        "the live successor stays eligible for new assignments",
    );

    // The current connection's own Draining does apply.
    assert!(apply_drain_mark(&setup, RelayId(1), current_generation));
    assert!(
        draining(),
        "the relay its own connection drained is excluded from new assignments",
    );
}

fn evidence_report_fixture() -> (
    CoordinatorState,
    u64,
    rally_point_proto::control::EvidenceReport,
) {
    use rally_point_proto::control::{
        CAPABILITY_PERIODIC_EVIDENCE_V1, EvidenceHistory, EvidenceKey, EvidenceObservation,
        EvidenceReport, EvidenceVerdict,
    };
    let state = state_with_relay_and_tenant();
    let generation = state
        .lifecycle
        .enroll_relay_epoch(RelayId(1), || {
            Ok::<_, ()>(registry::enroll(
                state.setup.registry(),
                hello(1, 14901)
                    .with_boot_id(7)
                    .with_capabilities(vec![CAPABILITY_PERIODIC_EVIDENCE_V1.into()]),
            ))
        })
        .unwrap();
    registry::note_boot_id(state.setup.registry(), RelayId(1), Some(7));
    let mut req = request(vec![player(0)]);
    req.periodic_evidence = true;
    req.evidence_keys = vec![EvidenceKey {
        key_id: 7,
        public_key: ClientPublicKey([4; 32]),
    }];
    let session = session::create_session(&state.setup, req, ExpiresAt(u64::MAX))
        .unwrap()
        .response
        .session;
    state.lifecycle.register_session(
        tenant_id(),
        session,
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0)]),
        Default::default(),
    );
    let admission = EvidenceObservation {
        interruption: None,

        sample_id: 0,
        connection_id: [9; 32],
        sequence: 1,
        assignment_revision: 1,
        verdict: EvidenceVerdict::Valid,
        key_id: Some(7),
        body: vec![1, 2, 3],
    };
    let report = EvidenceReport {
        tenant: tenant_id(),
        session,
        slot: SlotId(0),
        history: EvidenceHistory {
            failures: 1,
            latest: None,

            sample: EvidenceObservation {
                sample_id: 3,
                sequence: 5,
                verdict: EvidenceVerdict::Missing,
                key_id: None,
                body: vec![],
                ..admission.clone()
            },
            admission,
            observed_at_ms: 42,
        },
    };
    (state, generation, report)
}

fn report_action(
    state: &CoordinatorState,
    generation: u64,
    report: rally_point_proto::control::EvidenceReport,
) -> InboundAction {
    let message = Message::Text(
        serde_json::to_string(&RelayToCoordinator::EvidenceReport(Box::new(report)))
            .unwrap()
            .into(),
    );
    let regions = RegionsConfig::default();
    let rtts = pair_rtts::PairRttStore::new();
    note_inbound_frame(
        &state.setup,
        &state.lifecycle,
        RelayId(1),
        generation,
        &message,
        &idle_rtt_ingest(&regions, &rtts),
    )
}

#[tokio::test]
async fn decoded_evidence_report_returns_the_exact_receipt_again_after_receipt_loss() {
    let (state, generation, report) = evidence_report_fixture();
    let mut receipt = report.receipt();
    assert_eq!(
        report_action(&state, generation, report.clone()),
        InboundAction::EvidenceReceipt(receipt.clone())
    );
    receipt.disposition = rally_point_proto::control::EvidenceReceiptDisposition::Superseded;
    assert_eq!(
        report_action(&state, generation, report.clone()),
        InboundAction::EvidenceReceipt(receipt)
    );
    let snapshot = state
        .lifecycle
        .load_state(&report.tenant, report.session)
        .unwrap();
    assert!(
        snapshot.connected_slots.is_empty(),
        "historical delivery cannot activate a slot"
    );
    assert_eq!(
        snapshot.evidence.len(),
        1,
        "retry delivery does not duplicate history"
    );
    assert_eq!(snapshot.evidence[0].observation, report.history.sample);
}

#[tokio::test]
async fn stale_generation_and_mismatched_pairs_draw_no_evidence_receipt() {
    let (state, stale_generation, report) = evidence_report_fixture();
    let generation = state
        .lifecycle
        .enroll_relay_epoch(RelayId(1), || {
            Ok::<_, ()>(registry::enroll(
                state.setup.registry(),
                hello(1, 14901).with_boot_id(7).with_capabilities(vec![
                    rally_point_proto::control::CAPABILITY_PERIODIC_EVIDENCE_V1.into(),
                ]),
            ))
        })
        .unwrap();
    assert_ne!(generation, stale_generation);
    assert_eq!(
        report_action(&state, stale_generation, report.clone()),
        InboundAction::None
    );
    let mut wrong_connection = report.clone();
    wrong_connection.history.sample.connection_id = [8; 32];
    let mut wrong_revision = report.clone();
    wrong_revision.history.sample.assignment_revision += 1;
    let mut wrong_sequence = report.clone();
    wrong_sequence.history.sample.sequence = report.history.admission.sequence;
    for invalid in [wrong_connection, wrong_revision, wrong_sequence] {
        assert_eq!(
            report_action(&state, generation, invalid),
            InboundAction::None
        );
    }
    assert!(
        state
            .lifecycle
            .load_state(&report.tenant, report.session)
            .unwrap()
            .evidence
            .is_empty()
    );
    assert_eq!(
        report_action(&state, generation, report.clone()),
        InboundAction::EvidenceReceipt(report.receipt())
    );
}

fn future_value_frame(frame: RelayToCoordinator, pointer: &str) -> Message {
    let mut json = serde_json::to_value(frame).unwrap();
    *json.pointer_mut(pointer).unwrap() = "future_variant".into();
    Message::Text(json.to_string().into())
}

fn apply_frame(state: &CoordinatorState, generation: u64, frame: &Message) -> InboundAction {
    note_inbound_frame(
        &state.setup,
        &state.lifecycle,
        RelayId(1),
        generation,
        frame,
        &idle_rtt_ingest(&RegionsConfig::default(), &pair_rtts::PairRttStore::new()),
    )
}

#[tokio::test]
async fn future_evidence_variants_preserve_heartbeat_presence_and_known_observations() {
    use rally_point_proto::control::{EvidenceInterruption, SlotEvidence, SlotEvidenceHistory};
    for unknown_field in ["interruption", "verdict"] {
        let (state, generation, mut report) = evidence_report_fixture();
        report.history.sample.interruption = Some(EvidenceInterruption::Timeout);
        let mut presence = presence_entry(&report.tenant, report.session, &[0]);
        presence.evidence = vec![SlotEvidence {
            slot: report.slot,
            observation: report.history.admission.clone(),
            observed_at_ms: None,
            historical: false,
            failure_count: None,
        }];
        presence.periodic_evidence = vec![SlotEvidence {
            slot: report.slot,
            observation: report.history.sample.clone(),
            observed_at_ms: Some(42),
            historical: false,
            failure_count: None,
        }];
        presence.evidence_history = vec![SlotEvidenceHistory {
            slot: report.slot,
            history: report.history.clone(),
        }];
        let mut json = serde_json::to_value(RelayToCoordinator::Heartbeat {
            roster_complete: true,
            sessions: vec![presence],
            region_rtts: vec![],
        })
        .unwrap();
        json["sessions"][0]["periodic_evidence"][0]["observation"][unknown_field] =
            "future_variant".into();
        json["sessions"][0]["evidence_history"][0]["history"]["sample"][unknown_field] =
            "future_variant".into();
        apply_frame(&state, generation, &Message::Text(json.to_string().into()));
        assert_eq!(
            presence::fresh_slots(
                state.setup.presence(),
                &report.tenant,
                std::time::Instant::now()
            ),
            vec![(report.session, report.slot)]
        );
        let evidence = state
            .lifecycle
            .connection_evidence(&report.tenant, report.session);
        assert_eq!(
            evidence.len(),
            1,
            "unsupported samples cannot become failure history"
        );
        assert_eq!(evidence[0].observation, report.history.admission);
        // A known report still records normally after the unsupported snapshot.
        assert_eq!(
            report_action(&state, generation, report.clone()),
            InboundAction::EvidenceReceipt(report.receipt())
        );
    }
}

#[tokio::test]
async fn future_history_variants_are_not_acknowledged_or_counted() {
    for pointer in [
        "/history/admission/verdict",
        "/history/sample/verdict",
        "/history/sample/interruption",
    ] {
        let (state, generation, mut report) = evidence_report_fixture();
        report.history.sample.interruption =
            Some(rally_point_proto::control::EvidenceInterruption::Timeout);
        let frame = future_value_frame(
            RelayToCoordinator::EvidenceReport(Box::new(report.clone())),
            pointer,
        );
        assert_eq!(apply_frame(&state, generation, &frame), InboundAction::None);
        assert!(
            state
                .lifecycle
                .connection_evidence(&report.tenant, report.session)
                .is_empty()
        );
        assert_eq!(
            report_action(&state, generation, report.clone()),
            InboundAction::EvidenceReceipt(report.receipt())
        );
    }
}

#[tokio::test]
async fn future_admission_variants_preserve_authorized_arrival_without_evidence() {
    use rally_point_proto::control::{EvidenceInterruption, SlotConnectedNotice};
    for field in ["verdict", "interruption"] {
        let (state, generation, report) = evidence_report_fixture();
        let mut admission = report.history.admission.clone();
        if field == "interruption" {
            admission.interruption = Some(EvidenceInterruption::Timeout);
        }
        let frame = future_value_frame(
            RelayToCoordinator::SlotConnected(SlotConnectedNotice {
                predecessor: None,
                evidence: Some(admission),
                tenant: report.tenant.clone(),
                session: report.session,
                slot: report.slot,
                external_id: None,
                external_ref: None,
                resumed: false,
                connected_at_ms: 42,
            }),
            &format!("/evidence/{field}"),
        );
        apply_frame(&state, generation + 1, &frame);
        let Message::Text(text) = &frame else {
            unreachable!()
        };
        let mut wrong_assignment: serde_json::Value = serde_json::from_str(text).unwrap();
        wrong_assignment["evidence"]["assignment_revision"] = 2.into();
        apply_frame(
            &state,
            generation,
            &Message::Text(wrong_assignment.to_string().into()),
        );
        assert!(
            state
                .lifecycle
                .load_state(&report.tenant, report.session)
                .unwrap()
                .connected_slots
                .is_empty(),
            "unsupported evidence cannot bypass connection or assignment authorization"
        );
        apply_frame(&state, generation, &frame);
        let snapshot = state
            .lifecycle
            .load_state(&report.tenant, report.session)
            .unwrap();
        assert_eq!(snapshot.connected_slots, vec![report.slot]);
        assert!(snapshot.evidence.is_empty());
    }
}

#[tokio::test]
async fn future_admission_verdict_in_heartbeat_preserves_presence_without_trusting_body() {
    use rally_point_proto::control::SlotEvidence;
    let (state, generation, report) = evidence_report_fixture();
    let mut presence = presence_entry(&report.tenant, report.session, &[0]);
    presence.evidence = vec![SlotEvidence {
        slot: report.slot,
        observation: report.history.admission.clone(),
        observed_at_ms: None,
        historical: false,
        failure_count: None,
    }];
    let frame = future_value_frame(
        RelayToCoordinator::Heartbeat {
            roster_complete: true,
            sessions: vec![presence],
            region_rtts: vec![],
        },
        "/sessions/0/evidence/0/observation/verdict",
    );
    apply_frame(&state, generation, &frame);
    assert_eq!(
        presence::fresh_slots(
            state.setup.presence(),
            &report.tenant,
            std::time::Instant::now()
        ),
        vec![(report.session, report.slot)]
    );
    assert!(
        state
            .lifecycle
            .connection_evidence(&report.tenant, report.session)
            .is_empty()
    );
}
