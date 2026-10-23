use super::*;

fn observation() -> EvidenceObservation {
    EvidenceObservation {
        sample_id: 0,
        connection_id: [3; 32],
        sequence: 8,
        assignment_revision: 2,
        verdict: EvidenceVerdict::Valid,
        interruption: None,
        key_id: Some(7),
        body: vec![0, 255, 42],
    }
}

#[test]
fn session_evidence_defaults_are_wire_compatible() {
    let request: SessionRequest = serde_json::from_value(serde_json::json!({
        "tenant": "test", "players": [{
            "slot": 0, "client_pubkey": vec![0; 32],
        }],
    }))
    .unwrap();
    assert!(request.evidence_keys.is_empty());
    assert!(!request.players[0].require_evidence);
    let value = serde_json::to_value(&request).unwrap();
    assert!(value.get("evidence_keys").is_none());
    assert!(value["players"][0].get("require_evidence").is_none());

    let value = serde_json::to_value(a_descriptor()).unwrap();
    for field in [
        "evidence_keys",
        "required_evidence_slots",
        "evidence_assignments",
    ] {
        assert!(value.get(field).is_none());
    }
    let descriptor: SessionDescriptor = serde_json::from_value(value).unwrap();
    assert!(descriptor.evidence_keys.is_empty());
    assert!(descriptor.required_evidence_slots.is_empty());
    assert!(descriptor.evidence_assignments.is_empty());
}

#[test]
fn descriptor_evidence_round_trips() {
    let descriptor = SessionDescriptor {
        evidence_keys: vec![EvidenceKey {
            key_id: 7,
            public_key: ClientPublicKey([9; 32]),
        }],
        required_evidence_slots: vec![SlotId(1)],
        evidence_assignments: vec![SlotEvidenceAssignment {
            slot: SlotId(1),
            revision: 2,
        }],
        ..a_descriptor()
    };
    let value = serde_json::to_value(&descriptor).unwrap();
    assert_eq!(value["evidence_keys"][0]["key_id"], 7);
    assert_eq!(value["required_evidence_slots"], serde_json::json!([1]));
    assert_eq!(value["evidence_assignments"][0]["revision"], 2);
    assert_eq!(
        serde_json::from_value::<SessionDescriptor>(value).unwrap(),
        descriptor
    );
}

#[test]
fn notice_and_presence_defaults_and_observations_round_trip() {
    let mut notice: SlotConnectedNotice = serde_json::from_value(serde_json::json!({
        "tenant": "test", "session": 1, "slot": 0,
        "resumed": false, "connected_at_ms": 123,
    }))
    .unwrap();
    assert!(notice.evidence.is_none());
    assert!(
        serde_json::to_value(&notice)
            .unwrap()
            .get("evidence")
            .is_none()
    );
    notice.evidence = Some(observation());
    let value = serde_json::to_value(&notice).unwrap();
    assert_eq!(value["evidence"]["verdict"], "valid");
    assert_eq!(value["evidence"]["body"], "AP8q");
    assert_eq!(
        serde_json::from_value::<SlotConnectedNotice>(value).unwrap(),
        notice
    );

    let mut presence: SessionPresence = serde_json::from_value(serde_json::json!({
        "tenant": "test", "session": 1, "slots": [],
    }))
    .unwrap();
    assert!(presence.evidence.is_empty());
    assert!(
        serde_json::to_value(&presence)
            .unwrap()
            .get("evidence")
            .is_none()
    );
    presence.evidence = vec![SlotEvidence {
        observed_at_ms: None,
        historical: false,
        failure_count: None,

        slot: SlotId(0),
        observation: observation(),
    }];
    let value = serde_json::to_value(&presence).unwrap();
    assert_eq!(
        serde_json::from_value::<SessionPresence>(value).unwrap(),
        presence
    );
}

#[test]
fn verdict_names_are_stable() {
    for (verdict, name) in [
        (EvidenceVerdict::Missing, "missing"),
        (EvidenceVerdict::UnknownKey, "unknown_key"),
        (EvidenceVerdict::Invalid, "invalid"),
        (EvidenceVerdict::Valid, "valid"),
        (EvidenceVerdict::Unrecognized, "unrecognized"),
    ] {
        let value = serde_json::to_value(verdict).unwrap();
        assert_eq!(value, name);
        assert_eq!(
            serde_json::from_value::<EvidenceVerdict>(value).unwrap(),
            verdict
        );
    }
}

#[test]
fn observation_body_round_trips_as_bounded_base64() {
    use crate::handshake::MAX_EVIDENCE_BODY_LEN;

    for len in [0, 1, 2, 3, MAX_EVIDENCE_BODY_LEN] {
        let observation = EvidenceObservation {
            body: vec![255; len],
            ..observation()
        };
        let value = serde_json::to_value(&observation).unwrap();
        assert_eq!(value["body"].as_str().unwrap().len(), len.div_ceil(3) * 4);
        assert_eq!(
            serde_json::from_value::<EvidenceObservation>(value).unwrap(),
            observation
        );
    }
}

#[test]
fn observation_body_rejects_malformed_and_oversized_encodings() {
    use crate::handshake::MAX_EVIDENCE_BODY_LEN;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    for invalid in [
        serde_json::json!([0, 255, 42]),
        serde_json::json!("?!!!"),
        serde_json::json!("/w"),
        serde_json::json!(STANDARD.encode(vec![0; MAX_EVIDENCE_BODY_LEN + 1])),
        serde_json::json!(STANDARD.encode(vec![0; MAX_EVIDENCE_BODY_LEN + 3])),
    ] {
        let mut value = serde_json::to_value(observation()).unwrap();
        value["body"] = invalid;
        assert!(serde_json::from_value::<EvidenceObservation>(value).is_err());
    }
    let oversized = EvidenceObservation {
        body: vec![0; MAX_EVIDENCE_BODY_LEN + 1],
        ..observation()
    };
    assert!(serde_json::to_vec(&oversized).is_err());
}

#[test]
fn other_control_byte_fields_keep_their_array_encoding() {
    let command = AllowedLobbyCommand {
        slot: SlotId(0),
        payload: vec![0, 255, 42],
    };
    assert_eq!(
        serde_json::to_value(command).unwrap()["payload"],
        serde_json::json!([0, 255, 42])
    );
}

#[test]
fn periodic_fields_default_and_are_omitted_for_older_peers() {
    let old = serde_json::to_value(observation()).unwrap();
    assert!(old.get("sample_id").is_none());
    assert_eq!(
        serde_json::from_value::<EvidenceObservation>(old)
            .unwrap()
            .sample_id,
        0
    );
    let request: SessionRequest =
        serde_json::from_value(serde_json::json!({"tenant":"test", "players":[]})).unwrap();
    assert!(!request.periodic_evidence);
    assert!(
        serde_json::to_value(request)
            .unwrap()
            .get("periodic_evidence")
            .is_none()
    );
    let descriptor = serde_json::to_value(a_descriptor()).unwrap();
    assert!(descriptor.get("periodic_evidence").is_none());
    assert!(
        !serde_json::from_value::<SessionDescriptor>(descriptor)
            .unwrap()
            .periodic_evidence
    );
    let presence: SessionPresence =
        serde_json::from_value(serde_json::json!({"tenant":"test", "session":1, "slots":[]}))
            .unwrap();
    assert!(presence.periodic_evidence.is_empty());
    assert!(
        serde_json::to_value(presence)
            .unwrap()
            .get("periodic_evidence")
            .is_none()
    );
}

#[test]
fn periodic_policy_notice_and_presence_round_trip_independently() {
    let descriptor = SessionDescriptor {
        periodic_evidence: true,
        ..a_descriptor()
    };
    assert_eq!(
        serde_json::from_value::<SessionDescriptor>(serde_json::to_value(&descriptor).unwrap())
            .unwrap(),
        descriptor
    );
    let mut request: SessionRequest =
        serde_json::from_value(serde_json::json!({"tenant":"test", "players":[]})).unwrap();
    request.periodic_evidence = true;
    assert_eq!(
        serde_json::from_value::<SessionRequest>(serde_json::to_value(&request).unwrap()).unwrap(),
        request
    );
    let sample = EvidenceObservation {
        sample_id: 13,
        ..observation()
    };
    let notice = RelayToCoordinator::SlotEvidence(SlotEvidenceNotice {
        admission: None,
        historical_admission: None,
        tenant: TenantId("test".into()),
        session: SessionId(1),
        slot: SlotId(2),
        external_id: None,
        external_ref: None,
        observed_at_ms: 42,
        evidence: sample.clone(),
    });
    let encoded = serde_json::to_value(&notice).unwrap();
    assert_eq!(encoded["type"], "slot_evidence");
    assert_eq!(encoded["evidence"]["sample_id"], 13);
    assert!(encoded.get("external_id").is_none());
    assert_eq!(
        serde_json::from_value::<RelayToCoordinator>(encoded.clone()).unwrap(),
        notice
    );
    let mut missing = encoded;
    missing.as_object_mut().unwrap().remove("evidence");
    assert!(serde_json::from_value::<RelayToCoordinator>(missing).is_err());
    let mut presence: SessionPresence =
        serde_json::from_value(serde_json::json!({"tenant":"test", "session":1, "slots":[]}))
            .unwrap();
    presence.periodic_evidence = vec![SlotEvidence {
        observed_at_ms: None,
        historical: false,
        failure_count: None,

        slot: SlotId(2),
        observation: sample,
    }];
    let value = serde_json::to_value(&presence).unwrap();
    assert!(value.get("evidence").is_none());
    assert_eq!(
        serde_json::from_value::<SessionPresence>(value).unwrap(),
        presence
    );
}

#[test]
fn periodic_presence_bounds_sample_count_on_both_wire_directions() {
    let mut presence: SessionPresence =
        serde_json::from_value(serde_json::json!({"tenant":"test", "session":1, "slots":[]}))
            .unwrap();
    presence.periodic_evidence = (0..16)
        .map(|slot| SlotEvidence {
            observed_at_ms: None,
            historical: false,
            failure_count: None,

            slot: SlotId(slot),
            observation: EvidenceObservation {
                sample_id: 1,
                ..observation()
            },
        })
        .collect();
    let mut value = serde_json::to_value(&presence).unwrap();
    assert_eq!(
        serde_json::from_value::<SessionPresence>(value.clone()).unwrap(),
        presence
    );
    presence
        .periodic_evidence
        .push(presence.periodic_evidence[0].clone());
    assert!(serde_json::to_value(&presence).is_err());
    let extra = value["periodic_evidence"][0].clone();
    value["periodic_evidence"]
        .as_array_mut()
        .unwrap()
        .push(extra);
    assert!(serde_json::from_value::<SessionPresence>(value).is_err());
}

#[test]
fn history_is_optional_for_older_notices_and_bounded_for_recovery() {
    let mut presence: SessionPresence = serde_json::from_value(serde_json::json!({
        "tenant": "test", "session": 1, "slots": []
    }))
    .unwrap();
    assert!(presence.evidence_history.is_empty());
    assert!(
        serde_json::to_value(&presence)
            .unwrap()
            .get("evidence_history")
            .is_none()
    );
    let history = EvidenceHistory {
        failures: 1,
        latest: None,

        admission: observation(),
        sample: EvidenceObservation {
            sample_id: 1,
            verdict: EvidenceVerdict::Missing,
            interruption: None,
            body: Vec::new(),
            ..observation()
        },
        observed_at_ms: 42,
    };
    presence.evidence_history = (0..16)
        .map(|slot| SlotEvidenceHistory {
            slot: SlotId(slot),
            history: history.clone(),
        })
        .collect();
    let mut encoded = serde_json::to_value(&presence).unwrap();
    assert_eq!(
        serde_json::from_value::<SessionPresence>(encoded.clone()).unwrap(),
        presence
    );
    presence
        .evidence_history
        .push(presence.evidence_history[0].clone());
    assert!(serde_json::to_value(&presence).is_err());
    let extra = encoded["evidence_history"][0].clone();
    encoded["evidence_history"]
        .as_array_mut()
        .unwrap()
        .push(extra);
    assert!(serde_json::from_value::<SessionPresence>(encoded).is_err());

    let mut notice = SlotEvidenceNotice {
        admission: None,
        historical_admission: None,
        tenant: TenantId("test".into()),
        session: SessionId(1),
        slot: SlotId(0),
        external_id: None,
        external_ref: None,
        observed_at_ms: 42,
        evidence: history.sample.clone(),
    };
    let old = serde_json::to_value(&notice).unwrap();
    assert!(old.get("admission").is_none());
    assert!(old.get("historical_admission").is_none());
    assert_eq!(
        serde_json::from_value::<SlotEvidenceNotice>(old).unwrap(),
        notice
    );
    notice.historical_admission = Some(history.admission.clone());
    assert_eq!(
        serde_json::from_value::<SlotEvidenceNotice>(serde_json::to_value(&notice).unwrap())
            .unwrap(),
        notice
    );

    let mut connected = SlotConnectedNotice {
        predecessor: None,
        evidence: Some(observation()),
        tenant: TenantId("test".into()),
        session: SessionId(1),
        slot: SlotId(0),
        external_id: None,
        external_ref: None,
        resumed: true,
        connected_at_ms: 43,
    };
    let old = serde_json::to_value(&connected).unwrap();
    assert!(old.get("predecessor").is_none());
    assert_eq!(
        serde_json::from_value::<SlotConnectedNotice>(old).unwrap(),
        connected
    );
    connected.predecessor = Some(Box::new(history));
    assert_eq!(
        serde_json::from_value::<SlotConnectedNotice>(serde_json::to_value(&connected).unwrap())
            .unwrap(),
        connected
    );
}

#[test]
fn historical_report_and_memory_receipt_round_trip_without_capability_negotiation() {
    let admission = observation();
    let report = EvidenceReport {
        tenant: TenantId("test".into()),
        session: SessionId(4),
        slot: SlotId(2),
        history: EvidenceHistory {
            failures: 1,
            latest: None,

            sample: EvidenceObservation {
                sample_id: 3,
                sequence: admission.sequence + 1,
                verdict: EvidenceVerdict::Missing,
                interruption: None,
                body: vec![],
                ..admission.clone()
            },
            admission,
            observed_at_ms: 5,
        },
    };
    let receipt = report.receipt();
    let frame = RelayToCoordinator::EvidenceReport(Box::new(report));
    let encoded = serde_json::to_vec(&frame).unwrap();
    assert_eq!(
        serde_json::from_slice::<RelayToCoordinator>(&encoded).unwrap(),
        frame
    );
    let frame = CoordinatorToRelay::EvidenceReceipt(receipt);
    let encoded = serde_json::to_vec(&frame).unwrap();
    assert_eq!(
        serde_json::from_slice::<CoordinatorToRelay>(&encoded).unwrap(),
        frame
    );
    // Older receivers use this same catch-all shape for unfamiliar message tags.
    #[derive(serde::Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum OlderReceiver {
        #[serde(other)]
        Unknown,
    }
    assert!(matches!(
        serde_json::from_slice::<OlderReceiver>(&encoded).unwrap(),
        OlderReceiver::Unknown
    ));
}

#[test]
fn future_evidence_enum_values_are_unrecognized() {
    for value in ["future_value", "unknown", "unrecognized"] {
        let value = serde_json::json!(value);
        assert_eq!(
            serde_json::from_value::<EvidenceVerdict>(value.clone()).unwrap(),
            EvidenceVerdict::Unrecognized
        );
        assert_eq!(
            serde_json::from_value::<EvidenceInterruption>(value.clone()).unwrap(),
            EvidenceInterruption::Unrecognized
        );
        assert_eq!(
            serde_json::from_value::<EvidenceReceiptDisposition>(value).unwrap(),
            EvidenceReceiptDisposition::Unrecognized
        );
    }
    assert_eq!(
        serde_json::to_value(EvidenceInterruption::Unrecognized).unwrap(),
        "unrecognized"
    );
    assert_eq!(
        serde_json::to_value(EvidenceReceiptDisposition::Unrecognized).unwrap(),
        "unrecognized"
    );
}
