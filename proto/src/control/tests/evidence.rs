use super::*;

fn observation() -> EvidenceObservation {
    EvidenceObservation {
        connection_id: [3; 32],
        sequence: 8,
        assignment_revision: 2,
        verdict: EvidenceVerdict::Valid,
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
