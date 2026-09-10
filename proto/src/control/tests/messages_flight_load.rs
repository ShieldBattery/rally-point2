use super::*;

#[test]
fn relay_to_coordinator_flight_upload_request_roundtrips_json() {
    let message = RelayToCoordinator::FlightUploadRequest {
        request: 7,
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(42),
        desynced: true,
        bytes: 4096,
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"flight_upload_request\""));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
    let RelayToCoordinator::FlightUploadRequest {
        request,
        session,
        desynced,
        bytes,
        ..
    } = back
    else {
        panic!("expected a flight_upload_request frame");
    };
    assert_eq!(request, 7);
    assert_eq!(session, SessionId(42));
    assert!(desynced);
    assert_eq!(bytes, 4096);
}

#[test]
fn relay_to_coordinator_flight_upload_done_roundtrips_json() {
    let message = RelayToCoordinator::FlightUploadDone { request: 9 };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"flight_upload_done\""));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn coordinator_to_relay_flight_upload_grant_roundtrips_json() {
    let message = CoordinatorToRelay::FlightUploadGrant {
        request: 7,
        url: "https://bucket.example/desync/sb-staging/42/3.json.zst?X-Amz-Signature=abc"
            .to_owned(),
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"flight_upload_grant\""));
    let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
    let CoordinatorToRelay::FlightUploadGrant { request, url } = back else {
        panic!("expected a flight_upload_grant frame");
    };
    assert_eq!(request, 7);
    assert!(url.contains("X-Amz-Signature"));
}

#[test]
fn coordinator_to_relay_flight_upload_refused_roundtrips_json() {
    let message = CoordinatorToRelay::FlightUploadRefused { request: 7 };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"flight_upload_refused\""));
    let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn flight_upload_request_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Forward compatibility: a `FlightUploadRequest` up-frame decoded by the
    // down-direction `CoordinatorToRelay` (which has no such variant) folds into
    // `Unknown` rather than erroring — a coordinator that predates the variant
    // skips the request (the recording is lost) instead of tearing the connection
    // down.
    let json = r#"{"type":"flight_upload_request","request":1,"tenant":"sb-staging","session":42,"desynced":false,"bytes":10}"#;
    let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, CoordinatorToRelay::Unknown);
}

#[test]
fn flight_upload_grant_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // The mirror direction: a `FlightUploadGrant` down-frame decoded by the
    // up-direction `RelayToCoordinator` (which has no such variant) folds into
    // `Unknown` — a relay that predates the grant variant skips it, so a new
    // coordinator against an old relay degrades to lost blobs rather than a torn
    // connection.
    let json = r#"{"type":"flight_upload_grant","request":1,"url":"https://x/y"}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, RelayToCoordinator::Unknown);
}

#[test]
fn load_state_request_roundtrips_json() {
    let message = CoordinatorToRelay::LoadStateRequest {
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(42),
        request_id: 9,
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"load_state_request\""));
    let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn load_state_snapshot_roundtrips_json() {
    let message = RelayToCoordinator::LoadStateSnapshot {
        request_id: 9,
        state: SessionPresence {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            slots: vec![SlotId(1)],
            ever_connected: vec![SlotId(0), SlotId(1)],
            started: vec![SlotId(1)],
            started_at_ms: Some(1_700_000_000_000),
        },
        fenced: true,
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"load_state_snapshot\""));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn an_empty_load_state_snapshot_roundtrips_and_omits_its_absent_fields() {
    // The "I hold nothing for this session" attestation: every optional list
    // stays off the wire, so it is byte-cheap to answer for a session the relay
    // does not hold — and still decodes to the empty sets that say so.
    let message = RelayToCoordinator::LoadStateSnapshot {
        request_id: 1,
        state: SessionPresence {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(1),
            slots: vec![],
            ever_connected: vec![],
            started: vec![],
            started_at_ms: None,
        },
        fenced: false,
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(!json.contains("ever_connected"));
    assert!(!json.contains("started_at_ms"));
    assert!(!json.contains("fenced"));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn a_snapshot_from_a_relay_predating_the_fence_decodes_unfenced() {
    // The additive field's whole point: a relay that never ran a fence omits it,
    // and must never be read as having claimed one.
    let json = r#"{"type":"load_state_snapshot","request_id":3,"state":{"tenant":"sb-staging","session":7,"slots":[]}}"#;
    let back: RelayToCoordinator = serde_json::from_str(json).unwrap();
    let RelayToCoordinator::LoadStateSnapshot { fenced, .. } = back else {
        panic!("decodes as a snapshot");
    };
    assert!(!fenced);
}

#[test]
fn load_state_request_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // A relay that predates the request decodes it as `Unknown` and answers
    // nothing at all — which is why the coordinator reads a missing answer as
    // "did not attest" rather than as an empty snapshot.
    let json = r#"{"type":"load_state_request","tenant":"sb-staging","session":42,"request_id":9}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, RelayToCoordinator::Unknown);
}

#[test]
fn load_state_snapshot_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // The mirror direction: a coordinator that predates the snapshot skips it
    // rather than tearing the connection down.
    let json = r#"{"type":"load_state_snapshot","request_id":9,"state":{"tenant":"sb-staging","session":42,"slots":[]}}"#;
    let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, CoordinatorToRelay::Unknown);
}
