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
}

#[test]
fn the_one_field_flight_upload_frames_roundtrip_json() {
    // `FlightUploadDone` (up) and `FlightUploadRefused` (down) are the same
    // shape — a tag and the correlation id that pairs them with a request — so
    // the only thing to pin is that each keeps its own tag and carries the id.
    let done = RelayToCoordinator::FlightUploadDone { request: 9 };
    let json = serde_json::to_string(&done).unwrap();
    assert_eq!(json, r#"{"type":"flight_upload_done","request":9}"#);
    assert_eq!(
        serde_json::from_str::<RelayToCoordinator>(&json).unwrap(),
        done
    );

    let refused = CoordinatorToRelay::FlightUploadRefused { request: 7 };
    let json = serde_json::to_string(&refused).unwrap();
    assert_eq!(json, r#"{"type":"flight_upload_refused","request":7}"#);
    assert_eq!(
        serde_json::from_str::<CoordinatorToRelay>(&json).unwrap(),
        refused
    );
}

#[test]
fn coordinator_to_relay_flight_upload_grant_roundtrips_json() {
    // The presigned URL is the whole point of the frame: its query string must
    // survive serde untouched, or the relay uploads to an unsigned URL.
    let message = CoordinatorToRelay::FlightUploadGrant {
        request: 7,
        url: "https://bucket.example/desync/sb-staging/42/3.json.zst?X-Amz-Signature=abc"
            .to_owned(),
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"flight_upload_grant\""));
    assert!(json.contains("X-Amz-Signature=abc"));
    let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
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

    // A populated snapshot puts every field it does hold on the wire under the
    // key names the coordinator reads.
    let populated = RelayToCoordinator::LoadStateSnapshot {
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
    let json = serde_json::to_string(&populated).unwrap();
    assert!(json.contains("\"type\":\"load_state_snapshot\""));
    assert!(json.contains("\"ever_connected\":[0,1]"));
    assert!(json.contains("\"fenced\":true"));
    assert_eq!(
        serde_json::from_str::<RelayToCoordinator>(&json).unwrap(),
        populated
    );
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
