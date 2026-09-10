use super::*;

#[test]
fn departure_roundtrips_json() {
    let notice = DepartureNotice {
        finalized: false,
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(42),
        slot: SlotId(2),
        kind: DepartureKind::Dropped,
        reason: 0x4000_0006,
        leave_seq: 1,
        external_id: Some("game-99".to_owned()),
        external_ref: Some("sb-user-7".to_owned()),
        result: Some(ResultEcho {
            payload: vec![0xDE, 0xAD],
            arrival_ms: 1_700_000_000_000,
            session_frame: Some(4200),
            slot_frame: Some(4242),
        }),
        final_turn_count: Some(2100),
    };
    let message = RelayToCoordinator::Departure(notice.clone());
    let json = serde_json::to_string(&message).unwrap();
    // The notice's fields ride alongside the tag (internally tagged), and
    // the kind serializes snake_case.
    assert!(json.contains("\"type\":\"departure\""));
    assert!(json.contains("\"kind\":\"dropped\""));
    // The embedded result rides along.
    assert!(json.contains("\"result\""));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn departure_without_correlation_ids_decodes_to_none() {
    // A notice from a relay that never received (or predates) the
    // correlation ids must still decode — the fields are optional and
    // default to `None`, so the coordinator's own session-refs fallback
    // kicks in rather than a decode error.
    let json = r#"{"type":"departure","tenant":"sb-staging","session":42,"slot":2,"kind":"dropped","reason":1073741830,"leave_seq":1}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    let RelayToCoordinator::Departure(notice) = decoded else {
        panic!("decodes to the Departure variant");
    };
    assert!(notice.external_id.is_none());
    assert!(notice.external_ref.is_none());
    assert!(
        notice.result.is_none(),
        "a departure from a relay that predates the embedded result decodes to None",
    );
    assert!(
        notice.final_turn_count.is_none(),
        "a departure from a relay that predates counted leaves decodes to None",
    );
}

#[test]
fn departure_omits_absent_correlation_ids_on_the_wire() {
    let notice = DepartureNotice {
        finalized: false,
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(1),
        slot: SlotId(0),
        kind: DepartureKind::Left,
        reason: 3,
        leave_seq: 1,
        external_id: None,
        external_ref: None,
        result: None,
        final_turn_count: None,
    };
    let json = serde_json::to_string(&notice).unwrap();
    assert!(!json.contains("external_id"));
    assert!(!json.contains("external_ref"));
    assert!(
        !json.contains("result"),
        "an absent embedded result is omitted, not sent as null",
    );
    assert!(
        !json.contains("final_turn_count"),
        "an absent final turn count is omitted, not sent as null",
    );
}

#[test]
fn departure_kind_left_serializes_snake_case() {
    let json = serde_json::to_string(&DepartureKind::Left).unwrap();
    assert_eq!(json, r#""left""#);
}

#[test]
fn desync_roundtrips_json() {
    let notice = DesyncNotice {
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(42),
        sync_ordinal: 137,
        game_frame: Some(4242),
        detected_at_ms: 1_700_000_000_000,
        no_majority: false,
        diverged: vec![DivergedSlot {
            slot: SlotId(2),
            external_ref: Some("sb-user-7".to_owned()),
        }],
        external_id: Some("game-99".to_owned()),
    };
    let message = RelayToCoordinator::Desync(notice.clone());
    let json = serde_json::to_string(&message).unwrap();
    // The notice's fields ride alongside the tag (internally tagged).
    assert!(json.contains("\"type\":\"desync\""));
    assert!(json.contains("\"sync_ordinal\":137"));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn desync_omits_absent_optionals_on_the_wire() {
    // A no-majority (1v1) desync: no game frame, no correlation ids, and an
    // empty diverged set. The optional fields are omitted (not `null`); the
    // always-present ones (detected_at_ms, no_majority, diverged) still
    // serialize.
    let notice = DesyncNotice {
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(1),
        sync_ordinal: 5,
        game_frame: None,
        detected_at_ms: 123,
        no_majority: true,
        diverged: vec![],
        external_id: None,
    };
    let json = serde_json::to_string(&notice).unwrap();
    assert!(!json.contains("game_frame"));
    assert!(!json.contains("external_id"));
    assert!(json.contains("\"no_majority\":true"));
    assert!(json.contains("\"diverged\":[]"));
}

#[test]
fn desync_without_optionals_decodes() {
    // A notice from a relay that carried no game frame or correlation ids
    // must still decode — the optional fields default, so the coordinator's
    // own fallbacks apply rather than a decode error.
    let json = r#"{"type":"desync","tenant":"sb-staging","session":42,"sync_ordinal":9,"detected_at_ms":7,"no_majority":false,"diverged":[{"slot":3}]}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    let RelayToCoordinator::Desync(notice) = decoded else {
        panic!("decodes to the Desync variant");
    };
    assert!(notice.game_frame.is_none());
    assert!(notice.external_id.is_none());
    assert_eq!(notice.diverged.len(), 1);
    assert!(notice.diverged[0].external_ref.is_none());
}

#[test]
fn desync_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Forward compatibility: a `Desync` up-frame decoded by the down-direction
    // `CoordinatorToRelay` (which has no such variant) folds into `Unknown`
    // rather than erroring — the "old peer sees a new frame" path.
    let json = r#"{"type":"desync","tenant":"sb-staging","session":42,"sync_ordinal":9,"detected_at_ms":7,"no_majority":false,"diverged":[]}"#;
    let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, CoordinatorToRelay::Unknown);
}

#[test]
fn departure_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Forward compatibility, made concrete: `Departure` is an up-frame the
    // relay sends. A decoder that predates it — here the *down*-direction
    // `CoordinatorToRelay`, which has no `Departure` — must fold the frame
    // into its `Unknown` catch-all rather than erroring, exactly as an older
    // coordinator build would. This is the "old peer sees a new frame" path.
    let json = r#"{"type":"departure","tenant":"sb-staging","session":42,"slot":2,"kind":"dropped","reason":1073741830,"leave_seq":1}"#;
    let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, CoordinatorToRelay::Unknown);
}

#[test]
fn result_roundtrips_json() {
    let notice = ResultNotice {
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(42),
        slot: SlotId(1),
        external_id: Some("game-99".to_owned()),
        external_ref: Some("sb-user-7".to_owned()),
        payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        arrival_ms: 1_700_000_000_000,
        session_frame: Some(4200),
        slot_frame: Some(4242),
    };
    let message = RelayToCoordinator::Result(notice.clone());
    let json = serde_json::to_string(&message).unwrap();
    // The notice's fields ride alongside the tag (internally tagged).
    assert!(json.contains("\"type\":\"result\""));
    assert!(json.contains("\"arrival_ms\":1700000000000"));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn result_without_optionals_decodes() {
    // A notice from a relay that carried no correlation ids or frame stamps
    // must still decode — the optional fields default, so the coordinator's
    // own fallbacks apply rather than a decode error. The payload and
    // arrival stamp are always present.
    let json = r#"{"type":"result","tenant":"sb-staging","session":42,"slot":0,"payload":[1,2,3],"arrival_ms":7}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    let RelayToCoordinator::Result(notice) = decoded else {
        panic!("decodes to the Result variant");
    };
    assert!(notice.external_id.is_none());
    assert!(notice.external_ref.is_none());
    assert!(notice.session_frame.is_none());
    assert!(notice.slot_frame.is_none());
    assert_eq!(notice.payload, vec![1, 2, 3]);
}

#[test]
fn result_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Forward compatibility: a `Result` up-frame decoded by the
    // down-direction `CoordinatorToRelay` (which has no such variant) folds
    // into `Unknown` rather than erroring — the "old peer sees a new frame"
    // path an older coordinator build would take.
    let json = r#"{"type":"result","tenant":"sb-staging","session":42,"slot":0,"payload":[1,2,3],"arrival_ms":7}"#;
    let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, CoordinatorToRelay::Unknown);
}

#[test]
fn slot_connected_roundtrips_json() {
    let notice = SlotConnectedNotice {
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(42),
        slot: SlotId(1),
        external_id: Some("game-99".to_owned()),
        external_ref: Some("sb-user-7".to_owned()),
        resumed: true,
        connected_at_ms: 1_700_000_000_000,
    };
    let message = RelayToCoordinator::SlotConnected(notice.clone());
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"slot_connected\""));
    assert!(json.contains("\"resumed\":true"));
    assert!(json.contains("\"connected_at_ms\":1700000000000"));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn slot_connected_without_optionals_decodes() {
    // A notice from a relay whose descriptor carried no correlation ids must
    // still decode, leaving the coordinator's own fallbacks to fill them.
    let json = r#"{"type":"slot_connected","tenant":"sb-staging","session":42,"slot":0,"resumed":false,"connected_at_ms":7}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    let RelayToCoordinator::SlotConnected(notice) = decoded else {
        panic!("decodes to the SlotConnected variant");
    };
    assert!(notice.external_id.is_none());
    assert!(notice.external_ref.is_none());
    assert!(!notice.resumed);
    assert_eq!(notice.connected_at_ms, 7);
}

#[test]
fn session_started_roundtrips_json() {
    let notice = SessionStartedNotice {
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(42),
        external_id: Some("game-99".to_owned()),
        started_at_ms: 1_700_000_000_000,
        initial_buffer_turns: Some(6),
    };
    let message = RelayToCoordinator::SessionStarted(notice.clone());
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"session_started\""));
    assert!(json.contains("\"initial_buffer_turns\":6"));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn session_started_without_optionals_decodes() {
    // An authority that sized no depth (and a descriptor with no gameId)
    // still produces a decodable notice; the absent depth is distinct from a
    // present zero.
    let json = r#"{"type":"session_started","tenant":"sb-staging","session":42,"started_at_ms":7}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    let RelayToCoordinator::SessionStarted(notice) = decoded else {
        panic!("decodes to the SessionStarted variant");
    };
    assert!(notice.external_id.is_none());
    assert!(notice.initial_buffer_turns.is_none());
    assert_eq!(notice.started_at_ms, 7);
}

#[test]
fn slot_started_roundtrips_json() {
    let notice = SlotStartedNotice {
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(42),
        slot: SlotId(3),
        external_id: Some("game-99".to_owned()),
        external_ref: Some("sb-user-7".to_owned()),
        arrival_ms: 1_700_000_000_000,
        session_frame: Some(12),
        slot_frame: Some(14),
    };
    let message = RelayToCoordinator::SlotStarted(notice.clone());
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"slot_started\""));
    assert!(json.contains("\"arrival_ms\":1700000000000"));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn slot_started_without_optionals_decodes() {
    // The common shape: a client announcing its loop before any framed turn,
    // on a session whose descriptor carried no correlation ids.
    let json =
        r#"{"type":"slot_started","tenant":"sb-staging","session":42,"slot":0,"arrival_ms":7}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    let RelayToCoordinator::SlotStarted(notice) = decoded else {
        panic!("decodes to the SlotStarted variant");
    };
    assert!(notice.external_id.is_none());
    assert!(notice.external_ref.is_none());
    assert!(notice.session_frame.is_none());
    assert!(notice.slot_frame.is_none());
    assert_eq!(notice.arrival_ms, 7);
}

#[test]
fn the_load_progress_frames_decode_to_unknown_on_a_decoder_without_them() {
    // Forward compatibility for all three load-progress up-frames: a decoder
    // that predates them — here the down-direction `CoordinatorToRelay`,
    // which has no such variants — folds each into `Unknown` rather than
    // erroring, exactly as an older coordinator build would.
    for json in [
        r#"{"type":"slot_connected","tenant":"sb-staging","session":42,"slot":0,"resumed":false,"connected_at_ms":7}"#,
        r#"{"type":"session_started","tenant":"sb-staging","session":42,"started_at_ms":7}"#,
        r#"{"type":"slot_started","tenant":"sb-staging","session":42,"slot":0,"arrival_ms":7}"#,
    ] {
        let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, CoordinatorToRelay::Unknown);
    }
}
