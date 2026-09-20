use crate::messages::{
    ControlFrame, LeaveDirective, MeshControlFrame, Payload, SlotConnectivity, SlotDeparted,
    control_frame, mesh_control_frame,
};

use super::*;

fn oversize_turn(bytes: usize) -> ControlFrame {
    ControlFrame {
        kind: Some(control_frame::Kind::OversizeTurn(Payload {
            seq: 9,
            slot: 2,
            commands: vec![0x0C; bytes].into(),
            game_frame_count: Some(41),
            sync_generation: Some(73),
            buffer_directive: None,
        })),
    }
}

#[test]
fn payload_sync_generation_presence_and_round_trip_are_backward_compatible() {
    let legacy = Payload {
        seq: 9,
        slot: 2,
        commands: vec![0x0C].into(),
        game_frame_count: Some(41),
        sync_generation: None,
        buffer_directive: None,
    };
    let legacy_bytes = legacy.encode_to_vec();
    assert_eq!(
        Payload::decode(legacy_bytes.as_slice())
            .unwrap()
            .sync_generation,
        None
    );

    let explicit_zero = Payload {
        sync_generation: Some(0),
        ..legacy.clone()
    };
    let explicit_zero_bytes = explicit_zero.encode_to_vec();
    assert_ne!(explicit_zero_bytes, legacy_bytes);
    assert_eq!(
        Payload::decode(explicit_zero_bytes.as_slice())
            .unwrap()
            .sync_generation,
        Some(0)
    );

    let nonzero = Payload {
        sync_generation: Some(987_654_321),
        ..legacy
    };
    assert_eq!(
        Payload::decode(nonzero.encode_to_vec().as_slice())
            .unwrap()
            .sync_generation,
        Some(987_654_321)
    );
}

#[test]
fn frames_round_trip() {
    let frame = oversize_turn(2000);
    let encoded = encode_frame(&frame).unwrap();

    let mut prefix = [0u8; CONTROL_LEN_PREFIX];
    prefix.copy_from_slice(&encoded[..CONTROL_LEN_PREFIX]);
    let len = frame_len(prefix).unwrap();
    assert_eq!(len, encoded.len() - CONTROL_LEN_PREFIX);
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, frame);
}

#[test]
fn an_over_cap_length_prefix_is_rejected_before_any_read() {
    // An attacker-supplied length prefix demanding 4GB must fail at the
    // prefix check, never reach an allocation.
    let prefix = u32::MAX.to_le_bytes();
    assert!(matches!(
        frame_len(prefix),
        Err(ControlStreamError::FrameTooLarge { .. })
    ));
}

#[test]
fn an_over_cap_frame_is_refused_at_encode() {
    let frame = oversize_turn(MAX_CONTROL_FRAME_LEN + 1);
    assert!(matches!(
        encode_frame(&frame),
        Err(ControlStreamError::FrameTooLarge { .. })
    ));
}

#[test]
fn game_started_frames_round_trip_through_the_shared_framing() {
    use crate::messages::GameStarted;

    // The client's "my game loop is running" report rides the client-edge
    // control frame only — it is client → relay, never fanned to anyone —
    // and is fieldless, so the whole frame is just the oneof tag with an
    // empty body.
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::GameStarted(GameStarted {})),
    };
    let encoded = encode_frame(&frame).unwrap();
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, frame);

    // Field 14, length-delimited, zero-length body.
    assert_eq!(&encoded[CONTROL_LEN_PREFIX..], &[0x72, 0x00]);
}

#[test]
fn a_slot_departed_carries_an_embedded_result_through_the_frame() {
    // A departing slot that reported a result before leaving: the home relay
    // fills the result-echo fields, and they round-trip through the frame so
    // every relay folds the identical result into its departure record.
    let departed = MeshControlFrame {
        session: 5,
        kind: Some(mesh_control_frame::Kind::SlotDeparted(SlotDeparted {
            finalized: false,
            slot: 0,
            last_frame: Some(4242),
            reachable_frame: Some(4200),
            reason: 3,
            result_payload: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
            result_arrival_ms: 1_700_000_000_000,
            result_session_frame: Some(4200),
            result_slot_frame: Some(4242),
            connection_epoch: None,
            final_turn_count: Some(4243),
        })),
    };
    let encoded = encode_frame(&departed).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, departed);

    // A lobby/pre-game departure is the empty end of the same frame: no result
    // to echo and no frame basis at all. `last_frame` must come back absent,
    // which is a different fact from a present frame 0 — one says "this slot
    // never framed", the other says "it framed once, at the start".
    let never_framed = MeshControlFrame {
        session: 3,
        kind: Some(mesh_control_frame::Kind::SlotDeparted(SlotDeparted {
            finalized: false,
            slot: 1,
            last_frame: None,
            reachable_frame: None,
            reason: 3,
            result_payload: Vec::new().into(),
            result_arrival_ms: 0,
            result_session_frame: None,
            result_slot_frame: None,
            connection_epoch: None,
            final_turn_count: None,
        })),
    };
    let encoded = encode_frame(&never_framed).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, never_framed);
    let Some(mesh_control_frame::Kind::SlotDeparted(sd)) = decoded.kind else {
        panic!("expected SlotDeparted");
    };
    assert_eq!(sd.last_frame, None);
}

#[test]
fn a_session_start_without_a_depth_round_trips_and_matches_old_fieldless_bytes() {
    use crate::messages::SessionStart;

    // A directive whose authority sized no depth carries an absent
    // `initial_buffer_turns` — distinct from a present `Some(0)`.
    let absent = ControlFrame {
        kind: Some(control_frame::Kind::SessionStart(SessionStart {
            initial_buffer_turns: None,
        })),
    };
    let encoded = encode_frame(&absent).unwrap();
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, absent);

    // The depth-less directive encodes to exactly the pre-field fieldless
    // form: an empty `SessionStart` body, so the whole frame is just the
    // oneof tag (field 7, wire type 2) with a zero-length body. A build that
    // predates the field wrote precisely these bytes, and one that predates it
    // reads a `Some(depth)` frame by skipping the unknown field 1 — the
    // additive contract the field relies on.
    let old_fieldless_body: &[u8] = &[0x3A, 0x00]; // field 7, len-delimited, empty
    let decoded_old: ControlFrame = decode_frame(old_fieldless_body).unwrap();
    assert_eq!(decoded_old, absent);
    assert_eq!(&encoded[CONTROL_LEN_PREFIX..], old_fieldless_body);

    // A present depth (even 0) is distinguishable from absence on the wire.
    let zero = ControlFrame {
        kind: Some(control_frame::Kind::SessionStart(SessionStart {
            initial_buffer_turns: Some(0),
        })),
    };
    let encoded_zero = encode_frame(&zero).unwrap();
    let decoded_zero: ControlFrame = decode_frame(&encoded_zero[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded_zero, zero);
    assert_ne!(decoded_zero, absent);
}

#[test]
fn a_control_frame_kind_a_peer_predates_decodes_with_the_oneof_unset() {
    // Forward/backward compatibility, mirroring the mesh-side test below: a
    // build that predates a newer `ControlFrame.kind` (the slot-connectivity
    // addition is the current such kind) sees the unknown oneof arm decode to
    // `kind: None` and skips the frame rather than tearing the stream down.
    // Simulated with a hand-built body carrying only an unknown oneof field
    // (tag 99, length-delimited, empty) — the tag no ControlFrame arm claims.
    let unknown_oneof_body: &[u8] = &[0x9A, 0x06, 0x00];
    let decoded: ControlFrame = decode_frame(unknown_oneof_body).unwrap();
    assert_eq!(decoded.kind, None);
}

#[test]
fn an_unknown_mesh_control_kind_decodes_with_the_oneof_unset() {
    // The empty establishment/keepalive frame (and any future kind a peer
    // predates) decodes with kind = None so the reader skips it.
    let empty: MeshControlFrame = decode_frame(&[]).unwrap();
    assert_eq!(empty.session, 0);
    assert_eq!(empty.kind, None);
}

#[test]
fn every_control_frame_kind_round_trips_through_the_shared_framing() {
    use crate::messages::{
        GameChat, LoadStateProbe, LoadStateProbeAck, LobbyCommand, PlayerSkin, RegionLabel,
        RegionLabels, SessionStart,
    };

    // The framing is kind-agnostic — one length prefix, one prost body — so
    // this table is not re-testing prost per field. What it catches is a oneof
    // arm that cannot make the trip at all: removed, renumbered, or carrying a
    // shape the generated codec no longer produces. The kinds below are the
    // ones the *client-edge* stream carries. `OversizeTurn` has its own framing
    // smoke test and `GameStarted` its own golden-byte test, so neither is
    // repeated here.
    let kinds = [
        // The load-state fence is two frames whose whole content is one
        // correlation id, so the id surviving verbatim is all there is to check.
        (
            "load_state_probe",
            control_frame::Kind::LoadStateProbe(LoadStateProbe { probe_id: u64::MAX }),
        ),
        (
            "load_state_probe_ack",
            control_frame::Kind::LoadStateProbeAck(LoadStateProbeAck { probe_id: u64::MAX }),
        ),
        (
            "lobby_command",
            control_frame::Kind::LobbyCommand(LobbyCommand {
                slot: 3,
                payload: vec![0x0C, 1, 2, 3].into(),
            }),
        ),
        (
            "game_chat",
            control_frame::Kind::GameChat(GameChat {
                slot: 3,
                target_kind: 1,
                target_slot: 2,
                text: "gl hf".to_owned(),
            }),
        ),
        (
            "player_skin",
            control_frame::Kind::PlayerSkin(PlayerSkin {
                slot: 3,
                payload: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
            }),
        ),
        // The relay-driven start directive, carrying the depth its authority
        // computed.
        (
            "session_start",
            control_frame::Kind::SessionStart(SessionStart {
                initial_buffer_turns: Some(6),
            }),
        ),
        (
            "slot_connectivity",
            control_frame::Kind::SlotConnectivity(SlotConnectivity {
                slot: 2,
                connected: false,
                connection_epoch: Some(17),
            }),
        ),
        // The whole-session label map: client-edge only, since every relay gets
        // its own copy from its descriptor and has nothing to exchange.
        (
            "region_labels",
            control_frame::Kind::RegionLabels(RegionLabels {
                labels: vec![
                    RegionLabel {
                        relay_id: 7,
                        region: "us-east".to_owned(),
                    },
                    RegionLabel {
                        relay_id: 9,
                        region: "eu-central".to_owned(),
                    },
                ],
            }),
        ),
    ];

    for (name, kind) in kinds {
        let frame = ControlFrame { kind: Some(kind) };
        let encoded = encode_frame(&frame).unwrap();
        let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
        assert_eq!(decoded, frame, "{name}");
    }
}

#[test]
fn an_empty_region_label_map_is_a_set_oneof_not_an_unset_one() {
    use crate::messages::RegionLabels;

    // "The relay has no labels to hand out" and "this build predates the kind"
    // must stay distinguishable: an empty map is a *set* oneof arm carrying an
    // empty message, and it must not come back as `kind: None`.
    let empty = ControlFrame {
        kind: Some(control_frame::Kind::RegionLabels(RegionLabels::default())),
    };
    let encoded = encode_frame(&empty).unwrap();
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, empty);
    assert!(decoded.kind.is_some());
}

#[test]
fn every_mesh_control_frame_kind_round_trips_through_the_shared_framing() {
    use crate::messages::{
        DeliveryCursor, DeliveryCursors, GameChat, LobbyCommand, PlayerSkin, SessionStart,
        SlotPresent, SlotStarted,
    };

    // The relay ↔ relay half of the same kind-agnostic framing. Several kinds
    // here are the cross-relay twins of client-edge ones — a lobby command, a
    // chat line, or a skin blob reaches a peer's slots by being re-framed for
    // the mesh — while presence, started, delivery cursors and the leave
    // directive are mesh-only and never reach a client. Every mesh frame also
    // carries a session id outside the oneof, and the length prefix is checked
    // per row because these bodies vary from a few bytes to a diverted turn.
    let kinds = [
        (
            "lobby_command",
            mesh_control_frame::Kind::LobbyCommand(LobbyCommand {
                slot: 3,
                payload: vec![0x0C, 1, 2, 3].into(),
            }),
        ),
        (
            "game_chat",
            mesh_control_frame::Kind::GameChat(GameChat {
                slot: 3,
                target_kind: 1,
                target_slot: 2,
                text: "gl hf".to_owned(),
            }),
        ),
        (
            "player_skin",
            mesh_control_frame::Kind::PlayerSkin(PlayerSkin {
                slot: 3,
                payload: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
            }),
        ),
        (
            "session_start",
            mesh_control_frame::Kind::SessionStart(SessionStart {
                initial_buffer_turns: Some(6),
            }),
        ),
        (
            "slot_present",
            mesh_control_frame::Kind::SlotPresent(SlotPresent { slot: 3 }),
        ),
        // A client reports its game start to its home relay carrying no slot at
        // all; the home shares it stamped with the authenticated slot.
        (
            "slot_started",
            mesh_control_frame::Kind::SlotStarted(SlotStarted { slot: 4 }),
        ),
        (
            "slot_connectivity",
            mesh_control_frame::Kind::SlotConnectivity(SlotConnectivity {
                slot: 5,
                connected: true,
                connection_epoch: Some(18),
            }),
        ),
        (
            "delivery_cursors",
            mesh_control_frame::Kind::DeliveryCursors(DeliveryCursors {
                dest_slot: 1,
                cursors: vec![
                    DeliveryCursor {
                        origin_slot: 0,
                        delivered_seq: 4200,
                    },
                    DeliveryCursor {
                        origin_slot: 2,
                        delivered_seq: 17,
                    },
                ],
            }),
        ),
        (
            "leave_directive",
            mesh_control_frame::Kind::LeaveDirective(LeaveDirective {
                finalized: false,
                slot: 2,
                reason: 3,
                apply_at_frame: 42,
                leave_seq: 1,
                final_turn_count: Some(43),
            }),
        ),
        // An oversize turn diverted onto the mesh control stream: the same
        // Payload the client edge carries, well past any datagram budget but
        // under the shared frame cap.
        (
            "oversize_turn",
            mesh_control_frame::Kind::OversizeTurn(Payload {
                seq: 9,
                slot: 2,
                commands: vec![0x0C; 2000].into(),
                game_frame_count: Some(41),
                sync_generation: Some(73),
                buffer_directive: None,
            }),
        ),
    ];

    for (name, kind) in kinds {
        let frame = MeshControlFrame {
            session: 7,
            kind: Some(kind),
        };
        let encoded = encode_frame(&frame).unwrap();
        let mut prefix = [0u8; CONTROL_LEN_PREFIX];
        prefix.copy_from_slice(&encoded[..CONTROL_LEN_PREFIX]);
        assert_eq!(
            frame_len(prefix).unwrap(),
            encoded.len() - CONTROL_LEN_PREFIX,
            "{name}"
        );
        let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
        assert_eq!(decoded, frame, "{name}");
    }
}
