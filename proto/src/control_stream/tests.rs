use crate::messages::{
    ControlFrame, LeaveDirective, MeshControlFrame, Payload, SlotDeparted, control_frame,
    mesh_control_frame,
};

use super::*;

fn oversize_turn(bytes: usize) -> ControlFrame {
    ControlFrame {
        kind: Some(control_frame::Kind::OversizeTurn(Payload {
            seq: 9,
            slot: 2,
            commands: vec![0x0C; bytes].into(),
            game_frame_count: Some(41),
            buffer_directive: None,
        })),
    }
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
fn load_state_fence_frames_round_trip_through_the_shared_framing() {
    use crate::messages::{LoadStateProbe, LoadStateProbeAck};

    // The fence is two frames whose whole content is one correlation id, so
    // the id surviving the framing verbatim in both directions is the only
    // thing there is to check.
    let probe = ControlFrame {
        kind: Some(control_frame::Kind::LoadStateProbe(LoadStateProbe {
            probe_id: u64::MAX,
        })),
    };
    let encoded = encode_frame(&probe).unwrap();
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, probe);

    let ack = ControlFrame {
        kind: Some(control_frame::Kind::LoadStateProbeAck(LoadStateProbeAck {
            probe_id: u64::MAX,
        })),
    };
    let encoded = encode_frame(&ack).unwrap();
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, ack);
}

#[test]
fn lobby_command_frames_round_trip_through_the_shared_framing() {
    use crate::messages::LobbyCommand;

    // A lobby command rides the client-edge control frame with its author slot
    // and opaque bytes intact.
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::LobbyCommand(LobbyCommand {
            slot: 3,
            payload: vec![0x0C, 1, 2, 3].into(),
        })),
    };
    let encoded = encode_frame(&frame).unwrap();
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, frame);

    // And it rides the mesh control frame the same way, for cross-relay
    // fan-out.
    let mesh = MeshControlFrame {
        session: 7,
        kind: Some(mesh_control_frame::Kind::LobbyCommand(LobbyCommand {
            slot: 3,
            payload: vec![0x0C, 1, 2, 3].into(),
        })),
    };
    let encoded = encode_frame(&mesh).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, mesh);
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
fn game_chat_frames_round_trip_through_the_shared_framing() {
    use crate::messages::GameChat;

    // A game-chat message rides the client-edge control frame with its
    // author slot, scope hint, and text intact.
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::GameChat(GameChat {
            slot: 3,
            target_kind: 1,
            target_slot: 2,
            text: "gl hf".to_owned(),
        })),
    };
    let encoded = encode_frame(&frame).unwrap();
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, frame);

    // And it rides the mesh control frame the same way, for cross-relay
    // fan-out.
    let mesh = MeshControlFrame {
        session: 7,
        kind: Some(mesh_control_frame::Kind::GameChat(GameChat {
            slot: 3,
            target_kind: 1,
            target_slot: 2,
            text: "gl hf".to_owned(),
        })),
    };
    let encoded = encode_frame(&mesh).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, mesh);
}

#[test]
fn player_skin_frames_round_trip_through_the_shared_framing() {
    use crate::messages::PlayerSkin;

    // A player-skin blob rides the client-edge control frame with its author
    // slot and opaque bytes intact.
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::PlayerSkin(PlayerSkin {
            slot: 3,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
        })),
    };
    let encoded = encode_frame(&frame).unwrap();
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, frame);

    // And it rides the mesh control frame the same way, for cross-relay
    // fan-out.
    let mesh = MeshControlFrame {
        session: 7,
        kind: Some(mesh_control_frame::Kind::PlayerSkin(PlayerSkin {
            slot: 3,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF].into(),
        })),
    };
    let encoded = encode_frame(&mesh).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, mesh);
}

#[test]
fn an_unknown_frame_kind_decodes_with_the_oneof_unset() {
    // A frame kind a newer peer added: a field number past every one this
    // build knows, carrying some bytes. It must decode (kind = None) so the
    // reader can skip it, not fail the stream. The field number has to stay
    // ahead of the last one `ControlFrame` actually assigns — a number the
    // oneof now claims would decode as that kind (or fail to) instead of
    // exercising the skip.
    let unknown = [0x8A, 0x01, 0x03, 1, 2, 3]; // field 17, wire type 2, len 3
    let frame: ControlFrame = decode_frame(&unknown).unwrap();
    assert_eq!(frame.kind, None);
}

#[test]
fn mesh_control_frames_round_trip_through_the_shared_framing() {
    // A SlotDeparted frame and a LeaveDirective frame both ride the same
    // length-prefixed codec the client-edge ControlFrame uses.
    let departed = MeshControlFrame {
        session: 7,
        kind: Some(mesh_control_frame::Kind::SlotDeparted(SlotDeparted {
            finalized: false,
            slot: 2,
            last_frame: Some(41),
            reachable_frame: Some(38),
            reason: 0x4000_0006,
            result_payload: Vec::new().into(),
            result_arrival_ms: 0,
            result_session_frame: None,
            result_slot_frame: None,
            connection_epoch: None,
            final_turn_count: None,
        })),
    };
    let encoded = encode_frame(&departed).unwrap();
    let mut prefix = [0u8; CONTROL_LEN_PREFIX];
    prefix.copy_from_slice(&encoded[..CONTROL_LEN_PREFIX]);
    let len = frame_len(prefix).unwrap();
    assert_eq!(len, encoded.len() - CONTROL_LEN_PREFIX);
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, departed);

    let leave = MeshControlFrame {
        session: 7,
        kind: Some(mesh_control_frame::Kind::LeaveDirective(LeaveDirective {
            finalized: false,
            slot: 2,
            reason: 3,
            apply_at_frame: 42,
            leave_seq: 1,
            final_turn_count: Some(43),
        })),
    };
    let encoded = encode_frame(&leave).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, leave);

    // An oversize turn diverted onto the mesh control stream: the same
    // Payload shape the client-edge ControlFrame carries, well past any
    // datagram budget but under the shared frame cap.
    let oversize = MeshControlFrame {
        session: 7,
        kind: Some(mesh_control_frame::Kind::OversizeTurn(Payload {
            seq: 9,
            slot: 2,
            commands: vec![0x0C; 2000].into(),
            game_frame_count: Some(41),
            buffer_directive: None,
        })),
    };
    let encoded = encode_frame(&oversize).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, oversize);
}

#[test]
fn a_never_framed_departure_omits_last_frame() {
    // A lobby/pre-game departure carries no frame basis: `last_frame` is
    // absent, distinct from a present frame 0.
    let departed = MeshControlFrame {
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
    let encoded = encode_frame(&departed).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, departed);
    match decoded.kind {
        Some(mesh_control_frame::Kind::SlotDeparted(sd)) => assert_eq!(sd.last_frame, None),
        other => panic!("expected SlotDeparted, got {other:?}"),
    }
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
    match decoded.kind {
        Some(mesh_control_frame::Kind::SlotDeparted(sd)) => {
            assert_eq!(sd.result_payload.as_ref(), &[0xDE, 0xAD, 0xBE, 0xEF]);
            assert_eq!(sd.result_arrival_ms, 1_700_000_000_000);
        }
        other => panic!("expected SlotDeparted, got {other:?}"),
    }
}

#[test]
fn session_start_frames_round_trip_through_the_shared_framing() {
    use crate::messages::SessionStart;

    // The relay-driven session-start directive rides the client-edge control
    // frame, carrying the computed initial buffer depth.
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::SessionStart(SessionStart {
            initial_buffer_turns: Some(6),
        })),
    };
    let encoded = encode_frame(&frame).unwrap();
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, frame);

    // And it rides the mesh control frame the same way, for the authority's
    // cross-relay broadcast.
    let mesh = MeshControlFrame {
        session: 7,
        kind: Some(mesh_control_frame::Kind::SessionStart(SessionStart {
            initial_buffer_turns: Some(6),
        })),
    };
    let encoded = encode_frame(&mesh).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, mesh);
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
fn slot_present_frames_round_trip_through_the_shared_framing() {
    use crate::messages::SlotPresent;

    // A slot-presence announcement rides only the mesh control frame — it is
    // relay ↔ relay, never sent to a client.
    let mesh = MeshControlFrame {
        session: 7,
        kind: Some(mesh_control_frame::Kind::SlotPresent(SlotPresent {
            slot: 3,
        })),
    };
    let encoded = encode_frame(&mesh).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, mesh);
    match decoded.kind {
        Some(mesh_control_frame::Kind::SlotPresent(sp)) => assert_eq!(sp.slot, 3),
        other => panic!("expected SlotPresent, got {other:?}"),
    }
}

#[test]
fn a_slot_started_frame_round_trips_through_the_shared_framing() {
    use crate::messages::SlotStarted;

    // Mesh-only: a client's game-started report reaches its home relay on the
    // client-edge stream carrying no slot at all, and the home shares it with
    // its peers as this frame, stamped with the authenticated slot.
    let frame = MeshControlFrame {
        session: 12,
        kind: Some(mesh_control_frame::Kind::SlotStarted(SlotStarted {
            slot: 4,
        })),
    };
    let encoded = encode_frame(&frame).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, frame);
    match decoded.kind {
        Some(mesh_control_frame::Kind::SlotStarted(ss)) => assert_eq!(ss.slot, 4),
        other => panic!("expected SlotStarted, got {other:?}"),
    }
}

#[test]
fn slot_connectivity_frames_round_trip_through_the_shared_framing() {
    use crate::messages::SlotConnectivity;

    // A disconnect signal rides the client-edge control frame (relay → its
    // local slots), carrying the slot and its new connectivity verbatim.
    let down = ControlFrame {
        kind: Some(control_frame::Kind::SlotConnectivity(SlotConnectivity {
            slot: 2,
            connected: false,
            connection_epoch: Some(17),
        })),
    };
    let encoded = encode_frame(&down).unwrap();
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, down);
    match decoded.kind {
        Some(control_frame::Kind::SlotConnectivity(sc)) => {
            assert_eq!(sc.slot, 2);
            assert!(!sc.connected);
        }
        other => panic!("expected SlotConnectivity, got {other:?}"),
    }

    // And a (re)connect signal rides the mesh control frame the same way, for
    // the origin relay's cross-relay broadcast.
    let up = MeshControlFrame {
        session: 9,
        kind: Some(mesh_control_frame::Kind::SlotConnectivity(
            SlotConnectivity {
                slot: 5,
                connected: true,
                connection_epoch: Some(18),
            },
        )),
    };
    let encoded = encode_frame(&up).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, up);
    match decoded.kind {
        Some(mesh_control_frame::Kind::SlotConnectivity(sc)) => {
            assert_eq!(sc.slot, 5);
            assert!(sc.connected);
        }
        other => panic!("expected SlotConnectivity, got {other:?}"),
    }
}

#[test]
fn a_region_label_frame_round_trips_through_the_shared_framing() {
    use crate::messages::{RegionLabel, RegionLabels};

    // The whole-session label map rides the client-edge control frame only
    // (relay → its local slots): every relay gets the map from its own
    // descriptor, so there is no mesh counterpart to exchange.
    let frame = ControlFrame {
        kind: Some(control_frame::Kind::RegionLabels(RegionLabels {
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
        })),
    };
    let encoded = encode_frame(&frame).unwrap();
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, frame);
    match decoded.kind {
        Some(control_frame::Kind::RegionLabels(map)) => {
            assert_eq!(map.labels.len(), 2);
            assert_eq!(map.labels[0].relay_id, 7);
            assert_eq!(map.labels[1].region, "eu-central");
        }
        other => panic!("expected RegionLabels, got {other:?}"),
    }

    // An empty map is a valid frame that decodes back to an empty map, not
    // to an unset oneof — "the relay has no labels" and "this build predates
    // the kind" stay distinguishable.
    let empty = ControlFrame {
        kind: Some(control_frame::Kind::RegionLabels(RegionLabels::default())),
    };
    let encoded = encode_frame(&empty).unwrap();
    let decoded: ControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, empty);
}

#[test]
fn delivery_cursor_frames_round_trip_through_the_shared_framing() {
    use crate::messages::{DeliveryCursor, DeliveryCursors};

    // A destination's delivered-through cursors ride only the mesh control
    // frame — relay ↔ relay, never sent to a client — carrying the complete
    // per-origin map verbatim.
    let mesh = MeshControlFrame {
        session: 7,
        kind: Some(mesh_control_frame::Kind::DeliveryCursors(DeliveryCursors {
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
        })),
    };
    let encoded = encode_frame(&mesh).unwrap();
    let decoded: MeshControlFrame = decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap();
    assert_eq!(decoded, mesh);
    match decoded.kind {
        Some(mesh_control_frame::Kind::DeliveryCursors(dc)) => {
            assert_eq!(dc.dest_slot, 1);
            assert_eq!(dc.cursors.len(), 2);
            assert_eq!(dc.cursors[0].delivered_seq, 4200);
        }
        other => panic!("expected DeliveryCursors, got {other:?}"),
    }
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
