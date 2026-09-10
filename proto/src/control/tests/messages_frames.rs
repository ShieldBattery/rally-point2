use super::*;

#[test]
fn coordinator_to_relay_descriptors_roundtrips_json() {
    let message = CoordinatorToRelay::Descriptors {
        staged_at_unix_ms: None,
        descriptors: vec![SessionDescriptor {
            finalized_drops: false,
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            peers: vec![RelayPeer {
                relay_id: RelayId(2),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
                cert_der: vec![0x30, 0x82, 0xCC, 0xDD],
                relay_addrs: vec![],
            }],
            bounds: BufferBounds::new(1, 6).unwrap(),
            authority_order: vec![RelayId(1), RelayId(2)],
            external_id: None,
            slot_refs: vec![],
            observer_slots: vec![],
            expected_slots: vec![],
            homed_slots: vec![],
            resumed: false,
            departed_slots: vec![],
            latency_estimate_ms: Some(45),
            relay_regions: Vec::new(),
        }],
    };
    let json = serde_json::to_string(&message).unwrap();
    // The tagged frame is self-describing: a `type` discriminator names the
    // variant so the channel can grow new message kinds.
    assert!(json.contains("\"type\":\"descriptors\""));
    let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn coordinator_to_relay_descriptors_staging_stamp_roundtrips_and_defaults_absent() {
    // A stamped set round-trips carrying the millisecond stamp.
    let stamped = CoordinatorToRelay::Descriptors {
        descriptors: vec![],
        staged_at_unix_ms: Some(1_700_000_000_123),
    };
    let json = serde_json::to_string(&stamped).unwrap();
    assert!(json.contains("\"staged_at_unix_ms\":1700000000123"));
    assert_eq!(
        serde_json::from_str::<CoordinatorToRelay>(&json).unwrap(),
        stamped
    );

    // An absent stamp stays off the wire (byte-identical to the pre-field form)
    // and round-trips back to `None`.
    let unstamped = CoordinatorToRelay::Descriptors {
        descriptors: vec![],
        staged_at_unix_ms: None,
    };
    let json = serde_json::to_string(&unstamped).unwrap();
    assert!(!json.contains("staged_at_unix_ms"));
    assert_eq!(
        serde_json::from_str::<CoordinatorToRelay>(&json).unwrap(),
        unstamped
    );

    // An old coordinator's frame — one that predates the field entirely —
    // parses with the stamp absent rather than erroring, so a new relay reads
    // it as "no lag sample".
    let old = r#"{"type":"descriptors","descriptors":[]}"#;
    assert_eq!(
        serde_json::from_str::<CoordinatorToRelay>(old).unwrap(),
        unstamped,
    );
}

#[test]
fn coordinator_to_relay_descriptor_delta_roundtrips_json() {
    // A steady-state delta carrying an upsert, a removal, and the staging stamp
    // round-trips through its tagged frame intact.
    let message = CoordinatorToRelay::DescriptorDelta {
        staged_at_unix_ms: Some(1_700_000_000_123),
        upserts: vec![SessionDescriptor {
            finalized_drops: false,
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            peers: vec![RelayPeer {
                relay_id: RelayId(2),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
                cert_der: vec![0x30, 0x82, 0xCC, 0xDD],
                relay_addrs: vec![],
            }],
            bounds: BufferBounds::new(1, 6).unwrap(),
            authority_order: vec![RelayId(1), RelayId(2)],
            external_id: None,
            slot_refs: vec![],
            observer_slots: vec![],
            expected_slots: vec![],
            homed_slots: vec![],
            resumed: false,
            departed_slots: vec![],
            latency_estimate_ms: Some(45),
            relay_regions: Vec::new(),
        }],
        removals: vec![DescriptorKey {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(7),
        }],
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"descriptor_delta\""));
    assert!(json.contains("\"staged_at_unix_ms\":1700000000123"));
    let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn coordinator_to_relay_descriptor_delta_without_stamp_omits_empty_fields_and_defaults() {
    // A removal-only delta with no stamp keeps the stamp and the (empty) upserts
    // off the wire, and round-trips back to the same value.
    let removal_only = CoordinatorToRelay::DescriptorDelta {
        staged_at_unix_ms: None,
        upserts: vec![],
        removals: vec![DescriptorKey {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(7),
        }],
    };
    let json = serde_json::to_string(&removal_only).unwrap();
    assert!(!json.contains("staged_at_unix_ms"));
    assert!(!json.contains("upserts"));
    assert_eq!(
        serde_json::from_str::<CoordinatorToRelay>(&json).unwrap(),
        removal_only,
    );

    // A bare delta naming only its type — every list field defaulting — parses
    // rather than erroring, so a minimal frame stays readable.
    let bare = r#"{"type":"descriptor_delta"}"#;
    assert_eq!(
        serde_json::from_str::<CoordinatorToRelay>(bare).unwrap(),
        CoordinatorToRelay::DescriptorDelta {
            staged_at_unix_ms: None,
            upserts: vec![],
            removals: vec![],
        },
    );
}

#[test]
fn descriptor_delta_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Forward compatibility, the direction that matters here: a relay that
    // predates `DescriptorDelta` (modeled by the up-direction
    // `RelayToCoordinator`, which has no such variant) folds the frame into
    // `Unknown` rather than erroring. That silent skip is exactly the drift the
    // coordinator's version gate exists to prevent — an older relay is sent full
    // sets, never a delta.
    let json = r#"{"type":"descriptor_delta","upserts":[],"removals":[{"tenant":"sb-staging","session":7}]}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, RelayToCoordinator::Unknown);
}

#[test]
fn coordinator_to_relay_unknown_type_decodes_to_unknown_not_an_error() {
    // Forward compatibility: a message kind a newer coordinator added, which
    // this build predates, must decode to `Unknown` rather than failing — so
    // an older relay skips it instead of tearing down its control connection.
    let json = r#"{"type":"some_future_message","extra":123}"#;
    let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, CoordinatorToRelay::Unknown);
}

#[test]
fn coordinator_to_relay_close_slot_roundtrips_json() {
    let message = CoordinatorToRelay::CloseSlot {
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(42),
        slots: vec![SlotId(1), SlotId(3)],
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"close_slot\""));
    let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn close_slot_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Forward compatibility: a `CloseSlot` down-frame decoded by the
    // up-direction `RelayToCoordinator` (which has no such variant) folds
    // into `Unknown` rather than erroring — an older relay build's path.
    let json = r#"{"type":"close_slot","tenant":"sb-staging","session":42,"slots":[1]}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, RelayToCoordinator::Unknown);
}

#[test]
fn coordinator_to_relay_mesh_peers_roundtrips_json() {
    let message = CoordinatorToRelay::MeshPeers {
        peers: vec![
            MeshPeerIdentity {
                relay_id: RelayId(1),
                cert_sha256: [0x11; 32],
            },
            MeshPeerIdentity {
                relay_id: RelayId(2),
                cert_sha256: [0x22; 32],
            },
        ],
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"mesh_peers\""));
    let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
    // The fingerprint survives the round trip intact — the acceptor pins on it.
    let CoordinatorToRelay::MeshPeers { peers } = back else {
        panic!("expected a mesh_peers frame");
    };
    assert_eq!(peers[0].cert_sha256, [0x11; 32]);
    assert_eq!(peers[1].relay_id, RelayId(2));
}

#[test]
fn mesh_peers_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Forward compatibility: a `MeshPeers` down-frame decoded by a build whose
    // `CoordinatorToRelay` predates the variant (modeled by the up-direction
    // `RelayToCoordinator`, which has no such variant) folds into `Unknown`
    // rather than erroring — a coordinator that pushes the set to an older relay
    // is skipped, not fatal.
    let json = r#"{"type":"mesh_peers","peers":[]}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, RelayToCoordinator::Unknown);
}

#[test]
fn coordinator_to_relay_tenant_keys_roundtrips_json() {
    let message = CoordinatorToRelay::TenantKeys {
        keys: vec![
            TenantVerifyingKey {
                kid: KeyId("staging-key-1".to_owned()),
                tenant: TenantId("sb-staging".to_owned()),
                verifying_key: vec![0x11; PUBLIC_KEY_LEN],
            },
            TenantVerifyingKey {
                kid: KeyId("dev-key-1".to_owned()),
                tenant: TenantId("sb-dev".to_owned()),
                verifying_key: vec![0x22; PUBLIC_KEY_LEN],
            },
        ],
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"tenant_keys\""));
    let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
    // The verifying key survives the round trip intact — the relay verifies
    // client tokens against exactly these bytes.
    let CoordinatorToRelay::TenantKeys { keys } = back else {
        panic!("expected a tenant_keys frame");
    };
    assert_eq!(keys[0].verifying_key, vec![0x11; PUBLIC_KEY_LEN]);
    assert_eq!(keys[1].tenant, TenantId("sb-dev".to_owned()));
}

#[test]
fn tenant_keys_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Forward compatibility, mirroring `mesh_peers`: a `TenantKeys` down-frame
    // decoded by a build whose `CoordinatorToRelay` predates the variant
    // (modeled by the up-direction `RelayToCoordinator`, which has no such
    // variant) folds into `Unknown` rather than erroring — a coordinator that
    // pushes the set to an older relay is skipped, not fatal.
    let json = r#"{"type":"tenant_keys","keys":[]}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, RelayToCoordinator::Unknown);
}

#[test]
fn coordinator_to_relay_identity_challenge_roundtrips_json() {
    let message = CoordinatorToRelay::IdentityChallenge { nonce: [0x7A; 32] };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"identity_challenge\""));
    let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn identity_challenge_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Same forward-compatibility shape as `mesh_peers`: a build that predates
    // this variant (modeled by `RelayToCoordinator`, which has no such variant)
    // skips an IdentityChallenge it doesn't understand rather than erroring, so
    // the wire format stays forward-safe.
    let json = r#"{"type":"identity_challenge","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, RelayToCoordinator::Unknown);
}

#[test]
fn relay_to_coordinator_hello_roundtrips_json() {
    let message = RelayToCoordinator::Hello(RelayHello::new(
        RelayId(3),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion::CURRENT,
        vec![0xDE, 0xAD, 0xBE, 0xEF],
    ));
    let json = serde_json::to_string(&message).unwrap();
    // The Hello's fields ride alongside the tag (internally tagged).
    assert!(json.contains("\"type\":\"hello\""));
    assert!(json.contains("\"relay_id\""));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn relay_to_coordinator_identity_proof_roundtrips_json() {
    let message = RelayToCoordinator::IdentityProof {
        signature: vec![0x30, 0x45, 0x02, 0x21, 0x00],
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"identity_proof\""));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn identity_proof_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Forward compatibility, mirroring the down-direction IdentityChallenge
    // test: decoded by `CoordinatorToRelay` (no such variant), an
    // IdentityProof folds into `Unknown` rather than erroring.
    let json = r#"{"type":"identity_proof","signature":[1,2,3]}"#;
    let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, CoordinatorToRelay::Unknown);
}

#[test]
fn relay_to_coordinator_draining_roundtrips_json() {
    let message = RelayToCoordinator::Draining;
    let json = serde_json::to_string(&message).unwrap();
    // A payload-free drain request: just the tag, like a heartbeat.
    assert_eq!(json, r#"{"type":"draining"}"#);
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn coordinator_to_relay_drain_ack_roundtrips_json() {
    let message = CoordinatorToRelay::DrainAck;
    let json = serde_json::to_string(&message).unwrap();
    // A payload-free acknowledgement: just the tag.
    assert_eq!(json, r#"{"type":"drain_ack"}"#);
    let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn draining_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Forward compatibility: a `Draining` up-frame decoded by the down-direction
    // `CoordinatorToRelay` (which has no such variant) folds into `Unknown`
    // rather than erroring — an older coordinator's path against a newer relay.
    let json = r#"{"type":"draining"}"#;
    let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, CoordinatorToRelay::Unknown);
}

#[test]
fn drain_ack_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Forward compatibility: a `DrainAck` down-frame decoded by the up-direction
    // `RelayToCoordinator` (which has no such variant) folds into `Unknown`
    // rather than erroring — an older relay's path against a newer coordinator.
    let json = r#"{"type":"drain_ack"}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, RelayToCoordinator::Unknown);
}

#[test]
fn relay_to_coordinator_unknown_type_decodes_to_unknown_not_an_error() {
    // The up direction is forward-compatible too: a frame a newer relay sends
    // that an older coordinator predates decodes to `Unknown`, not an error.
    let json = r#"{"type":"future_up_frame","x":1}"#;
    let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, RelayToCoordinator::Unknown);
}

#[test]
fn relay_to_coordinator_session_closed_roundtrips_json() {
    let message = RelayToCoordinator::SessionClosed {
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(42),
    };
    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains("\"type\":\"session_closed\""));
    let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
    assert_eq!(back, message);
}

#[test]
fn session_closed_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
    // Forward compatibility: a `SessionClosed` up-frame decoded by the
    // down-direction `CoordinatorToRelay` (which has no such variant) folds
    // into `Unknown` rather than erroring — an older coordinator's path.
    let json = r#"{"type":"session_closed","tenant":"sb-staging","session":42}"#;
    let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
    assert_eq!(decoded, CoordinatorToRelay::Unknown);
}
