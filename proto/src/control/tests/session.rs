use super::*;

#[test]
fn buffer_bounds_new_rejects_inverted() {
    assert!(BufferBounds::new(5, 3).is_err());
}

#[test]
fn buffer_bounds_clamp_pulls_a_depth_into_the_range() {
    // A pinned range (min == max, a fixed-latency game) is the degenerate row:
    // every depth lands on the single legal value.
    for (min, max, cases) in [
        (2u32, 8u32, [(0u32, 2u32), (5, 5), (99, 8)]),
        (3, 3, [(0, 3), (5, 3), (99, 3)]),
    ] {
        let bounds = BufferBounds::new(min, max).unwrap();
        for (depth, expected) in cases {
            assert_eq!(
                bounds.clamp(depth),
                expected,
                "clamp({depth}) in [{min},{max}]"
            );
        }
    }
}

#[test]
fn buffer_bounds_clamp_does_not_panic_on_an_inverted_range() {
    // `new` rejects `min > max`, but `Deserialize` is derived and bypasses it
    // entirely -- a corrupted or malicious coordinator payload decodes into an
    // inverted range without error, exactly as below. `u32::clamp` panics if
    // `min > max`; `BufferBounds::clamp` must not, however the value reached it.
    let inverted: BufferBounds = serde_json::from_str(r#"{"min":8,"max":2}"#).unwrap();
    assert_eq!(inverted, BufferBounds { min: 8, max: 2 });
    assert_eq!(inverted.clamp(0), 2, "swapped bounds treat 2 as the floor");
    assert_eq!(inverted.clamp(5), 5, "5 already falls within [2, 8]");
    assert_eq!(
        inverted.clamp(99),
        8,
        "swapped bounds treat 8 as the ceiling"
    );
}

#[test]
fn player_handoff_region_is_omitted_when_absent_and_decodes_to_none() {
    // An untagged handoff keeps `region` off the wire, and a handoff from an app
    // server that predates the field decodes with `region` defaulting to None
    // (no preference, the coordinator's fallback pick).
    let handoff = PlayerHandoff {
        slot: SlotId(0),
        client_pubkey: ClientPublicKey([0xAA; 32]),
        external_ref: None,
        observer: false,
        region: None,
    };
    let json = serde_json::to_string(&handoff).unwrap();
    assert!(!json.contains("region"));
    let back: PlayerHandoff = serde_json::from_str(&json).unwrap();
    assert_eq!(back.region, None);

    let tagged = PlayerHandoff {
        region: Some(RegionId("us-west".to_owned())),
        ..handoff
    };
    let json = serde_json::to_string(&tagged).unwrap();
    assert!(json.contains("\"region\":\"us-west\""));
    assert_eq!(
        serde_json::from_str::<PlayerHandoff>(&json).unwrap(),
        tagged
    );
}

#[test]
fn session_request_latency_estimate_defaults_absent_and_omits_from_the_wire() {
    // A request that predates the field parses with the estimate absent — the
    // control protos don't `deny_unknown_fields`, and the field defaults.
    let old = r#"{
        "tenant":"sb-staging",
        "players":[]
    }"#;
    let back: SessionRequest = serde_json::from_str(old).unwrap();
    assert_eq!(back.latency_estimate_ms, None);

    // An absent estimate stays off the wire (byte-identical to the pre-field
    // form), while a present one round-trips.
    let request = SessionRequest {
        tenant: TenantId("sb-staging".to_owned()),
        players: vec![],
        external_id: None,
        latency_estimate_ms: None,
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(!json.contains("latency_estimate_ms"));
    assert_eq!(
        serde_json::from_str::<SessionRequest>(&json).unwrap(),
        request
    );

    let with_estimate = SessionRequest {
        latency_estimate_ms: Some(72),
        ..request
    };
    let json = serde_json::to_string(&with_estimate).unwrap();
    assert!(json.contains("\"latency_estimate_ms\":72"));
    assert_eq!(
        serde_json::from_str::<SessionRequest>(&json).unwrap(),
        with_estimate
    );
}

#[test]
fn session_descriptor_roundtrips_json() {
    let desc = SessionDescriptor {
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
        external_id: Some("game-99".to_owned()),
        slot_refs: vec![SlotExternalRef {
            slot: SlotId(0),
            external_ref: "sb-user-7".to_owned(),
        }],
        observer_slots: vec![SlotId(1)],
        expected_slots: vec![SlotId(0), SlotId(1)],
        homed_slots: vec![SlotId(0)],
        resumed: true,
        departed_slots: vec![DepartedSlot {
            finalized: false,
            slot: SlotId(2),
            kind: DepartureKind::Dropped,
            final_turn_count: Some(240),
        }],
        latency_estimate_ms: Some(30),
        relay_regions: vec![RelayRegionLabel {
            relay_id: RelayId(2),
            region: RegionId("us-east".to_owned()),
        }],
    };
    let json = serde_json::to_string(&desc).unwrap();
    // Pin the key names of the fields added most recently — a rename of one of
    // these is invisible to a round trip, and is what a relay running a build
    // behind the coordinator would silently read as absent. Not a full golden
    // string: every additive field would break it without anything being wrong.
    for key in [
        "\"latency_estimate_ms\":30",
        "\"relay_regions\":[{\"relay_id\":2,\"region\":\"us-east\"}]",
        "\"homed_slots\":[0]",
        "\"resumed\":true",
        "\"final_turn_count\":240",
    ] {
        assert!(json.contains(key), "{key} missing from {json}");
    }
    let back: SessionDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(back, desc);
}

#[test]
fn session_descriptor_ignores_fields_it_does_not_know() {
    // The mirror of the case above: a relay running behind the coordinator
    // must still parse a descriptor carrying fields it has never heard of,
    // rather than refusing the whole session. This is what makes every
    // descriptor addition safe to roll out to the coordinator first.
    let json = r#"{
        "tenant":"sb-staging","session":42,
        "peers":[],
        "bounds":{"min":1,"max":6},
        "some_field_from_a_newer_coordinator":[{"relay_id":2,"region":"us-east"}]
    }"#;
    let back: SessionDescriptor = serde_json::from_str(json).unwrap();
    assert_eq!(back.session, SessionId(42));
}

#[test]
fn session_descriptor_slot_sets_decode_verbatim() {
    // The homed and expected slot sets ride the same literal: the relay's
    // admission check enforces against `homed_slots`, and its authority sizes
    // the start-coverage check against `expected_slots`.
    let json = r#"{
        "tenant":"sb-staging","session":42,
        "peers":[],
        "bounds":{"min":1,"max":6},
        "homed_slots":[0,2],
        "expected_slots":[0,1,2]
    }"#;
    let back: SessionDescriptor = serde_json::from_str(json).unwrap();
    assert_eq!(back.homed_slots, vec![SlotId(0), SlotId(2)]);
    assert_eq!(back.expected_slots, vec![SlotId(0), SlotId(1), SlotId(2)]);
}

#[test]
fn session_descriptor_with_rehome_fields_decodes_them() {
    // A rehome-rebuilt descriptor: `resumed` and the seeded departed slots
    // round-trip verbatim so a fresh relay taking over the session can seed
    // its consensus with the already-decided departures. One entry carries a
    // final turn count, one omits it (a coordinator that recorded the
    // departure before counted leaves) — both must decode.
    let json = r#"{
        "tenant":"sb-staging","session":42,
        "peers":[],
        "bounds":{"min":1,"max":6},
        "resumed":true,
        "departed_slots":[{"slot":1,"kind":"left","final_turn_count":312},{"slot":3,"kind":"dropped"}]
    }"#;
    let back: SessionDescriptor = serde_json::from_str(json).unwrap();
    assert!(back.resumed);
    assert_eq!(
        back.departed_slots,
        vec![
            DepartedSlot {
                finalized: false,
                slot: SlotId(1),
                kind: DepartureKind::Left,
                final_turn_count: Some(312),
            },
            DepartedSlot {
                finalized: false,
                slot: SlotId(3),
                kind: DepartureKind::Dropped,
                final_turn_count: None,
            },
        ],
    );
}

#[test]
fn session_descriptor_omits_absent_correlation_ids_on_the_wire() {
    // `skip_serializing_if` keeps an unset session id off the wire (matching
    // `SessionRequest`'s style); `slot_refs` has no such attribute (it mirrors
    // `authority_order`'s plain `#[serde(default)]`), so an empty Vec still
    // serializes as `[]`, not omitted.
    let desc = SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(1),
        peers: vec![],
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
        relay_regions: Vec::new(),
    };
    let json = serde_json::to_string(&desc).unwrap();
    assert!(!json.contains("external_id"));
    assert!(!json.contains("latency_estimate_ms"));
    assert!(json.contains("\"slot_refs\":[]"));
    assert!(json.contains("\"observer_slots\":[]"));
    assert!(json.contains("\"expected_slots\":[]"));
    assert!(json.contains("\"homed_slots\":[]"));
}

#[test]
fn a_pre_additive_descriptor_decodes_with_every_added_field_at_its_default() {
    // One minimal literal — the shape a coordinator sent before any of the
    // fields below existed — against every default at once. Each field has a
    // consumer that reads the default as "unstated" (relay-id order for the
    // authority, the configured mesh roots for an uncertified peer, the normal
    // start-on-coverage path for an unresumed session), so a decode error here
    // would tear down the control connection over a field that was never sent.
    let json = r#"{
        "tenant":"sb-staging","session":42,
        "peers":[{"relay_id":2,"relay_addr":"127.0.0.1:14901"}],
        "bounds":{"min":1,"max":6}
    }"#;
    let back: SessionDescriptor = serde_json::from_str(json).unwrap();
    assert!(back.authority_order.is_empty());
    assert_eq!(back.latency_estimate_ms, None);
    assert!(
        back.relay_regions.is_empty(),
        "a descriptor that predates the region labels leaves the relay with          nothing to release, not a decode error",
    );
    assert!(
        !back.resumed,
        "a descriptor that predates rehome is not resumed, so the normal          start-on-coverage path runs unchanged",
    );
    assert!(back.departed_slots.is_empty());
    assert!(
        back.peers[0].cert_der.is_empty(),
        "a peer without a cert decodes to an empty pin (mesh-roots fallback)",
    );
    assert!(back.external_id.is_none());
    assert!(
        back.slot_refs.is_empty(),
        "a descriptor from a coordinator that predates the correlation ids \
         decodes to no external_id and no slot_refs, not a decode error",
    );
    assert!(
        back.observer_slots.is_empty(),
        "a descriptor that predates the observer field decodes to no \
         observer_slots, not a decode error",
    );
    assert!(
        back.expected_slots.is_empty(),
        "a descriptor that predates the expected-slots field decodes to no \
         expected_slots, not a decode error — the start directive is simply off",
    );
    assert!(
        back.homed_slots.is_empty(),
        "a descriptor that predates the homed-slots field decodes to no \
         homed_slots, not a decode error — home-relay binding is simply unenforced",
    );
}

#[test]
fn session_response_roundtrips_json() {
    let resp = SessionResponse {
        session: SessionId(1),
        home_relay: RelayEndpoint {
            relay_id: RelayId(1),
            relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            cert_der: vec![0x30, 0x82, 0x01, 0x02],
            relay_addrs: vec![],
        },
        slot_homes: vec![SlotHome {
            slot: SlotId(1),
            relay: RelayEndpoint {
                relay_id: RelayId(2),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
                cert_der: vec![0x30, 0x82, 0x03, 0x04],
                relay_addrs: vec![],
            },
        }],
        tokens: vec![PlayerToken {
            slot: SlotId(0),
            token: vec![0xAB, 0xCD],
        }],
        bounds: BufferBounds::new(1, 6).unwrap(),
        relay_regions: vec![RelayRegionLabel {
            relay_id: RelayId(1),
            region: RegionId("us-east".to_owned()),
        }],
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"relay_regions\":[{\"relay_id\":1,\"region\":\"us-east\"}]"));
    let back: SessionResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(back, resp);
}

#[test]
fn session_response_with_no_tagged_relays_omits_relay_regions() {
    // A coordinator with no region catalog (or a session whose relays are all
    // untagged) mints a response with an empty `relay_regions`, which the
    // `skip_serializing_if` drops from the wire entirely rather than sending
    // an empty array — this is what an app-server client built against an
    // older coordinator with no `relay_regions` field at all still parses.
    let resp = SessionResponse {
        session: SessionId(1),
        home_relay: RelayEndpoint {
            relay_id: RelayId(1),
            relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            cert_der: vec![0x30, 0x82, 0x01, 0x02],
            relay_addrs: vec![],
        },
        slot_homes: vec![],
        tokens: vec![PlayerToken {
            slot: SlotId(0),
            token: vec![0xAB, 0xCD],
        }],
        bounds: BufferBounds::new(1, 6).unwrap(),
        relay_regions: vec![],
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(!json.contains("relay_regions"));
    let back: SessionResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(back, resp);
}

#[test]
fn session_response_without_slot_homes_decodes_to_empty() {
    // A production session (and a response from a coordinator that predates the
    // field) carries no slot homes: the field defaults to empty rather than
    // failing to decode, so every slot homes on `home_relay`.
    let json = r#"{
        "session":1,
        "home_relay":{"relay_id":1,"relay_addr":"127.0.0.1:14900","cert_der":[48,130,1,2]},
        "tokens":[{"slot":0,"token":[171,205]}],
        "bounds":{"min":1,"max":6}
    }"#;
    let back: SessionResponse = serde_json::from_str(json).unwrap();
    assert!(back.slot_homes.is_empty());
    assert!(back.relay_regions.is_empty());
}

#[test]
fn session_request_without_external_id_decodes() {
    // A request from an app server that predates the correlation ids must
    // still decode — the field is optional and defaults to `None`, so old
    // and new peers interop (the control protos don't `deny_unknown_fields`).
    let json = r#"{
        "tenant":"sb-staging",
        "players":[{"slot":0,"client_pubkey":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]}]
    }"#;
    let back: SessionRequest = serde_json::from_str(json).unwrap();
    assert!(back.external_id.is_none());
    assert!(
        back.players[0].external_ref.is_none(),
        "a player handoff without external_ref decodes to None too",
    );
    assert!(
        !back.players[0].observer,
        "a player handoff without the observer field decodes to a competitor",
    );
}

#[test]
fn session_request_omits_absent_correlation_ids_on_the_wire() {
    // `skip_serializing_if` keeps an unset id off the wire, so a new
    // encoder talking to an old decoder emits exactly the old shape.
    let req = SessionRequest {
        tenant: TenantId("sb-staging".to_owned()),
        players: vec![PlayerHandoff {
            slot: SlotId(0),
            client_pubkey: ClientPublicKey([0x11; 32]),
            external_ref: None,
            observer: false,
            region: None,
        }],
        external_id: None,
        latency_estimate_ms: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(!json.contains("external_id"));
    assert!(!json.contains("external_ref"));
    assert!(!json.contains("latency_estimate_ms"));
    // `observer` is a plain `#[serde(default)]` bool with no
    // `skip_serializing_if`, so a competitor still serializes as
    // `"observer":false` — an old decoder just ignores it.
    assert!(json.contains("\"observer\":false"));
}
