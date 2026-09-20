use super::*;

#[test]
fn relay_hello_with_an_enroll_token_roundtrips_json() {
    let hello = a_hello().with_enroll_token("s3cr3t-token".to_owned());
    let json = serde_json::to_string(&hello).unwrap();
    assert!(json.contains("\"enroll_token\":\"s3cr3t-token\""));
    let back: RelayHello = serde_json::from_str(&json).unwrap();
    assert_eq!(back, hello);
}

#[test]
fn a_plain_hello_keeps_every_additive_field_off_the_wire() {
    // The additive-field contract in one place: a hello with none of the later
    // fields set emits exactly the shape a pre-additive peer would, so a relay
    // enrolling against a coordinator with no ledger, no region catalog and no
    // boot-id awareness produces bytes that coordinator has always understood.
    // A field that started serializing its `None`/empty form would break every
    // older consumer at once, so they are checked together.
    let json = serde_json::to_string(&a_hello()).unwrap();
    for field in [
        "min_protocol",
        "relay_addrs",
        "region",
        "enroll_token",
        "boot_id",
    ] {
        assert!(!json.contains(field), "{field} must stay off the wire");
    }
    assert_eq!(
        serde_json::from_str::<RelayHello>(&json).unwrap(),
        a_hello()
    );
}

#[test]
fn a_pre_additive_hello_decodes_with_every_additive_field_at_its_default() {
    // The other direction, against the byte-identical literal the test above
    // describes: a hello from a relay that predates all five fields decodes
    // rather than erroring, and each field lands on the default its consumers
    // treat as "unstated" — a one-version window at `protocol`, a single
    // address at `relay_addr`, no region, no token, and no continuity claim.
    let legacy = r#"{
        "relay_id":7,
        "relay_addr":"127.0.0.1:14900",
        "protocol":2,
        "cert_der":[1,2,3]
    }"#;
    let back: RelayHello = serde_json::from_str(legacy).unwrap();
    assert_eq!(back.protocol, ProtocolVersion(2));
    assert_eq!(back.min_protocol, None);
    assert!(back.relay_addrs.is_empty());
    assert_eq!(back.region, None);
    assert_eq!(back.enroll_token, None);
    assert_eq!(back.boot_id, None);
}

#[test]
fn relay_hello_with_min_protocol_roundtrips_json() {
    let hello = RelayHello::new(
        RelayId(7),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion(3),
        vec![0x30, 0x82, 0xAA, 0xBB],
    )
    .with_min_protocol(ProtocolVersion(2));
    let json = serde_json::to_string(&hello).unwrap();
    assert!(json.contains("\"min_protocol\":2"));
    let back: RelayHello = serde_json::from_str(&json).unwrap();
    assert_eq!(back, hello);
}

#[test]
fn relay_hello_with_a_region_roundtrips_json() {
    // A tagged relay carries its region on the wire as a bare string, which is
    // what the coordinator matches its region catalog against.
    let tagged = a_hello().with_region(RegionId("us-east".to_owned()));
    let json = serde_json::to_string(&tagged).unwrap();
    assert!(json.contains("\"region\":\"us-east\""));
    assert_eq!(serde_json::from_str::<RelayHello>(&json).unwrap(), tagged);
}

#[test]
fn relay_hello_with_a_dual_stack_set_roundtrips_json() {
    let v4: SocketAddr = "203.0.113.7:14900".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::7]:14900".parse().unwrap();
    let hello = RelayHello::new(RelayId(7), v4, ProtocolVersion::CURRENT, vec![0xAA; 4])
        .with_relay_addrs(vec![v4, v6]);
    let json = serde_json::to_string(&hello).unwrap();
    assert!(json.contains("\"relay_addrs\""));
    let back: RelayHello = serde_json::from_str(&json).unwrap();
    // Full equality covers both the unchanged primary and the v4-then-v6 order
    // of the advertised set, which is the relay's stated preference.
    assert_eq!(back, hello);
}

#[test]
fn addr_selection_walks_the_advertised_order_and_falls_back_to_the_primary() {
    let v4: SocketAddr = "203.0.113.7:14900".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::7]:14900".parse().unwrap();

    // A dual-stack endpoint: the candidates are the set, in advertised order
    // (the relay's preference), and family selection picks within it.
    let dual = RelayEndpoint {
        relay_id: RelayId(1),
        relay_addr: v4,
        cert_der: vec![],
        relay_addrs: vec![v6, v4], // the relay prefers v6
    };
    assert_eq!(dual.addrs(), vec![v6, v4], "advertised order is preserved");
    assert_eq!(dual.addr_for_family(true), Some(v6));
    assert_eq!(dual.addr_for_family(false), Some(v4));

    // A single-address peer: the candidates collapse to the primary, and a
    // family it doesn't serve yields None (the caller walks the candidates).
    let single = RelayPeer {
        relay_id: RelayId(2),
        relay_addr: v4,
        cert_der: vec![],
        relay_addrs: vec![],
    };
    assert_eq!(single.addrs(), vec![v4]);
    assert_eq!(single.addr_for_family(false), Some(v4));
    assert_eq!(single.addr_for_family(true), None);
}

#[test]
fn relay_hello_with_a_boot_id_roundtrips_json() {
    // A relay that stamps its process identity carries the boot id as a JSON
    // *number*, not a string — a large u64 is the classic place for a codec to
    // quietly switch representations, and a coordinator reading the other form
    // would see every reconnect as a fresh process.
    let stamped = a_hello().with_boot_id(0xDEAD_BEEF_1234_5678);
    let json = serde_json::to_string(&stamped).unwrap();
    assert!(json.contains(&format!("\"boot_id\":{}", 0xDEAD_BEEF_1234_5678u64)));
    assert_eq!(serde_json::from_str::<RelayHello>(&json).unwrap(), stamped);
}
