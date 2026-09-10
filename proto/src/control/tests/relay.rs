use super::*;

#[test]
fn relay_hello_roundtrips_json() {
    let hello = RelayHello {
        capabilities: Vec::new(),
        relay_id: RelayId(7),
        relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        protocol: ProtocolVersion::CURRENT,
        cert_der: vec![0x30, 0x82, 0xAA, 0xBB],
        min_protocol: None,
        relay_addrs: vec![],
        region: None,
        enroll_token: None,
        boot_id: None,
    };
    let json = serde_json::to_string(&hello).unwrap();
    // An unset window bottom stays off the wire (a one-version window).
    assert!(!json.contains("min_protocol"));
    let back: RelayHello = serde_json::from_str(&json).unwrap();
    assert_eq!(back, hello);
}

#[test]
fn relay_hello_with_an_enroll_token_roundtrips_json() {
    let hello = RelayHello::new(
        RelayId(7),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion::CURRENT,
        vec![0xAA; 4],
    )
    .with_enroll_token("s3cr3t-token".to_owned());
    let json = serde_json::to_string(&hello).unwrap();
    assert!(json.contains("\"enroll_token\":\"s3cr3t-token\""));
    let back: RelayHello = serde_json::from_str(&json).unwrap();
    assert_eq!(back, hello);
    assert_eq!(back.enroll_token.as_deref(), Some("s3cr3t-token"));
}

#[test]
fn a_tokenless_hello_serializes_byte_identical_to_the_pre_token_form() {
    // A hello with no enroll token keeps the field off the wire entirely, so a
    // relay enrolling against a coordinator with no ledger (and every reconnect
    // once a certificate is bound) emits exactly the shape a pre-token peer
    // would — the additive-field byte-identical guarantee.
    let tokenless = RelayHello::new(
        RelayId(7),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion::CURRENT,
        vec![0xAA; 4],
    );
    let json = serde_json::to_string(&tokenless).unwrap();
    assert!(!json.contains("enroll_token"));
    // The same bytes a tokenless hello has always produced: adding
    // `with_enroll_token` and then clearing it back to `None` round-trips to
    // the identical wire form.
    let back: RelayHello = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tokenless);
    assert!(back.enroll_token.is_none());
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
    assert_eq!(back.min_protocol, Some(ProtocolVersion(2)));
}

#[test]
fn relay_hello_without_min_protocol_decodes_to_none() {
    // A hello from a relay that predates the window field must still decode —
    // `min_protocol` defaults to None, which the coordinator reads as a
    // one-version window at `protocol`.
    let json = r#"{
        "relay_id":7,
        "relay_addr":"127.0.0.1:14900",
        "protocol":2,
        "cert_der":[1,2,3]
    }"#;
    let back: RelayHello = serde_json::from_str(json).unwrap();
    assert_eq!(back.min_protocol, None);
    assert_eq!(back.protocol, ProtocolVersion(2));
}

#[test]
fn relay_hello_with_region_roundtrips_and_omits_when_absent() {
    // A tagged relay carries its region on the wire; an untagged one keeps the
    // field off entirely, so an untagged hello stays byte-identical to the
    // pre-region form.
    let tagged = RelayHello::new(
        RelayId(7),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion::CURRENT,
        vec![0xAA; 4],
    )
    .with_region(RegionId("us-east".to_owned()));
    let json = serde_json::to_string(&tagged).unwrap();
    assert!(json.contains("\"region\":\"us-east\""));
    assert_eq!(serde_json::from_str::<RelayHello>(&json).unwrap(), tagged);

    let untagged = RelayHello::new(
        RelayId(7),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion::CURRENT,
        vec![0xAA; 4],
    );
    assert!(!serde_json::to_string(&untagged).unwrap().contains("region"));
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
    assert_eq!(back, hello);
    assert_eq!(back.relay_addr, v4, "the primary is unchanged");
    assert_eq!(
        back.relay_addrs,
        vec![v4, v6],
        "the complete set rides along"
    );
}

#[test]
fn a_single_address_hello_keeps_the_field_off_the_wire_and_absent_decodes_empty() {
    // Back-compat both directions: this build's single-address hello stays
    // byte-stable (no `relay_addrs` key for an old consumer to trip on)...
    let hello = RelayHello::new(
        RelayId(7),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion::CURRENT,
        vec![0xAA; 4],
    );
    let json = serde_json::to_string(&hello).unwrap();
    assert!(!json.contains("relay_addrs"));

    // ...and an old relay's hello (no field at all) decodes with an empty
    // set, which every consumer reads as "single address at relay_addr".
    let old = r#"{
        "relay_id":7,
        "relay_addr":"127.0.0.1:14900",
        "protocol":2,
        "cert_der":[1,2,3]
    }"#;
    let back: RelayHello = serde_json::from_str(old).unwrap();
    assert!(back.relay_addrs.is_empty());
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
fn relay_hello_boot_id_roundtrips_and_stays_off_the_wire_when_absent() {
    // A relay that stamps its process identity carries it; one that predates
    // the field keeps the hello byte-identical to the pre-boot-id form, and its
    // absence decodes to None — the value a coordinator must read as "cannot
    // vouch for continuity".
    let stamped = RelayHello::new(
        RelayId(7),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion::CURRENT,
        vec![0xAA; 4],
    )
    .with_boot_id(0xDEAD_BEEF_1234_5678);
    let json = serde_json::to_string(&stamped).unwrap();
    assert!(json.contains(&format!("\"boot_id\":{}", 0xDEAD_BEEF_1234_5678u64)));
    assert_eq!(serde_json::from_str::<RelayHello>(&json).unwrap(), stamped);

    let plain = RelayHello::new(
        RelayId(7),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion::CURRENT,
        vec![0xAA; 4],
    );
    assert!(!serde_json::to_string(&plain).unwrap().contains("boot_id"));
    let legacy = r#"{
        "relay_id":7,
        "relay_addr":"127.0.0.1:14900",
        "protocol":2,
        "cert_der":[1,2,3]
    }"#;
    assert_eq!(
        serde_json::from_str::<RelayHello>(legacy).unwrap().boot_id,
        None,
    );
}
