//! The per-relay descriptors a session produces: what `descriptor_for` puts in
//! one, what `create_session` stages, and how a dual-stack enrollment's
//! addresses flow through the response, the descriptor, and a re-home.

use super::*;

#[test]
fn descriptor_for_lists_other_session_relays_as_peers() {
    let setup = region_b_fleet();
    let resp = create_session(
        &setup,
        // Slot 1 names region-b so it homes on relay 2, giving both relays a
        // slot to serve and mesh — the only way a session spans two relays.
        request(two_players_slot_1_in_region_b()),
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;

    // Relay 1's peers are the other relays serving this session → relay 2.
    let desc = descriptor_for(&setup, &tid(), resp.session, RelayId(1)).unwrap();
    assert_eq!(desc.peers.len(), 1);
    assert_eq!(desc.peers[0].relay_id, RelayId(2));
    assert_eq!(
        desc.peers[0].cert_der,
        fake_cert(2),
        "the peer carries relay 2's enrolled cert, so relay 1's mesh dial pins it",
    );
    assert_eq!(desc.bounds, BufferBounds::new(1, 6).unwrap());

    // Relay 2's peers → relay 1.
    let desc2 = descriptor_for(&setup, &tid(), resp.session, RelayId(2)).unwrap();
    assert_eq!(desc2.peers.len(), 1);
    assert_eq!(desc2.peers[0].relay_id, RelayId(1));
    assert_eq!(desc2.peers[0].cert_der, fake_cert(1));

    // Both descriptors carry the same buffer-authority order, with this
    // session's rotated primary home first. Every relay must rank the
    // candidates identically or the presence-driven handoff would crown
    // different authorities.
    let other = if resp.home_relay.relay_id == RelayId(1) {
        RelayId(2)
    } else {
        RelayId(1)
    };
    assert_eq!(desc.authority_order, vec![resp.home_relay.relay_id, other],);
    assert_eq!(desc2.authority_order, desc.authority_order);

    // Each relay's descriptor names only the slots the coordinator
    // actually assigned to it, not the whole session's slot set -- a relay
    // uses this to refuse a client whose token authorizes a slot homed
    // elsewhere. Slot 0 stays on relay 1 and slot 1 stays on relay 2,
    // independently of which tied relay is represented as the primary.
    assert_eq!(desc.homed_slots, vec![SlotId(0)]);
    assert_eq!(desc2.homed_slots, vec![SlotId(1)]);
}

#[test]
fn descriptor_for_includes_the_stored_session_refs() {
    // The correlation ids the app server sent at create_session must ride
    // in every descriptor built for the session, so a relay can stamp them
    // into a departure notice itself rather than depending on the
    // coordinator's in-memory session-refs store surviving to notice time.
    // The tenant's one-way latency estimate rides alongside them, so the
    // authority relay can fold it into the initial buffer depth it sizes at
    // session start.
    let setup = two_relay_fleet();
    let resp = create_session(
        &setup,
        SessionRequest {
            external_id: Some("game-99".to_owned()),
            latency_estimate_ms: Some(72),
            ..request(vec![
                PlayerHandoff {
                    external_ref: Some("sb-user-7".to_owned()),
                    ..player(0)
                },
                PlayerHandoff {
                    // An observer: it must show up in the descriptor's
                    // observer_slots so relays exclude it from desync checks.
                    observer: true,
                    ..player(1)
                },
            ])
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;

    let desc = descriptor_for(&setup, &tid(), resp.session, RelayId(1)).unwrap();
    assert_eq!(desc.external_id, Some("game-99".to_owned()));
    assert_eq!(desc.slot_refs.len(), 1, "only the slot with a ref appears");
    assert_eq!(desc.slot_refs[0].slot, SlotId(0));
    assert_eq!(desc.slot_refs[0].external_ref, "sb-user-7");
    assert_eq!(
        desc.observer_slots,
        vec![SlotId(1)],
        "the observer-flagged slot is carried into the descriptor",
    );
    assert_eq!(
        desc.latency_estimate_ms,
        Some(72),
        "the tenant's latency hint is carried into the descriptor",
    );
    // Every slot the request listed — the competitor and the observer alike —
    // is carried as an expected slot so the authority relay knows the full set
    // that must connect before it fires the session-start directive.
    let mut expected = desc.expected_slots.clone();
    expected.sort_by_key(|s| s.0);
    assert_eq!(expected, vec![SlotId(0), SlotId(1)]);
}

#[test]
fn descriptor_for_without_stored_refs_has_none_and_empty() {
    // A session created with no correlation ids at all still builds a
    // descriptor — just with the fields empty, not an error.
    let setup = two_relay_fleet();
    let resp = create_default_session(&setup);

    let desc = descriptor_for(&setup, &tid(), resp.session, RelayId(1)).unwrap();
    assert!(desc.external_id.is_none());
    assert!(desc.slot_refs.is_empty());
    assert!(
        desc.latency_estimate_ms.is_none(),
        "a request with no latency estimate carries none in the descriptor",
    );
    assert!(
        desc.observer_slots.is_empty(),
        "no observer-flagged players -> empty observer_slots",
    );
    // Expected slots track the request's players even when no correlation ids
    // were sent: the two competitors must both connect before start.
    let mut expected = desc.expected_slots.clone();
    expected.sort_by_key(|s| s.0);
    assert_eq!(expected, vec![SlotId(0), SlotId(1)]);
}

#[test]
fn descriptor_for_unknown_session_returns_none() {
    let setup = two_relay_fleet();
    // No session was created → no membership recorded.
    assert!(descriptor_for(&setup, &tid(), SessionId(999), RelayId(1)).is_none());
}

#[test]
fn descriptor_for_excludes_relays_not_in_session() {
    // Three relays registered, but a session only uses two (region-b resolves
    // slot 1 onto relay 2). The third relay must NOT appear in the
    // descriptor's peer list.
    let setup = region_fleet(&[
        (1, 14900, None),
        (2, 14901, Some("region-b")),
        (3, 14902, None),
    ]);
    let resp = create_session(
        &setup,
        request(two_players_slot_1_in_region_b()),
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;

    // Relays 1 and 2 serve the session. Relay 3 is registered but unused.
    let desc = descriptor_for(&setup, &tid(), resp.session, RelayId(1)).unwrap();
    // Only relay 2 is a peer — relay 3 is excluded.
    assert_eq!(desc.peers.len(), 1);
    assert_eq!(desc.peers[0].relay_id, RelayId(2));
}

#[test]
fn create_session_stages_descriptors_for_each_relay() {
    let setup = region_b_fleet();
    let resp = create_session(
        &setup,
        // Slot 1 names region-b, giving both relays a slot.
        request(two_players_slot_1_in_region_b()),
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;

    // The region override's home is the relay slot 1 was placed onto.
    let secondary_relay = resp.slot_homes[0].relay.relay_id;

    // Both relays serving the session have a descriptor staged in the outbox,
    // each naming the other as its mesh peer.
    let for_home = setup.descriptors().current_for(resp.home_relay.relay_id);
    assert_eq!(for_home.len(), 1);
    assert_eq!(for_home[0].session, resp.session);
    assert_eq!(for_home[0].peers.len(), 1);
    assert_eq!(for_home[0].peers[0].relay_id, secondary_relay);

    let for_secondary = setup.descriptors().current_for(secondary_relay);
    assert_eq!(for_secondary.len(), 1);
    assert_eq!(for_secondary[0].peers[0].relay_id, resp.home_relay.relay_id);
}

#[test]
fn create_session_single_relay_stages_a_peerless_descriptor() {
    // A single-relay session still stages a descriptor (with no peers) so the
    // relay learns the session and its bounds, even with no mesh.
    let setup = fleet(&[(5, 14900, None, false)]).0;

    create_session(&setup, request(two_players()), ExpiresAt(u64::MAX)).unwrap();

    let staged = setup.descriptors().current_for(RelayId(5));
    assert_eq!(staged.len(), 1);
    assert!(staged[0].peers.is_empty());
}

// --- Dual-stack advertise ---

#[test]
fn a_dual_stack_enrollment_flows_through_response_descriptor_and_rehome() {
    // Two dual-stack relays enroll with complete v4+v6 sets. The set must
    // survive every consumer-facing path unchanged — session response,
    // descriptor peers, and a rehome's NewTarget — with the primary intact.
    let v4_1: SocketAddr = "203.0.113.1:14900".parse().unwrap();
    let v6_1: SocketAddr = "[2001:db8::1]:14900".parse().unwrap();
    let v4_2: SocketAddr = "203.0.113.2:14900".parse().unwrap();
    let v6_2: SocketAddr = "[2001:db8::2]:14900".parse().unwrap();

    let reg = registry::RelayRegistry::new();
    registry::enroll(
        &reg,
        RelayHello::new(RelayId(1), v4_1, ProtocolVersion::CURRENT, fake_cert(1))
            .with_relay_addrs(vec![v4_1, v6_1]),
    );
    registry::enroll(
        &reg,
        RelayHello::new(RelayId(2), v4_2, ProtocolVersion::CURRENT, fake_cert(2))
            .with_relay_addrs(vec![v4_2, v6_2])
            .with_region(region("region-b")),
    );
    let setup = SessionSetup::new(reg, tenant_store());

    // A cross-relay session so both relays serve (and each descriptor names
    // the other as a peer): slot 1 names region-b, homing it on relay 2.
    let resp = create_session(
        &setup,
        request(two_players_slot_1_in_region_b()),
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;

    // The session response's endpoints carry each relay's set unchanged,
    // whichever tied relay this session rotates into the primary position.
    let relay_1 = response_endpoint_for_relay(&resp, RelayId(1));
    assert_eq!(relay_1.relay_addr, v4_1);
    assert_eq!(relay_1.relay_addrs, vec![v4_1, v6_1]);
    assert_eq!(relay_1.addr_for_family(true), Some(v6_1));
    let relay_2 = response_endpoint_for_relay(&resp, RelayId(2));
    assert_eq!(relay_2.relay_addr, v4_2);
    assert_eq!(relay_2.relay_addrs, vec![v4_2, v6_2]);
    assert_eq!(relay_2.addr_for_family(true), Some(v6_2));

    // The descriptor's peer carries the other relay's full set.
    let desc = descriptor_for(&setup, &tid(), resp.session, RelayId(1)).unwrap();
    assert_eq!(desc.peers[0].relay_id, RelayId(2));
    assert_eq!(desc.peers[0].relay_addr, v4_2);
    assert_eq!(desc.peers[0].relay_addrs, vec![v4_2, v6_2]);
    assert_eq!(desc.peers[0].addrs(), vec![v4_2, v6_2]);

    // Serving relay 1 dies; the rehome's NewTarget carries the survivor's set.
    registry::remove(setup.registry(), RelayId(1));
    let RehomeOutcome::NewTarget(endpoint) =
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![])
    else {
        panic!("expected a NewTarget re-home decision");
    };
    assert_eq!(endpoint.relay_id, RelayId(2));
    assert_eq!(endpoint.relay_addr, v4_2);
    assert_eq!(endpoint.relay_addrs, vec![v4_2, v6_2]);
}
