//! Descriptor-diff unit tests: what the writer sends as a delta and what it
//! leaves out.

use super::*;

/// A session descriptor for `session` meshing the given peer relays — a compact
/// fixture for the descriptor-diff unit tests.
fn diff_descriptor(session: u64, peers: &[u64]) -> SessionDescriptor {
    SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId("sb-test".to_owned()),
        session: SessionId(session),
        peers: peers
            .iter()
            .map(|&id| rally_point_proto::control::RelayPeer {
                relay_id: RelayId(id),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900 + id as u16)),
                cert_der: vec![id as u8; 4],
                relay_addrs: vec![],
            })
            .collect(),
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
    }
}

#[test]
fn diff_of_an_unchanged_set_is_empty() {
    // The steady-state arm relies on this: a coalesced wake that nets to no change
    // diffs to nothing, so the writer sends no frame.
    let set = vec![diff_descriptor(1, &[2]), diff_descriptor(2, &[3])];
    let baseline = index_descriptors(&set);
    let (upserts, removals) = diff_descriptors(&baseline, &set);
    assert!(upserts.is_empty(), "an unchanged set produces no upserts");
    assert!(removals.is_empty(), "an unchanged set produces no removals");
}

#[test]
fn diff_reports_adds_removals_and_in_place_mutations() {
    // Baseline: sessions 1 and 2. Target: session 1 mutated in place (its peers
    // change), session 2 removed, session 3 added.
    let baseline = index_descriptors(&[diff_descriptor(1, &[2]), diff_descriptor(2, &[2])]);
    let current = vec![diff_descriptor(1, &[9]), diff_descriptor(3, &[2])];
    let (upserts, removals) = diff_descriptors(&baseline, &current);

    let mut upsert_sessions: Vec<u64> = upserts.iter().map(|d| d.session.0).collect();
    upsert_sessions.sort_unstable();
    assert_eq!(
        upsert_sessions,
        vec![1, 3],
        "the mutated session and the added one are both upserts",
    );
    // The mutated session's upsert carries the new value, not the stale one.
    let one = upserts.iter().find(|d| d.session == SessionId(1)).unwrap();
    assert_eq!(one.peers[0].relay_id, RelayId(9));
    assert_eq!(
        removals,
        vec![DescriptorKey {
            tenant: TenantId("sb-test".to_owned()),
            session: SessionId(2),
        }],
    );
}
