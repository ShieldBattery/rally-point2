use std::net::{Ipv4Addr, SocketAddr};

use super::*;
use rally_point_proto::control::RelayHello;
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::ProtocolVersion;

fn hello(id: u64, port: u16) -> RelayHello {
    RelayHello::new(
        RelayId(id),
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ProtocolVersion::CURRENT,
        vec![id as u8; 4],
    )
}

#[test]
fn enroll_then_peer_roundtrips() {
    let reg = new_registry();
    assert!(is_empty(&reg));

    enroll(&reg, hello(1, 14900));
    assert!(!is_empty(&reg));

    let e = entry(&reg, RelayId(1)).unwrap();
    assert_eq!(e.relay_id, RelayId(1));

    let p = peer(&reg, RelayId(1)).unwrap();
    assert_eq!(p.relay_id, RelayId(1));
    assert_eq!(p.relay_addr, SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)));
    assert_eq!(
        p.cert_der,
        vec![1u8; 4],
        "the peer carries the cert the relay enrolled with, for the mesh dial to pin",
    );
}

#[test]
fn re_enroll_replaces_address() {
    let reg = new_registry();
    enroll(&reg, hello(1, 14900));
    enroll(&reg, hello(1, 14999)); // same id, new address

    let p = peer(&reg, RelayId(1)).unwrap();
    assert_eq!(p.relay_addr, SocketAddr::from((Ipv4Addr::LOCALHOST, 14999)));
    assert_eq!(len(&reg), 1);
}

#[test]
fn enroll_hands_out_strictly_increasing_generations() {
    let reg = new_registry();
    let g0 = enroll(&reg, hello(1, 14900));
    let g1 = enroll(&reg, hello(1, 14999)); // same relay reconnecting
    let g2 = enroll(&reg, hello(2, 14901)); // a different relay
    assert!(g1 > g0, "a re-enroll gets a later generation");
    assert!(g2 > g1, "every enroll gets a distinct, later generation");
}

#[test]
fn remove_if_current_removes_on_a_matching_generation() {
    let reg = new_registry();
    let generation = enroll(&reg, hello(1, 14900));
    assert!(remove_if_current(&reg, RelayId(1), generation));
    assert!(is_empty(&reg));
    // A second drop of the same connection is a no-op (already gone).
    assert!(!remove_if_current(&reg, RelayId(1), generation));
}

#[test]
fn remove_if_current_keeps_a_relay_that_already_reconnected() {
    // The reconnect race: connection #1 enrolls, connection #2 re-enrolls the
    // same relay (a reconnect), then connection #1's drop fires. The stale
    // generation must not evict the live entry connection #2 installed.
    let reg = new_registry();
    let stale = enroll(&reg, hello(1, 14900));
    let current = enroll(&reg, hello(1, 14999));
    assert_ne!(stale, current);

    assert!(
        !remove_if_current(&reg, RelayId(1), stale),
        "a stale connection must not deregister a reconnected relay",
    );
    assert!(!is_empty(&reg), "the relay stays registered");
    // The current connection's own later drop still deregisters it.
    assert!(remove_if_current(&reg, RelayId(1), current));
    assert!(is_empty(&reg));
}

#[test]
fn peer_for_unknown_returns_none() {
    let reg = new_registry();
    enroll(&reg, hello(1, 14900));
    assert!(peer(&reg, RelayId(99)).is_none());
}

#[test]
fn all_entries_lists_everyone() {
    let reg = new_registry();
    enroll(&reg, hello(1, 14900));
    enroll(&reg, hello(2, 14901));
    let entries = all_entries(&reg);
    assert_eq!(entries.len(), 2);
}

#[test]
fn remove_clears_an_entry() {
    let reg = new_registry();
    enroll(&reg, hello(1, 14900));
    remove(&reg, RelayId(1));
    assert!(is_empty(&reg));
    assert!(peer(&reg, RelayId(1)).is_none());
}

#[test]
fn mark_draining_applies_under_the_current_generation() {
    let reg = new_registry();
    let generation = enroll(&reg, hello(1, 14900));
    assert!(is_available(&reg, RelayId(1)));

    assert!(mark_draining(&reg, RelayId(1), generation));
    assert!(
        !is_available(&reg, RelayId(1)),
        "a marked relay is unavailable"
    );
    // Idempotent: re-marking under the same generation still reports applied.
    assert!(mark_draining(&reg, RelayId(1), generation));
    // Still enrolled — draining excludes only new assignments, not the entry.
    assert!(entry(&reg, RelayId(1)).is_some());
}

#[test]
fn mark_draining_ignores_a_stale_generation() {
    // A stale connection's Draining must not mark an entry a newer connection
    // re-enrolled (whose fresh enroll cleared the flag deliberately).
    let reg = new_registry();
    let stale = enroll(&reg, hello(1, 14900));
    let current = enroll(&reg, hello(1, 14999));
    assert_ne!(stale, current);

    assert!(
        !mark_draining(&reg, RelayId(1), stale),
        "a stale generation must not mark the reconnected relay draining",
    );
    assert!(
        is_available(&reg, RelayId(1)),
        "the reconnected relay stays available",
    );
    // The live connection's own Draining applies.
    assert!(mark_draining(&reg, RelayId(1), current));
    assert!(!is_available(&reg, RelayId(1)));
}

#[test]
fn generation_is_current_tracks_re_enrollment() {
    let reg = new_registry();
    let stale = enroll(&reg, hello(1, 14900));
    assert!(generation_is_current(&reg, RelayId(1), stale));

    // A reconnect re-enrolls with a newer generation: the old one is stale.
    let current = enroll(&reg, hello(1, 14999));
    assert!(!generation_is_current(&reg, RelayId(1), stale));
    assert!(generation_is_current(&reg, RelayId(1), current));

    // An unknown relay has no current generation at all.
    assert!(!generation_is_current(&reg, RelayId(9), current));
}

#[test]
fn mark_draining_on_an_unknown_relay_is_a_no_op() {
    let reg = new_registry();
    assert!(!mark_draining(&reg, RelayId(7), 0));
}

#[test]
fn re_enroll_clears_the_draining_flag() {
    // A relay that reconnects mid-drain is fresh: its enroll clears the flag, so
    // it must re-send Draining to re-mark itself.
    let reg = new_registry();
    let g0 = enroll(&reg, hello(1, 14900));
    assert!(mark_draining(&reg, RelayId(1), g0));
    assert!(!is_available(&reg, RelayId(1)));

    enroll(&reg, hello(1, 14999)); // reconnect
    assert!(
        is_available(&reg, RelayId(1)),
        "a re-enroll clears draining — the relay is fresh again",
    );
}

#[test]
fn clear_draining_re_admits_under_the_current_generation() {
    let reg = new_registry();
    let generation = enroll(&reg, hello(1, 14900));
    assert!(mark_draining(&reg, RelayId(1), generation));
    assert!(!is_available(&reg, RelayId(1)));

    // Clearing under the same generation re-admits the relay.
    assert!(clear_draining(&reg, RelayId(1), generation));
    assert!(
        is_available(&reg, RelayId(1)),
        "a cleared relay is available for new assignments again",
    );
    // Idempotent: clearing an already-cleared entry still reports applied.
    assert!(clear_draining(&reg, RelayId(1), generation));
    assert!(is_available(&reg, RelayId(1)));
}

#[test]
fn clear_draining_ignores_a_stale_generation() {
    // A stale connection's clear must not re-admit an entry a newer connection
    // re-enrolled — the same fence mark_draining honors, in the other direction.
    let reg = new_registry();
    let stale = enroll(&reg, hello(1, 14900));
    let current = enroll(&reg, hello(1, 14999));
    assert!(mark_draining(&reg, RelayId(1), current));
    assert!(!is_available(&reg, RelayId(1)));

    assert!(
        !clear_draining(&reg, RelayId(1), stale),
        "a stale generation must not clear the reconnected relay's mark",
    );
    assert!(
        !is_available(&reg, RelayId(1)),
        "the relay stays draining under the stale clear",
    );
    // The live generation's own clear applies.
    assert!(clear_draining(&reg, RelayId(1), current));
    assert!(is_available(&reg, RelayId(1)));
}

#[test]
fn clear_draining_on_an_unknown_relay_is_a_no_op() {
    let reg = new_registry();
    assert!(!clear_draining(&reg, RelayId(7), 0));
}

#[test]
fn is_enrolled_tracks_presence_including_draining() {
    let reg = new_registry();
    assert!(!is_enrolled(&reg, RelayId(1)));
    let generation = enroll(&reg, hello(1, 14900));
    assert!(is_enrolled(&reg, RelayId(1)));

    // A draining relay is still enrolled (present), even though unavailable.
    mark_draining(&reg, RelayId(1), generation);
    assert!(is_enrolled(&reg, RelayId(1)));
    assert!(!is_available(&reg, RelayId(1)));

    remove(&reg, RelayId(1));
    assert!(!is_enrolled(&reg, RelayId(1)));
}

#[test]
fn enrolled_relays_snapshots_id_region_generation_and_draining() {
    let reg = new_registry();
    let region = rally_point_proto::control::RegionId("us-east".to_owned());
    let g1 = enroll(&reg, hello(1, 14900).with_region(region.clone()));
    enroll(&reg, hello(2, 14901)); // untagged
    mark_draining(&reg, RelayId(1), g1);

    let mut snapshot = enrolled_relays(&reg);
    snapshot.sort_by_key(|r| r.relay_id.0);
    assert_eq!(snapshot.len(), 2);

    assert_eq!(snapshot[0].relay_id, RelayId(1));
    assert_eq!(snapshot[0].region.as_ref(), Some(&region));
    assert_eq!(snapshot[0].generation, g1);
    assert!(snapshot[0].draining, "relay 1 was marked draining");

    assert_eq!(snapshot[1].relay_id, RelayId(2));
    assert_eq!(snapshot[1].region, None, "relay 2 enrolled untagged");
    assert!(!snapshot[1].draining);
}

#[test]
fn available_entries_excludes_a_draining_relay() {
    let reg = new_registry();
    let g1 = enroll(&reg, hello(1, 14900));
    enroll(&reg, hello(2, 14901));

    // Both enrolled: both available.
    assert_eq!(available_entries(&reg).len(), 2);
    assert_eq!(all_entries(&reg).len(), 2);

    mark_draining(&reg, RelayId(1), g1);
    // available_entries drops the draining relay; all_entries keeps it.
    let available: Vec<_> = available_entries(&reg)
        .into_iter()
        .map(|e| e.relay_id)
        .collect();
    assert_eq!(available, vec![RelayId(2)]);
    assert_eq!(
        all_entries(&reg).len(),
        2,
        "the draining relay stays enrolled"
    );
}

#[test]
fn enroll_publishes_a_fingerprinted_mesh_peer_set() {
    let reg = new_registry();
    assert!(mesh_peers(&reg).is_empty(), "no relays enrolled, no peers");

    enroll(&reg, hello(2, 14902));
    enroll(&reg, hello(1, 14901));

    // Sorted by relay id, each peer carrying the SHA-256 of the cert it
    // enrolled with (`hello` enrolls with `vec![id; 4]`).
    let peers = mesh_peers(&reg);
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].relay_id, RelayId(1));
    assert_eq!(peers[0].cert_sha256, cert_fingerprint(&[1u8; 4]));
    assert_eq!(peers[1].relay_id, RelayId(2));
    assert_eq!(peers[1].cert_sha256, cert_fingerprint(&[2u8; 4]));
}

#[test]
fn a_subscriber_re_syncs_the_current_set_and_wakes_on_membership_change() {
    let reg = new_registry();
    enroll(&reg, hello(1, 14901));

    // A fresh subscriber re-syncs the current set as its initial value.
    let mut rx = subscribe_mesh_peers(&reg);
    let initial = rx.borrow_and_update().clone();
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0].relay_id, RelayId(1));

    // A later enroll wakes the subscriber and grows the set.
    enroll(&reg, hello(2, 14902));
    assert!(rx.has_changed().unwrap());
    let grown = rx.borrow_and_update().clone();
    assert_eq!(grown.len(), 2);

    // Re-enrolling the same relay with the same cert (only its address
    // differs) leaves the mesh-peer set unchanged, so it must not wake the
    // subscriber — the set keys on id + cert fingerprint, nothing else.
    enroll(&reg, hello(2, 14999));
    assert!(
        !rx.has_changed().unwrap(),
        "an unchanged mesh-peer set must not wake a subscriber",
    );
}

#[test]
fn live_cert_fingerprint_tracks_the_current_entry() {
    let reg = new_registry();
    assert_eq!(
        live_cert_fingerprint(&reg, RelayId(1)),
        None,
        "an unenrolled id has nothing to compare against",
    );

    enroll(&reg, hello(1, 14900));
    assert_eq!(
        live_cert_fingerprint(&reg, RelayId(1)),
        Some(cert_fingerprint(&[1u8; 4])),
    );

    // Deregistering clears it.
    remove(&reg, RelayId(1));
    assert_eq!(live_cert_fingerprint(&reg, RelayId(1)), None);
}

/// Builds a hello like [`hello`] but with an explicit certificate, for
/// exercising same-id/different-cert enrollment conflicts.
fn hello_with_cert(id: u64, port: u16, cert_der: Vec<u8>) -> RelayHello {
    RelayHello::new(
        RelayId(id),
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ProtocolVersion::CURRENT,
        cert_der,
    )
}

#[test]
fn try_enroll_refuses_a_live_id_bound_to_a_different_certificate() {
    let reg = new_registry();
    enroll(&reg, hello(1, 14900)); // cert [1u8; 4]

    // A different certificate claiming the live id is refused, and the
    // refusal leaves everything untouched: the entry, its fingerprint, and
    // the published mesh-peer set.
    let before_peers = mesh_peers(&reg);
    let refused = try_enroll(&reg, hello_with_cert(1, 15000, vec![0xAA; 4]));
    assert_eq!(refused, Err(EnrollConflict));
    assert_eq!(
        live_cert_fingerprint(&reg, RelayId(1)),
        Some(cert_fingerprint(&[1u8; 4])),
        "the refused enroll must not displace the live entry",
    );
    assert_eq!(
        entry(&reg, RelayId(1)).unwrap().relay_addr.port(),
        14900,
        "the refused enroll must not touch the live entry's address",
    );
    assert_eq!(mesh_peers(&reg), before_peers);
}

#[test]
fn try_enroll_replaces_on_the_same_certificate_and_enrolls_fresh_ids() {
    let reg = new_registry();
    let g1 = try_enroll(&reg, hello(1, 14900)).expect("a fresh id enrolls");

    // The same certificate re-enrolling is this relay's own reconnect: it
    // replaces the entry (new address) under a strictly greater generation.
    let g2 = try_enroll(&reg, hello_with_cert(1, 15000, vec![1u8; 4]))
        .expect("the same certificate reconnecting replaces");
    assert!(g2 > g1);
    assert_eq!(entry(&reg, RelayId(1)).unwrap().relay_addr.port(), 15000);
}

#[test]
fn deregistration_shrinks_the_mesh_peer_set() {
    let reg = new_registry();
    let g1 = enroll(&reg, hello(1, 14901));
    enroll(&reg, hello(2, 14902));
    assert_eq!(mesh_peers(&reg).len(), 2);

    // A generation-fenced deregister drops the relay and shrinks the set.
    assert!(remove_if_current(&reg, RelayId(1), g1));
    let peers = mesh_peers(&reg);
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].relay_id, RelayId(2));

    // An unconditional remove shrinks it too.
    remove(&reg, RelayId(2));
    assert!(mesh_peers(&reg).is_empty());
}

#[test]
fn a_repeated_boot_id_is_the_only_thing_that_proves_continuity() {
    let reg = new_registry();
    // A relay id never seen before has no prior process to have lost anything.
    assert_eq!(
        note_boot_id(&reg, RelayId(1), Some(7)),
        BootLineage::Continuous,
    );
    // The same process redialing.
    assert_eq!(
        note_boot_id(&reg, RelayId(1), Some(7)),
        BootLineage::Continuous,
    );
    // A restart: a different process behind the same id.
    assert_eq!(note_boot_id(&reg, RelayId(1), Some(8)), BootLineage::Broken);
    // And the new value is what the next enroll is judged against.
    assert_eq!(
        note_boot_id(&reg, RelayId(1), Some(8)),
        BootLineage::Continuous,
    );
}

#[test]
fn an_absent_boot_id_never_proves_continuity_in_either_direction() {
    // A relay build that predates the field cannot say whether its memory
    // survived, and neither can the coordinator on its behalf — so its every
    // enroll reads as a restart, and an enroll that follows one cannot lean on
    // it either.
    let reg = new_registry();
    assert_eq!(note_boot_id(&reg, RelayId(1), None), BootLineage::Broken);
    assert_eq!(note_boot_id(&reg, RelayId(1), None), BootLineage::Broken);
    assert_eq!(note_boot_id(&reg, RelayId(1), Some(7)), BootLineage::Broken);
    assert_eq!(note_boot_id(&reg, RelayId(1), None), BootLineage::Broken);
}

#[test]
fn boot_id_memory_is_per_relay_and_outlives_deregistration() {
    // The registry entry goes away when a control connection drops; the process
    // identity must not, or every reconnect would read as a first enroll and
    // silently claim a continuity nothing verified.
    let reg = new_registry();
    let generation = enroll(&reg, hello(1, 14901));
    assert_eq!(
        note_boot_id(&reg, RelayId(1), Some(7)),
        BootLineage::Continuous,
    );
    assert_eq!(
        note_boot_id(&reg, RelayId(2), Some(9)),
        BootLineage::Continuous
    );
    assert!(remove_if_current(&reg, RelayId(1), generation));

    assert_eq!(
        note_boot_id(&reg, RelayId(1), Some(7)),
        BootLineage::Continuous,
    );
    assert_eq!(note_boot_id(&reg, RelayId(1), Some(8)), BootLineage::Broken);
    assert_eq!(
        note_boot_id(&reg, RelayId(2), Some(9)),
        BootLineage::Continuous,
        "another relay's memory is untouched",
    );

    // Only a permanently retired id may be forgotten, at which point it reads
    // as one never seen.
    forget_boot_id(&reg, RelayId(1));
    assert_eq!(
        note_boot_id(&reg, RelayId(1), Some(99)),
        BootLineage::Continuous,
    );
    forget_boot_id(&reg, RelayId(1));
}
