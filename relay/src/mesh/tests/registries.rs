//! The conditions registry's publish/snapshot/unpublish epoch contract, and
//! the batch session-id collision guard.

use super::*;

#[test]
fn conditions_registry_snapshot_unpublish_contract() {
    // snapshot returns slots sorted by slot id (deterministic diff order),
    // None when the session has no published conditions. unpublish removes
    // a slot, and when the last slot leaves, the session's entry is gone
    // (no stale empty key lingering). Covers the registry's own contract
    // independent of the transport round-trip tests.
    let registry = new_conditions_registry();
    let key = SessionKey {
        tenant: rally_point_proto::control::TenantId("t".to_owned()),
        session: rally_point_proto::ids::SessionId(1),
    };

    // No local clients yet: no conditions.
    assert!(snapshot_conditions(&registry, &key).is_none());

    // Activate two slots out of order; snapshot sorts them by slot.
    activate_conditions(
        &registry,
        &key,
        SlotId(1),
        SlotConditions {
            slot: 1,
            rtt_us: 45_000,
            lost_packets: 10,
            sent_packets: 500,
            connection_epoch: None,
        },
    );
    activate_conditions(
        &registry,
        &key,
        SlotId(0),
        SlotConditions {
            slot: 0,
            rtt_us: 12_000,
            lost_packets: 3,
            sent_packets: 1000,
            connection_epoch: None,
        },
    );

    let snap = snapshot_conditions(&registry, &key).expect("two slots published");
    assert_eq!(snap.slots.len(), 2);
    assert_eq!(snap.slots[0].slot, 0, "sorted by slot");
    assert_eq!(snap.slots[1].slot, 1, "sorted by slot");

    // Unpublish one: snapshot now has a single slot.
    unpublish_conditions(&registry, &key, SlotId(0), None);
    let snap = snapshot_conditions(&registry, &key).expect("one slot remains");
    assert_eq!(snap.slots.len(), 1);
    assert_eq!(snap.slots[0].slot, 1);

    // Unpublish the last: snapshot is None again, and the session's entry
    // was removed (re-publishing a fresh slot starts clean, not appended).
    unpublish_conditions(&registry, &key, SlotId(1), None);
    assert!(snapshot_conditions(&registry, &key).is_none());
}

#[test]
fn old_connection_cannot_publish_over_or_unpublish_its_replacement() {
    let registry = new_conditions_registry();
    let key = control_key();
    let sample = |epoch, rtt_us| SlotConditions {
        slot: 0,
        rtt_us,
        lost_packets: 0,
        sent_packets: 1,
        connection_epoch: Some(epoch),
    };

    activate_conditions(&registry, &key, SlotId(0), sample(11, 70_000));
    activate_conditions(&registry, &key, SlotId(0), sample(22, 30_000));

    assert!(!publish_conditions(
        &registry,
        &key,
        SlotId(0),
        sample(11, 900_000),
    ));
    assert!(!unpublish_conditions(&registry, &key, SlotId(0), Some(11),));
    let current = snapshot_conditions(&registry, &key).expect("replacement stays published");
    assert_eq!(current.slots[0].connection_epoch, Some(22));
    assert_eq!(current.slots[0].rtt_us, 30_000);

    assert!(unpublish_conditions(&registry, &key, SlotId(0), Some(22),));
    assert!(snapshot_conditions(&registry, &key).is_none());
    assert!(
        !publish_conditions(&registry, &key, SlotId(0), sample(22, 40_000)),
        "only activation may recreate an unpublished slot",
    );
}

#[test]
fn join_sessions_refuses_a_colliding_session_id_across_tenants() {
    // The wire carries a bare session id with no tenant. Two tenants that
    // both assigned session id 1 can't be told apart on recv, so the second
    // join is refused rather than overwriting the first.
    let links = new_mesh_links();
    let tenant_a = rally_point_proto::control::TenantId("tenant-a".to_owned());
    let tenant_b = rally_point_proto::control::TenantId("tenant-b".to_owned());
    let key_a = SessionKey {
        tenant: tenant_a.clone(),
        session: rally_point_proto::ids::SessionId(1),
    };
    let key_b = SessionKey {
        tenant: tenant_b.clone(),
        session: rally_point_proto::ids::SessionId(1),
    };

    // Same tenant, same session id: not a collision (the game rejoins).
    join_sessions(&links, std::slice::from_ref(&key_a)).expect("same tenant is fine");

    // Different tenant, same session id: collision — refuse.
    let err = join_sessions(&links, &[key_a.clone(), key_b]).unwrap_err();
    assert_eq!(err.session, rally_point_proto::ids::SessionId(1));
    assert_eq!(err.existing_tenant, tenant_a);
    assert_eq!(err.new_tenant, tenant_b);
}
