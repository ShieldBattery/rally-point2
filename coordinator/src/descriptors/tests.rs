use super::*;
use crate::test_support::{addr, fake_cert};
use rally_point_proto::control::RelayPeer;

/// A descriptor for `(tenant, session)` naming `peers` as its mesh peers, each
/// at a loopback address with its id-derived certificate. Every other field is
/// the shared builder's empty default — these tests read back only the key and
/// the peer list.
fn descriptor(tenant: &str, session: u64, peers: &[u64]) -> SessionDescriptor {
    SessionDescriptor {
        peers: peers
            .iter()
            .map(|&id| RelayPeer {
                relay_id: RelayId(id),
                relay_addr: addr(14900 + id as u16),
                cert_der: fake_cert(id),
                relay_addrs: vec![],
            })
            .collect(),
        ..crate::test_support::descriptor(TenantId(tenant.to_owned()), session)
    }
}

#[test]
fn records_and_reads_back_per_relay() {
    let outbox = RelayDescriptors::new();
    outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
    outbox.record(RelayId(2), descriptor("sb-test", 1, &[1]));

    let for_1 = outbox.current_for(RelayId(1));
    assert_eq!(for_1.len(), 1);
    assert_eq!(for_1[0].peers[0].relay_id, RelayId(2));

    let for_2 = outbox.current_for(RelayId(2));
    assert_eq!(for_2.len(), 1);
    assert_eq!(for_2[0].peers[0].relay_id, RelayId(1));
    assert_eq!(
        outbox.current_keys_for(RelayId(1)),
        vec![DescriptorKey {
            tenant: TenantId("sb-test".to_owned()),
            session: SessionId(1),
        }],
    );

    // A relay the coordinator never recorded for reads as an empty set rather
    // than a missing channel, on both read paths.
    assert!(outbox.current_for(RelayId(99)).is_empty());
    assert!(outbox.current_keys_for(RelayId(99)).is_empty());
}

#[test]
fn recording_same_session_replaces_rather_than_accumulates() {
    let outbox = RelayDescriptors::new();
    outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
    // The session's topology changes: peer 3 replaces peer 2.
    outbox.record(RelayId(1), descriptor("sb-test", 1, &[3]));

    let set = outbox.current_for(RelayId(1));
    assert_eq!(set.len(), 1, "same (relay, session) overwrites");
    assert_eq!(set[0].peers[0].relay_id, RelayId(3));
}

#[test]
fn distinct_sessions_for_one_relay_coexist() {
    // One relay serving several sessions keeps one entry per (tenant, session)
    // key — a session id reused across tenants is two entries, not a collision —
    // and the set comes out in a stable (session, tenant) order whatever order
    // the records arrived in.
    let outbox = RelayDescriptors::new();
    outbox.record(RelayId(1), descriptor("tenant-a", 2, &[2]));
    outbox.record(RelayId(1), descriptor("tenant-b", 1, &[2]));
    outbox.record(RelayId(1), descriptor("tenant-a", 1, &[2]));

    let set = outbox.current_for(RelayId(1));
    assert_eq!(
        set.len(),
        3,
        "the (tenant, session) key keeps them distinct"
    );
    let keys: Vec<(&str, u64)> = set
        .iter()
        .map(|d| (d.tenant.as_ref(), d.session.0))
        .collect();
    assert_eq!(
        keys,
        vec![("tenant-a", 1), ("tenant-b", 1), ("tenant-a", 2)],
        "sorted by session id, then tenant",
    );
}

#[test]
fn remove_drops_one_session_and_leaves_the_rest() {
    let outbox = RelayDescriptors::new();
    outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
    outbox.record(RelayId(1), descriptor("sb-test", 2, &[2]));

    outbox.remove(RelayId(1), &TenantId("sb-test".to_owned()), SessionId(1));
    let set = outbox.current_for(RelayId(1));
    assert_eq!(set.len(), 1);
    assert_eq!(set[0].session, SessionId(2));

    // Removing the last session leaves the set empty.
    outbox.remove(RelayId(1), &TenantId("sb-test".to_owned()), SessionId(2));
    assert!(outbox.current_for(RelayId(1)).is_empty());
}

#[test]
fn remove_on_unknown_relay_or_session_is_a_no_op() {
    let outbox = RelayDescriptors::new();
    outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
    outbox.remove(RelayId(9), &TenantId("sb-test".to_owned()), SessionId(1));
    outbox.remove(RelayId(1), &TenantId("sb-test".to_owned()), SessionId(9));
    assert_eq!(outbox.current_for(RelayId(1)).len(), 1);
}

#[test]
fn forget_drops_the_relays_whole_channel() {
    let outbox = RelayDescriptors::new();
    outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
    outbox.record(RelayId(2), descriptor("sb-test", 2, &[1]));
    assert_eq!(outbox.relay_count(), 2);

    outbox.forget(RelayId(1));
    assert_eq!(
        outbox.relay_count(),
        1,
        "the forgotten relay's shell is gone, not just emptied"
    );
    assert!(outbox.current_for(RelayId(1)).is_empty());
    // The other relay's channel is untouched.
    assert_eq!(outbox.current_for(RelayId(2)).len(), 1);

    // Forgetting an id with no channel is idempotent, not a resurrection.
    outbox.forget(RelayId(9));
    assert_eq!(outbox.relay_count(), 1);
}

#[test]
fn a_subscriber_is_woken_on_record_and_sees_the_current_set() {
    let outbox = RelayDescriptors::new();
    let mut rx = outbox.subscribe(RelayId(1));
    // Subscribing creates the channel; its initial value is the (empty) set.
    assert!(rx.borrow_and_update().is_empty());

    // A record marks the channel changed, so the connection task wakes.
    outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
    assert!(rx.has_changed().unwrap());
    let set = rx.borrow_and_update().clone();
    assert_eq!(set.len(), 1);
    assert_eq!(set[0].session, SessionId(1));
}

#[test]
fn an_identical_re_record_does_not_wake_the_subscriber() {
    let outbox = RelayDescriptors::new();
    outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
    let mut rx = outbox.subscribe(RelayId(1));
    rx.borrow_and_update(); // mark current as seen

    // Re-recording the identical descriptor changes nothing — no wake.
    outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
    assert!(
        !rx.has_changed().unwrap(),
        "an unchanged set must not wake the relay"
    );
}

fn slot_close(tenant: &str, session: u64, slots: &[u8]) -> SlotClose {
    SlotClose {
        tenant: TenantId(tenant.to_owned()),
        session: SessionId(session),
        slots: slots.iter().map(|&s| SlotId(s)).collect(),
    }
}

#[test]
fn a_reap_armed_while_disconnected_is_delivered_on_the_next_subscribe() {
    // A directive sent while the relay has no live control connection is not
    // lost — it stays pending and rides the next subscribe.
    let reaps = RelayReaps::new();
    reaps.send(RelayId(1), slot_close("sb-test", 1, &[3]));

    let mut rx = reaps.subscribe(RelayId(1));
    let close = rx
        .try_recv()
        .expect("the pending directive re-syncs on connect");
    assert_eq!(close.session, SessionId(1));
    assert_eq!(close.slots, vec![SlotId(3)]);
}

#[test]
fn a_reap_sent_while_connected_is_delivered_and_also_replayed_on_resubscribe() {
    // A connected relay gets the directive immediately; because re-delivery is
    // idempotent, a reconnect (fresh subscribe) is re-synced with it too, until
    // the session retires.
    let reaps = RelayReaps::new();
    let mut rx = reaps.subscribe(RelayId(1));
    reaps.send(RelayId(1), slot_close("sb-test", 1, &[2]));
    let live = rx
        .try_recv()
        .expect("a connected relay is nudged immediately");
    assert_eq!(live.slots, vec![SlotId(2)]);

    // A reconnect re-subscribes and is primed with the still-pending directive.
    let mut rx2 = reaps.subscribe(RelayId(1));
    let replayed = rx2
        .try_recv()
        .expect("the pending directive replays on reconnect");
    assert_eq!(replayed.session, SessionId(1));
    assert_eq!(replayed.slots, vec![SlotId(2)]);
    // The replaced subscription's channel is closed.
    assert!(rx.try_recv().is_err());
}

#[test]
fn retiring_a_session_leaves_another_relays_pending_for_it_only_by_key() {
    // Retire fans across every relay: a session retired removes its pending
    // entry from all relays that held one, not just one — and spares the other
    // sessions those relays still have pending, slots and all.
    let reaps = RelayReaps::new();
    reaps.send(RelayId(1), slot_close("sb-test", 1, &[0]));
    reaps.send(RelayId(2), slot_close("sb-test", 1, &[0]));
    reaps.send(RelayId(2), slot_close("sb-test", 3, &[1, 4]));

    reaps.retire(&TenantId("sb-test".to_owned()), SessionId(1));

    assert!(
        reaps.subscribe(RelayId(1)).try_recv().is_err(),
        "relay 1's only (retired) directive is gone",
    );
    let mut rx2 = reaps.subscribe(RelayId(2));
    let close = rx2.try_recv().expect("relay 2 still has session 3 pending");
    assert_eq!(close.session, SessionId(3));
    assert_eq!(
        close.slots,
        vec![SlotId(1), SlotId(4)],
        "the surviving session replays with its slots intact",
    );
    assert!(
        rx2.try_recv().is_err(),
        "session 1 was retired for relay 2 too"
    );
}

#[test]
fn forget_drops_the_relays_whole_entry() {
    let reaps = RelayReaps::new();
    reaps.send(RelayId(1), slot_close("sb-test", 1, &[0]));
    reaps.send(RelayId(2), slot_close("sb-test", 1, &[0]));
    assert_eq!(reaps.relay_count(), 2);

    // Forgetting an id with no entry is idempotent, not a resurrection.
    reaps.forget(RelayId(9));
    assert_eq!(reaps.relay_count(), 2);

    reaps.forget(RelayId(1));
    assert_eq!(
        reaps.relay_count(),
        1,
        "the forgotten relay's shell is gone, not just emptied"
    );
    assert!(
        reaps.subscribe(RelayId(1)).try_recv().is_err(),
        "a forgotten relay's pending directive does not replay",
    );
    // The other relay's pending directive is untouched.
    let close = reaps
        .subscribe(RelayId(2))
        .try_recv()
        .expect("relay 2's directive survives");
    assert_eq!(close.session, SessionId(1));
}

#[test]
fn repeats_for_one_session_union_their_slots() {
    // Two directives for the same session merge into one pending entry whose
    // slots are the union — repeats don't accumulate separate entries.
    let reaps = RelayReaps::new();
    reaps.send(RelayId(1), slot_close("sb-test", 1, &[2]));
    reaps.send(RelayId(1), slot_close("sb-test", 1, &[5, 2]));

    let mut rx = reaps.subscribe(RelayId(1));
    let close = rx.try_recv().expect("the single merged directive replays");
    assert_eq!(close.session, SessionId(1));
    assert_eq!(
        close.slots,
        vec![SlotId(2), SlotId(5)],
        "slots union, the duplicate is not re-added",
    );
    assert!(
        rx.try_recv().is_err(),
        "one entry per session, not one per send"
    );
}

#[test]
fn a_disconnected_sender_is_cleared_so_a_send_does_not_wedge() {
    // Dropping the receiver (the connection ended) makes the next send's nudge
    // fail; the stale sender is cleared and the directive stays pending for the
    // next subscribe rather than being silently swallowed by a dead channel.
    let reaps = RelayReaps::new();
    let rx = reaps.subscribe(RelayId(1));
    drop(rx); // the control connection ended without a re-subscribe

    reaps.send(RelayId(1), slot_close("sb-test", 1, &[7]));
    let mut rx2 = reaps.subscribe(RelayId(1));
    let close = rx2
        .try_recv()
        .expect("the directive survived the dead connection and replays");
    assert_eq!(close.slots, vec![SlotId(7)]);
}
