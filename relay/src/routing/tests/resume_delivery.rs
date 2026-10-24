//! A returning client's peer cursors bound which recovered turns enter its queue.

use super::*;

fn resumed(
    sessions: &Sessions,
    key: &SessionKey,
    slot: SlotId,
    cursors: &[(SlotId, u64)],
) -> SlotInbox {
    let (mut guard, inbox) = register_with_transport(
        sessions,
        key,
        slot,
        1,
        None,
        &cursors.iter().copied().collect(),
    )
    .expect("the returning slot registers");
    guard.disarm();
    inbox
}

fn forward(sessions: &Sessions, key: &SessionKey, origin: SlotId, seq: u64) {
    fan_out(
        sessions,
        key,
        origin,
        Payload {
            seq,
            slot: u32::from(origin.0),
            ..payload()
        },
    );
}

#[test]
fn confirmed_history_never_spends_a_returning_clients_forward_capacity() {
    let sessions: Sessions = Arc::default();
    let k = key();
    let next_needed = (FORWARD_CAPACITY * 3) as u64;
    let mut inbox = resumed(&sessions, &k, SlotId(1), &[(SlotId(0), next_needed)]);

    // No consumer runs while recovery supplies more history than the queue can hold.
    for seq in 0..next_needed {
        forward(&sessions, &k, SlotId(0), seq);
    }
    assert!(inbox.try_recv_forward().is_none());
    assert_eq!(inbox.close_reason(), SlotCloseReason::Unspecified);

    // The cursor is the first missing turn, not the last confirmed turn.
    forward(&sessions, &k, SlotId(0), next_needed);
    forward(&sessions, &k, SlotId(0), next_needed + 1);
    assert_eq!(inbox.try_recv_forward().unwrap().seq, next_needed);
    assert_eq!(inbox.try_recv_forward().unwrap().seq, next_needed + 1);
    assert!(inbox.try_recv_forward().is_none());
}

#[test]
fn peer_cursors_apply_per_destination_and_per_origin() {
    let sessions: Sessions = Arc::default();
    let k = key();
    let mut first = resumed(&sessions, &k, SlotId(1), &[(SlotId(0), 8), (SlotId(3), 4)]);
    let mut second = resumed(&sessions, &k, SlotId(2), &[(SlotId(0), 5)]);

    forward(&sessions, &k, SlotId(0), 5);
    assert!(first.try_recv_forward().is_none());
    assert_eq!(second.try_recv_forward().unwrap().seq, 5);
    forward(&sessions, &k, SlotId(0), 8);
    assert_eq!(first.try_recv_forward().unwrap().seq, 8);
    assert_eq!(second.try_recv_forward().unwrap().seq, 8);

    forward(&sessions, &k, SlotId(3), 3);
    assert!(first.try_recv_forward().is_none());
    assert_eq!(second.try_recv_forward().unwrap().seq, 3);
    forward(&sessions, &k, SlotId(3), 4);
    assert_eq!(first.try_recv_forward().unwrap().seq, 4);
    assert_eq!(second.try_recv_forward().unwrap().seq, 4);
}

#[test]
fn zero_and_absent_peer_cursors_keep_fresh_delivery() {
    let sessions: Sessions = Arc::default();
    let k = key();
    let mut with_zero = resumed(&sessions, &k, SlotId(1), &[(SlotId(0), 0)]);
    let mut fresh = registered(&sessions, &k, SlotId(2));

    forward(&sessions, &k, SlotId(0), 0);
    assert_eq!(with_zero.try_recv_forward().unwrap().seq, 0);
    assert_eq!(fresh.try_recv_forward().unwrap().seq, 0);
    forward(&sessions, &k, SlotId(3), 0);
    assert_eq!(with_zero.try_recv_forward().unwrap().slot, 3);
    assert_eq!(fresh.try_recv_forward().unwrap().slot, 3);
}

#[test]
fn reregistering_uses_only_the_new_connections_peer_cursors() {
    let sessions: Sessions = Arc::default();
    let k = key();
    let mut old = resumed(&sessions, &k, SlotId(1), &[(SlotId(0), 100)]);
    forward(&sessions, &k, SlotId(0), 10);
    assert!(old.try_recv_forward().is_none());
    deregister(&sessions, &k, SlotId(1));

    let mut current = resumed(&sessions, &k, SlotId(1), &[(SlotId(0), 10)]);
    forward(&sessions, &k, SlotId(0), 9);
    assert!(current.try_recv_forward().is_none());
    forward(&sessions, &k, SlotId(0), 10);
    assert_eq!(current.try_recv_forward().unwrap().seq, 10);
    assert!(old.try_recv_forward().is_none());
}
