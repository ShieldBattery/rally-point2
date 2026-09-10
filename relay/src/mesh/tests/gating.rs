//! The provisional-turn journal's overflow and the retirement gate's
//! treatment of client and mesh turns for a session that has ended.

use super::*;

/// Journal overflow closes the overflowing slot's link — the overflowed
/// turn is transport-acknowledged and unrecoverable, so the offender
/// fails closed while the rest of the session's journal is untouched.
#[tokio::test]
async fn journal_overflow_closes_the_overflowing_slots_link() {
    let sessions = routing::Sessions::default();
    let key = control_key();
    let mesh_state = new_mesh_state();
    mesh_state.provisional_turns.arm();
    let (_reg, inbox) =
        routing::register(&sessions, &key, SlotId(1), 1).expect("the flooder registers");
    let shutdown = inbox.shutdown_handle();

    for seq in 0..=(crate::session::provisional_turns::PER_SESSION_CAP as u64) {
        forward_client_turn(
            &sessions,
            &mesh_state,
            &key,
            SlotId(1),
            Payload {
                seq,
                slot: 1,
                commands: vec![0x05].into(),
                ..Default::default()
            },
        );
    }
    tokio::time::timeout(std::time::Duration::from_millis(100), shutdown.notified())
        .await
        .expect("the overflowing slot's link is signaled closed");
    assert_eq!(
        mesh_state.provisional_turns.held(&key),
        crate::session::provisional_turns::PER_SESSION_CAP,
        "the journal keeps everything below the cap",
    );
    assert!(
        mesh_state.provisional_turns.slot_sealed(&key, SlotId(1)),
        "overflow seals the slot terminally — an ordinary reconnect would \
         resume past the permanent hole",
    );
}

/// A retired session's client turn is refused by the gate BEFORE the
/// provisional journal too — retirement discards the journal, so a
/// still-live link must not recreate entries for the ended session.
#[test]
fn a_retired_sessions_client_turn_never_grows_the_journal() {
    let sessions = routing::Sessions::default();
    let key = control_key();
    let mesh_state = new_mesh_state();
    mesh_state.provisional_turns.arm();
    mesh_state.gates.retire(&key);
    forward_client_turn(
        &sessions,
        &mesh_state,
        &key,
        SlotId(0),
        Payload {
            seq: 0,
            slot: 0,
            commands: vec![0x05].into(),
            ..Default::default()
        },
    );
    assert_eq!(
        mesh_state.provisional_turns.held(&key),
        0,
        "the gate refuses before the journal deposit",
    );
}

/// A retired session's mesh turn is dropped by the ingress gate before it
/// can touch per-session state — the datagram counterpart of the
/// mesh-control dispatch fence.
#[test]
fn a_retired_sessions_mesh_turn_is_dropped_by_the_gate() {
    let sessions = routing::Sessions::default();
    let key = control_key();
    let mesh_state = new_mesh_state();
    let (_reg, mut survivor) =
        routing::register(&sessions, &key, SlotId(1), 1).expect("survivor registers");

    mesh_state.gates.retire(&key);
    deliver_mesh_turn(
        &sessions,
        &mesh_state,
        &key,
        SlotId(0),
        Payload {
            seq: 3,
            slot: 0,
            commands: vec![0x05].into(),
            ..Default::default()
        },
        RelayId(2),
    );
    assert!(
        survivor.try_recv_forward().is_none(),
        "a retired session's mesh turn is dropped",
    );
    assert_eq!(
        mark_seen(&mesh_state.seen, &key, SlotId(0), 3).seen,
        Seen::New,
        "the dropped turn never touched the session-level gate",
    );
}
