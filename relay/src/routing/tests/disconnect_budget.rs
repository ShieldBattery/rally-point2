//! Disconnect-budget enforcement at the drop and reconnect boundaries.

use super::*;
use crate::consensus::ReconnectAdmission;
use crate::session::disconnect_budget::{DISCONNECT_ALLOWANCE, EpisodeSnapshot};
use std::time::Instant;

fn seed_budget(mesh: &crate::mesh::MeshState, key: &SessionKey, elapsed: Duration) {
    mesh.session.disconnect_budgets.configure_session(
        key,
        false,
        &[SlotId(0), SlotId(1)],
        &[SlotId(0), SlotId(1)],
        &[],
    );
    mesh.session.disconnect_budgets.merge(
        key,
        &[EpisodeSnapshot {
            slot: SlotId(1),
            connection_epoch: 7,
            elapsed,
            complete: false,
        }],
        Instant::now(),
    );
}

fn hold_target(h: &DropHarness, holds: &DropHolds, key: &SessionKey) {
    hold_or_decide_leave(
        holds,
        &h.makers,
        &h.sessions,
        &h.mesh_links,
        key,
        SlotId(1),
        LEAVE_REASON_DROPPED,
    );
}

#[tokio::test(start_paused = true)]
async fn exhausted_budget_stays_held_and_reconnects_without_a_drop_request() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0, 1]));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let mesh = h.mesh(&holds);
    hold_target(&h, &holds, &k);
    seed_budget(&mesh, &k, DISCONNECT_ALLOWANCE);
    let watch =
        tokio::spawn(super::super::disconnect_budget::run_disconnect_budget_watch(mesh.clone()));
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(h.inbox.try_recv_leave().is_none());
    assert!(holds.is_pending(&k, SlotId(1)));
    assert!(matches!(
        mesh.session.admit_reconnect(&k, SlotId(1), Some(8)),
        ReconnectAdmission::Admitted { .. }
    ));
    assert!(!holds.is_pending(&k, SlotId(1)));
    assert!(
        mesh.session
            .disconnect_budgets
            .exhausted(&k, SlotId(1), Instant::now())
    );
    watch.abort();
}

#[tokio::test]
async fn manual_drop_at_zero_finalizes_and_rejects_reconnect() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0, 1]));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let mesh = h.mesh(&holds);
    hold_target(&h, &holds, &k);
    for seq in 0..3 {
        let _ = crate::mesh::mark_seen(&h.seen, &k, SlotId(1), seq);
    }
    seed_budget(&mesh, &k, DISCONNECT_ALLOWANCE);
    honor_drop_request(&h.sessions, &mesh, &k, SlotId(1), 0);
    let leave = h
        .inbox
        .try_recv_leave()
        .expect("manual drop reaches survivor");
    assert_eq!(leave.reason, LEAVE_REASON_DROPPED);
    assert!(leave.finalized);
    assert_eq!(leave.final_turn_count, Some(3));
    assert!(!holds.is_pending(&k, SlotId(1)));
    assert!(matches!(
        mesh.session.admit_reconnect(&k, SlotId(1), Some(8)),
        ReconnectAdmission::Rejected
    ));
}

#[tokio::test]
async fn unexhausted_budget_does_not_bypass_manual_drop_floor() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0, 1]));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let mesh = h.mesh(&holds);
    hold_target(&h, &holds, &k);
    for seq in 0..3 {
        let _ = crate::mesh::mark_seen(&h.seen, &k, SlotId(1), seq);
    }
    seed_budget(&mesh, &k, Duration::from_secs(30));

    honor_drop_request(&h.sessions, &mesh, &k, SlotId(1), 0);
    assert!(h.inbox.try_recv_leave().is_none());
    assert!(holds.is_pending(&k, SlotId(1)));
}

#[tokio::test]
async fn exhausted_budget_without_a_cursor_still_requires_finalization_proof() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0, 1]));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let mesh = h.mesh(&holds);
    hold_target(&h, &holds, &k);
    seed_budget(&mesh, &k, DISCONNECT_ALLOWANCE);

    honor_drop_request(&h.sessions, &mesh, &k, SlotId(1), 0);
    assert!(h.inbox.try_recv_leave().is_none());
    assert!(holds.is_pending(&k, SlotId(1)));
}

#[tokio::test]
async fn emptied_session_keeps_budget_until_retirement() {
    let k = key();
    let h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0, 1]));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let mesh = h.mesh(&holds);
    seed_budget(&mesh, &k, DISCONNECT_ALLOWANCE);

    mesh.session.close_emptied(&k, &mesh.seen);
    assert!(
        mesh.session
            .disconnect_budgets
            .exhausted(&k, SlotId(1), Instant::now())
    );
    mesh.session.retire(&k, &mesh.seen);
    assert!(
        mesh.session
            .disconnect_budgets
            .snapshot(&k, Instant::now())
            .is_empty()
    );
}

#[tokio::test]
async fn a_peer_accepts_the_homes_reconnect_even_if_its_projection_has_expired() {
    let k = key();
    let h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0, 1]));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let mesh = h.mesh(&holds);
    hold_target(&h, &holds, &k);
    seed_budget(&mesh, &k, DISCONNECT_ALLOWANCE);
    assert!(matches!(
        mesh.session.observe_reconnect(&k, SlotId(1), Some(8)),
        ReconnectAdmission::Admitted { .. }
    ));
    assert!(!holds.is_pending(&k, SlotId(1)));
}
