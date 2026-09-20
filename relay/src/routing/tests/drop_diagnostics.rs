//! Rejected requests share a diagnostics budget without spending admission
//! tokens or evicting history at control-stream input rates.

use super::*;
use crate::observability::events::{
    DropRequestRefusalReason, DropRequestRejectionReason, FlightEvent,
};
use crate::observability::flight_recorder::MAX_EVENTS_PER_SESSION;
use rally_point_proto::messages::mesh_control_frame;

#[tokio::test]
async fn every_edge_rejection_is_sampled_with_its_original_reason_and_never_fanned_out() {
    for (target, reason) in [
        (u32::MAX, DropRequestRejectionReason::OutOfRange),
        (0, DropRequestRejectionReason::SelfTarget),
        (2, DropRequestRejectionReason::NotDisconnected),
        (1, DropRequestRejectionReason::RateCapped),
    ] {
        let k = key();
        let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), None);
        let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK)
            .with_request_rate(2, UNREACHABLE_UNLOCK);
        drop_slot(&h.makers, &holds, &k, SlotId(1));
        if reason == DropRequestRejectionReason::RateCapped {
            assert!(holds.admit_request(&k, SlotId(0)));
            assert!(holds.admit_request(&k, SlotId(0)));
        }
        let mesh = h.mesh(&holds);
        let (forward_tx, _forward_rx) = mpsc::channel(1);
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        let _registration = crate::mesh::register_mesh_link(
            &h.mesh_links,
            k.clone(),
            forward_tx,
            control_tx,
            Arc::new(Notify::new()),
        );
        let recorder = h.makers.flight_recorder();
        let sentinel = FlightEvent::SlotConnected {
            slot: 0,
            resumed: false,
        };
        recorder.record(&k, sentinel.clone());
        let before = recorder.events(&k).len();
        for _ in 0..(MAX_EVENTS_PER_SESSION * 2) {
            handle_drop_request(&h.sessions, &mesh, &k, SlotId(0), target);
        }
        let events: Vec<_> = recorder.events(&k).into_iter().map(|r| r.event).collect();
        assert_eq!(
            events.len(),
            before + 2,
            "only the diagnostic burst is recorded: {reason:?}"
        );
        assert!(
            events.contains(&sentinel),
            "the session's history survived the flood"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| **event
                    == FlightEvent::DropRequestRejected {
                        requester: 0,
                        target,
                        reason,
                    })
                .count(),
            2
        );
        assert!(
            control_rx.try_recv().is_err(),
            "rejected requests never reach the mesh"
        );
        assert!(h.inbox.try_recv_leave().is_none());
        assert!(holds.is_pending(&k, SlotId(1)));
    }
}

#[tokio::test]
async fn cycling_invalid_targets_and_reasons_shares_one_budget_without_spending_drop_admissions() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), None);
    let holds = DropHolds::new(IMMEDIATE_UNLOCK, UNREACHABLE_UNLOCK)
        .with_request_rate(2, UNREACHABLE_UNLOCK);
    drop_slot(&h.makers, &holds, &k, SlotId(1));
    let mesh = h.mesh(&holds);
    for i in 0..(MAX_EVENTS_PER_SESSION * 2) {
        let target = match i % 3 {
            0 => 0,
            1 => 2 + (i % 254) as u32,
            _ => 256 + i as u32,
        };
        handle_drop_request(&h.sessions, &mesh, &k, SlotId(0), target);
    }
    let recorder = h.makers.flight_recorder();
    assert_eq!(
        recorder
            .events(&k)
            .iter()
            .filter(|r| matches!(r.event, FlightEvent::DropRequestRejected { .. }))
            .count(),
        2
    );
    assert!(h.inbox.try_recv_leave().is_none());

    // Invalid requests never charged the admission bucket. A real request still
    // decides the held drop and is recorded even with diagnostics exhausted.
    handle_drop_request(&h.sessions, &mesh, &k, SlotId(0), 1);
    assert_eq!(
        h.inbox.try_recv_leave().unwrap().reason,
        LEAVE_REASON_DROPPED
    );
    assert!(!holds.is_pending(&k, SlotId(1)));
    assert!(recorder.events(&k).iter().any(|r| r.event
        == FlightEvent::DropRequested {
            requester: 0,
            target: 1,
        }));
    assert!(
        holds.admit_request(&k, SlotId(0)),
        "the second admission token also survived"
    );
    assert!(!holds.admit_request(&k, SlotId(0)));
}

#[tokio::test]
async fn admitted_requests_keep_their_mesh_rate_cap_and_leave_a_rate_rejection_breadcrumb() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), None);
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK)
        .with_request_rate(2, UNREACHABLE_UNLOCK);
    drop_slot(&h.makers, &holds, &k, SlotId(1));
    let mesh = h.mesh(&holds);
    let (forward_tx, _forward_rx) = mpsc::channel(1);
    let (control_tx, mut control_rx) = mpsc::unbounded_channel();
    let _registration = crate::mesh::register_mesh_link(
        &h.mesh_links,
        k.clone(),
        forward_tx,
        control_tx,
        Arc::new(Notify::new()),
    );
    for _ in 0..10 {
        handle_drop_request(&h.sessions, &mesh, &k, SlotId(0), 1);
    }
    for _ in 0..2 {
        assert!(matches!(control_rx.try_recv().unwrap().kind,
            Some(mesh_control_frame::Kind::RequestDrop(request))
                if request.slot == 1 && request.requester == 0
        ));
    }
    assert!(control_rx.try_recv().is_err());
    assert!(h.inbox.try_recv_leave().is_none());
    assert!(holds.is_pending(&k, SlotId(1)));
    let events = h.makers.flight_recorder().events(&k);
    assert_eq!(
        events
            .iter()
            .filter(|r| matches!(r.event, FlightEvent::DropRequested { .. }))
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|r| r.event
                == FlightEvent::DropRequestRejected {
                    requester: 0,
                    target: 1,
                    reason: DropRequestRejectionReason::RateCapped,
                })
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|r| matches!(
                r.event,
                FlightEvent::DropRequestRefused {
                    requester: 0,
                    target: 1,
                    held_ms: Some(_),
                    reason: DropRequestRefusalReason::BelowFloor,
                }
            ))
            .count(),
        2,
        "admitted requests still record the authority's refusal"
    );
}
