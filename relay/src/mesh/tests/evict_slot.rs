//! A peer authority's `EvictSlot`: the relay that strictly homes the named slot
//! marks it evicted and closes its link; every other relay leaves it alone.

use super::*;

use std::time::Duration;

use rally_point_proto::messages::EvictSlot;

use crate::observability::flight_recorder::FlightEvent;

const SUBJECT: SlotId = SlotId(FINALIZE_SUBJECT_SLOT);

fn evict_frame(fixture: &FinalizeFixture) -> MeshControlFrame {
    MeshControlFrame {
        session: fixture.key.session.0,
        kind: Some(mesh_control_frame::Kind::EvictSlot(EvictSlot {
            slot: u32::from(FINALIZE_SUBJECT_SLOT),
            sync_ordinal: 8,
        })),
    }
}

/// The home marks the slot evicted before closing its live link, records
/// the eviction with the verdict's step, and sends nothing back across the
/// mesh while the link is still up: the drop is finalized by the link's own
/// teardown.
#[tokio::test(start_paused = true)]
async fn the_home_evicts_a_named_slot() {
    let fixture = finalize_fixture(
        crate::consensus::Authority::Peer,
        &[FINALIZE_SUBJECT_SLOT],
        PeerDrop::Untouched,
    );
    let (_registration, inbox) =
        routing::register(&fixture.sessions, &fixture.key, SUBJECT, 1).expect("subject registers");
    let shutdown = inbox.shutdown_handle();
    let (_echo_fwd_rx, mut ctl_rx) = register_link_channels(&fixture.mesh.links, &fixture.key);

    fixture.dispatch(evict_frame(&fixture));

    assert_eq!(
        fixture
            .mesh
            .session
            .decision_makers
            .eviction(&fixture.key, SUBJECT),
        Some(crate::consensus::EvictionCause::Desync),
        "the home marks the slot, refusing every later dial for it",
    );
    tokio::time::timeout(Duration::from_secs(60), shutdown.notified())
        .await
        .expect("the home signals the slot's link to close");
    let events: Vec<FlightEvent> = fixture
        .mesh
        .session
        .decision_makers
        .flight_recorder()
        .events(&fixture.key)
        .into_iter()
        .map(|record| record.event)
        .collect();
    assert!(
        events.contains(&FlightEvent::SlotEvictedDesync {
            slot: FINALIZE_SUBJECT_SLOT,
            sync_ordinal: 8,
        }),
        "the home records the eviction: {events:?}",
    );
    assert!(
        ctl_rx.try_recv().is_err(),
        "nothing goes back across the mesh while the link is still up",
    );
}

/// A slot that had already dropped when the order arrived is finalized by its
/// home at once, and the sealed count goes to the authority unasked.
#[test]
fn the_home_finalizes_a_named_slot_that_already_dropped() {
    let fixture = finalize_fixture(
        crate::consensus::Authority::Peer,
        &[FINALIZE_SUBJECT_SLOT],
        PeerDrop::Untouched,
    );
    fixture.mesh.session.decision_makers.record_departure(
        &fixture.key,
        SUBJECT,
        crate::consensus::DepartureStamps {
            last_frame: Some(rally_point_proto::ids::GameFrameCount(40)),
            ..crate::consensus::DepartureStamps::default()
        },
        crate::consensus::LEAVE_REASON_DROPPED,
    );
    for seq in 0..3 {
        let _ = mark_seen(&fixture.mesh.seen, &fixture.key, SUBJECT, seq);
    }
    let (_echo_fwd_rx, mut ctl_rx) = register_link_channels(&fixture.mesh.links, &fixture.key);

    fixture.dispatch(evict_frame(&fixture));

    let frame = ctl_rx.try_recv().expect("the home sends its result");
    match frame.kind {
        Some(mesh_control_frame::Kind::FinalizeDropResult(result)) => {
            assert_eq!(result.slot, u32::from(FINALIZE_SUBJECT_SLOT));
            assert_eq!(result.outcome, FINALIZE_OUTCOME_FINALIZED);
            assert_eq!(result.final_turn_count, Some(3));
        }
        other => panic!("expected a FinalizeDropResult, got {other:?}"),
    }
}

/// A relay that does not strictly home the slot neither marks nor closes it,
/// and does not re-broadcast the order.
#[tokio::test(start_paused = true)]
async fn a_relay_that_does_not_home_the_slot_ignores_the_order() {
    let fixture = finalize_fixture(crate::consensus::Authority::Peer, &[0], PeerDrop::Untouched);
    let (_registration, inbox) =
        routing::register(&fixture.sessions, &fixture.key, SUBJECT, 1).expect("subject registers");
    let shutdown = inbox.shutdown_handle();
    let (_echo_fwd_rx, mut ctl_rx) = register_link_channels(&fixture.mesh.links, &fixture.key);

    fixture.dispatch(evict_frame(&fixture));

    assert_eq!(
        fixture
            .mesh
            .session
            .decision_makers
            .eviction(&fixture.key, SUBJECT),
        None,
    );
    // With the clock paused nothing else is pending, so the timeout resolves
    // without real time passing, and a close signalled by the dispatch would
    // have left its permit behind for this wait to take.
    assert!(
        tokio::time::timeout(Duration::from_secs(60), shutdown.notified())
            .await
            .is_err(),
        "a relay that does not home the slot never closes a link for it",
    );
    assert!(ctl_rx.try_recv().is_err(), "the order is not re-broadcast");
}
