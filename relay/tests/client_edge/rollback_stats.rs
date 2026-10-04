//! A rollback client's statistics reports end to end: kept for the slot whose
//! link sent them, within a rate and size limit that drops rather than closes,
//! and recorded once more as the link ends.

use crate::helpers::*;
use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::RollbackStats;
use rally_point_relay::consensus::{Authority, DecisionMakers, MakerSync};
use rally_point_relay::key::SessionKey;
use rally_point_relay::observability::flight_recorder::FlightEvent;
use rally_point_transport::control::{
    send_control_game_started, send_control_leave_intent, send_control_rollback_stats,
};

/// A session over slots 0 and 1, both homed on a relay that is its authority,
/// rolling back as `rollback` says.
fn relay_for(session: SessionId, rollback: bool) -> (TestRelay, SessionKey, Tenant) {
    let tenant = make_default_tenant();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let mesh = rally_point_relay::mesh::MeshState::default();
    let _ = mesh.session.decision_makers.sync_maker(
        &key,
        MakerSync {
            expected_slots: [SlotId(0), SlotId(1)].into(),
            homed_slots: [SlotId(0), SlotId(1)].into(),
            rollback,
            ..MakerSync::new(BufferBounds::new(0, 20).unwrap(), Authority::SelfRelay)
        },
    );
    let relay = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    (relay, key, tenant)
}

fn stats(through_turn: u32) -> RollbackStats {
    RollbackStats {
        version: 1,
        through_turn,
        rollback_histogram: vec![10, 5, 1],
        pipe_histogram: vec![0, 16],
        ..Default::default()
    }
}

/// The turn the slot's stored statistics run through, if it has any.
fn stored(makers: &DecisionMakers, key: &SessionKey, slot: u8) -> Option<u32> {
    makers
        .flight_recorder()
        .slot_counters(key, SlotId(slot))
        .rollback_stats()
        .map(|stats| stats.through_turn)
}

/// Waits until the relay has handled every control frame written before a
/// game-started report, which it records when it reaches it: the stream is
/// processed in order.
async fn wait_past_game_started(makers: &DecisionMakers, key: &SessionKey) {
    wait_until("the relay never reached the game-started report", || {
        makers
            .flight_recorder()
            .events(key)
            .iter()
            .any(|record| matches!(record.event, FlightEvent::SlotGameStarted { slot: 0 }))
    })
    .await;
}

#[tokio::test]
async fn reports_are_kept_for_their_own_slot_within_the_limits_and_recorded_at_the_end() {
    let session = SessionId(350);
    let (relay, key, tenant) = relay_for(session, true);
    let makers = relay.mesh.session.decision_makers.clone();
    let endpoint = client_endpoint(&relay.ca);
    let mut slot0 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(1)).await;
    wait_for_slots(&relay.sessions, &key, 2).await;
    let (mut control, _unused_recv) = slot0.connection().open_bi().await.unwrap();

    // A histogram past the cap is dropped without spending the rate limit, then
    // two reports in quick succession (a periodic one and the game-end one) are
    // both kept, and a third inside the same window is dropped.
    send_control_rollback_stats(
        &mut control,
        RollbackStats {
            through_turn: 1,
            pipe_histogram: vec![1; 65],
            ..stats(1)
        },
    )
    .await
    .unwrap();
    for through_turn in [720, 1_000, 1_001] {
        send_control_rollback_stats(&mut control, stats(through_turn))
            .await
            .unwrap();
    }
    send_control_game_started(&mut control).await.unwrap();
    wait_past_game_started(&makers, &key).await;
    assert_eq!(
        stored(&makers, &key, 0),
        Some(1_000),
        "the oversize report and the one over the rate limit are dropped",
    );
    assert_eq!(
        stored(&makers, &key, 1),
        None,
        "a report belongs to the slot whose link sent it",
    );
    assert!(
        slot1.connection().close_reason().is_none() && slot0.connection().close_reason().is_none(),
        "a dropped report closes nothing",
    );

    // The link ends: its last kept report is recorded once, just ahead of the
    // disconnect.
    send_control_leave_intent(&mut control).await.unwrap();
    expect_closed(&mut slot0).await;
    wait_until("the disconnect was never recorded", || {
        makers
            .flight_recorder()
            .events(&key)
            .iter()
            .any(|record| matches!(record.event, FlightEvent::SlotDisconnected { slot: 0 }))
    })
    .await;
    let events: Vec<FlightEvent> = makers
        .flight_recorder()
        .events(&key)
        .into_iter()
        .map(|record| record.event)
        .collect();
    let finals: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, event)| matches!(event, FlightEvent::SlotRollbackStats { .. }))
        .map(|(at, _)| at)
        .collect();
    assert_eq!(finals.len(), 1, "one final report per link: {events:?}");
    let FlightEvent::SlotRollbackStats { slot, stats } = &events[finals[0]] else {
        unreachable!();
    };
    assert_eq!((*slot, stats.through_turn), (0, 1_000));
    assert_eq!(
        events[finals[0] + 1],
        FlightEvent::SlotDisconnected { slot: 0 },
        "the final report comes just ahead of the disconnect",
    );
}

#[tokio::test]
async fn a_lockstep_session_keeps_no_reports() {
    let session = SessionId(351);
    let (relay, key, tenant) = relay_for(session, false);
    let makers = relay.mesh.session.decision_makers.clone();
    let endpoint = client_endpoint(&relay.ca);
    let mut slot0 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)).await;
    let _slot1 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(1)).await;
    wait_for_slots(&relay.sessions, &key, 2).await;
    let (mut control, _unused_recv) = slot0.connection().open_bi().await.unwrap();

    send_control_rollback_stats(&mut control, stats(720))
        .await
        .unwrap();
    send_control_game_started(&mut control).await.unwrap();
    wait_past_game_started(&makers, &key).await;
    assert_eq!(stored(&makers, &key, 0), None);

    send_control_leave_intent(&mut control).await.unwrap();
    expect_closed(&mut slot0).await;
    wait_until("the disconnect was never recorded", || {
        makers
            .flight_recorder()
            .events(&key)
            .iter()
            .any(|record| matches!(record.event, FlightEvent::SlotDisconnected { slot: 0 }))
    })
    .await;
    assert!(
        !makers
            .flight_recorder()
            .events(&key)
            .iter()
            .any(|record| matches!(record.event, FlightEvent::SlotRollbackStats { .. })),
        "no final report from a link that kept none",
    );
}
