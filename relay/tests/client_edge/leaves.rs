//! Departures: a coordinator reap and the leave-intent path that decides a
//! departure once, closes the sender, and cuts the slot's serving.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_relay::consensus::LEAVE_REASON_LEFT;

/// A coordinator reap (`routing::close_slots`, the same signal a holdout reap
/// fires) actually closes the client's QUIC connection promptly, not just the
/// relay's own internal roster bookkeeping. Before the fix, `run_slot_link`'s
/// `shutdown.notified()` arm broke its serve loop without ever calling
/// `connection.close()` (despite its own comment saying it would) — the
/// beacon and control-stream reader tasks it spawned each held their own
/// `connection.clone()`, so the connection lingered until QUIC's own idle
/// timeout instead of freeing promptly.
#[tokio::test]
async fn a_coordinator_reap_closes_the_connection_so_the_client_observes_it_end() {
    use rally_point_relay::key::SessionKey;
    use rally_point_relay::routing;

    let tenant = make_default_tenant();
    let session = SessionId(12);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let relay = start_relay(registry_for_one(&tenant));
    let endpoint = client_endpoint(&relay.ca);

    let slot0 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)).await;
    let client_connection = slot0.connection().clone();
    // The reap acts on the roster, so the slot has to be in it first.
    wait_for_slots(&relay.sessions, &key, 1).await;

    routing::close_slots(&relay.sessions, &key, &[SlotId(0)]);

    tokio::time::timeout(Duration::from_secs(5), client_connection.closed())
        .await
        .expect("the client never observed the connection end after a coordinator reap");
}

#[tokio::test]
async fn a_leave_intent_broadcasts_reason_left_and_closes_the_sender() {
    use rally_point_relay::consensus;
    use rally_point_relay::key::SessionKey;
    use rally_point_transport::control::{
        ControlInbound, send_control_leave_intent, spawn_control_reader,
    };

    let tenant = make_default_tenant();
    let session = SessionId(200);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Seed this relay as the session's authority: `decide_leave` is a no-op on
    // a non-authority relay, and a lone relay with no descriptor never becomes
    // one on its own outside a real coordinator-driven deployment.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    seed_authority(&makers, &key).apply();

    let TestRelay { addr, ca, .. } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    // Accept the relay's own control stream to slot 1 so its pushed leave
    // directive lands here.
    let mut ctrl1 = spawn_control_reader(slot1.connection().clone());

    // A framed turn from slot 0 gives `decide_leave` a basis to schedule
    // against -- without any observed frame (pure lobby) it would hold.
    slot0.send(Some(build_turn(0, 0, Some(10)))).unwrap();
    // The intent must land on a relay that has already observed that frame.
    wait_until("the relay never observed the leaver's turn", || {
        consensus::slot_frame(&makers, &key, SlotId(0)).is_some()
    })
    .await;

    // Slot 0 announces its own clean departure on the control stream it opens
    // (mirroring the real client driver, which never reuses the relay's
    // opened stream to send its own frames).
    let (mut leave_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_leave_intent(&mut leave_send).await.unwrap();

    let frame = recv_meaningful(&mut ctrl1).await;
    let ControlInbound::Leave(leave) = frame else {
        panic!("expected a LeaveDirective, got {frame:?}");
    };
    assert_eq!(leave.slot, 0);
    assert_eq!(
        leave.reason, LEAVE_REASON_LEFT,
        "an intent-decided leave uses the native quit path's reason, not the drop one",
    );
    let events: Vec<_> = makers
        .flight_recorder()
        .events(&key)
        .into_iter()
        .map(|record| record.event)
        .collect();
    assert!(
        events.iter().any(|event| matches!(
            event,
            rally_point_relay::observability::flight_recorder::FlightEvent::LeaveControlWrite {
                recipient: 1,
                slot: 0,
                reason: LEAVE_REASON_LEFT,
                replayed: false,
                succeeded: true,
                ..
            }
        )),
        "the live write is recorded at the control-stream boundary: {events:?}",
    );

    // The relay's confirmation that it processed the intent is closing the
    // departing client's own link.
    expect_closed(&mut slot0).await;
}

#[tokio::test]
async fn an_intent_decided_leave_is_not_redecided_when_the_link_then_closes() {
    use rally_point_relay::consensus;
    // The same task that decides the leave from the intent also runs the
    // post-loop Trigger-A cleanup on its way out (deregister, decide_leave,
    // remove_slot, presence). This proves that follow-through doesn't produce
    // a *second* directive for the same slot: the survivor sees exactly one
    // leave push, not two.
    use rally_point_relay::key::SessionKey;
    use rally_point_transport::control::{
        ControlInbound, send_control_leave_intent, spawn_control_reader,
    };

    let tenant = make_default_tenant();
    let session = SessionId(201);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    seed_authority(&makers, &key).apply();

    let TestRelay { addr, ca, .. } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut ctrl1 = spawn_control_reader(slot1.connection().clone());

    slot0.send(Some(build_turn(0, 0, Some(10)))).unwrap();
    wait_until("the relay never observed the leaver's turn", || {
        consensus::slot_frame(&makers, &key, SlotId(0)).is_some()
    })
    .await;

    let (mut leave_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_leave_intent(&mut leave_send).await.unwrap();

    let first = recv_meaningful(&mut ctrl1).await;
    assert!(matches!(first, ControlInbound::Leave(_)));

    // Let the slot's task finish tearing down (deregister, the post-loop
    // Trigger-A decide_leave, remove_slot, presence) well past when it would
    // have run, then confirm no second leave push ever follows. A clean leave
    // fans no connectivity(false) frame (that is the disconnect path only), so
    // the stream is silent from here — any frame at all would be a regression.
    expect_closed(&mut slot0).await;
    let second = tokio::time::timeout(Duration::from_millis(300), ctrl1.recv()).await;
    assert!(
        second.is_err(),
        "the post-loop cleanup must not re-decide and re-broadcast the same slot's leave",
    );
}

#[tokio::test]
async fn a_turn_sent_after_the_leave_intent_is_never_forwarded() {
    // The relay stops serving a slot's link the moment it processes that
    // slot's leave-intent (the determinism cut), so nothing sent afterward
    // can still reach a survivor. Sending only once the relay has confirmed
    // the intent by closing the link (rather than racing the intent and a
    // turn on the wire) is what makes this deterministic to test.
    use rally_point_relay::key::SessionKey;
    use rally_point_transport::control::send_control_leave_intent;

    let tenant = make_default_tenant();
    let session = SessionId(202);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    seed_authority(&makers, &key).apply();

    let TestRelay { addr, ca, .. } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    slot0.send(Some(build_turn(0, 0, Some(10)))).unwrap();
    // Drain that first turn at slot 1 so it can't be mistaken for the later,
    // forbidden one.
    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot1.recv().await.unwrap().fresh;
    }
    assert_eq!(&delivered[0].commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);

    let (mut leave_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_leave_intent(&mut leave_send).await.unwrap();
    expect_closed(&mut slot0).await;

    // Only now, with the relay's slot-0 link task confirmed gone, try to send
    // a further turn. Nothing on the relay is left reading this connection,
    // so it can never be forwarded.
    let _ = slot0.send(Some(Payload {
        seq: 1,
        slot: 0,
        game_frame_count: Some(11),
        commands: vec![0x0C, 8, 8, 8, 8, 8, 8, 8].into(),
        ..Default::default()
    }));

    // Drain whatever the relay's own idle-ack flush still sends slot 1 (it
    // owes acks regardless of the leave) for a few flush cycles, and confirm
    // none of it ever carries the forbidden turn.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now()) {
        match tokio::time::timeout(remaining, slot1.recv()).await {
            Ok(Ok(received)) => assert!(
                received.fresh.is_empty(),
                "a turn sent after the leave intent must never reach a survivor: {:?}",
                received.fresh,
            ),
            // The relay's ack-only flush timed out this cycle (nothing owed,
            // or the window elapsed) or the link itself ended -- either way,
            // no leaked turn arrived.
            Ok(Err(_)) | Err(_) => break,
        }
    }
}
