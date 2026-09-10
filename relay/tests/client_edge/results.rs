//! Game-result reports: the admissible one that is forwarded ahead of the
//! reporter's departure, and the malformed ones the relay drops without
//! punishing the link.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;

#[tokio::test]
async fn a_result_report_is_forwarded_before_the_departure_and_leaves_survivors_alone() {
    // A client writes its result report then its leave intent on the one control
    // stream it opens. The relay processes that stream in order, so it fires the
    // result notice (stamped with the reporting slot, payload, and frames) before
    // the departure notice, and the surviving second client still gets the synced
    // leave and keeps its link.
    use rally_point_relay::consensus::{self, Authority, RelayNotice};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{
        ControlInbound, send_control_game_result, send_control_leave_intent, spawn_control_reader,
    };

    // The native SC:R `pending_leave_reason` a voluntary quit writes.
    const LEAVE_REASON_LEFT: u32 = 3;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(203);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    // Watch the notices the relay would send up its coordinator connection.
    let (notice_tx, mut notice_rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut ctrl1 = spawn_control_reader(slot1.connection().clone());

    // A framed turn from slot 0 gives the result its frame stamps and gives
    // `decide_leave` a basis to schedule against.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Slot 0 writes its result report then its leave intent on the one control
    // stream it opens — the ordering the relay must preserve on the wire.
    let (mut ctrl0_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_game_result(&mut ctrl0_send, vec![0xDE, 0xAD, 0xBE, 0xEF].into())
        .await
        .unwrap();
    send_control_leave_intent(&mut ctrl0_send).await.unwrap();

    // The relay processes the stream in order, so the result notice fires before
    // the departure notice.
    let first = recv_event_notice(&mut notice_rx).await;
    let RelayNotice::Result(result) = first else {
        panic!("expected the result notice first, got {first:?}");
    };
    assert_eq!(result.tenant, TenantId(TENANT.to_owned()));
    assert_eq!(result.session, session);
    assert_eq!(
        result.slot,
        SlotId(0),
        "the reporting slot is the authenticated connection's",
    );
    assert_eq!(result.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(result.session_frame, Some(10));
    assert_eq!(result.slot_frame, Some(10));
    assert!(result.arrival_ms > 0, "a wall-clock arrival stamp is set");

    let second = recv_event_notice(&mut notice_rx).await;
    let RelayNotice::Departure(departure) = second else {
        panic!("expected the departure notice second, got {second:?}");
    };
    assert_eq!(departure.slot, SlotId(0));
    assert_eq!(
        departure.reason, LEAVE_REASON_LEFT,
        "an intent-decided leave uses the native quit reason",
    );

    // The surviving second client is unaffected: it still receives the synced
    // leave for slot 0 over its own control stream (past any connectivity frame).
    let pushed = recv_meaningful(&mut ctrl1).await;
    let ControlInbound::Leave(leave) = pushed else {
        panic!("expected a LeaveDirective at the survivor, got {pushed:?}");
    };
    assert_eq!(leave.slot, 0);

    // The departing client's link is closed by the relay; the survivor's is not.
    expect_closed(&mut slot0).await;
    assert!(
        slot1.connection().close_reason().is_none(),
        "the surviving client's link must stay open",
    );
}

#[tokio::test]
async fn an_oversize_result_report_is_dropped_without_closing_the_link() {
    // A result payload past the size cap is an ill-formed report: the relay drops
    // it (no notice) but keeps the link — a within-cap report that follows on the
    // same stream is still accepted, proving the stream wasn't torn down.
    use rally_point_relay::consensus::{self, Authority, RelayNotice};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::send_control_game_result;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(204);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    let (notice_tx, mut notice_rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;

    // A payload past the 4096-byte cap, well within the 64 KiB control-frame cap
    // (so it reaches the relay's own size check rather than the framing guard).
    let (mut ctrl0_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_game_result(&mut ctrl0_send, vec![0x7u8; 5000].into())
        .await
        .unwrap();

    // No result notice fires for the oversize report.
    assert_no_event_notice(
        &mut notice_rx,
        Duration::from_millis(400),
        "an oversize result payload must fire no notice",
    )
    .await;

    // The link is still up: a within-cap report on the same stream is accepted
    // and fires its notice — the first record for the slot, since the oversize
    // one was dropped rather than recorded.
    send_control_game_result(&mut ctrl0_send, vec![0x1u8, 0x2, 0x3].into())
        .await
        .unwrap();
    let notice = recv_event_notice(&mut notice_rx).await;
    let RelayNotice::Result(result) = notice else {
        panic!("expected a result notice, got {notice:?}");
    };
    assert_eq!(result.slot, SlotId(0));
    assert_eq!(result.payload, vec![0x1, 0x2, 0x3]);

    // And the relay never closed the connection over the oversize report.
    assert!(
        slot0.connection().close_reason().is_none(),
        "an oversize result must not close the link",
    );
}

#[tokio::test]
async fn an_empty_result_report_is_dropped_without_closing_the_link() {
    // A zero-length result payload is the wire sentinel `SlotDeparted` uses for
    // "no result reported" (see wire.proto), never a genuine report, so the relay
    // must never record one: doing so would make a real empty result
    // indistinguishable from no result once the slot departs. The relay drops it
    // (no notice) but keeps the link, exactly like an oversize report.
    use rally_point_relay::consensus::{self, Authority, RelayNotice};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::send_control_game_result;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(205);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    let (notice_tx, mut notice_rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;

    let (mut ctrl0_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
    send_control_game_result(&mut ctrl0_send, Vec::new().into())
        .await
        .unwrap();

    // No result notice fires for the empty report.
    assert_no_event_notice(
        &mut notice_rx,
        Duration::from_millis(400),
        "an empty result payload must fire no notice",
    )
    .await;
    assert!(
        consensus::result_for(&makers, &key, SlotId(0)).is_none(),
        "an empty result payload must never be retained",
    );

    // The link is still up: a real report on the same stream is still accepted
    // and fires its notice — the first record for the slot, since the empty one
    // was dropped rather than recorded.
    send_control_game_result(&mut ctrl0_send, vec![0x1u8, 0x2, 0x3].into())
        .await
        .unwrap();
    let notice = tokio::time::timeout(Duration::from_secs(5), notice_rx.recv())
        .await
        .expect("the real result never fired a notice — the link was torn down")
        .expect("the notice channel closed early");
    let RelayNotice::Result(result) = notice else {
        panic!("expected a result notice, got {notice:?}");
    };
    assert_eq!(result.slot, SlotId(0));
    assert_eq!(result.payload, vec![0x1, 0x2, 0x3]);

    // And the relay never closed the connection over the empty report.
    assert!(
        slot0.connection().close_reason().is_none(),
        "an empty result must not close the link",
    );
}
