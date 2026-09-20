//! Game-result reports: the admissible one that is forwarded ahead of the
//! reporter's departure, and the malformed ones the relay drops without
//! punishing the link.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};

#[tokio::test]
async fn a_result_report_is_forwarded_before_the_departure_and_leaves_survivors_alone() {
    // A client writes its result report then its leave intent on the one control
    // stream it opens. The relay processes that stream in order, so it fires the
    // result notice (stamped with the reporting slot, payload, and frames) before
    // the departure notice, and the surviving second client still gets the synced
    // leave and keeps its link.
    use rally_point_relay::consensus::{LEAVE_REASON_LEFT, RelayNotice};
    use rally_point_relay::key::SessionKey;
    use rally_point_transport::control::{
        ControlInbound, send_control_game_result, send_control_leave_intent, spawn_control_reader,
    };

    let tenant = make_default_tenant();
    let session = SessionId(203);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let mesh = rally_point_relay::mesh::MeshState::default();
    let makers = mesh.session.decision_makers.clone();
    seed_authority(&makers, &key).apply();
    // Watch the notices the relay would send up its coordinator connection.
    let (notice_tx, mut notice_rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);

    let TestRelay { addr, ca, .. } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut ctrl1 = spawn_control_reader(slot1.connection().clone());

    // A framed turn from slot 0 gives the result its frame stamps and gives
    // `decide_leave` a basis to schedule against.
    slot0.send(Some(build_turn(0, 0, Some(10)))).unwrap();
    wait_until("the relay never observed the reporter's turn", || {
        makers.slot_frame(&key, SlotId(0)).is_some()
    })
    .await;

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

/// Both malformed result reports the relay must refuse to record, and the
/// property that only a live link shows: it survives them, so a real report on
/// the same control stream still lands afterwards.
///
/// The rows are the two shapes a report can be ill-formed in. An oversize
/// payload is past the 4096-byte cap but well inside the 64 KiB control-frame
/// cap, so it reaches the relay's own size check rather than the framing guard.
/// A zero-length payload is the wire sentinel `SlotDeparted` uses for "no
/// result reported", never a genuine report: recording one would make a real
/// empty result indistinguishable from no result once the slot departs.
#[tokio::test]
async fn a_malformed_result_report_is_dropped_without_closing_the_link() {
    use rally_point_relay::consensus::{self, RelayNotice};
    use rally_point_relay::key::SessionKey;
    use rally_point_transport::control::send_control_game_result;

    let tenant = make_default_tenant();
    let mesh = rally_point_relay::mesh::MeshState::default();
    let makers = mesh.session.decision_makers.clone();
    let (notice_tx, mut notice_rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);

    let TestRelay { addr, ca, .. } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let endpoint = client_endpoint(&ca);

    // Each row's client and its control stream stay alive for the rest of the
    // test: dropping the stream resets it, which the relay reads as a lost
    // control stream and closes the link over — emptying that session and
    // firing a close notice into the next row's negative window.
    let mut connected = Vec::new();

    // A session of its own per row, so the good report each row ends with
    // cannot stand in for the next row's dropped one.
    for (case, session, malformed) in [
        (
            "an oversize result payload",
            SessionId(204),
            vec![0x7u8; 5000],
        ),
        ("an empty result payload", SessionId(205), Vec::new()),
    ] {
        let key = SessionKey {
            tenant: TenantId(TENANT.to_owned()),
            session,
        };
        seed_authority(&makers, &key).apply();

        let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
        let (mut ctrl0_send, _unused_recv) = slot0.connection().open_bi().await.unwrap();
        send_control_game_result(&mut ctrl0_send, malformed.into())
            .await
            .unwrap();

        assert_no_event_notice(
            &mut notice_rx,
            Duration::from_millis(400),
            &format!("{case} must fire no notice"),
        )
        .await;
        assert!(
            consensus::result_for(&makers, &key, SlotId(0)).is_none(),
            "{case} must never be retained",
        );

        // The link is still up: a within-cap report on the same stream is
        // accepted and fires its notice — the first record for the slot, since
        // the malformed one was dropped rather than recorded.
        send_control_game_result(&mut ctrl0_send, vec![0x1u8, 0x2, 0x3].into())
            .await
            .unwrap();
        let notice = recv_event_notice(&mut notice_rx).await;
        let RelayNotice::Result(result) = notice else {
            panic!("expected a result notice after {case}, got {notice:?}");
        };
        assert_eq!(result.slot, SlotId(0));
        assert_eq!(result.payload, vec![0x1, 0x2, 0x3]);

        assert!(
            slot0.connection().close_reason().is_none(),
            "{case} must not close the link",
        );
        connected.push((slot0, ctrl0_send));
    }
}
