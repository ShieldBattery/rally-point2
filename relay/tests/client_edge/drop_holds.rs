//! Drop holds around the last local slot leaving: the session close is deferred,
//! its state kept, and a reconnect inside the abandon window cancels it.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;

/// `end_slot_link`'s session-emptied teardown must not sweep away a hold its
/// own disconnect just marked: the sweep may only discard *decided* holds, not
/// every hold for the session, or a client reconnecting into that same window
/// would find its drop hold already erased — with the departure record still
/// standing, that reads as an already-decided leave, so the admission gate
/// would wrongly refuse the very client the hold exists to let back in. On a
/// session split across relays, each relay's local roster holds only its own
/// slot(s), so **every** disconnect empties it and hits this teardown — a
/// single connected slot reproduces the exact condition without needing a
/// second relay.
///
/// Drives the real teardown (a genuine disconnect, not a hand-simulated
/// hold+release) and the real admission gate (`server.rs`'s `serve_connection`,
/// not a direct call into `routing`/`consensus`) end to end: the slot must be
/// reinstated, not refused.
#[tokio::test]
async fn a_last_local_slots_disconnect_still_reinstates_on_reconnect_through_the_real_gate() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(310);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // A single local slot: it is always "the last local slot" for this relay, so
    // its own disconnect always empties the roster and runs the session-emptied
    // teardown in the same breath that marks its hold.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let drop_holds = mesh.drop_holds.clone();
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

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;

    // Sever the connection -- a real disconnect, not a clean leave-intent -- so
    // `end_slot_link` runs its real session-emptied teardown.
    drop(slot0);

    // Wait for the relay's async teardown to actually finish: the departure
    // recorded and the hold marked. Polled on the shared registries (cloned before
    // the relay took ownership of `mesh`) since there is no local peer to observe
    // this through a control frame.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    wait_until(
        deadline,
        "the relay never recorded the disconnected slot's departure and hold",
        || {
            consensus::slot_departed(&makers, &key, SlotId(0))
                && drop_holds.is_pending(&key, SlotId(0))
        },
    )
    .await;

    // Re-dial through the REAL admission gate end to end -- this is exactly the bug
    // Finding 1 fixed: before the fix, the session-emptied teardown above had
    // already swept the hold this disconnect just marked, so this handshake would
    // be refused with `SLOT_DEPARTED_CLOSE` instead of admitted.
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(0), client_key.public);
    let redial = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    handshake(&redial, &token, &client_key, &[])
        .await
        .expect("the re-register must be admitted -- the hold must survive the roster-empty sweep");

    // And the slot is genuinely reinstated: no departure, no hold, either.
    assert!(
        !consensus::slot_departed(&makers, &key, SlotId(0)),
        "the reconnect reinstated the slot",
    );
    assert!(!drop_holds.is_pending(&key, SlotId(0)));
}

/// The structural companion to the hold-sweep case above: the same last-slot
/// disconnect that marks the hold also empties the local roster — and while
/// that hold promises a reconnect, the emptying must not report `SessionClosed`
/// (on a single-relay session the coordinator would retire the session on the
/// spot, refusing the promised reconnect) nor drop the session's serving state
/// (the lobby log and replay ring are what make the admitted resume whole).
/// End to end through the real gate: the close is deferred, the reconnected
/// client is replayed the lobby log, and the close then fires exactly once,
/// when the client later leaves cleanly.
#[tokio::test]
async fn a_held_last_slot_disconnect_defers_the_session_close_and_keeps_its_state() {
    use rally_point_relay::consensus::{self, Authority, RelayNotice};
    use rally_point_relay::routing::SessionKey;
    use rally_point_relay::session::presence::{self, Candidate};
    use rally_point_transport::control::{
        ControlInbound, send_control_leave_intent, spawn_control_reader,
    };

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(312);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // A single local slot over an expected {0} set, this relay the authority and
    // first in its own presence order: slot 0 arriving is full coverage, so the
    // session starts — the deferral applies only to a started session, whose
    // abandoned-session timer bounds it.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let drop_holds = mesh.drop_holds.clone();
    let lobby = mesh.lobby.clone();
    let (notice_tx, mut notice_rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(notice_tx);
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    presence::set_order(&mesh.presence, &key, vec![Candidate::SelfRelay]);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    wait_until(deadline, "the session never started", || {
        consensus::session_started(&makers, &key)
    })
    .await;

    // A framed turn gives the session a frame basis (a clean leave's decide
    // schedules against it), and a lobby command goes into the replay log the
    // reconnect below must still find.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    // A peer-authored lobby command into the replay log (a member's own
    // commands are skipped on its replay, so the survivable content must be
    // authored by another slot — here injected as a mesh delivery would be).
    rally_point_relay::session::lobby::deliver(
        &lobby,
        &key,
        rally_point_proto::messages::LobbyCommand {
            slot: 1,
            payload: vec![0xAB, 0xCD].into(),
        },
    );
    // Let the relay validate the turn before the blip.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // The blip: a real disconnect of the relay's only local slot.
    drop(slot0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    wait_until(
        deadline,
        "the relay never recorded the disconnected slot's departure and hold",
        || {
            consensus::slot_departed(&makers, &key, SlotId(0))
                && drop_holds.is_pending(&key, SlotId(0))
        },
    )
    .await;

    // The emptying ran, the hold is pending — and no close was reported.
    while let Ok(notice) = notice_rx.try_recv() {
        assert!(
            !matches!(notice, RelayNotice::SessionClosed { .. }),
            "no close may be reported while the slot's drop is held",
        );
    }

    // Re-dial through the real gate: admitted (the hold), and the lobby log —
    // which the emptying must not have dropped — replays to the returning member.
    let slot0b = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut ctrl0b = spawn_control_reader(slot0b.connection().clone());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let frame = tokio::time::timeout_at(deadline, ctrl0b.recv())
            .await
            .expect("the lobby log was not replayed to the reconnected member")
            .expect("control stream closed early");
        if let ControlInbound::Lobby(command) = frame {
            assert_eq!(&command.payload[..], &[0xAB, 0xCD]);
            assert_eq!(command.slot, 1, "the replayed command keeps its author");
            break;
        }
    }

    // The client leaves cleanly: the emptying now has nothing held, so the
    // close runs — exactly once.
    let (mut leave_send, _unused_recv) = slot0b.connection().open_bi().await.unwrap();
    send_control_leave_intent(&mut leave_send).await.unwrap();

    let mut deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut closes = 0usize;
    loop {
        match tokio::time::timeout_at(deadline, notice_rx.recv()).await {
            Ok(Some(RelayNotice::SessionClosed { .. })) => {
                closes += 1;
                // A duplicate close would ride the same teardown, so a short
                // quiesce window after the first is enough to catch one.
                deadline = tokio::time::Instant::now() + Duration::from_millis(700);
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            // Quiesced: nothing more is coming within the window.
            Err(_) => break,
        }
    }
    assert_eq!(closes, 1, "the clean emptying reported exactly one close");
}

/// The mass-blip variant: every slot in a session drops together (a shared uplink
/// hiccup), arming the abandoned-session timer -- and then one of them reconnects
/// inside the window. The reconnect must be admitted through the real gate, the
/// timer must stand down (nothing gets force-decided while a reconnect is live),
/// and the *other*, still-disconnected slot's hold must still be exactly what it
/// was before the blip: alive, and honorable by a `RequestDrop` once its own
/// unlock floor passes.
#[tokio::test]
async fn a_reconnect_inside_the_abandon_window_cancels_it_and_the_other_holds_still_honor_a_request()
 {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_relay::session::presence::{self, Candidate};
    use rally_point_transport::control::{
        ControlInbound, send_control_request_drop, spawn_control_reader,
    };

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(311);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Tiny unlock and abandon windows so the test doesn't wait the production 30s
    // / 45s. Authority over the full {0, 1} expected set so the session actually
    // starts (the abandon condition requires it) and set this relay first in its
    // own presence order so its own roster count drives the authority verdict.
    let unlock = Duration::from_millis(200);
    let abandon_timeout = Duration::from_millis(300);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_timings(unlock, abandon_timeout);
    let makers = mesh.decision_makers.clone();
    let presence_registry = mesh.presence.clone();
    let drop_holds = mesh.drop_holds.clone();
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    presence::set_order(&presence_registry, &key, vec![Candidate::SelfRelay]);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // Both slots produce a framed turn so their own departure records carry a last
    // frame -- a basis their eventual leave (however it's decided) can schedule
    // against.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    slot1
        .send(Some(Payload {
            seq: 0,
            slot: 1,
            game_frame_count: Some(10),
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The shared uplink blip: both slots' links die. Slot 1 first (session stays
    // non-empty, ordinary disconnect path), then slot 0 -- whose disconnect empties
    // the local roster and arms the abandon timer.
    drop(slot1);
    drop(slot0);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    wait_until(
        deadline,
        "the relay never marked holds for both disconnected slots",
        || drop_holds.is_pending(&key, SlotId(0)) && drop_holds.is_pending(&key, SlotId(1)),
    )
    .await;
    wait_until(deadline, "the abandoned-session timer never armed", || {
        drop_holds.abandon_armed(&key)
    })
    .await;

    // Slot 0 re-dials inside the (short) abandon window, through the real gate.
    let slot0b = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut ctrl0 = spawn_control_reader(slot0b.connection().clone());

    // The reconnect must have cancelled the timer -- verify directly, and then
    // outlast the original window with nothing decided.
    wait_until(
        tokio::time::Instant::now() + Duration::from_secs(2),
        "the reconnect never cancelled the abandoned-session timer",
        || !drop_holds.abandon_armed(&key),
    )
    .await;
    assert!(
        !consensus::slot_departed(&makers, &key, SlotId(0)),
        "the reconnected slot is reinstated",
    );
    assert!(
        drop_holds.is_pending(&key, SlotId(1)),
        "the other slot's hold is untouched by the reconnect",
    );

    // Wait well past the original abandon window: nothing was force-decided while
    // the reconnect was in flight, so slot 0 (now live) sees no leave at all yet.
    let past_window = tokio::time::Instant::now() + abandon_timeout + Duration::from_millis(300);
    loop {
        match tokio::time::timeout_at(past_window, ctrl0.recv()).await {
            Ok(Some(ControlInbound::Leave(leave))) => {
                panic!("the cancelled abandon timer still decided a leave: {leave:?}")
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("slot 0's control stream closed early"),
            Err(_) => break,
        }
    }
    assert!(
        drop_holds.is_pending(&key, SlotId(1)),
        "slot 1's drop is still held, undecided, after the window that would have abandoned it",
    );

    // Slot 1's hold survived intact: reconnected slot 0 can still request its drop,
    // and past slot 1's own unlock floor (already well past, at this point) it is
    // honored -- proof the hold that outlived the blip is a fully live one, not a
    // stale leftover.
    let (mut req_send, _unused) = slot0b.connection().open_bi().await.unwrap();
    send_control_request_drop(&mut req_send, 1).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, ctrl0.recv()).await {
            Ok(Some(ControlInbound::Leave(leave))) => {
                assert_eq!(leave.slot, 1);
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => panic!("slot 0's control stream closed before the honored drop arrived"),
            Err(_) => panic!("the request-drop for the still-held slot 1 was never honored"),
        }
    }
}
