//! A session everyone left: arming and cancelling the abandoned-session
//! timer, what its expiry decides, and how it orders against the close.

use super::*;

/// Regression for a relay assigned to a multi-relay session whose own client
/// never connected. The peer connected briefly but the full expected roster
/// never formed, so the relay session never reached `started`; once that peer
/// reports zero, this relay still has to run the ordinary close.
#[test]
fn peer_zero_closes_a_never_started_session_on_a_relay_with_no_local_slots() {
    use crate::consensus::{self, Authority, RelayNotice};
    use crate::session::presence::Candidate;
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::ids::RelayId;

    let k = key();
    let sessions: Sessions = Arc::default();
    let mesh = crate::mesh::new_mesh_state_with_timings(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let _ = consensus::sync_maker(
        &mesh.decision_makers,
        &k,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    assert!(
        !consensus::session_started(&mesh.decision_makers, &k),
        "only one peer ever connected, so the session never started",
    );
    crate::session::presence::set_order(
        &mesh.presence,
        &k,
        vec![Candidate::SelfRelay, Candidate::Peer(RelayId(2))],
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    mesh.decision_makers.set_notice_notifier(tx);

    // No slot was ever inserted into `sessions`, and deliberately no
    // `record_own(0)` call was made. The local roster itself is authoritative.
    // The peer was briefly live, matching the incident: activity happened,
    // but the full expected roster never formed on this relay.
    assert!(
        !crate::session::presence::record_peer(&mesh.presence, &k, RelayId(2), 1,),
        "the unknown peer was already conservatively treated as live"
    );
    reconcile_abandon(&sessions, &mesh, &k);
    assert!(
        rx.try_recv().is_err(),
        "a live peer keeps the serving state open",
    );
    assert!(crate::session::presence::record_peer(
        &mesh.presence,
        &k,
        RelayId(2),
        0,
    ));
    reconcile_abandon(&sessions, &mesh, &k);

    assert_eq!(
        rx.try_recv(),
        Ok(RelayNotice::SessionClosed {
            tenant: k.tenant.clone(),
            session: k.session,
        }),
    );
    assert!(
        !mesh.drop_holds.abandon_armed(&k),
        "a clean empty session has no departures to time out",
    );
}

/// A relay closes only after every named peer explicitly reports zero. Both
/// silence and a positive report keep the session open even when the local
/// roster is empty.
#[test]
fn unknown_or_live_peer_presence_blocks_the_empty_session_close() {
    use crate::session::presence::Candidate;
    use rally_point_proto::ids::RelayId;

    let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
    crate::session::presence::set_order(
        &presence,
        &k,
        vec![Candidate::SelfRelay, Candidate::Peer(RelayId(2))],
    );
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(tx);
    let mesh = mesh_with(&holds, &makers, &mesh_links, &presence);

    reconcile_abandon(&sessions, &mesh, &k);
    assert!(
        rx.try_recv().is_err(),
        "an unknown peer is assumed live and blocks close",
    );

    crate::session::presence::record_peer(&presence, &k, RelayId(2), 1);
    reconcile_abandon(&sessions, &mesh, &k);
    assert!(
        rx.try_recv().is_err(),
        "an explicitly live peer blocks close",
    );
}

/// Every player dropping leaves the session empty session-wide with undecided
/// departures; past the abandoned-session window, they are all decided so the
/// session can proceed to its normal teardown — including the session-emptied
/// close those undecided departures had been deferring.
#[tokio::test]
async fn all_players_dropping_decides_every_departure_after_the_abandon_timeout() {
    use crate::consensus::RelayNotice;

    let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(tx);
    drop_slot(&makers, &holds, &k, SlotId(0));
    drop_slot(&makers, &holds, &k, SlotId(1));
    // The session goes empty session-wide.
    crate::session::presence::record_own(&presence, &k, 0);

    assert!(crate::consensus::has_undecided_departure(&makers, &k));
    reconcile_abandon(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );
    assert!(
        holds.abandon_armed(&k),
        "an empty session with undecided departures arms the timer",
    );

    // Past the window, every departure is decided — nothing is left held.
    tokio::time::sleep(TINY_ABANDON + Duration::from_millis(80)).await;
    assert!(
        !crate::consensus::has_undecided_departure(&makers, &k),
        "the abandoned session's departures are all decided",
    );
    assert!(!holds.abandon_armed(&k), "the fired timer removed itself");
    let mut saw_closed = false;
    while let Ok(notice) = rx.try_recv() {
        saw_closed |= matches!(notice, RelayNotice::SessionClosed { .. });
    }
    assert!(
        saw_closed,
        "the expiry's decides ran the deferred session-emptied close",
    );
}

/// A slot re-registering inside the window cancels the timer: nothing is decided,
/// the returning slot is reinstated, and the other slot's drop stays held
/// (undecided) — now requestable by that slot once it returns, or never.
#[tokio::test]
async fn a_re_register_inside_the_window_cancels_the_timer_and_decides_nothing() {
    let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
    drop_slot(&makers, &holds, &k, SlotId(0));
    drop_slot(&makers, &holds, &k, SlotId(1));
    crate::session::presence::record_own(&presence, &k, 0);
    reconcile_abandon(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );
    assert!(holds.abandon_armed(&k));

    // Slot 0 re-registers: claim its hold and reinstate its departure
    // atomically, and report the roster live again — the server's
    // re-register path — then reconcile.
    assert!(
        holds.take_if_pending(&k, SlotId(0), || crate::consensus::reinstate_slot(
            &makers,
            &k,
            SlotId(0)
        ))
    );
    let (_registration, _inbox) =
        register(&sessions, &k, SlotId(0), 1).expect("the returning slot registers");
    crate::session::presence::record_own(&presence, &k, 1);
    reconcile_abandon(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );
    assert!(
        !holds.abandon_armed(&k),
        "the re-register cancelled the abandoned-session timer",
    );

    // Past the original window, nothing was decided.
    tokio::time::sleep(TINY_ABANDON + Duration::from_millis(80)).await;
    assert!(
        !crate::consensus::slot_departed(&makers, &k, SlotId(0)),
        "the reconnected slot is reinstated",
    );
    assert!(
        holds.is_pending(&k, SlotId(1)),
        "the other slot's drop is still held, undecided",
    );
    assert!(
        crate::consensus::has_undecided_departure(&makers, &k),
        "no departure was decided",
    );
}

/// An expiry that races a re-registration and loses the cancellation (the
/// sleep completed in the same instant the cancel landed) must still not
/// force-decide: the expiry re-derives the abandoned condition, finds a
/// slot live again on the local roster, and stands down — leaving the other
/// slot's drop held for the live machinery (the returned survivor's drop
/// request, or a later re-abandonment) instead of force-deciding it out
/// from under a live session.
#[test]
fn an_expiry_that_lost_the_cancel_race_stands_down_when_a_slot_is_live_again() {
    let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(tx);
    drop_slot(&makers, &holds, &k, SlotId(0));
    drop_slot(&makers, &holds, &k, SlotId(1));
    crate::session::presence::record_own(&presence, &k, 0);

    // Slot 0 re-registers exactly as the server's re-register path does...
    assert!(
        holds.take_if_pending(&k, SlotId(0), || crate::consensus::reinstate_slot(
            &makers,
            &k,
            SlotId(0)
        ))
    );
    let (_registration, _inbox) =
        register(&sessions, &k, SlotId(0), 1).expect("the returning slot registers");
    crate::session::presence::record_own(&presence, &k, 1);

    // ...and the expiry callback fires anyway (the ordering where its sleep
    // completed before the cancellation reached the select).
    decide_and_broadcast_abandoned(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
        false,
    );

    assert!(
        crate::consensus::has_undecided_departure(&makers, &k),
        "the raced expiry decided nothing",
    );
    assert!(
        holds.is_pending(&k, SlotId(1)),
        "the other slot's drop is still held for the live session",
    );
    assert_eq!(closes_reported(&mut rx), 0, "no close was reported");
}

/// The same stand-down applies when the liveness is on a peer relay: an
/// expiry that finds a peer explicitly reporting a live slot leaves the
/// departures held.
#[test]
fn an_expiry_stands_down_when_a_peer_reports_a_live_slot() {
    use crate::session::presence::Candidate;
    use rally_point_proto::ids::RelayId;

    let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
    crate::session::presence::set_order(
        &presence,
        &k,
        vec![Candidate::SelfRelay, Candidate::Peer(RelayId(2))],
    );
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(tx);
    drop_slot(&makers, &holds, &k, SlotId(0));
    drop_slot(&makers, &holds, &k, SlotId(1));
    crate::session::presence::record_own(&presence, &k, 0);
    crate::session::presence::record_peer(&presence, &k, RelayId(2), 1);

    decide_and_broadcast_abandoned(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
        false,
    );

    assert!(
        crate::consensus::has_undecided_departure(&makers, &k),
        "a peer's live slot keeps the departures held",
    );
    assert_eq!(closes_reported(&mut rx), 0, "no close was reported");
}

/// The timer never arms while at least one slot is live session-wide, no matter
/// how many others have dropped.
#[tokio::test]
async fn the_timer_never_arms_while_a_slot_is_live() {
    let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
    drop_slot(&makers, &holds, &k, SlotId(1));
    // Slot 0 is still connected: the session is not empty session-wide.
    let (_registration, _inbox) =
        register(&sessions, &k, SlotId(0), 1).expect("the live slot registers");
    crate::session::presence::record_own(&presence, &k, 1);

    reconcile_abandon(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );
    assert!(
        !holds.abandon_armed(&k),
        "a session with a live slot never arms the timer",
    );

    // Well past the window, the still-held slot 1 is not decided.
    tokio::time::sleep(TINY_ABANDON + Duration::from_millis(80)).await;
    assert!(
        crate::consensus::has_undecided_departure(&makers, &k),
        "no departure is decided while a slot remains live",
    );
}

/// A duplicate arm leaves a single timer, and a duplicate decide after expiry
/// finds nothing left — the abandoned close is idempotent.
#[tokio::test]
async fn duplicate_arm_and_expiry_decide_at_most_once() {
    let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
    drop_slot(&makers, &holds, &k, SlotId(0));
    drop_slot(&makers, &holds, &k, SlotId(1));
    crate::session::presence::record_own(&presence, &k, 0);

    // Arm twice: the second is idempotent, leaving a single timer.
    reconcile_abandon(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );
    reconcile_abandon(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );
    assert!(holds.abandon_armed(&k));

    tokio::time::sleep(TINY_ABANDON + Duration::from_millis(80)).await;
    assert!(
        !crate::consensus::has_undecided_departure(&makers, &k),
        "the departures decided once",
    );

    // A duplicate decide after the fact is a no-op — all already decided.
    let again = crate::consensus::decide_abandoned_departures(&makers, &k);
    assert!(
        again.is_empty(),
        "a duplicate abandoned-decide finds nothing left to decide",
    );
}

/// A window that elapses on a session this relay already closed reports no
/// A retired session's emptied-close evaluation is refused by the ingress
/// gate outright: with the maker swept, the no-maker close default would
/// otherwise claim and report a second SessionClosed.
#[test]
fn a_retired_sessions_emptied_close_reports_nothing() {
    let sessions: Sessions = Arc::default();
    let mesh = crate::mesh::new_mesh_state();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    mesh.decision_makers.set_notice_notifier(tx);
    let k = key();

    mesh.gates.retire(&k);
    maybe_close_emptied_session(&sessions, &mesh, &k);
    assert!(
        rx.try_recv().is_err(),
        "a retired session's close evaluation reports nothing",
    );
}

/// second close — not even once the decision-maker is gone, which is what a
/// retired session's descriptor removal leaves behind and which takes the
/// close-report latch with it.
#[tokio::test]
async fn an_elapsed_window_reports_no_second_close_for_a_closed_session() {
    let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(tx);
    // Both slots are gone with nothing holding them: the timer arms, and the
    // close runs rather than deferring on a promised reconnect.
    depart_slot_unheld(&makers, &holds, &k, SlotId(0));
    depart_slot_unheld(&makers, &holds, &k, SlotId(1));
    crate::session::presence::record_own(&presence, &k, 0);

    reconcile_abandon(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );
    assert!(holds.abandon_armed(&k), "the emptying armed the timer");
    assert_eq!(closes_reported(&mut rx), 1, "the emptying reported a close");

    // The coordinator retires the session and drops its descriptor.
    crate::consensus::deregister_maker(&makers, &k);

    tokio::time::sleep(TINY_ABANDON + Duration::from_millis(80)).await;
    assert_eq!(
        closes_reported(&mut rx),
        0,
        "the elapsed window left the reported close alone",
    );
}

/// The window still force-decides after a close: the close ends this relay's
/// serving state, not the departures the timer was armed to decide.
#[tokio::test]
async fn an_elapsed_window_still_decides_departures_after_a_close() {
    let (presence, sessions, mesh_links, makers, k) = abandoned_harness();
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, TINY_ABANDON);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(tx);
    depart_slot_unheld(&makers, &holds, &k, SlotId(0));
    depart_slot_unheld(&makers, &holds, &k, SlotId(1));
    crate::session::presence::record_own(&presence, &k, 0);

    reconcile_abandon(
        &sessions,
        &mesh_with(&holds, &makers, &mesh_links, &presence),
        &k,
    );
    assert_eq!(closes_reported(&mut rx), 1, "the emptying reported a close");
    assert!(
        crate::consensus::has_undecided_departure(&makers, &k),
        "the close decided nothing on its own",
    );

    tokio::time::sleep(TINY_ABANDON + Duration::from_millis(80)).await;
    assert!(
        !crate::consensus::has_undecided_departure(&makers, &k),
        "the elapsed window decided the abandoned session's departures",
    );
    assert_eq!(
        closes_reported(&mut rx),
        0,
        "deciding them reported no further close",
    );
}
