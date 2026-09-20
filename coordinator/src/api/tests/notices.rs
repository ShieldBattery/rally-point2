//! Notice reporter authorization: which relay may report a session's terminal
//! and load-progress notices, and what a rejected report leaves behind.
//!
//! The gate's verdict is readable synchronously — an accepted notice claims its
//! dedup entry and lands its fact on the lifecycle before any webhook is
//! enqueued, and a rejected one returns before either — so none of this needs a
//! socket or a delivery wait. That an accepted notice then signs and posts a
//! webhook is what the `notify` tests prove.

use super::*;

use rally_point_proto::control::{SessionStartedNotice, SlotConnectedNotice, SlotStartedNotice};

/// Frames a relay→coordinator message as the text frame the reader sees.
fn frame(message: &RelayToCoordinator) -> Message {
    Message::Text(serde_json::to_string(message).unwrap().into())
}

/// One reported notice per gated kind for `session`, each carrying its own
/// correlation ids so it would sign and deliver a webhook if accepted.
fn notices_of_every_kind(session: SessionId) -> Vec<(&'static str, Message)> {
    vec![
        ("result", result_message(session, 0)),
        (
            "slotConnected",
            frame(&RelayToCoordinator::SlotConnected(SlotConnectedNotice {
                tenant: tenant_id(),
                session,
                slot: SlotId(0),
                external_id: Some("game-1".to_owned()),
                external_ref: Some("sb-user-0".to_owned()),
                resumed: false,
                connected_at_ms: 1_700_000_000_000,
            })),
        ),
        (
            "sessionStarted",
            frame(&RelayToCoordinator::SessionStarted(SessionStartedNotice {
                tenant: tenant_id(),
                session,
                external_id: Some("game-1".to_owned()),
                started_at_ms: 1_700_000_000_000,
                initial_buffer_turns: Some(6),
            })),
        ),
        (
            "slotStarted",
            frame(&RelayToCoordinator::SlotStarted(SlotStartedNotice {
                tenant: tenant_id(),
                session,
                slot: SlotId(0),
                external_id: Some("game-1".to_owned()),
                external_ref: Some("sb-user-0".to_owned()),
                arrival_ms: 1_700_000_000_000,
                session_frame: Some(1),
                slot_frame: Some(1),
            })),
        ),
    ]
}

/// How many entries the four notice dedup sets hold between them.
fn claimed_dedup_entries(notices: &NoticeDedup) -> usize {
    notices.results.lock().len()
        + notices.slot_connects.lock().len()
        + notices.session_starts.lock().len()
        + notices.slot_starts.lock().len()
}

/// The URL a notice's webhook would be posted to. Nothing listens on it: these
/// tests read the gate's verdict off the dedup sets and the lifecycle, and an
/// accepted notice's delivery attempt has no bearing on either.
const UNSERVED_HOOK: &str = "http://127.0.0.1:1/hook";

/// Feeds one frame through `note_inbound` as `relay`'s current connection.
fn report(
    setup: &SessionSetup,
    notices: &NoticeDedup,
    lifecycle: &Lifecycle,
    relay: RelayId,
    message: &Message,
) {
    note_inbound_frame(
        setup,
        notices,
        lifecycle,
        relay,
        // No live connection generation in this direct-call test: only the
        // heartbeat and terminal-close arms consult it.
        0,
        message,
        &idle_rtt_ingest(&RegionsConfig::default(), &pair_rtts::new_store()),
    );
}

#[tokio::test]
async fn a_notice_from_a_relay_not_serving_the_session_is_refused_before_any_effect() {
    // The cross-tenant forgery guard: relay 2 never served this session, so
    // nothing it reports for the victim tenant may reach the lifecycle, claim a
    // dedup entry, or (therefore) be signed with the tenant's key and posted.
    // Every notice kind the relay can report is behind the same gate — a new
    // one must join them rather than quietly bypass the check.
    let (setup, notices, lifecycle, session) =
        setup_with_session_and_notify(UNSERVED_HOOK.to_owned());

    for (kind, message) in notices_of_every_kind(session) {
        report(&setup, &notices, &lifecycle, RelayId(2), &message);
        assert_eq!(
            claimed_dedup_entries(&notices),
            0,
            "a {kind} notice from outside the serving set claims no dedup entry",
        );
        assert!(
            !lifecycle.contains_state(&tenant_id(), session),
            "a {kind} notice from outside the serving set records no session state",
        );
    }
}

#[tokio::test]
async fn a_notice_from_a_serving_relay_is_accounted_and_claims_its_dedup_entry() {
    let (setup, notices, lifecycle, session) =
        setup_with_session_and_notify(UNSERVED_HOOK.to_owned());

    for (_, message) in notices_of_every_kind(session) {
        report(&setup, &notices, &lifecycle, RelayId(1), &message);
    }

    assert_eq!(
        claimed_dedup_entries(&notices),
        4,
        "every kind the serving relay reported claimed its own dedup entry",
    );
    let load = lifecycle
        .load_state(&tenant_id(), session)
        .expect("the accepted notices created the session's state");
    assert_eq!(
        (load.connected_slots, load.started_slots, load.started_at_ms),
        (vec![SlotId(0)], vec![SlotId(0)], Some(1_700_000_000_000),),
        "each notice's fact landed on the lifecycle, not just on the webhook feed",
    );
}

#[tokio::test]
async fn a_notice_for_a_session_with_no_serving_record_is_still_honored() {
    // Post-restart tail: the coordinator holds no serving-relay record for the
    // session (created in a previous lifetime), so there is nothing to check the
    // reporter against and the notice must still be honored.
    let (setup, notices, lifecycle, _created) =
        setup_with_session_and_notify(UNSERVED_HOOK.to_owned());
    let unrecorded = SessionId(4242);

    for (kind, message) in notices_of_every_kind(unrecorded) {
        report(&setup, &notices, &lifecycle, RelayId(2), &message);
        assert!(
            lifecycle.contains_state(&tenant_id(), unrecorded),
            "with no serving record there is nothing to check against, so a \
             {kind} notice from any relay is honored",
        );
    }
    assert_eq!(
        claimed_dedup_entries(&notices),
        4,
        "each honored notice claimed its own dedup entry",
    );
}

#[tokio::test]
async fn a_reconnect_does_not_re_fire_slot_connected_and_the_first_start_instant_wins() {
    // The two dedup rules the tenant's load feed depends on. `slotConnected` is
    // keyed on `(tenant, session, slot)`, so a slot that drops and dials back in
    // updates the coordinator's record without telling the tenant its player
    // arrived twice. `sessionStarted` is keyed on `(tenant, session)` and the
    // first instant told wins, so a peer restating the latch after adopting the
    // directive can never displace the authority's stamp.
    let (setup, notices, lifecycle, session) =
        setup_with_session_and_notify(UNSERVED_HOOK.to_owned());

    let connected = |resumed: bool, at_ms: u64| {
        frame(&RelayToCoordinator::SlotConnected(SlotConnectedNotice {
            tenant: tenant_id(),
            session,
            slot: SlotId(0),
            external_id: Some("game-1".to_owned()),
            external_ref: Some("sb-user-0".to_owned()),
            resumed,
            connected_at_ms: at_ms,
        }))
    };
    let started = |at_ms: u64| {
        frame(&RelayToCoordinator::SessionStarted(SessionStartedNotice {
            tenant: tenant_id(),
            session,
            external_id: Some("game-1".to_owned()),
            started_at_ms: at_ms,
            initial_buffer_turns: Some(6),
        }))
    };

    report(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        &connected(false, 1),
    );
    report(&setup, &notices, &lifecycle, RelayId(1), &started(1_000));
    // The reconnect and the peer's later restatement.
    report(
        &setup,
        &notices,
        &lifecycle,
        RelayId(1),
        &connected(true, 2),
    );
    report(&setup, &notices, &lifecycle, RelayId(1), &started(9_999));

    assert_eq!(
        notices.slot_connects.lock().len(),
        1,
        "the reconnect is the same (tenant, session, slot): one entry, one webhook",
    );
    assert_eq!(
        notices.session_starts.lock().len(),
        1,
        "a session starts once, whoever restates it",
    );
    let load = lifecycle
        .load_state(&tenant_id(), session)
        .expect("the notices created the session's state");
    assert_eq!(
        load.started_at_ms,
        Some(1_000),
        "the first start instant told wins; the tenant may already have recorded it",
    );
    assert_eq!(
        load.connected_slots,
        vec![SlotId(0)],
        "the reconnect still updates the durable record the load-state read serves",
    );
}
