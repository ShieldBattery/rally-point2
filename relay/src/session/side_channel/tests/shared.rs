//! What every side channel owes regardless of its replay policy: the author
//! exclusion, the member lifecycle, and the two admission caps. Each body is
//! written once, generic over a [`Probe`], and instantiated for every row the
//! guarantee applies to — never written three times.

use rally_point_proto::ids::SlotId;

use super::{Chat, Lobby, Probe, Skin, drain, line};
use crate::session::side_channel::{CHAT, LOBBY, SKIN};
use crate::test_support::session_key;

/// The author is never echoed its own message — its own game applied it
/// locally — while every other local member receives it. A mesh-received
/// message carries a remote author no local member matches, so it reaches every
/// one of them.
fn the_author_is_skipped_and_every_other_member_is_reached<P: Probe>() {
    let channel = P::channel();
    let k = session_key(1);
    let mut host = channel.register_member(&k, SlotId(0));
    let mut peer = channel.register_member(&k, SlotId(1));

    channel.deliver(&k, P::message(0, "from the host"));
    assert_eq!(
        drain::<P>(&mut host),
        vec![],
        "the author is not echoed its own",
    );
    assert_eq!(drain::<P>(&mut peer), vec![line(0, "from the host")]);

    // Authored by a remote slot and arriving off the mesh: neither local member
    // is its author, so both of them receive it.
    channel.deliver(&k, P::message(7, "from relay B"));
    assert_eq!(drain::<P>(&mut host), vec![line(7, "from relay B")]);
    assert_eq!(drain::<P>(&mut peer), vec![line(7, "from relay B")]);
}

/// A deregistered member stops receiving — its slot-link task has ended, so
/// nothing may keep filling a queue nobody drains — while the members that
/// remain are undisturbed. Ending the session then drops the state wholesale,
/// so a fresh join starts from empty.
fn a_deregistered_member_stops_receiving_and_end_session_clears_the_state<P: Probe>() {
    let channel = P::channel();
    let k = session_key(1);
    let mut leaving = channel.register_member(&k, SlotId(0));
    let mut staying = channel.register_member(&k, SlotId(1));

    channel.deliver(&k, P::message(7, "first"));
    channel.deregister_member(&k, SlotId(0));
    channel.deliver(&k, P::message(7, "second"));

    assert_eq!(
        drain::<P>(&mut leaving),
        vec![line(7, "first")],
        "the removed member received nothing fanned out after its deregistration",
    );
    assert_eq!(
        drain::<P>(&mut staying),
        vec![line(7, "first"), line(7, "second")],
        "the remaining member is undisturbed",
    );

    channel.end_session(&k);
    let mut after = channel.register_member(&k, SlotId(1));
    assert_eq!(
        drain::<P>(&mut after),
        vec![],
        "a join after end_session has nothing to catch up on",
    );
}

/// The rate cap's burst-then-reject half: an authoring slot may spend its whole
/// burst back-to-back, and the next message inside the window is refused.
/// Recovery after a refill is the token bucket's own test
/// (`crate::rate_limit`), driven off synthetic instants rather than a real wait
/// on the production interval.
fn a_burst_past_the_rate_cap_is_rejected<P: Probe>(burst: u32) {
    let channel = P::channel();
    let k = session_key(1);
    for _ in 0..burst {
        assert!(channel.admit(&k, SlotId(0), 4));
    }
    assert!(!channel.admit(&k, SlotId(0), 4));
}

/// The cap is keyed per authoring slot, so one flooding member can never spend
/// another member's budget.
fn the_rate_cap_is_independent_per_slot<P: Probe>(burst: u32) {
    let channel = P::channel();
    let k = session_key(1);
    for _ in 0..burst {
        assert!(channel.admit(&k, SlotId(0), 4));
    }
    assert!(
        !channel.admit(&k, SlotId(0), 4),
        "slot 0 exhausted its burst",
    );
    assert!(
        channel.admit(&k, SlotId(1), 4),
        "a different slot has its own, untouched budget",
    );
}

/// The size cap's exact boundary: a message sized at the cap is admitted, one
/// byte past it is refused.
fn the_size_cap_admits_exactly_its_boundary<P: Probe>(cap: usize) {
    let channel = P::channel();
    let k = session_key(1);
    assert!(channel.admit(&k, SlotId(0), cap));
    assert!(!channel.admit(&k, SlotId(0), cap + 1));
}

/// A channel with no size cap ignores the length it is handed: what bounds it
/// is its replay policy's session-wide ceiling, not one message's size.
fn an_unconfigured_size_cap_admits_any_length<P: Probe>() {
    let channel = P::channel();
    let k = session_key(1);
    assert!(channel.admit(&k, SlotId(0), usize::MAX));
}

#[test]
fn lobby_skips_the_author_and_reaches_every_other_member() {
    the_author_is_skipped_and_every_other_member_is_reached::<Lobby>();
}

#[test]
fn chat_skips_the_author_and_reaches_every_other_member() {
    the_author_is_skipped_and_every_other_member_is_reached::<Chat>();
}

#[test]
fn skin_skips_the_author_and_reaches_every_other_member() {
    the_author_is_skipped_and_every_other_member_is_reached::<Skin>();
}

#[test]
fn lobby_deregister_removes_a_member_and_end_session_clears_the_state() {
    a_deregistered_member_stops_receiving_and_end_session_clears_the_state::<Lobby>();
}

#[test]
fn chat_deregister_removes_a_member_and_end_session_clears_the_state() {
    a_deregistered_member_stops_receiving_and_end_session_clears_the_state::<Chat>();
}

#[test]
fn skin_deregister_removes_a_member_and_end_session_clears_the_state() {
    a_deregistered_member_stops_receiving_and_end_session_clears_the_state::<Skin>();
}

#[test]
fn a_lobby_burst_past_the_rate_cap_is_rejected() {
    a_burst_past_the_rate_cap_is_rejected::<Lobby>(LOBBY.rate_burst);
}

#[test]
fn a_chat_burst_past_the_rate_cap_is_rejected() {
    a_burst_past_the_rate_cap_is_rejected::<Chat>(CHAT.rate_burst);
}

#[test]
fn a_skin_burst_past_the_rate_cap_is_rejected() {
    a_burst_past_the_rate_cap_is_rejected::<Skin>(SKIN.rate_burst);
}

#[test]
fn the_lobby_rate_cap_is_independent_per_slot() {
    the_rate_cap_is_independent_per_slot::<Lobby>(LOBBY.rate_burst);
}

#[test]
fn the_chat_rate_cap_is_independent_per_slot() {
    the_rate_cap_is_independent_per_slot::<Chat>(CHAT.rate_burst);
}

#[test]
fn the_skin_rate_cap_is_independent_per_slot() {
    the_rate_cap_is_independent_per_slot::<Skin>(SKIN.rate_burst);
}

#[test]
fn oversize_chat_text_is_rejected_by_admit() {
    the_size_cap_admits_exactly_its_boundary::<Chat>(
        CHAT.message_max_bytes.expect("chat caps a message's size"),
    );
}

#[test]
fn an_oversize_skin_payload_is_rejected_by_admit() {
    the_size_cap_admits_exactly_its_boundary::<Skin>(
        SKIN.message_max_bytes.expect("skins cap a blob's size"),
    );
}

#[test]
fn the_lobby_admits_any_command_length() {
    // The lobby caps a session's whole log, not one command's size -- a
    // game-init that seeds the synced RNG is legitimately far larger than a
    // chat line.
    assert!(LOBBY.message_max_bytes.is_none());
    an_unconfigured_size_cap_admits_any_length::<Lobby>();
}
