//! The ordered-log policy's own guarantees: the replay is the whole log, in
//! arrival order, exactly once per member, and it stops at the ceilings.

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::LobbyCommand;

use super::{Lobby, Probe, drain, line};
use crate::session::side_channel::LOBBY;
use crate::test_support::session_key;

/// A command carrying one opaque byte — what the replay-order and log-cap tests
/// below fill the log with.
fn command(slot: u32, byte: u8) -> LobbyCommand {
    LobbyCommand {
        slot,
        payload: vec![byte].into(),
    }
}

/// `(author, byte)` for each command queued on a member's receiver.
fn bytes(rx: &mut tokio::sync::mpsc::Receiver<LobbyCommand>) -> Vec<(u32, u8)> {
    let mut got = Vec::new();
    while let Ok(command) = rx.try_recv() {
        got.push((command.slot, command.payload[0]));
    }
    got
}

#[test]
fn a_command_appended_before_a_join_is_not_also_delivered_live() {
    // The exactly-once boundary for a channel that replays: a message already
    // retained when a member joins reaches it through the replay and is not
    // also fanned to it live. Nothing else asserts the absence of that
    // duplicate.
    let channel = Lobby::channel();
    let k = session_key(1);
    let _host = channel.register_member(&k, SlotId(0));
    channel.deliver(&k, Lobby::message(0, "before the join"));

    let mut peer = channel.register_member(&k, SlotId(1));
    assert_eq!(
        drain::<Lobby>(&mut peer),
        vec![line(0, "before the join")],
        "exactly one copy -- from the replay, never a second live delivery",
    );
}

#[test]
fn a_late_member_replays_the_whole_log_in_order_then_tails_live() {
    let channel = Lobby::channel();
    let k = session_key(1);
    // The host is up and authors setup commands before the peer's link exists.
    let _host = channel.register_member(&k, SlotId(0));
    channel.deliver(&k, command(0, 0x01));
    channel.deliver(&k, command(0, 0x02));
    channel.deliver(&k, command(0, 0x03));

    // The peer joins late: it replays every earlier command in arrival order.
    let mut peer = channel.register_member(&k, SlotId(1));
    assert_eq!(bytes(&mut peer), vec![(0, 0x01), (0, 0x02), (0, 0x03)]);

    // A live command after the join tails the replay with no gap, no dup.
    channel.deliver(&k, command(0, 0x04));
    assert_eq!(bytes(&mut peer), vec![(0, 0x04)]);
}

#[test]
fn replay_skips_a_reconnecting_members_own_authored_commands() {
    let channel = Lobby::channel();
    let k = session_key(1);
    let _host = channel.register_member(&k, SlotId(0));
    let _peer = channel.register_member(&k, SlotId(1));
    channel.deliver(&k, command(0, 0x10)); // host authored
    channel.deliver(&k, command(1, 0x20)); // peer authored

    // Slot 1 re-registers (a reconnect): it replays the host's command but not
    // its own, so it never re-applies a command it authored.
    let mut peer_again = channel.register_member(&k, SlotId(1));
    assert_eq!(bytes(&mut peer_again), vec![(0, 0x10)]);
}

#[test]
fn the_log_survives_a_members_deregistration() {
    // Unlike the chat channel's, a member leaving must not take the setup
    // stream with it -- whoever joins next still has to catch up on it.
    let channel = Lobby::channel();
    let k = session_key(1);
    let _host = channel.register_member(&k, SlotId(0));
    channel.deliver(&k, command(0, 0x01));
    channel.deregister_member(&k, SlotId(0));

    let mut late = channel.register_member(&k, SlotId(1));
    assert_eq!(bytes(&mut late), vec![(0, 0x01)]);
}

#[test]
fn the_log_stops_growing_past_the_message_cap_and_deliver_reports_it() {
    // `deliver`'s own admission concern is the session-wide log cap, not the
    // rate cap (that is `admit`, checked separately by the caller before
    // `deliver` is ever reached). Its bool is the caller's cue for whether to
    // also forward the command across the mesh: a command this relay refused
    // was never logged or fanned to its own locals, so a peer that received it
    // anyway would be out of sync with it.
    let channel = Lobby::channel();
    let k = session_key(1);
    let mut peer = channel.register_member(&k, SlotId(1));
    // Author the whole cap from slot 0, so the peer receives them all.
    for i in 0..LOBBY.replay.max_messages {
        assert!(
            channel.deliver(&k, command(0, i as u8)),
            "command {i} is still under the log cap",
        );
    }
    assert!(
        !channel.deliver(&k, command(0, 0)),
        "the cap is exhausted; deliver refuses",
    );
    assert!(
        !channel.deliver(&k, command(0, 0)),
        "and the overflow latch keeps refusing",
    );

    // The peer received exactly the cap's worth — the refused commands were
    // dropped, not fanned out.
    assert_eq!(bytes(&mut peer).len(), LOBBY.replay.max_messages);

    // And a member joining afterwards replays exactly the cap's worth, the
    // truncated but consistent prefix.
    let mut late = channel.register_member(&k, SlotId(2));
    assert_eq!(bytes(&mut late).len(), LOBBY.replay.max_messages);
}

#[test]
fn the_log_stops_growing_past_the_byte_cap() {
    // The bound's other half: a session far under the message count can still
    // pin memory with a few large payloads, so the running byte total is what
    // has to refuse here.
    let channel = Lobby::channel();
    let k = session_key(1);
    let big = LobbyCommand {
        slot: 0,
        payload: vec![0u8; LOBBY.replay.max_bytes * 2 / 3].into(),
    };
    assert!(
        channel.deliver(&k, big.clone()),
        "the first payload fits under the byte cap",
    );
    assert!(
        !channel.deliver(&k, big),
        "the second would cross it, and is refused far under the message cap",
    );
}
