//! The latest-per-slot policy's own guarantees: a re-send replaces rather than
//! appends, the replay is one message per slot, and the map's distinct-slot
//! ceiling refuses only genuinely new slots.

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::PlayerSkin;

use super::{Probe, Skin, drain, line};
use crate::session::side_channel::SKIN;
use crate::test_support::session_key;

/// A blob carrying one opaque byte — what the map-shape tests below fill the
/// latest-per-slot map with.
fn skin(slot: u32, byte: u8) -> PlayerSkin {
    PlayerSkin {
        slot,
        payload: vec![byte].into(),
    }
}

/// `(author, byte)` for each blob queued on a member's receiver.
fn bytes(rx: &mut tokio::sync::mpsc::Receiver<PlayerSkin>) -> Vec<(u32, u8)> {
    let mut got = Vec::new();
    while let Ok(skin) = rx.try_recv() {
        got.push((skin.slot, skin.payload[0]));
    }
    got
}

#[test]
fn a_blob_stored_before_a_join_is_not_also_delivered_live() {
    // The exactly-once boundary for a channel that replays: a blob already
    // retained when a member joins reaches it through the replay and is not
    // also fanned to it live.
    let channel = Skin::channel();
    let k = session_key(1);
    let _host = channel.register_member(&k, SlotId(0));
    channel.deliver(&k, Skin::message(0, "before the join"));

    let mut peer = channel.register_member(&k, SlotId(1));
    assert_eq!(
        drain::<Skin>(&mut peer),
        vec![line(0, "before the join")],
        "exactly one copy -- from the replay, never a second live delivery",
    );
}

#[test]
fn a_late_member_replays_stored_blobs_but_not_its_own() {
    let channel = Skin::channel();
    let k = session_key(1);
    // Two members are up and each broadcasts a blob before the third joins.
    let _host = channel.register_member(&k, SlotId(0));
    let _peer = channel.register_member(&k, SlotId(1));
    channel.deliver(&k, skin(0, 0x01));
    channel.deliver(&k, skin(1, 0x02));

    // Slot 1 re-registers (a reconnect): it replays the host's blob but not its
    // own, so it never re-applies a blob it authored.
    let mut peer_again = channel.register_member(&k, SlotId(1));
    assert_eq!(bytes(&mut peer_again), vec![(0, 0x01)]);

    // A fresh late joiner replays every stored slot's blob (neither is its
    // own), and tails a live blob after with no gap or dup.
    let mut late = channel.register_member(&k, SlotId(2));
    let mut got = bytes(&mut late);
    got.sort_unstable();
    assert_eq!(got, vec![(0, 0x01), (1, 0x02)]);
    channel.deliver(&k, skin(0, 0x03));
    assert_eq!(bytes(&mut late), vec![(0, 0x03)]);
}

#[test]
fn a_re_sent_blob_replaces_so_a_late_joiner_gets_only_the_latest() {
    let channel = Skin::channel();
    let k = session_key(1);
    let _host = channel.register_member(&k, SlotId(0));
    // Slot 0 broadcasts twice — the second supersedes the first.
    channel.deliver(&k, skin(0, 0x10));
    channel.deliver(&k, skin(0, 0x11));

    // A late joiner replays exactly one blob for slot 0: the newest.
    let mut late = channel.register_member(&k, SlotId(1));
    assert_eq!(bytes(&mut late), vec![(0, 0x11)]);
}

#[test]
fn a_new_slot_past_the_map_cap_is_refused_but_a_re_send_still_admits() {
    let channel = Skin::channel();
    let k = session_key(1);
    // Fill the map to its cap with distinct authoring slots. (A distinct slot
    // per blob so no one slot's rate cap interferes; deliver does not consult
    // the rate limiter, so this only exercises the map's slot cap.)
    for i in 0..SKIN.replay.max_slots {
        assert!(
            channel.deliver(&k, skin(i as u32, 0)),
            "slot {i} should still be under the map cap",
        );
    }
    // A brand-new authoring slot is refused — the map is full.
    assert!(
        !channel.deliver(&k, skin(SKIN.replay.max_slots as u32, 0)),
        "a new slot past the map cap is refused",
    );
    // But a slot already in the map re-sends fine (it replaces, not grows).
    assert!(
        channel.deliver(&k, skin(0, 0x99)),
        "a re-send from an existing slot is always admitted",
    );
}

#[test]
fn a_slot_id_out_of_range_is_refused_rather_than_aliased() {
    // The author is relay-stamped upstream, so this is unreachable in practice
    // — but it is the one place a slot id wider than a real slot could silently
    // truncate onto a valid slot's entry, so the refusal is asserted rather
    // than assumed.
    let channel = Skin::channel();
    let k = session_key(1);
    let mut member = channel.register_member(&k, SlotId(0));
    assert!(!channel.deliver(&k, skin(300, 0x01)));
    assert_eq!(
        bytes(&mut member),
        vec![],
        "nothing out of range is ever fanned out",
    );
    // And it left no entry behind for a late joiner to replay.
    let mut late = channel.register_member(&k, SlotId(1));
    assert_eq!(bytes(&mut late), vec![]);
}
