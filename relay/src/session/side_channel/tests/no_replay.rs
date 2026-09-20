//! The no-replay policy's own guarantees: nothing is retained, so nothing is
//! ever caught up on — and nothing is held for a session no local member
//! registered on.

use rally_point_proto::ids::SlotId;

use super::{Chat, Probe, drain, line};
use crate::test_support::session_key;

#[test]
fn a_member_registered_after_a_message_never_sees_it() {
    // The load-bearing difference from the lobby channel: no replay log, so a
    // message delivered before a member joins is simply missed, not replayed to
    // it later.
    let channel = Chat::channel();
    let k = session_key(1);
    let _host = channel.register_member(&k, SlotId(0));
    channel.deliver(&k, Chat::message(0, "before you joined"));

    let mut late = channel.register_member(&k, SlotId(1));
    assert_eq!(
        drain::<Chat>(&mut late),
        vec![],
        "chat is ephemeral -- a late joiner gets no replay",
    );

    // But it does tail live messages from that point on.
    channel.deliver(&k, Chat::message(0, "hi"));
    assert_eq!(drain::<Chat>(&mut late), vec![line(0, "hi")]);
}

#[test]
fn a_delivery_with_no_members_creates_no_state_and_still_reports_admitted() {
    // A mesh copy for a session this relay homes no member of has nothing to
    // retain and nobody to fan to, so it must not start holding state for that
    // session -- there is no local teardown coming to sweep it. It still
    // reports admitted: a channel that retains nothing refuses nothing.
    let channel = Chat::channel();
    let k = session_key(1);
    assert!(channel.deliver(&k, Chat::message(7, "from relay B")));

    // Nothing was kept: a member registering afterwards sees an empty channel,
    // exactly as it would have before the delivery.
    let mut late = channel.register_member(&k, SlotId(0));
    assert_eq!(drain::<Chat>(&mut late), vec![]);
}
