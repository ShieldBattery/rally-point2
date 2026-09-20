//! The side channels' tests, split the way the type is: everything that is not
//! the replay policy is asserted once in [`shared`], generically over the three
//! configured channels; a guarantee that belongs to exactly one policy lives in
//! that policy's own file.

use tokio::sync::mpsc;

use rally_point_proto::messages::{GameChat, LobbyCommand, PlayerSkin};

use crate::session::side_channel::{
    CHAT, LOBBY, LatestPerSlot, NoReplay, OrderedLog, ReplayPolicy, SKIN, SideChannel,
};

mod latest_per_slot;
mod no_replay;
mod ordered_log;
mod shared;

/// One configured channel as the test bodies drive it. The registry, the caps
/// and the lifecycle are the same code for all three, so a probe only has to
/// say which channel it is and how to build and read back its message type.
trait Probe {
    /// The replay policy the channel is configured with.
    type Policy: ReplayPolicy;

    /// A fresh channel with this row's production caps.
    fn channel() -> SideChannel<Self::Policy>;

    /// A message stamped as authored by `slot`, carrying `body`.
    fn message(slot: u32, body: &str) -> <Self::Policy as ReplayPolicy>::Message;

    /// `(author, body)` — what a member's receiver yields.
    fn parts(message: &<Self::Policy as ReplayPolicy>::Message) -> (u32, String);
}

/// The lobby row: an ordered replay log.
struct Lobby;

impl Probe for Lobby {
    type Policy = OrderedLog<LobbyCommand>;

    fn channel() -> SideChannel<Self::Policy> {
        SideChannel::new(LOBBY)
    }

    fn message(slot: u32, body: &str) -> LobbyCommand {
        LobbyCommand {
            slot,
            payload: body.as_bytes().to_vec().into(),
        }
    }

    fn parts(message: &LobbyCommand) -> (u32, String) {
        (
            message.slot,
            String::from_utf8(message.payload.to_vec()).expect("test payloads are text"),
        )
    }
}

/// The chat row: no replay at all.
struct Chat;

impl Probe for Chat {
    type Policy = NoReplay<GameChat>;

    fn channel() -> SideChannel<Self::Policy> {
        SideChannel::new(CHAT)
    }

    fn message(slot: u32, body: &str) -> GameChat {
        GameChat {
            slot,
            target_kind: 0,
            target_slot: 0,
            text: body.to_owned(),
        }
    }

    fn parts(message: &GameChat) -> (u32, String) {
        (message.slot, message.text.clone())
    }
}

/// The skin row: the latest message per authoring slot.
struct Skin;

impl Probe for Skin {
    type Policy = LatestPerSlot<PlayerSkin>;

    fn channel() -> SideChannel<Self::Policy> {
        SideChannel::new(SKIN)
    }

    fn message(slot: u32, body: &str) -> PlayerSkin {
        PlayerSkin {
            slot,
            payload: body.as_bytes().to_vec().into(),
        }
    }

    fn parts(message: &PlayerSkin) -> (u32, String) {
        (
            message.slot,
            String::from_utf8(message.payload.to_vec()).expect("test payloads are text"),
        )
    }
}

/// Everything currently queued on a member's receiver, in delivery order — the
/// member's slot-link task would write these to its control stream in exactly
/// this order.
fn drain<P: Probe>(
    rx: &mut mpsc::Receiver<<P::Policy as ReplayPolicy>::Message>,
) -> Vec<(u32, String)> {
    let mut got = Vec::new();
    while let Ok(message) = rx.try_recv() {
        got.push(P::parts(&message));
    }
    got
}

/// One expected `(author, body)` line, as [`drain`] yields it.
fn line(author: u32, body: &str) -> (u32, String) {
    (author, body.to_owned())
}
