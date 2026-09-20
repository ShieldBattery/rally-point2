//! The three configured side channels — one table, three rows — and the bundle
//! the per-session tasks carry them in.

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{GameChat, LobbyCommand, PlayerSkin};
use tokio::sync::mpsc;

use std::time::Duration;

use crate::key::SessionKey;
use crate::session::side_channel::{
    LatestPerSlot, LogLimits, NoReplay, OrderedLog, SideChannel, SideChannelConfig,
    SideChannelMessage, SlotMapLimits,
};

impl SideChannelMessage for LobbyCommand {
    fn author(&self) -> u32 {
        self.slot
    }

    fn retained_bytes(&self) -> usize {
        self.payload.len()
    }
}

impl SideChannelMessage for GameChat {
    fn author(&self) -> u32 {
        self.slot
    }

    fn retained_bytes(&self) -> usize {
        self.text.len()
    }
}

impl SideChannelMessage for PlayerSkin {
    fn author(&self) -> u32 {
        self.slot
    }

    fn retained_bytes(&self) -> usize {
        self.payload.len()
    }
}

/// Pre-game lobby-command fan-out with its ordered replay log.
///
/// Before a game starts, the host's game authors the lobby's setup commands —
/// slot and color assignments, the game-init that seeds the synced RNG — and
/// every other session member must apply that byte stream, in the order the
/// host emitted it, before the first turn. Members also author their own small
/// requests (a join, a ready toggle, a race change) that must reach the host
/// and the other members.
pub type LobbyChannel = SideChannel<OrderedLog<LobbyCommand>>;

/// Mid-game game-chat fan-out — the reliable, ephemeral in-game chat channel.
///
/// Once the game starts, members still need to reach each other's chat UI, and
/// chat has no datagram turn stream to ride (no simulated step to key a turn
/// on), so it travels the reliable control stream as a `GameChat`.
pub type ChatChannel = SideChannel<NoReplay<GameChat>>;

/// Cosmetic-skin fan-out with its latest-blob-per-slot replay map.
///
/// Near game start each session member broadcasts one opaque cosmetic-skin blob
/// — the game's own serialized skin state — so every other member can render it
/// with the cosmetics that member chose. Like a chat message and a lobby
/// command, a skin blob has no simulated step to key a turn on, so it rides the
/// reliable control stream as a `PlayerSkin`.
pub type SkinChannel = SideChannel<LatestPerSlot<PlayerSkin>>;

/// The lobby channel's caps.
pub const LOBBY: SideChannelConfig<LogLimits> = SideChannelConfig {
    name: "lobby",
    // Sized above the log's message ceiling so a full replay always fits with
    // headroom for the live commands that can arrive while a newcomer is still
    // draining its replay.
    push_capacity: 2048,
    // No per-command size cap: what bounds a lobby is the whole session's log,
    // not one command's size (a legitimate game-init is much larger than a chat
    // line, and the log's byte ceiling already bounds the total).
    message_max_bytes: None,
    // Setup is a burst authored by one slot (almost always the host): a full
    // 8-player lobby's slot, color, race and team assignments plus the game-init
    // that seeds the synced RNG is on the order of thirty commands, all emitted
    // back-to-back the moment the host's UI populates, with nothing pacing them
    // (unlike chat, no human types that fast). 32 covers that whole burst from a
    // single slot with a little room to spare, while still bounding a flooding
    // client to a small, cheap admission check per command.
    rate_burst: 32,
    // Ordinary post-setup lobby traffic is a member's own occasional request (a
    // ready toggle, a race or team change) — nothing close to chat's typing
    // cadence, let alone a flood. 200ms (5/sec sustained) is generous enough
    // that a player rapidly clicking through settings is never throttled, while
    // still keeping a misbehaving or hostile client's sustained rate an order of
    // magnitude below what could meaningfully grow the mesh control channel or
    // the local push queues.
    rate_refill: Duration::from_millis(200),
    replay: LogLimits {
        // A real lobby is a burst of setup commands and a handful of per-member
        // requests — tens, not thousands — so this is far above any legitimate
        // session.
        max_messages: 1024,
        // Like the count cap, far above any real lobby; it is what stops a few
        // large payloads pinning memory under the count ceiling.
        max_bytes: 256 * 1024,
    },
};

/// The chat channel's caps.
///
/// Size and rate are the relay's own enforced boundary — unlike `target_kind`
/// (see `GameChat` in wire.proto), which the relay deliberately does NOT check:
/// scope is a receiver-side display hint, so filtering it here would be purely
/// advisory against a modified client anyway (which could just as easily choose
/// to display every message it receives), exactly the trust model native SC:R's
/// own channel-based chat has always had. Size and rate are different: they
/// bound the relay's own resource use (buffered memory, fan-out volume), so
/// those the relay enforces regardless of what any client would otherwise
/// choose to send.
pub const CHAT: SideChannelConfig<()> = SideChannelConfig {
    name: "chat",
    // Chat is bursty but small (a human typing, or a short flurry of "gg"s), and
    // the fan-out is non-blocking, so a generous backstop against a scheduling
    // hiccup is enough; this is not a tuned buffer.
    push_capacity: 256,
    // A real chat line is at most a couple hundred characters; this is
    // comfortably above any real message while well under the control frame's
    // own 64 KiB cap (`rally_point_proto::control_stream::MAX_CONTROL_FRAME_LEN`),
    // so an over-cap message is a misbehaving or hostile client, not a real
    // player typing a long line.
    message_max_bytes: Some(256),
    // Loose enough for a human typing quickly.
    rate_burst: 8,
    // Tight enough that a flooding client is throttled to two messages a second.
    rate_refill: Duration::from_millis(500),
    // Chat retains nothing, so it has no retention ceiling to configure.
    replay: (),
};

/// The skin channel's caps.
pub const SKIN: SideChannelConfig<SlotMapLimits> = SideChannelConfig {
    name: "skin",
    // A replay is at most one blob per authoring slot, so this is sized above
    // the map's slot ceiling: a full map replay always fits with headroom for
    // the live blobs that can arrive while a newcomer is still draining it.
    push_capacity: 64,
    // A real cosmetic-skin blob is a few hundred bytes; this is comfortably
    // above any real blob while bounding the relay's per-slot map memory, and
    // well under the control frame's own 64 KiB cap, so an over-cap blob is a
    // misbehaving or hostile client, not a real player.
    message_max_bytes: Some(2048),
    // A member legitimately sends one blob per game, maybe a couple on a
    // re-send, so this small burst covers every honest use while bounding a
    // flooding client.
    rate_burst: 4,
    // Skin blobs flow at most a handful of times per game (nothing like chat's
    // typing cadence), so a slow refill is ample for every honest use while
    // throttling a misbehaving client hard.
    rate_refill: Duration::from_secs(10),
    replay: SlotMapLimits {
        // A session tops out at 16 members, so this is far above any real
        // session; at the blob size cap it bounds a session's map to 64 KiB.
        max_slots: 32,
    },
};

/// The three per-session side channels, held together because they are used
/// together: every slot link registers on all three as its control stream comes
/// up, deregisters from all three as it ends, and every session teardown sweeps
/// all three at once. A fourth kind of side traffic is added by adding a row to
/// the table above and a field here, not by finding the lockstep call sites.
#[derive(Clone)]
pub struct SideChannels {
    /// Pre-game lobby commands and the ordered log a late-joining member
    /// catches up from.
    pub lobby: LobbyChannel,
    /// In-game chat. The mid-game counterpart to `lobby`, with no replay.
    pub chat: ChatChannel,
    /// Cosmetic skin blobs and the latest-per-slot map replayed on register.
    pub skins: SkinChannel,
}

impl Default for SideChannels {
    /// Empty channels with the production caps, for a relay serving no session
    /// yet.
    fn default() -> Self {
        SideChannels {
            lobby: SideChannel::new(LOBBY),
            chat: SideChannel::new(CHAT),
            skins: SideChannel::new(SKIN),
        }
    }
}

/// The three receivers one slot-link task drains, one per side channel, each
/// already carrying whatever its channel replayed to this member.
pub struct SideChannelReceivers {
    /// This member's lobby-command receiver, pre-loaded with the session's
    /// replay log (minus any command this member authored itself) in arrival
    /// order, ahead of any live command.
    pub lobby: mpsc::Receiver<LobbyCommand>,
    /// This member's chat receiver. Nothing to catch up on: chat is ephemeral,
    /// so this member simply starts tailing whatever is delivered from here on.
    pub chat: mpsc::Receiver<GameChat>,
    /// This member's skin receiver, pre-loaded with every other slot's latest
    /// blob (unordered — a map, not a sequence), ahead of any live blob.
    pub skins: mpsc::Receiver<PlayerSkin>,
}

impl SideChannels {
    /// Registers `slot` as a member of all three channels for `key`, returning
    /// the receivers its slot-link task drains. Called as the slot's control
    /// stream comes up, which is what makes each channel's replay land ahead of
    /// anything live — see
    /// [`SideChannel::register_member`](super::SideChannel::register_member).
    pub(crate) fn register_member(&self, key: &SessionKey, slot: SlotId) -> SideChannelReceivers {
        SideChannelReceivers {
            lobby: self.lobby.register_member(key, slot),
            chat: self.chat.register_member(key, slot),
            skins: self.skins.register_member(key, slot),
        }
    }

    /// Drops `slot`'s membership in all three channels — its slot-link task has
    /// ended. The session-scoped state behind each channel stays.
    pub(crate) fn deregister_member(&self, key: &SessionKey, slot: SlotId) {
        self.lobby.deregister_member(key, slot);
        self.chat.deregister_member(key, slot);
        self.skins.deregister_member(key, slot);
    }

    /// Drops all three channels' state for `key`.
    pub(crate) fn end_session(&self, key: &SessionKey) {
        self.lobby.end_session(key);
        self.chat.end_session(key);
        self.skins.end_session(key);
    }
}
