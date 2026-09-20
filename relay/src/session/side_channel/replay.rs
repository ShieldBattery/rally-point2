//! What a side channel keeps for a member that was not there when a message
//! was delivered — the one axis the three channels differ on.

use std::collections::HashMap;
use std::marker::PhantomData;

use rally_point_proto::ids::SlotId;

use crate::rate_limit::RateLimitedCounter;
use crate::session::side_channel::{SideChannelMessage, Warn};

/// The replay policy one [`SideChannel`](super::SideChannel) is parameterized
/// by: what it retains from each delivery, and what a newly registered member
/// is replayed.
///
/// A policy owns the state its own ceilings bound, so the ceilings are typed to
/// it ([`Limits`](Self::Limits)) and the refusal warning is its to emit. The
/// registry around it owns everything a policy does not vary: the member
/// channels, the rate and size caps, the author exclusion, the lock.
pub trait ReplayPolicy: Default {
    /// The message this policy retains.
    type Message: SideChannelMessage;
    /// The ceilings that bound what this policy retains. `()` for a policy that
    /// retains nothing, so a channel that keeps no state cannot be handed a cap
    /// for state it does not have.
    type Limits: Copy;

    /// Whether this policy retains anything at all. A channel that retains
    /// nothing never creates per-session state on delivery alone — see
    /// [`SideChannel::deliver`](super::SideChannel::deliver).
    const RETAINS: bool;

    /// Offers `message` to the policy before it is fanned out, returning
    /// whether it may be delivered. A refusal is the policy's session-wide
    /// ceiling saying no: the message is neither retained nor fanned out, and
    /// the caller is told so it does not forward a copy across the mesh either.
    fn retain(&mut self, message: &Self::Message, limits: &Self::Limits, warn: Warn<'_>) -> bool;

    /// The retained messages a newly registered member replays, in the order it
    /// must apply them.
    fn replay(&self) -> impl Iterator<Item = &Self::Message>;
}

/// Retain nothing: a member whose control stream comes up after a message
/// flowed simply never sees that message.
///
/// The policy for **chat**, and the one load-bearing difference from the lobby
/// channel. A lobby command's ordered log exists because a missed setup command
/// leaves a member's pre-game state permanently incomplete, and the host can
/// emit commands before every member has dialed in. Chat has neither property —
/// there is no game state a missed chat line could corrupt, and a member whose
/// stream comes up late misses what was said the same way a real chat client
/// that was offline for a moment does.
pub struct NoReplay<M>(PhantomData<M>);

impl<M> Default for NoReplay<M> {
    fn default() -> Self {
        NoReplay(PhantomData)
    }
}

impl<M: SideChannelMessage> ReplayPolicy for NoReplay<M> {
    type Message = M;
    type Limits = ();

    const RETAINS: bool = false;

    fn retain(&mut self, _message: &M, _limits: &(), _warn: Warn<'_>) -> bool {
        true
    }

    fn replay(&self) -> impl Iterator<Item = &M> {
        std::iter::empty()
    }
}

/// The ceilings on an [`OrderedLog`]. Defensive, not tuning: a session past
/// either one is a misbehaving client, so the log stops growing rather than
/// growing without limit.
#[derive(Debug, Clone, Copy)]
pub struct LogLimits {
    /// The largest number of messages one session's log retains.
    pub max_messages: usize,
    /// The largest total payload bytes one session's log retains. Bounds the
    /// memory a misbehaving client can pin across the log even if each message
    /// is small.
    pub max_bytes: usize,
}

/// Retain every message in arrival order and replay the whole log to a member
/// that joins later.
///
/// The policy for **lobby commands**. Setup runs while members are still
/// dialing in with real clock skew, and nothing back-pressures the host: its
/// own local turn barrier is satisfied, so its lobby machine can emit setup
/// commands before a given member's link even exists. A plain fan-out would
/// deliver those commands to nobody and lose them. Every command delivered is
/// therefore appended here, and a member whose control stream comes up later
/// replays the log in arrival order, before any live command — so every member
/// ends up with the identical sequence regardless of when it joined.
///
/// The log is phase-agnostic: the relay forwards and logs without gating on
/// game-started (usage keeps this to the lobby phase).
///
/// Once either ceiling is hit the overflow latch stays set and further messages
/// are refused, so a late joiner replays a truncated but *consistent prefix*
/// rather than the relay growing the log without bound.
pub struct OrderedLog<M> {
    /// Every message delivered for this session, in arrival order — the replay
    /// source for a member whose stream comes up after messages flowed.
    log: Vec<M>,
    /// Running byte total of `log`'s payloads, for the byte ceiling.
    log_bytes: usize,
    /// Whether the log has hit a ceiling. Once set, further messages are
    /// dropped (the session is misbehaving).
    overflowed: bool,
}

impl<M> Default for OrderedLog<M> {
    fn default() -> Self {
        OrderedLog {
            log: Vec::new(),
            log_bytes: 0,
            overflowed: false,
        }
    }
}

impl<M: SideChannelMessage> ReplayPolicy for OrderedLog<M> {
    type Message = M;
    type Limits = LogLimits;

    const RETAINS: bool = true;

    fn retain(&mut self, message: &M, limits: &LogLimits, warn: Warn<'_>) -> bool {
        if self.overflowed {
            return false;
        }
        let new_bytes = message.retained_bytes();
        if self.log.len() >= limits.max_messages
            || self.log_bytes.saturating_add(new_bytes) > limits.max_bytes
        {
            self.overflowed = true;
            tracing::warn!(
                tenant = warn.key.tenant.as_ref(),
                session = warn.key.session.0,
                channel = warn.channel,
                messages = self.log.len(),
                bytes = self.log_bytes,
                "side-channel replay log exceeded its cap; dropping this and further messages",
            );
            return false;
        }
        self.log.push(message.clone());
        self.log_bytes += new_bytes;
        true
    }

    fn replay(&self) -> impl Iterator<Item = &M> {
        self.log.iter()
    }
}

/// The ceiling on a [`LatestPerSlot`] map.
#[derive(Debug, Clone, Copy)]
pub struct SlotMapLimits {
    /// The largest number of distinct authoring slots one session's map
    /// retains — a defensive cap. A session that blows it is misbehaving, and
    /// the map stops admitting new slots rather than growing without limit.
    pub max_slots: usize,
}

/// Retain only each authoring slot's newest message and replay all of them to a
/// member that joins later.
///
/// The policy for **cosmetic skins**, and the load-bearing difference from both
/// siblings. A skin is one-shot *state*, not a stream of events: unlike chat
/// (ephemeral — a member whose stream comes up after a message flowed simply
/// missed it), a member that registers late or reconnects must still end up
/// with every other member's *current* blob. And unlike an ordered log (where
/// every message is distinct and order matters), a slot's newer blob wholly
/// supersedes its older one — only the latest matters. So a re-send from a slot
/// already in the map *replaces* its entry rather than appending, and a late
/// joiner replays only the newest message per slot. Receivers apply a blob
/// idempotently, so a replayed duplicate a reconnect produces is harmless.
///
/// A slot already present in the map is always admitted (a re-send replaces
/// without growing the map); only a *new* authoring slot that would push the
/// map past its ceiling is refused.
pub struct LatestPerSlot<M> {
    /// The latest message each authoring slot broadcast — the replay source for
    /// a member whose stream comes up after messages flowed.
    latest: HashMap<SlotId, M>,
    /// Rate-limited warn counter for the distinct-slot-cap refusal —
    /// session-wide because the refused slot is one not yet in the map, so
    /// there is no per-slot budget to key it on.
    slot_cap_warns: RateLimitedCounter,
}

impl<M> Default for LatestPerSlot<M> {
    fn default() -> Self {
        LatestPerSlot {
            latest: HashMap::new(),
            slot_cap_warns: RateLimitedCounter::default(),
        }
    }
}

impl<M: SideChannelMessage> ReplayPolicy for LatestPerSlot<M> {
    type Message = M;
    type Limits = SlotMapLimits;

    const RETAINS: bool = true;

    fn retain(&mut self, message: &M, limits: &SlotMapLimits, warn: Warn<'_>) -> bool {
        let author = message.author();
        let Ok(author_slot) = u8::try_from(author).map(SlotId) else {
            // A slot id past `u8` range names no real slot; a silent truncation
            // would alias it onto a valid one. Refuse it (defensive — the
            // author is relay-stamped upstream, so this is unreachable in
            // practice).
            tracing::warn!(
                tenant = warn.key.tenant.as_ref(),
                session = warn.key.session.0,
                channel = warn.channel,
                slot = author,
                "side-channel message names a slot id out of range; dropping",
            );
            return false;
        };
        if !self.latest.contains_key(&author_slot) && self.latest.len() >= limits.max_slots {
            if self.slot_cap_warns.observe() {
                tracing::warn!(
                    tenant = warn.key.tenant.as_ref(),
                    session = warn.key.session.0,
                    channel = warn.channel,
                    slot = author,
                    slots = self.latest.len(),
                    "side-channel replay map hit its distinct-slot cap; dropping this new slot's \
                     message",
                );
            }
            return false;
        }
        self.latest.insert(author_slot, message.clone());
        true
    }

    fn replay(&self) -> impl Iterator<Item = &M> {
        self.latest.values()
    }
}
