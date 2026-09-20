//! The relay's per-session side channels: the reliable, non-turn traffic
//! members exchange over their control streams.
//!
//! Three kinds of message ride this path — pre-game lobby commands, in-game
//! chat, and cosmetic skin blobs — and all three are the same registry with a
//! different *replay policy*. The registry is one
//! `Arc<Mutex<HashMap<SessionKey, _>>>` of per-member push channels, a
//! register/deregister/end-session lifecycle keyed to a slot link's own, an
//! [`admit`](SideChannel::admit) gate the client edge runs before anything is
//! fanned out, and a [`deliver`](SideChannel::deliver) that fans a message to
//! every local member except its relay-stamped author. What differs is what a
//! channel *retains* for a member whose control stream comes up after messages
//! already flowed — nothing, an ordered log, or the latest message per
//! authoring slot — which is the [`ReplayPolicy`] each channel is parameterized
//! by. The three configured channels and their caps are the [`LOBBY`], [`CHAT`]
//! and [`SKIN`] rows of one table.
//!
//! **One lock, so the replay/live handoff is exactly-once.** A channel's
//! retained state and its live per-member push channels live under one plain
//! (non-async) mutex — deliberate, matching the routing roster: every critical
//! section here is a short, await-free edit (retain the message, `try_send` to
//! each member, insert or remove a member), so the lock is never held across a
//! control-stream write. [`register_member`](SideChannel::register_member)
//! snapshots the retained state into the newcomer's channel and inserts that
//! channel under the same lock [`deliver`](SideChannel::deliver) retains and
//! fans out under, so the two steps never interleave: a message retained
//! *before* a member registered is in that member's replay snapshot and was not
//! fanned to it live (it was not yet a member); a message retained *after* is
//! fanned live and is not in the snapshot. Each member therefore sees every
//! retained message exactly once, whichever side of its join it fell on. The
//! author is never echoed its own message (its own game applied it locally), on
//! either the replay or the live path.
//!
//! **The fan-out never blocks.** Delivery to a member is a non-blocking
//! `try_send`: a full push queue is a member hopelessly behind — these messages
//! are small and rare next to the turn stream — so the fan-out warns and drops
//! for that member rather than stalling every other member behind it. A closed
//! queue is a member whose task already ended; it deregisters itself.
//!
//! **Two admission caps, enforced at the relay, not by the fan-out.** A
//! client-authored message must pass a size cap and a per-slot token-bucket
//! rate cap before the relay ever calls `deliver` on it or forwards it across
//! the mesh — see [`admit`](SideChannel::admit). A mesh-received message skips
//! `admit` entirely: the origin relay already ran its own client-authored copy
//! through the same checks, so re-checking here would only re-penalize an
//! already-admitted message against a second, independent bucket keyed on the
//! same slot. Both caps drop the offending frame rather than closing the
//! connection: none of this traffic is correctness-critical the way a turn is,
//! so losing one costs nothing more than a dropped chat line, a stale cosmetic,
//! or a setup command a misbehaving client was never entitled to send.
//!
//! The relay never parses a message's bytes — they are the game's own, opaque
//! here exactly as a turn's commands or a result's payload are.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;

use rally_point_proto::ids::SlotId;

use crate::key::SessionKey;
use crate::rate_limit::{RateLimitedCounter, TokenBucket};

mod channels;
mod replay;
#[cfg(test)]
mod tests;

pub use channels::{
    CHAT, ChatChannel, LOBBY, LobbyChannel, SKIN, SideChannelReceivers, SideChannels, SkinChannel,
};
pub use replay::{LatestPerSlot, LogLimits, NoReplay, OrderedLog, ReplayPolicy, SlotMapLimits};

/// One message a side channel carries. Implemented for the three wire types
/// the control stream frames; the registry reads only the two things every
/// channel needs from any of them.
pub trait SideChannelMessage: Clone {
    /// The authoritative authoring slot, already stamped — by the client edge
    /// to the authenticated slot for a client-authored message, or by the
    /// origin relay for a mesh-received one. The fan-out excludes the author by
    /// matching it: a client-authored message's author is a local member and is
    /// not echoed; a mesh-received message's author is a remote slot absent
    /// from this relay's members, so every local member receives it.
    fn author(&self) -> u32;

    /// What one message costs a replay policy that charges for bytes. Only the
    /// opaque game payload varies materially in size; the rest of a message is
    /// a handful of fixed scalar fields.
    fn retained_bytes(&self) -> usize;
}

/// The knobs one side channel is configured with — the four every channel
/// shares. A policy's own ceilings ride in `replay`, typed to that policy, so a
/// channel can only be handed the limits its policy actually reads. The three
/// configured rows are [`LOBBY`], [`CHAT`] and [`SKIN`].
#[derive(Debug, Clone, Copy)]
pub struct SideChannelConfig<L> {
    /// This channel's name in a log line's `channel` field — what
    /// distinguishes one channel's cap refusal from another's in the shared
    /// warnings below.
    pub name: &'static str,
    /// Depth of one member's push channel. Sized above whatever the replay
    /// policy can retain, so a full replay always fits with headroom for the
    /// live messages that can arrive while a newcomer is still draining it; a
    /// member further behind than this is effectively a dead client, and the
    /// fan-out warns rather than blocking.
    pub push_capacity: usize,
    /// The largest single message the relay forwards, or `None` for a channel
    /// whose traffic is bounded by its replay policy instead of one message at
    /// a time. Measured by the caller and passed to
    /// [`admit`](SideChannel::admit), because which field carries the payload
    /// is the message type's business, not this registry's.
    pub message_max_bytes: Option<usize>,
    /// The rate cap's burst size: an authoring slot may send this many messages
    /// back-to-back before the limiter starts rejecting.
    pub rate_burst: u32,
    /// The rate cap's refill rate — one additional token every this long, up to
    /// `rate_burst`.
    pub rate_refill: Duration,
    /// The ceilings this channel's replay policy is bounded by.
    pub replay: L,
}

/// The tracing coordinates a replay policy logs a cap refusal against. The
/// policy owns the refusal (it owns the state the cap bounds) but not the
/// session it happened in.
pub struct Warn<'a> {
    /// The configured channel's [`name`](SideChannelConfig::name).
    pub channel: &'static str,
    /// The session the refused message was addressed to.
    pub key: &'a SessionKey,
}

/// One session's state on one side channel: whatever its replay policy
/// retains, the live per-member push channels, and each authoring slot's rate
/// limiter and rate-limited warn counters.
struct ChannelSession<R: ReplayPolicy> {
    /// The replay policy's retained state — the source a newly registered
    /// member replays from.
    replay: R,
    /// The live per-member push channels: slot → that member's sender, drained
    /// by the member's slot-link task and written to its control stream.
    members: HashMap<SlotId, mpsc::Sender<R::Message>>,
    /// Per-authoring-slot token buckets for the rate cap. Keyed separately from
    /// `members` (and outliving a member's own deregistration) so a slot's
    /// budget is not reset by a reconnect, which would otherwise be a free way
    /// to dodge the rate cap.
    limiters: HashMap<SlotId, TokenBucket>,
    /// Per-slot rate-limited warn counter for the size-cap violation.
    size_warns: HashMap<SlotId, RateLimitedCounter>,
    /// Per-slot rate-limited warn counter for the rate-cap violation.
    rate_warns: HashMap<SlotId, RateLimitedCounter>,
}

impl<R: ReplayPolicy> Default for ChannelSession<R> {
    fn default() -> Self {
        ChannelSession {
            replay: R::default(),
            members: HashMap::new(),
            limiters: HashMap::new(),
            size_warns: HashMap::new(),
            rate_warns: HashMap::new(),
        }
    }
}

/// One per-session side channel, configured by its caps and parameterized by
/// its replay policy. Keyed like the turn roster by `(tenant, session)`.
///
/// Clone it cheaply (the sessions map is behind an `Arc`) to hand a copy to a
/// spawned task; every clone shares one registry.
pub struct SideChannel<R: ReplayPolicy> {
    config: SideChannelConfig<R::Limits>,
    sessions: Arc<Mutex<HashMap<SessionKey, ChannelSession<R>>>>,
}

impl<R: ReplayPolicy> Clone for SideChannel<R> {
    fn clone(&self) -> Self {
        SideChannel {
            config: self.config,
            sessions: Arc::clone(&self.sessions),
        }
    }
}

impl<R: ReplayPolicy> SideChannel<R> {
    /// An empty channel with `config`'s caps, for a relay with no sessions yet.
    pub fn new(config: SideChannelConfig<R::Limits>) -> Self {
        SideChannel {
            config,
            sessions: Arc::default(),
        }
    }

    /// The caps this channel was configured with.
    pub fn config(&self) -> &SideChannelConfig<R::Limits> {
        &self.config
    }

    /// Registers a member for `key` and returns the receiver its slot-link task
    /// drains, replaying whatever the policy retains to it first.
    ///
    /// Under the registry lock: the newcomer's channel is created, the retained
    /// messages are enqueued into it (skipping any the newcomer authored itself
    /// — the author is never echoed), and the sender is inserted into the
    /// session's member set. Doing all three under the one lock
    /// [`deliver`](Self::deliver) also holds is what makes the replay/live
    /// handoff exactly-once — see the module docs. The replay's order is the
    /// policy's: an ordered log replays in arrival order, a latest-per-slot map
    /// replays unordered (each slot's message is independent state, so the
    /// order they arrive in carries no meaning).
    pub fn register_member(&self, key: &SessionKey, slot: SlotId) -> mpsc::Receiver<R::Message> {
        let (tx, rx) = mpsc::channel(self.config.push_capacity);
        let mut sessions = self.sessions.lock();
        let session = sessions.entry(key.clone()).or_default();
        let joiner = u32::from(slot.0);
        for message in session.replay.replay() {
            // Never replay a member its own authored message; its game applied
            // it locally, exactly as live fan-out skips the author.
            if message.author() == joiner {
                continue;
            }
            if tx.try_send(message.clone()).is_err() {
                // The channel is sized above what the policy can retain, so a
                // legitimate replay always fits; a failure here means the
                // retained state overflowed its cap (already warned when it
                // did), so there is nothing more to do.
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    channel = self.config.name,
                    "side-channel replay did not fit the push channel; retained messages dropped",
                );
                break;
            }
        }
        session.members.insert(slot, tx);
        rx
    }

    /// Removes `slot` from `key`'s live member set — its slot-link task has
    /// ended. Deliberately leaves that slot's rate limiter and warn counters in
    /// place: a reconnecting slot keeps its accumulated budget and warn cadence
    /// rather than getting a fresh burst (and a fresh "first occurrence" warn)
    /// on every reconnect. The session's retained state is left intact too — it
    /// belongs to the session, not to this member, so any remaining or
    /// late-arriving member still replays it; the whole session is torn down by
    /// [`end_session`](Self::end_session).
    pub fn deregister_member(&self, key: &SessionKey, slot: SlotId) {
        let mut sessions = self.sessions.lock();
        if let Some(session) = sessions.get_mut(key) {
            session.members.remove(&slot);
        }
    }

    /// Drops all of `key`'s state on this channel, called when the relay's last
    /// local member for the session departs (the same emptied-roster signal
    /// that closes the session for the coordinator) and again, terminally, at
    /// descriptor retirement. A relay that never homed a member for the session
    /// — one that only relayed mesh copies into its retained state — keeps that
    /// state until its own first-and-last local member's teardown runs, which
    /// it always eventually does (a serving relay homes at least one slot).
    pub fn end_session(&self, key: &SessionKey) {
        self.sessions.lock().remove(key);
    }

    /// Checks whether one client-authored message from `slot` in `key`'s
    /// session may proceed to [`deliver`](Self::deliver): `len` fits the
    /// configured size cap (if this channel has one), and `slot`'s token bucket
    /// has budget. Only ever called at the client edge, before `deliver` and
    /// the mesh fan-out — a mesh-received message has already passed its origin
    /// relay's `admit` and goes straight to `deliver` (see the module docs).
    ///
    /// A failing message is dropped by the caller without closing the
    /// connection; each failure kind logs through its own rate-limited counter
    /// so a spam burst produces O(log n) log lines rather than one per message.
    pub fn admit(&self, key: &SessionKey, slot: SlotId, len: usize) -> bool {
        let name = self.config.name;
        let size_cap = self.config.message_max_bytes;
        let burst = self.config.rate_burst;
        let refill = self.config.rate_refill;
        let mut sessions = self.sessions.lock();
        let session = sessions.entry(key.clone()).or_default();
        if let Some(cap) = size_cap
            && len > cap
        {
            if session.size_warns.entry(slot).or_default().observe() {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    channel = name,
                    len,
                    cap,
                    "dropping an oversize side-channel message",
                );
            }
            return false;
        }
        if !session
            .limiters
            .entry(slot)
            .or_insert_with(|| TokenBucket::new(burst, refill))
            .try_take()
        {
            if session.rate_warns.entry(slot).or_default().observe() {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    channel = name,
                    "dropping a side-channel message; slot exceeded its rate cap",
                );
            }
            return false;
        }
        true
    }

    /// Delivers one message to `key`'s local members: offers it to the replay
    /// policy, then fans it out to every member except its author, without ever
    /// blocking on a slow peer.
    ///
    /// Retaining and fanning out happen under the one lock
    /// [`register_member`](Self::register_member) snapshots under, so a
    /// concurrent join sees this message in exactly one of {its replay
    /// snapshot, its live tail}.
    ///
    /// Only ever called after [`admit`](Self::admit) has cleared a
    /// client-authored message (or, for a mesh-received one, unconditionally —
    /// see `admit`'s docs); this function's own admission concern is the
    /// policy's session-wide ceiling, independent of any one slot's rate.
    /// Returns whether the message was retained and delivered — the caller's
    /// cue for whether to also forward a copy across the mesh: a message this
    /// relay refused was never retained or fanned to its own locals, so a peer
    /// that received it anyway would be out of step with every relay that
    /// refused it. A channel that retains nothing refuses nothing and always
    /// reports `true`.
    pub fn deliver(&self, key: &SessionKey, message: R::Message) -> bool {
        let name = self.config.name;
        let limits = self.config.replay;
        let mut sessions = self.sessions.lock();
        // A channel that retains nothing has nothing to create an entry for: a
        // delivery into a session no local member has registered on is simply a
        // no-op, not a reason to start holding state for that session.
        if !R::RETAINS && !sessions.contains_key(key) {
            return true;
        }
        let session = sessions.entry(key.clone()).or_default();
        if !session
            .replay
            .retain(&message, &limits, Warn { channel: name, key })
        {
            return false;
        }
        let author = message.author();
        for (slot, tx) in &session.members {
            if author == u32::from(slot.0) {
                continue;
            }
            match tx.try_send(message.clone()) {
                Ok(()) => {}
                // A full push queue is a member hopelessly behind (side-channel
                // messages are small and rare next to the turn stream) — log
                // rather than drop silently, since a missed setup command would
                // leave that member's pre-game state incomplete.
                Err(mpsc::error::TrySendError::Full(_)) => tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    channel = name,
                    "side-channel push queue full; a message was dropped for this member",
                ),
                // The member's task already ended; it deregisters itself.
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        }
        true
    }
}
