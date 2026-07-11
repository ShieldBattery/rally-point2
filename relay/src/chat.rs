//! Per-session game-chat fan-out — the reliable, ephemeral in-game chat channel.
//!
//! [`LobbyCommand`](rally_point_proto::messages::LobbyCommand)'s pre-game setup
//! channel has a mid-game counterpart: once the game starts, members still need
//! to reach each other's chat UI, and chat has no datagram turn stream to ride
//! (no simulated step to key a turn on) — so, like a lobby command, it travels
//! the reliable control stream as a [`GameChat`]. This module is the relay's
//! fan-out of those messages to a session's local members.
//!
//! **No replay log.** This is the one load-bearing difference from
//! [`crate::lobby`]: a lobby command's ordered log exists because a missed setup
//! command leaves a member's pre-game state permanently incomplete, and the host
//! can emit commands before every member has dialed in. Chat has neither
//! property — there is no game state a missed chat line could corrupt, and a
//! member whose control stream comes up after a message already flowed simply
//! never sees that message, the same way a real chat client that was offline for
//! a moment misses what was said. So this module keeps no log: [`deliver`] fans a
//! message out to whoever is a registered member *right now* and nothing more.
//!
//! **Two admission caps, enforced at the relay, not by this module.** A
//! client-authored message must pass a size cap ([`CHAT_TEXT_MAX_BYTES`]) and a
//! per-slot rate cap ([`RateLimiter`]) before the relay ever calls [`deliver`] on
//! it or forwards it across the mesh — see [`admit`]. A mesh-received message
//! skips `admit` entirely: the origin relay already ran its own client-authored
//! copy through the same checks, so re-checking here would only re-penalize an
//! already-admitted message (mirroring how a mesh-received lobby command is
//! delivered without re-validating its bytes). Both caps drop the offending
//! frame rather than closing the connection: an oversize or too-frequent chat
//! message is not correctness-critical the way a turn or a lobby command is, so
//! losing one costs nothing more than a dropped line.
//!
//! These two caps are the relay's own enforced boundary — unlike `target_kind`
//! (see `GameChat` in wire.proto), which the relay deliberately does NOT check:
//! scope is a receiver-side display hint, so filtering it here would be purely
//! advisory against a modified client anyway (which could just as easily choose
//! to display every message it receives), exactly the trust model native SC:R's
//! own channel-based chat has always had. Size and rate are different: they bound
//! the relay's own resource use (buffered memory, fan-out volume), so those the
//! relay enforces regardless of what any client would otherwise choose to send.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::GameChat;

use crate::consensus::{RateLimitedCounter, TokenBucket};
use crate::routing::SessionKey;

/// Depth of one member's chat-push channel. Chat is bursty but small (a human
/// typing, or a short flurry of "gg"s), and this is a non-blocking `try_send`
/// fan-out like the lobby channel's — a member this far behind is effectively a
/// dead client, so a generous backstop against a scheduling hiccup is enough; it
/// is not a tuned buffer.
pub(crate) const CHAT_PUSH_CAPACITY: usize = 256;

/// The largest `text` byte length the relay forwards. A real chat line is at
/// most a couple hundred characters; this is comfortably above any real message
/// while well under the control frame's own 64 KiB cap
/// ([`rally_point_proto::control_stream::MAX_CONTROL_FRAME_LEN`]), so an
/// over-cap message is a misbehaving or hostile client, not a real player typing
/// a long line.
pub const CHAT_TEXT_MAX_BYTES: usize = 256;

/// The chat rate cap's burst size: an authoring slot may send up to this many
/// messages back-to-back before the limiter starts rejecting.
const CHAT_RATE_BURST: u32 = 8;

/// The chat rate cap's refill rate: one additional token every this long, up to
/// [`CHAT_RATE_BURST`]. Loose enough for a human typing quickly, tight enough
/// that a flooding client is throttled to two messages a second.
const CHAT_RATE_REFILL_INTERVAL: Duration = Duration::from_millis(500);

/// Every session's chat state on this relay, keyed like the lobby registry by
/// `(tenant, session)`. A plain (non-async) mutex is deliberate, matching the
/// lobby and turn-routing registries: every critical section here is a short,
/// await-free edit (fan a message to each member, touch one slot's limiter), so
/// the lock is never held across a control-stream write.
pub type ChatRegistry = Arc<Mutex<HashMap<SessionKey, ChatSession>>>;

/// Creates an empty chat registry for a relay with no sessions yet.
pub fn new_chat_registry() -> ChatRegistry {
    Arc::default()
}

/// One session's chat state: the live per-member push channels, plus each
/// authoring slot's rate limiter and rate-limited warn counters. No log — see
/// the module docs.
#[derive(Default)]
pub struct ChatSession {
    /// The live per-member push channels: slot → that member's chat-push sender,
    /// drained by the member's slot-link task and written to its control stream.
    members: HashMap<SlotId, mpsc::Sender<GameChat>>,
    /// Per-authoring-slot token buckets for the rate cap. Keyed separately from
    /// `members` (and outliving a member's own deregistration — see
    /// [`deregister_member`]) so a slot's budget is not reset by a reconnect.
    limiters: HashMap<SlotId, TokenBucket>,
    /// Per-slot rate-limited warn counter for the size-cap violation.
    size_warns: HashMap<SlotId, RateLimitedCounter>,
    /// Per-slot rate-limited warn counter for the rate-cap violation.
    rate_warns: HashMap<SlotId, RateLimitedCounter>,
}

/// Registers a member for `key` and returns the receiver its slot-link task
/// drains. Unlike [`crate::lobby::register_member`], there is no log to replay —
/// the newcomer simply starts tailing whatever is delivered from this point on.
pub fn register_member(
    registry: &ChatRegistry,
    key: &SessionKey,
    slot: SlotId,
) -> mpsc::Receiver<GameChat> {
    let (tx, rx) = mpsc::channel(CHAT_PUSH_CAPACITY);
    let mut registry = registry.lock();
    let session = registry.entry(key.clone()).or_default();
    session.members.insert(slot, tx);
    rx
}

/// Removes `slot` from `key`'s live member set — its slot-link task has ended.
/// Deliberately leaves that slot's rate limiter and warn counters in place: a
/// reconnecting slot keeps its accumulated budget and warn cadence rather than
/// getting a fresh burst (and a fresh "first occurrence" warn) on every
/// reconnect, which would otherwise be a free way to dodge the rate cap.
pub fn deregister_member(registry: &ChatRegistry, key: &SessionKey, slot: SlotId) {
    let mut registry = registry.lock();
    if let Some(session) = registry.get_mut(key) {
        session.members.remove(&slot);
    }
}

/// Drops all chat state for `key`, called when the relay's last local member for
/// the session departs — mirroring [`crate::lobby::end_session`].
pub fn end_session(registry: &ChatRegistry, key: &SessionKey) {
    registry.lock().remove(key);
}

/// Checks whether one client-authored chat message from `slot` in `key`'s
/// session may be forwarded: `text_len` fits [`CHAT_TEXT_MAX_BYTES`], and the
/// slot's token bucket has budget. Only ever called at the client edge, before
/// [`deliver`] and the mesh fan-out — a mesh-received message has already passed
/// its origin relay's `admit` and is delivered directly (see the module docs).
///
/// A failing message is dropped by the caller without closing the connection;
/// each failure kind logs through its own rate-limited counter so a spam burst
/// produces O(log n) log lines rather than one per message.
pub fn admit(registry: &ChatRegistry, key: &SessionKey, slot: SlotId, text_len: usize) -> bool {
    let mut registry = registry.lock();
    let session = registry.entry(key.clone()).or_default();
    if text_len > CHAT_TEXT_MAX_BYTES {
        if session.size_warns.entry(slot).or_default().observe() {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                len = text_len,
                cap = CHAT_TEXT_MAX_BYTES,
                "dropping oversize game-chat message",
            );
        }
        return false;
    }
    if !session
        .limiters
        .entry(slot)
        .or_insert_with(|| TokenBucket::new(CHAT_RATE_BURST, CHAT_RATE_REFILL_INTERVAL))
        .try_take()
    {
        if session.rate_warns.entry(slot).or_default().observe() {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                "dropping game-chat message; slot exceeded its chat rate cap",
            );
        }
        return false;
    }
    true
}

/// Delivers one game-chat message to `key`'s local members: fans it out to
/// every member except its author, without ever blocking on a slow peer. No
/// replay log to append to (see the module docs) — a session with no members
/// registered yet simply has nothing to deliver to.
///
/// `chat.slot` is the authoritative author, already stamped — by the client
/// edge to the authenticated slot for a client-authored message, or by the
/// origin relay for a mesh-received one — so the author is excluded by matching
/// it, exactly as [`crate::lobby::deliver`] does.
pub fn deliver(registry: &ChatRegistry, key: &SessionKey, chat: GameChat) {
    let registry = registry.lock();
    let Some(session) = registry.get(key) else {
        return;
    };
    for (slot, tx) in &session.members {
        if chat.slot == u32::from(slot.0) {
            continue;
        }
        match tx.try_send(chat.clone()) {
            Ok(()) => {}
            // A full push queue is a member hopelessly behind (chat is small and
            // rare relative to the turn stream) — log rather than drop silently,
            // matching the lobby channel's treatment of the same condition.
            Err(mpsc::error::TrySendError::Full(_)) => tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                "chat push queue full; a game-chat message was dropped for this member",
            ),
            // The member's task already ended; it deregisters itself.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rally_point_proto::control::TenantId;
    use rally_point_proto::ids::SessionId;

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(1),
        }
    }

    fn chat(slot: u32, text: &str) -> GameChat {
        GameChat {
            slot,
            target_kind: 0,
            target_slot: 0,
            text: text.to_owned(),
        }
    }

    fn drain(rx: &mut mpsc::Receiver<GameChat>) -> Vec<(u32, String)> {
        let mut got = Vec::new();
        while let Ok(chat) = rx.try_recv() {
            got.push((chat.slot, chat.text));
        }
        got
    }

    #[test]
    fn a_message_fans_out_to_every_member_but_its_author() {
        let registry = new_chat_registry();
        let k = key();
        let mut host = register_member(&registry, &k, SlotId(0));
        let mut peer = register_member(&registry, &k, SlotId(1));

        deliver(&registry, &k, chat(0, "gl hf"));
        assert_eq!(drain(&mut host), vec![], "the author is not echoed its own");
        assert_eq!(drain(&mut peer), vec![(0, "gl hf".to_owned())]);
    }

    #[test]
    fn a_member_registered_after_a_message_never_sees_it() {
        // The load-bearing difference from the lobby channel: no replay log, so
        // a message delivered before a member joins is simply missed, not
        // replayed to it later.
        let registry = new_chat_registry();
        let k = key();
        let _host = register_member(&registry, &k, SlotId(0));
        deliver(&registry, &k, chat(0, "before you joined"));

        let mut late = register_member(&registry, &k, SlotId(1));
        assert_eq!(
            drain(&mut late),
            vec![],
            "chat is ephemeral -- a late joiner gets no replay"
        );

        // But it does tail live messages from that point on.
        deliver(&registry, &k, chat(0, "hi"));
        assert_eq!(drain(&mut late), vec![(0, "hi".to_owned())]);
    }

    #[test]
    fn a_mesh_authored_message_reaches_every_local_member() {
        let registry = new_chat_registry();
        let k = key();
        let mut a = register_member(&registry, &k, SlotId(0));
        let mut b = register_member(&registry, &k, SlotId(1));

        // A remote slot (7) authored this, arriving off the mesh: neither local
        // member is its author, so both receive it.
        deliver(&registry, &k, chat(7, "hey from relay B"));
        assert_eq!(drain(&mut a), vec![(7, "hey from relay B".to_owned())]);
        assert_eq!(drain(&mut b), vec![(7, "hey from relay B".to_owned())]);
    }

    #[test]
    fn oversize_text_is_rejected_by_admit() {
        let registry = new_chat_registry();
        let k = key();
        assert!(admit(&registry, &k, SlotId(0), CHAT_TEXT_MAX_BYTES));
        assert!(!admit(&registry, &k, SlotId(0), CHAT_TEXT_MAX_BYTES + 1));
    }

    #[test]
    fn a_burst_past_the_rate_cap_is_rejected_then_recovers_after_refill() {
        let registry = new_chat_registry();
        let k = key();
        let slot = SlotId(0);

        // The first CHAT_RATE_BURST messages in a burst are all admitted.
        for _ in 0..CHAT_RATE_BURST {
            assert!(admit(&registry, &k, slot, 4));
        }
        // The next one, still within the burst window, is rejected.
        assert!(!admit(&registry, &k, slot, 4));

        // After a refill interval passes, at least one more token is available.
        std::thread::sleep(CHAT_RATE_REFILL_INTERVAL + Duration::from_millis(50));
        assert!(admit(&registry, &k, slot, 4));
    }

    #[test]
    fn deregister_removes_a_member_but_a_late_joiner_still_gets_no_replay() {
        let registry = new_chat_registry();
        let k = key();
        let _host = register_member(&registry, &k, SlotId(0));
        deliver(&registry, &k, chat(0, "before"));
        deregister_member(&registry, &k, SlotId(0));

        let mut late = register_member(&registry, &k, SlotId(1));
        assert_eq!(drain(&mut late), vec![]);

        end_session(&registry, &k);
        let mut after = register_member(&registry, &k, SlotId(1));
        assert_eq!(drain(&mut after), vec![]);
    }
}
