//! Per-session cosmetic-skin fan-out and its latest-blob-per-slot replay map.
//!
//! Near game start each session member broadcasts one opaque cosmetic-skin blob
//! — the game's own serialized skin state — so every other member can render it
//! with the cosmetics that member chose. Like [`GameChat`](rally_point_proto::messages::GameChat)
//! and a lobby command, a skin blob has no simulated step to key a turn on, so it
//! rides the reliable control stream as a [`PlayerSkin`], and this module is the
//! relay's fan-out of those blobs to a session's local members.
//!
//! **A latest-per-slot map, not a log and not a bare fan-out.** This is the load-bearing
//! difference from both siblings. A skin is one-shot *state*, not a stream of
//! events: unlike [`crate::chat`] (ephemeral — a member whose stream comes up
//! after a message flowed simply missed it), a member that registers late or
//! reconnects must still end up with every other member's *current* blob. And
//! unlike [`crate::lobby`]'s append-only ordered log (where every command is
//! distinct and order matters), a slot's newer blob wholly supersedes its older
//! one — only the latest matters. So this module keeps one blob per authoring
//! slot and, when a member registers, replays every stored blob to it (before
//! any live one), exactly as the lobby log replays to a late joiner — except a
//! re-sent blob from the same slot *replaces* that slot's map entry rather than
//! appending, so a late joiner replays only the newest blob per slot. Receivers
//! apply a blob idempotently, so a replayed duplicate a reconnect produces is
//! harmless.
//!
//! **Exactly-once across the replay/live boundary.** The map and the live
//! per-member push channels live under one lock, mirroring [`crate::lobby`].
//! [`register_member`] snapshots the map into the newcomer's channel and inserts
//! that channel under the same lock that [`deliver`] inserts into the map and
//! fans out under, so the two steps never interleave: a blob stored *before* a
//! member registered is in that member's replay snapshot and was not fanned to it
//! live (it was not yet a member); a blob stored *after* is fanned live and is
//! not in the snapshot. The author is never echoed its own blob (its own game
//! already has it), on either the replay or the live path.
//!
//! **Two admission caps, enforced at the relay, not by this module's fan-out.**
//! A client-authored blob must pass a size cap ([`SKIN_BLOB_MAX_BYTES`]) and a
//! per-slot rate cap (`TokenBucket`) before the relay ever calls [`deliver`] on
//! it or forwards it across the mesh — see [`admit`]. A mesh-received blob skips
//! `admit` entirely: the origin relay already ran its own client-authored copy
//! through the same checks, so re-checking here would only re-penalize an
//! already-admitted blob against a second, independent bucket (mirroring how a
//! mesh-received chat message or lobby command is delivered without re-validating
//! its bytes). Both caps drop the offending frame rather than closing the
//! connection: a skin is cosmetic, non-synced, and best-effort, so losing one
//! costs nothing more than a wrong cosmetic — never correctness, the way a turn
//! or a lobby command would. The relay never parses a blob's bytes; they are the
//! game's own, opaque here exactly as a chat line's text or a result's payload is.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::PlayerSkin;

use crate::consensus::{RateLimitedCounter, TokenBucket};
use crate::routing::SessionKey;

/// Depth of one member's skin-push channel. A replay is at most one blob per
/// authoring slot ([`SKIN_MAX_SLOTS`]), so this is sized above that cap: a full
/// map replay always fits with headroom for the live blobs that can arrive while
/// a newcomer is still draining its replay. A member further behind than this is
/// effectively a dead client, and the fan-out warns rather than blocking (a skin
/// push is delivered non-blocking, like a chat or lobby push).
pub(crate) const SKIN_PUSH_CAPACITY: usize = 64;

/// The largest `payload` byte length the relay forwards. A real cosmetic-skin
/// blob is a few hundred bytes; this is comfortably above any real blob while
/// bounding the relay's per-slot map memory, and well under the control frame's
/// own 64 KiB cap ([`rally_point_proto::control_stream::MAX_CONTROL_FRAME_LEN`]),
/// so an over-cap blob is a misbehaving or hostile client, not a real player.
pub const SKIN_BLOB_MAX_BYTES: usize = 2048;

/// The skin rate cap's burst size: an authoring slot may send up to this many
/// blobs back-to-back before the limiter starts rejecting. A member legitimately
/// sends one blob per game, maybe a couple on a re-send, so this small burst
/// covers every honest use while bounding a flooding client.
const SKIN_RATE_BURST: u32 = 4;

/// The skin rate cap's refill rate: one additional token every this long, up to
/// [`SKIN_RATE_BURST`]. Skin blobs flow at most a handful of times per game
/// (nothing like chat's typing cadence), so a slow refill is ample for every
/// honest use while throttling a misbehaving client hard.
const SKIN_RATE_REFILL_INTERVAL: Duration = Duration::from_secs(10);

/// The largest number of distinct authoring slots one session's map retains — a
/// defensive cap. A session tops out at 16 members, so this is far above any real
/// session; at [`SKIN_BLOB_MAX_BYTES`] it bounds a session's map to 64 KiB. A
/// session that blows it is misbehaving, and the map stops admitting new slots
/// (see [`deliver`]) rather than growing without limit.
const SKIN_MAX_SLOTS: usize = 32;

/// Every session's skin state on this relay, keyed like the lobby and chat
/// registries by `(tenant, session)`. A plain (non-async) mutex is deliberate,
/// matching those registries: every critical section here is a short, await-free
/// edit (replace one slot's blob and fan it to each member, snapshot the map into
/// a newcomer, touch one slot's limiter), so the lock is never held across a
/// control-stream write, and the replay/live handoff stays atomic under it.
pub type SkinRegistry = Arc<Mutex<HashMap<SessionKey, SkinSession>>>;

/// Creates an empty skin registry for a relay with no sessions yet.
pub fn new_skin_registry() -> SkinRegistry {
    Arc::default()
}

/// One session's skin state: the latest blob per authoring slot (the replay
/// source), the live per-member push channels, plus each authoring slot's rate
/// limiter and rate-limited warn counters. Public only because it appears in the
/// [`SkinRegistry`] alias; its fields are private, so the state is built and read
/// solely through this module.
#[derive(Default)]
pub struct SkinSession {
    /// The latest blob each authoring slot broadcast — the replay source for a
    /// member whose stream comes up after blobs flowed. A slot's newer blob
    /// replaces its older one (see the module docs), so this is a map, not a log.
    skins: HashMap<SlotId, PlayerSkin>,
    /// The live per-member push channels: slot → that member's skin-push sender,
    /// drained by the member's slot-link task and written to its control stream.
    members: HashMap<SlotId, mpsc::Sender<PlayerSkin>>,
    /// Per-authoring-slot token buckets for the rate cap. Keyed separately from
    /// `members` (and outliving a member's own deregistration — see
    /// [`deregister_member`]) so a slot's budget is not reset by a reconnect,
    /// mirroring [`crate::chat`].
    limiters: HashMap<SlotId, TokenBucket>,
    /// Per-slot rate-limited warn counter for the size-cap violation.
    size_warns: HashMap<SlotId, RateLimitedCounter>,
    /// Per-slot rate-limited warn counter for the rate-cap violation.
    rate_warns: HashMap<SlotId, RateLimitedCounter>,
    /// Rate-limited warn counter for the distinct-slot-cap refusal — session-wide
    /// because the refused slot is one not yet in the map, so there is no per-slot
    /// budget to key it on.
    slot_cap_warns: RateLimitedCounter,
}

/// Registers a member for `key` and returns the receiver its slot-link task
/// drains, replaying every stored blob to it first.
///
/// Under the registry lock: the newcomer's channel is created, every stored blob
/// is enqueued into it (skipping any blob the newcomer authored itself — the
/// author is never echoed), and the sender is inserted into the session's member
/// set. Doing all three under the one lock [`deliver`] also holds is what makes
/// the replay/live handoff exactly-once — see the module docs. Unlike
/// [`crate::lobby::register_member`] the replay is unordered (a map, not a log):
/// each slot's blob is independent state, so the order they arrive in carries no
/// meaning.
pub fn register_member(
    registry: &SkinRegistry,
    key: &SessionKey,
    slot: SlotId,
) -> mpsc::Receiver<PlayerSkin> {
    let (tx, rx) = mpsc::channel(SKIN_PUSH_CAPACITY);
    let mut registry = registry.lock();
    let session = registry.entry(key.clone()).or_default();
    for skin in session.skins.values() {
        // Never replay a member its own authored blob; its game already has it,
        // exactly as live fan-out skips the author.
        if skin.slot == u32::from(slot.0) {
            continue;
        }
        if tx.try_send(skin.clone()).is_err() {
            // The channel is sized above the slot cap, so a legitimate replay
            // always fits; a failure here means the map somehow outgrew its cap
            // (already warned when it did), so there is nothing more to do.
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                "skin map replay did not fit the push channel; some blobs dropped",
            );
            break;
        }
    }
    session.members.insert(slot, tx);
    rx
}

/// Removes `slot` from `key`'s live member set — its slot-link task has ended.
/// Deliberately leaves that slot's rate limiter and warn counters in place: a
/// reconnecting slot keeps its accumulated budget and warn cadence rather than
/// getting a fresh burst (and a fresh "first occurrence" warn) on every
/// reconnect, which would otherwise be a free way to dodge the rate cap. The
/// session's blob map is left intact too, so any remaining or late-arriving
/// member still replays it; the whole session is torn down by [`end_session`]
/// when the relay's last local member for it departs.
pub fn deregister_member(registry: &SkinRegistry, key: &SessionKey, slot: SlotId) {
    let mut registry = registry.lock();
    if let Some(session) = registry.get_mut(key) {
        session.members.remove(&slot);
    }
}

/// Drops all skin state for `key`, called when the relay's last local member for
/// the session departs — mirroring [`crate::lobby::end_session`] and
/// [`crate::chat::end_session`].
pub fn end_session(registry: &SkinRegistry, key: &SessionKey) {
    registry.lock().remove(key);
}

/// Checks whether one client-authored skin blob from `slot` in `key`'s session
/// may be forwarded: `payload_len` fits [`SKIN_BLOB_MAX_BYTES`], and the slot's
/// token bucket has budget. Only ever called at the client edge, before
/// [`deliver`] and the mesh fan-out — a mesh-received blob has already passed its
/// origin relay's `admit` and is delivered directly (see the module docs).
///
/// A failing blob is dropped by the caller without closing the connection; each
/// failure kind logs through its own rate-limited counter so a spam burst
/// produces O(log n) log lines rather than one per blob.
pub fn admit(registry: &SkinRegistry, key: &SessionKey, slot: SlotId, payload_len: usize) -> bool {
    let mut registry = registry.lock();
    let session = registry.entry(key.clone()).or_default();
    if payload_len > SKIN_BLOB_MAX_BYTES {
        if session.size_warns.entry(slot).or_default().observe() {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                len = payload_len,
                cap = SKIN_BLOB_MAX_BYTES,
                "dropping oversize player-skin blob",
            );
        }
        return false;
    }
    if !session
        .limiters
        .entry(slot)
        .or_insert_with(|| TokenBucket::new(SKIN_RATE_BURST, SKIN_RATE_REFILL_INTERVAL))
        .try_take()
    {
        if session.rate_warns.entry(slot).or_default().observe() {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                "dropping player-skin blob; slot exceeded its skin rate cap",
            );
        }
        return false;
    }
    true
}

/// Delivers one skin blob to `key`'s local members: stores it as the authoring
/// slot's latest blob and fans it out to every member except its author, without
/// ever blocking on a slow peer.
///
/// `skin.slot` is the authoritative author, already stamped — by the client edge
/// to the authenticated slot for a client-authored blob, or by the origin relay
/// for a mesh-received one — so the author is excluded by matching it (a
/// client-authored blob's author is a local member and is not echoed; a
/// mesh-received blob's author is a remote slot absent from this relay's members,
/// so every local member receives it). Storing and fanning out happen under the
/// one lock [`register_member`] snapshots under, so a concurrent join sees this
/// blob in exactly one of {its replay snapshot, its live tail}.
///
/// Only ever called after [`admit`] has already cleared a client-authored blob
/// (or, for a mesh-received one, unconditionally — see `admit`'s docs); this
/// function's own admission concern is the session-wide distinct-slot cap,
/// independent of any one slot's rate. Returns whether the blob was admitted and
/// delivered — the caller's cue for whether to also forward a copy across the
/// mesh: a blob this relay refused was never stored or fanned to its own locals,
/// so a peer that received it anyway would hold state this relay's own members
/// never will. A slot already present in the map is always admitted (a re-send
/// replaces its entry without growing the map); only a *new* authoring slot that
/// would push the map past the session-wide distinct-slot cap is refused.
pub fn deliver(registry: &SkinRegistry, key: &SessionKey, skin: PlayerSkin) -> bool {
    let mut registry = registry.lock();
    let session = registry.entry(key.clone()).or_default();

    let Ok(author) = u8::try_from(skin.slot).map(SlotId) else {
        // A slot id past `u8` range names no real slot; a silent truncation would
        // alias it onto a valid one. Refuse it (defensive — the author is
        // relay-stamped upstream, so this is unreachable in practice).
        tracing::warn!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            slot = skin.slot,
            "player-skin blob names a slot id out of range; dropping",
        );
        return false;
    };

    if !session.skins.contains_key(&author) && session.skins.len() >= SKIN_MAX_SLOTS {
        if session.slot_cap_warns.observe() {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = skin.slot,
                slots = session.skins.len(),
                "player-skin map hit its distinct-slot cap; dropping this new slot's blob",
            );
        }
        return false;
    }
    session.skins.insert(author, skin.clone());
    for (slot, tx) in &session.members {
        if skin.slot == u32::from(slot.0) {
            continue;
        }
        match tx.try_send(skin.clone()) {
            Ok(()) => {}
            // A full push queue is a member hopelessly behind (skin blobs are
            // rare relative to the turn stream) — log rather than drop silently,
            // matching the lobby and chat channels' treatment of the same
            // condition.
            Err(mpsc::error::TrySendError::Full(_)) => tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                "skin push queue full; a player-skin blob was dropped for this member",
            ),
            // The member's task already ended; it deregisters itself.
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
    true
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

    fn skin(slot: u32, byte: u8) -> PlayerSkin {
        PlayerSkin {
            slot,
            payload: vec![byte].into(),
        }
    }

    /// Draining every blob currently queued on a member's receiver, without
    /// blocking — the member's slot-link task would write these to its control
    /// stream in this order.
    fn drain(rx: &mut mpsc::Receiver<PlayerSkin>) -> Vec<(u32, u8)> {
        let mut got = Vec::new();
        while let Ok(skin) = rx.try_recv() {
            got.push((skin.slot, skin.payload[0]));
        }
        got
    }

    #[test]
    fn a_blob_fans_out_to_every_member_but_its_author() {
        let registry = new_skin_registry();
        let k = key();
        let mut host = register_member(&registry, &k, SlotId(0));
        let mut peer = register_member(&registry, &k, SlotId(1));

        assert!(deliver(&registry, &k, skin(0, 0xA1)));
        assert_eq!(drain(&mut host), vec![], "the author is not echoed its own");
        assert_eq!(drain(&mut peer), vec![(0, 0xA1)]);
    }

    #[test]
    fn a_late_member_replays_stored_blobs_but_not_its_own() {
        let registry = new_skin_registry();
        let k = key();
        // Two members are up and each broadcasts a blob before the third joins.
        let _host = register_member(&registry, &k, SlotId(0));
        let _peer = register_member(&registry, &k, SlotId(1));
        deliver(&registry, &k, skin(0, 0x01));
        deliver(&registry, &k, skin(1, 0x02));

        // Slot 1 re-registers (a reconnect): it replays the host's blob but not
        // its own, so it never re-applies a blob it authored.
        let mut peer_again = register_member(&registry, &k, SlotId(1));
        assert_eq!(drain(&mut peer_again), vec![(0, 0x01)]);

        // A fresh late joiner replays every stored slot's blob (neither is its
        // own), and tails a live blob after with no gap or dup.
        let mut late = register_member(&registry, &k, SlotId(2));
        let mut got = drain(&mut late);
        got.sort_unstable();
        assert_eq!(got, vec![(0, 0x01), (1, 0x02)]);
        deliver(&registry, &k, skin(0, 0x03));
        assert_eq!(drain(&mut late), vec![(0, 0x03)]);
    }

    #[test]
    fn a_re_sent_blob_replaces_so_a_late_joiner_gets_only_the_latest() {
        let registry = new_skin_registry();
        let k = key();
        let _host = register_member(&registry, &k, SlotId(0));
        // Slot 0 broadcasts twice — the second supersedes the first.
        deliver(&registry, &k, skin(0, 0x10));
        deliver(&registry, &k, skin(0, 0x11));

        // A late joiner replays exactly one blob for slot 0: the newest.
        let mut late = register_member(&registry, &k, SlotId(1));
        assert_eq!(drain(&mut late), vec![(0, 0x11)]);
    }

    #[test]
    fn a_blob_stored_before_a_join_is_not_also_delivered_live() {
        // The exactly-once boundary: a blob already in the map when a member
        // joins is delivered by the replay, and is not re-fanned live (the member
        // was not yet in the set when it was stored).
        let registry = new_skin_registry();
        let k = key();
        let _host = register_member(&registry, &k, SlotId(0));
        deliver(&registry, &k, skin(0, 0x55));

        let mut peer = register_member(&registry, &k, SlotId(1));
        // Exactly one copy — from the replay, not a second live delivery.
        assert_eq!(drain(&mut peer), vec![(0, 0x55)]);
    }

    #[test]
    fn a_mesh_authored_blob_reaches_every_local_member_and_is_stored() {
        let registry = new_skin_registry();
        let k = key();
        let mut a = register_member(&registry, &k, SlotId(0));
        let mut b = register_member(&registry, &k, SlotId(1));

        // A blob authored by a remote slot (7) arriving off the mesh: no local
        // member is its author, so both locals receive it.
        assert!(deliver(&registry, &k, skin(7, 0xEE)));
        assert_eq!(drain(&mut a), vec![(7, 0xEE)]);
        assert_eq!(drain(&mut b), vec![(7, 0xEE)]);

        // And it was stored, so a local member joining afterwards replays it.
        let mut late = register_member(&registry, &k, SlotId(2));
        assert_eq!(drain(&mut late), vec![(7, 0xEE)]);
    }

    #[test]
    fn oversize_payload_is_rejected_by_admit() {
        let registry = new_skin_registry();
        let k = key();
        assert!(admit(&registry, &k, SlotId(0), SKIN_BLOB_MAX_BYTES));
        assert!(!admit(&registry, &k, SlotId(0), SKIN_BLOB_MAX_BYTES + 1));
    }

    #[test]
    fn a_burst_past_the_rate_cap_is_rejected_then_recovers_after_refill() {
        let registry = new_skin_registry();
        let k = key();
        let slot = SlotId(0);

        // The first SKIN_RATE_BURST blobs in a burst are all admitted.
        for _ in 0..SKIN_RATE_BURST {
            assert!(admit(&registry, &k, slot, 4));
        }
        // The next one, still within the burst window, is rejected.
        assert!(!admit(&registry, &k, slot, 4));

        // After a refill interval passes, at least one more token is available.
        std::thread::sleep(SKIN_RATE_REFILL_INTERVAL + Duration::from_millis(50));
        assert!(admit(&registry, &k, slot, 4));
    }

    #[test]
    fn the_rate_cap_is_independent_per_slot() {
        let registry = new_skin_registry();
        let k = key();
        for _ in 0..SKIN_RATE_BURST {
            assert!(admit(&registry, &k, SlotId(0), 4));
        }
        assert!(
            !admit(&registry, &k, SlotId(0), 4),
            "slot 0 exhausted its burst"
        );
        // A different slot has its own, untouched budget.
        assert!(admit(&registry, &k, SlotId(1), 4));
    }

    #[test]
    fn a_new_slot_past_the_map_cap_is_refused_but_a_re_send_still_admits() {
        let registry = new_skin_registry();
        let k = key();
        // Fill the map to its cap with distinct authoring slots. (A distinct slot
        // per blob so no one slot's rate cap interferes; deliver does not consult
        // the rate limiter, so this only exercises the map's slot cap.)
        for i in 0..SKIN_MAX_SLOTS {
            assert!(
                deliver(&registry, &k, skin(i as u32, 0)),
                "slot {i} should still be under the map cap",
            );
        }
        // A brand-new authoring slot is refused — the map is full.
        assert!(
            !deliver(&registry, &k, skin(SKIN_MAX_SLOTS as u32, 0)),
            "a new slot past the map cap is refused",
        );
        // But a slot already in the map re-sends fine (it replaces, not grows).
        assert!(
            deliver(&registry, &k, skin(0, 0x99)),
            "a re-send from an existing slot is always admitted",
        );
    }

    #[test]
    fn deregister_keeps_the_map_but_end_session_drops_it() {
        let registry = new_skin_registry();
        let k = key();
        let _host = register_member(&registry, &k, SlotId(0));
        deliver(&registry, &k, skin(0, 0x01));
        deregister_member(&registry, &k, SlotId(0));

        // The map survives the member leaving, so a late joiner still catches up.
        let mut late = register_member(&registry, &k, SlotId(1));
        assert_eq!(drain(&mut late), vec![(0, 0x01)]);

        // end_session drops everything; a fresh join then starts from empty.
        end_session(&registry, &k);
        let mut after = register_member(&registry, &k, SlotId(1));
        assert_eq!(drain(&mut after), vec![]);
    }
}
