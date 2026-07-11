//! Per-session lobby-command fan-out and its ordered replay log.
//!
//! Before a game starts, the host's game authors the lobby's setup commands —
//! slot and color assignments, the game-init that seeds the synced RNG — and
//! every other session member must apply that byte stream, in the order the host
//! emitted it, before the first turn. Members also author their own small
//! requests (a join, a ready toggle, a race change) that must reach the host and
//! the other members. Those commands ride the reliable control stream as
//! [`LobbyCommand`]s; this module is the relay's fan-out of them to a session's
//! local members plus the ordered log that lets a member who joined late catch
//! up.
//!
//! **Why a log, not a bare fan-out.** Setup runs while members are still dialing
//! in with real clock skew, and nothing back-pressures the host: its own local
//! turn barrier is satisfied, so its lobby machine can emit setup commands before
//! a given member's link even exists. A plain fan-out would deliver those
//! commands to nobody and lose them. So every command the relay delivers is
//! appended to a per-session ordered log, and when a member's control stream
//! comes up the relay replays the log to that member — in arrival order, before
//! any live command — so every member ends up with the identical sequence
//! regardless of when it joined.
//!
//! **Exactly-once across the replay/live boundary.** The log and the live
//! per-member push channels live under one lock. [`register_member`] snapshots
//! the log into the newcomer's channel and inserts that channel under the same
//! lock that [`deliver`] appends to the log and fans out under, so the two steps
//! never interleave: a command appended *before* a member registered is in that
//! member's replay snapshot and was not fanned to it live (it was not yet a
//! member); a command appended *after* is fanned live and is not in the snapshot.
//! Each member therefore sees every command exactly once, in order, whichever
//! side of its join the command fell on. The author is never echoed its own
//! command (its game echoes locally), on either the replay or the live path.
//!
//! The relay never parses a command's bytes — they are the game's own, opaque
//! here exactly as a turn's commands or a result's payload are. The log is
//! phase-agnostic: the relay forwards and logs without gating on game-started
//! (usage keeps this to the lobby phase). It is bounded defensively by a command
//! count and a byte total — a session past either cap is a misbehaving client,
//! so the relay warns once and drops further commands rather than growing the log
//! without limit.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::LobbyCommand;

use crate::consensus::{RateLimitedCounter, TokenBucket};
use crate::routing::SessionKey;

/// Depth of one member's lobby-push channel. Sized above [`LOBBY_LOG_MAX_COMMANDS`]
/// so a full log replay always fits with headroom for the live commands that can
/// arrive while a newcomer is still draining its replay; a member further behind
/// than this is effectively a dead client, and the fan-out warns rather than
/// blocking (a lobby push is delivered non-blocking, like a leave push).
pub(crate) const LOBBY_PUSH_CAPACITY: usize = 2048;

/// The largest number of lobby commands one session's log retains. A real lobby
/// is a burst of setup commands and a handful of per-member requests — tens, not
/// thousands — so this is far above any legitimate session; a session that blows
/// it is misbehaving, and the log stops growing (see [`deliver`]).
const LOBBY_LOG_MAX_COMMANDS: usize = 1024;

/// The largest total payload bytes one session's log retains. Bounds the memory a
/// misbehaving client can pin across the log even if each command is small; like
/// the count cap, it is far above any real lobby.
const LOBBY_LOG_MAX_BYTES: usize = 256 * 1024;

/// The lobby rate cap's burst size, mirroring [`crate::chat`]'s
/// [`TokenBucket`]-based admission but sized for lobby traffic rather than
/// chat's human-typing cadence. Setup is a burst authored by one slot (almost
/// always the host): a full 8-player lobby's slot, color, race, and team
/// assignments plus the game-init that seeds the synced RNG is on the order
/// of thirty commands, all emitted back-to-back the moment the host's UI
/// populates, with nothing pacing them (unlike chat, no human types that
/// fast). 32 covers that whole burst from a single slot with a little room to
/// spare, while still bounding a flooding client to a small, cheap admission
/// check per command.
const LOBBY_RATE_BURST: u32 = 32;

/// The lobby rate cap's refill rate: one additional token every this long, up
/// to [`LOBBY_RATE_BURST`]. Ordinary post-setup lobby traffic is a member's own
/// occasional request (a ready toggle, a race or team change) — nothing close
/// to chat's typing cadence, let alone a flood. 200ms (5/sec sustained) is
/// generous enough that a player rapidly clicking through settings is never
/// throttled, while still keeping a misbehaving or hostile client's sustained
/// rate an order of magnitude below what could meaningfully grow the mesh
/// control channel or the local push queues.
const LOBBY_RATE_REFILL_INTERVAL: Duration = Duration::from_millis(200);

/// Every session's lobby state on this relay, keyed like the turn roster by
/// `(tenant, session)`. A plain (non-async) mutex is deliberate, matching the
/// routing roster: every critical section here is a short, await-free edit
/// (append the log, `try_send` to each member, insert/remove a member), so the
/// lock is never held across an `.await`, and the replay/live handoff stays
/// atomic under it.
pub type LobbyRegistry = Arc<Mutex<HashMap<SessionKey, LobbySession>>>;

/// Creates an empty lobby registry for a relay with no sessions yet.
pub fn new_lobby_registry() -> LobbyRegistry {
    Arc::default()
}

/// One session's lobby state: the ordered replay log plus the live per-member
/// push channels. Public only because it appears in the [`LobbyRegistry`] alias;
/// its fields are private, so the state is built and read solely through this
/// module.
#[derive(Default)]
pub struct LobbySession {
    /// Every lobby command delivered for this session, in arrival order — the
    /// replay source for a member whose stream comes up after commands flowed.
    log: Vec<LobbyCommand>,
    /// Running byte total of `log`'s payloads, for the byte cap.
    log_bytes: usize,
    /// Whether the log has hit a cap. Once set, further commands are dropped
    /// (the session is misbehaving), so a late joiner replays a truncated but
    /// consistent prefix rather than the relay growing the log without bound.
    overflowed: bool,
    /// The live per-member push channels: slot → that member's lobby-push
    /// sender, drained by the member's slot-link task and written to its control
    /// stream.
    members: HashMap<SlotId, mpsc::Sender<LobbyCommand>>,
    /// Per-authoring-slot token buckets for the rate cap. Keyed separately from
    /// `members` (and outliving a member's own deregistration) so a slot's
    /// budget is not reset by a reconnect, mirroring [`crate::chat`].
    limiters: HashMap<SlotId, TokenBucket>,
    /// Per-slot rate-limited warn counter for the rate-cap violation.
    rate_warns: HashMap<SlotId, RateLimitedCounter>,
}

/// Registers a member for `key` and returns the receiver its slot-link task
/// drains, replaying every earlier lobby command to it in order first.
///
/// Under the registry lock: the newcomer's channel is created, the existing log
/// is enqueued into it (skipping any command the newcomer authored itself — the
/// author is never echoed), and the sender is inserted into the session's member
/// set. Doing all three under the one lock [`deliver`] also holds is what makes
/// the replay/live handoff exactly-once — see the module docs.
pub fn register_member(
    registry: &LobbyRegistry,
    key: &SessionKey,
    slot: SlotId,
) -> mpsc::Receiver<LobbyCommand> {
    let (tx, rx) = mpsc::channel(LOBBY_PUSH_CAPACITY);
    let mut registry = registry.lock();
    let session = registry.entry(key.clone()).or_default();
    for command in &session.log {
        // Never replay a member its own authored command; its game echoes those
        // locally, exactly as live fan-out skips the author.
        if command.slot == u32::from(slot.0) {
            continue;
        }
        if tx.try_send(command.clone()).is_err() {
            // The channel is sized above the log cap, so a legitimate replay
            // always fits; a failure here means the log overflowed its cap
            // (already warned when it did), so there is nothing more to do.
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                "lobby log replay did not fit the push channel; early commands dropped",
            );
            break;
        }
    }
    session.members.insert(slot, tx);
    rx
}

/// Removes `slot` from `key`'s live member set — its slot-link task has ended.
/// The session's log is left intact so any remaining or late-arriving member
/// still replays it; the whole session is torn down by [`end_session`] when the
/// relay's last local member for it departs.
pub fn deregister_member(registry: &LobbyRegistry, key: &SessionKey, slot: SlotId) {
    let mut registry = registry.lock();
    if let Some(session) = registry.get_mut(key) {
        session.members.remove(&slot);
    }
}

/// Drops all lobby state for `key`, called when the relay's last local member
/// for the session departs (the same emptied-roster signal that closes the
/// session for the coordinator). A relay that never homed a member for the
/// session — one that only relayed mesh copies into the log — keeps the state
/// until its own first-and-last local member's teardown runs, which it always
/// eventually does (a serving relay homes at least one slot).
pub fn end_session(registry: &LobbyRegistry, key: &SessionKey) {
    registry.lock().remove(key);
}

/// Checks whether one client-authored lobby command from `slot` in `key`'s
/// session may proceed to [`deliver`]: `slot`'s token bucket has budget.
/// Only ever called at the client edge, before `deliver` and the mesh
/// fan-out — mirroring [`crate::chat::admit`], a mesh-received command has
/// already passed its origin relay's `admit` and goes straight to `deliver`
/// (see `dispatch_mesh_control`'s `LobbyCommand` arm in the mesh module), so
/// re-checking here would only re-penalize an already-admitted command
/// against a second, independent bucket keyed on the same slot.
///
/// A failing command is dropped by the caller without closing the
/// connection; the failure logs through a rate-limited counter so a spam
/// burst produces O(log n) log lines rather than one per command.
pub fn admit(registry: &LobbyRegistry, key: &SessionKey, slot: SlotId) -> bool {
    let mut registry = registry.lock();
    let session = registry.entry(key.clone()).or_default();
    if session
        .limiters
        .entry(slot)
        .or_insert_with(|| TokenBucket::new(LOBBY_RATE_BURST, LOBBY_RATE_REFILL_INTERVAL))
        .try_take()
    {
        return true;
    }
    if session.rate_warns.entry(slot).or_default().observe() {
        tracing::warn!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            slot = slot.0,
            "dropping lobby command; slot exceeded its lobby rate cap",
        );
    }
    false
}

/// Delivers one lobby command to `key`'s local members: appends it to the replay
/// log and fans it out to every member except its author.
///
/// `command.slot` is the authoritative author, already stamped — by the client
/// edge to the authenticated slot for a client-authored command, or by the
/// origin relay for a mesh-received one — so the author is excluded by matching
/// it (a client-authored command's author is a local member and is not echoed; a
/// mesh-received command's author is a remote slot absent from this relay's
/// members, so every local member receives it). Appending and fanning out happen
/// under the one lock [`register_member`] snapshots under, so a concurrent join
/// sees this command in exactly one of {its replay snapshot, its live tail}.
///
/// Only ever called after [`admit`] has already cleared a client-authored
/// command (or, for a mesh-received one, unconditionally — see `admit`'s
/// docs); this function's own admission concern is the session-wide log cap,
/// independent of any one slot's rate. Returns whether the command was
/// admitted and delivered — the caller's cue for whether to also forward a
/// copy across the mesh: a command this relay refused was never added to its
/// own log or fanned to its own locals, so a peer that received it anyway
/// would be out of sync with every relay that refused it.
pub fn deliver(registry: &LobbyRegistry, key: &SessionKey, command: LobbyCommand) -> bool {
    let mut registry = registry.lock();
    let session = registry.entry(key.clone()).or_default();

    if session.overflowed {
        return false;
    }
    let new_bytes = command.payload.len();
    if session.log.len() >= LOBBY_LOG_MAX_COMMANDS
        || session.log_bytes.saturating_add(new_bytes) > LOBBY_LOG_MAX_BYTES
    {
        session.overflowed = true;
        tracing::warn!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            commands = session.log.len(),
            bytes = session.log_bytes,
            "lobby command log exceeded its cap; dropping this and further lobby commands",
        );
        return false;
    }
    session.log.push(command.clone());
    session.log_bytes += new_bytes;
    for (slot, tx) in &session.members {
        if command.slot == u32::from(slot.0) {
            continue;
        }
        match tx.try_send(command.clone()) {
            Ok(()) => {}
            // A full push queue is a member hopelessly behind (lobby commands are
            // tiny and rare) — log rather than drop silently, since a missed setup
            // command would leave that member's pre-game state incomplete.
            Err(mpsc::error::TrySendError::Full(_)) => tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                "lobby push queue full; a lobby command may be delayed for this member",
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

    fn command(slot: u32, byte: u8) -> LobbyCommand {
        LobbyCommand {
            slot,
            payload: vec![byte].into(),
        }
    }

    /// Draining every command currently queued on a member's receiver, without
    /// blocking — the member's slot-link task would write these to its control
    /// stream in this order.
    fn drain(rx: &mut mpsc::Receiver<LobbyCommand>) -> Vec<(u32, u8)> {
        let mut got = Vec::new();
        while let Ok(command) = rx.try_recv() {
            got.push((command.slot, command.payload[0]));
        }
        got
    }

    #[test]
    fn a_command_fans_out_to_every_member_but_its_author() {
        let registry = new_lobby_registry();
        let k = key();
        let mut host = register_member(&registry, &k, SlotId(0));
        let mut peer = register_member(&registry, &k, SlotId(1));

        // Slot 0 (host) authors a command: it reaches slot 1, never slot 0.
        deliver(&registry, &k, command(0, 0xA1));
        assert_eq!(drain(&mut host), vec![], "the author is not echoed its own");
        assert_eq!(drain(&mut peer), vec![(0, 0xA1)]);
    }

    #[test]
    fn a_late_member_replays_the_whole_log_in_order_then_tails_live() {
        let registry = new_lobby_registry();
        let k = key();
        // The host is up and authors setup commands before the peer's link exists.
        let _host = register_member(&registry, &k, SlotId(0));
        deliver(&registry, &k, command(0, 0x01));
        deliver(&registry, &k, command(0, 0x02));
        deliver(&registry, &k, command(0, 0x03));

        // The peer joins late: it replays every earlier command in arrival order.
        let mut peer = register_member(&registry, &k, SlotId(1));
        assert_eq!(drain(&mut peer), vec![(0, 0x01), (0, 0x02), (0, 0x03)]);

        // A live command after the join tails the replay with no gap, no dup.
        deliver(&registry, &k, command(0, 0x04));
        assert_eq!(drain(&mut peer), vec![(0, 0x04)]);
    }

    #[test]
    fn replay_skips_a_reconnecting_members_own_authored_commands() {
        let registry = new_lobby_registry();
        let k = key();
        let _host = register_member(&registry, &k, SlotId(0));
        let _peer = register_member(&registry, &k, SlotId(1));
        deliver(&registry, &k, command(0, 0x10)); // host authored
        deliver(&registry, &k, command(1, 0x20)); // peer authored

        // Slot 1 re-registers (a reconnect): it replays the host's command but not
        // its own, so it never re-applies a command it authored.
        let mut peer_again = register_member(&registry, &k, SlotId(1));
        assert_eq!(drain(&mut peer_again), vec![(0, 0x10)]);
    }

    #[test]
    fn a_mesh_authored_command_reaches_every_local_member() {
        let registry = new_lobby_registry();
        let k = key();
        let mut a = register_member(&registry, &k, SlotId(0));
        let mut b = register_member(&registry, &k, SlotId(1));

        // A command authored by a remote slot (7) arriving off the mesh: no local
        // member is its author, so both locals receive it.
        deliver(&registry, &k, command(7, 0xEE));
        assert_eq!(drain(&mut a), vec![(7, 0xEE)]);
        assert_eq!(drain(&mut b), vec![(7, 0xEE)]);
    }

    #[test]
    fn a_command_appended_before_a_join_is_not_also_delivered_live() {
        // The exactly-once boundary: a command already in the log when a member
        // joins is delivered by the replay, and is not re-fanned live (the member
        // was not yet in the set when it was delivered).
        let registry = new_lobby_registry();
        let k = key();
        let _host = register_member(&registry, &k, SlotId(0));
        deliver(&registry, &k, command(0, 0x55));

        let mut peer = register_member(&registry, &k, SlotId(1));
        // Exactly one copy — from the replay, not a second live delivery.
        assert_eq!(drain(&mut peer), vec![(0, 0x55)]);
    }

    #[test]
    fn the_log_stops_growing_past_the_command_cap() {
        let registry = new_lobby_registry();
        let k = key();
        let mut peer = register_member(&registry, &k, SlotId(1));
        // Author one past the cap from slot 0 (so the peer receives them all).
        for i in 0..(LOBBY_LOG_MAX_COMMANDS + 1) {
            deliver(&registry, &k, command(0, i as u8));
        }
        // The peer received exactly the cap's worth — the overflow command was
        // dropped, not fanned out.
        assert_eq!(drain(&mut peer).len(), LOBBY_LOG_MAX_COMMANDS);

        // And a member joining afterwards replays exactly the cap's worth, the
        // consistent prefix.
        let mut late = register_member(&registry, &k, SlotId(2));
        assert_eq!(drain(&mut late).len(), LOBBY_LOG_MAX_COMMANDS);
    }

    #[test]
    fn deregister_removes_a_member_but_keeps_the_log() {
        let registry = new_lobby_registry();
        let k = key();
        let _host = register_member(&registry, &k, SlotId(0));
        deliver(&registry, &k, command(0, 0x01));
        deregister_member(&registry, &k, SlotId(0));

        // The log survives the member leaving, so a late joiner still catches up.
        let mut late = register_member(&registry, &k, SlotId(1));
        assert_eq!(drain(&mut late), vec![(0, 0x01)]);

        // end_session drops everything; a fresh join then starts from empty.
        end_session(&registry, &k);
        let mut after = register_member(&registry, &k, SlotId(1));
        assert_eq!(drain(&mut after), vec![]);
    }

    #[test]
    fn a_burst_past_the_rate_cap_is_rejected_then_recovers_after_refill() {
        let registry = new_lobby_registry();
        let k = key();
        let slot = SlotId(0);

        // The first LOBBY_RATE_BURST commands in a burst are all admitted --
        // covering a full lobby's worth of setup commands from one slot.
        for _ in 0..LOBBY_RATE_BURST {
            assert!(admit(&registry, &k, slot));
        }
        // The next one, still within the burst window, is rejected.
        assert!(!admit(&registry, &k, slot));

        // After a refill interval passes, at least one more token is available.
        std::thread::sleep(LOBBY_RATE_REFILL_INTERVAL + std::time::Duration::from_millis(50));
        assert!(admit(&registry, &k, slot));
    }

    #[test]
    fn the_rate_cap_is_independent_per_slot() {
        let registry = new_lobby_registry();
        let k = key();
        for _ in 0..LOBBY_RATE_BURST {
            assert!(admit(&registry, &k, SlotId(0)));
        }
        assert!(
            !admit(&registry, &k, SlotId(0)),
            "slot 0 exhausted its burst"
        );
        // A different slot has its own, untouched budget.
        assert!(admit(&registry, &k, SlotId(1)));
    }

    #[test]
    fn deliver_reports_admit_or_refuse_and_the_caller_gates_mesh_fan_out_on_it() {
        // `deliver`'s own admission concern is the session-wide log cap, not
        // the rate cap (that's `admit`, checked separately by the caller
        // before `deliver` is ever reached). Exhaust the log cap directly, so
        // `deliver` itself is what refuses, without touching the rate cap.
        let registry = new_lobby_registry();
        let k = key();
        // A distinct authoring slot per command so no one slot's rate cap
        // interferes with filling the session-wide log cap.
        for i in 0..LOBBY_LOG_MAX_COMMANDS {
            let slot = (i % 200) as u32; // cycle slots well past any u8 rate cap window
            assert!(
                deliver(&registry, &k, command(slot, 0)),
                "command {i} should still be under the log cap",
            );
        }
        assert!(
            !deliver(&registry, &k, command(250, 0)),
            "the log cap is now exhausted; deliver refuses",
        );
    }
}
