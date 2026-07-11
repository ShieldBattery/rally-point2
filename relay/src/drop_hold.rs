//! Indefinite holds on the authority's synced-leave decision for a slot that
//! *dropped* (its link died) rather than left cleanly, plus the per-requester
//! rate cap on the manual drop requests that resolve those holds.
//!
//! A dropped slot's departure is recorded and announced immediately (so every
//! relay knows it left and survivors learn who disconnected), but the decision
//! that removes it from lockstep — the permanent
//! [`LeaveDirective`](rally_point_proto::messages::LeaveDirective) — is **never
//! made automatically**. A disconnect drop is always a human decision: after a
//! slot has been gone a while, any single surviving member sends a `RequestDrop`
//! for it, and the session's authority relay honors that request once the hold
//! has stood past [`DROP_UNLOCK`]. Until such a request arrives — which may be
//! never — the slot stays held, the survivors stay stalled but alive, and the
//! game waits on a person rather than a timer. A clean leave (the client
//! announced its own intent) is never held: an F10 quit must unstall survivors
//! at once.
//!
//! A hold is therefore just a marker — the instant the drop was first observed —
//! not a timer. There is no task, no expiry, and no automatic firing. The
//! marker's timestamp answers two questions: whether a slot is still an
//! undecided drop ([`is_pending`](DropHolds::is_pending) /
//! [`pending_slots`](DropHolds::pending_slots)), and how long it has stood
//! ([`held_for`](DropHolds::held_for)), which the authority compares against
//! [`DROP_UNLOCK`] before honoring a request. A duplicate drop signal for a slot
//! already held keeps the original timestamp — the window never restarts.
//!
//! The holds are deliberately **local and ephemeral**, not replicated state. The
//! durable record is the departure every relay already keeps (from
//! `record_departure` / a mesh `SlotDeparted`); this only gates *whether and
//! when* the relay that is currently authority decides against that record. Every
//! relay marks its own hold when it observes the drop, so a failover does not lose
//! the departure — the promoted authority re-derives it from the shared record on
//! promotion, and each relay's leftover marker is a harmless read the next
//! promotion or request consults. Because a hold never fires on its own, an ended
//! session's leftover markers must be swept explicitly (see
//! [`end_session`](DropHolds::end_session)), where the old timed hold's expiry
//! would once have removed them.
//!
//! **The sweep must not discard a hold that is still the reconnect-admission
//! token for an undecided drop.** A relay's local roster can empty — and
//! [`end_session`](DropHolds::end_session) fire — at the very moment a hold is
//! freshly marked (the last local slot disconnecting *is* what both creates its
//! own hold and empties the roster, in the same teardown): a session split across
//! relays hits this on every single disconnect, since each relay's local roster
//! only ever holds the slots it is home to. So the sweep removes only holds whose
//! slot's leave is **already decided** (an earlier honored request, or an earlier
//! abandoned-session force-decide); an undecided hold survives to keep serving as
//! the re-register admission check and the unlock clock, no matter how many times
//! the local roster empties and refills around it. It is still memory-bounded: the
//! abandoned-session timer decides every session-wide-empty session's remaining
//! holds within [`ABANDONED_SESSION_TIMEOUT`], and deciding one there releases its
//! hold too (see `routing::decide_and_broadcast_abandoned`), so nothing here
//! outlives that window undecided.
//!
//! Release covers three orderings, and — because two of them can race a
//! concurrent claimant for the very same hold — [`release`](DropHolds::release)
//! reports whether it actually found and removed a pending entry, so every path
//! that decides a leave off a hold treats that boolean as a claim: only the side
//! that actually removed the entry may act on it, and a side that finds it
//! already gone must stand down rather than decide (or resurrect) a departure
//! for a slot that may already be live again. A clean-leave intent arriving
//! while a drop's hold for the same slot is still pending releases the hold and
//! decides immediately regardless of the claim — a clean leave is authoritative
//! on its own, never contingent on a hold having existed — so the "left" outcome
//! wins over the held "dropped" one. A client that re-registers while its drop
//! is held claims the hold atomically with reinstating the slot (see
//! [`take_if_pending`](DropHolds::take_if_pending)), rather than a separate
//! release-then-reinstate whose gap a concurrent decide could land in. An
//! honored manual request — whether from a live survivor's `RequestDrop` or the
//! abandoned-session timer's force-decide — claims the hold before deciding
//! against it, standing down if it lost the claim.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rally_point_proto::ids::SlotId;
use tokio::sync::oneshot;

use crate::routing::SessionKey;

/// The map of live drop holds: each held `(session, slot)` mapped to the instant
/// the drop was first observed on this relay. Presence means the slot is an
/// undecided drop; the instant is the basis for [`DropHolds::held_for`].
type Holds = Arc<Mutex<HashMap<(SessionKey, SlotId), Instant>>>;

/// The map of per-requester drop-request rate limiters, keyed by the session and
/// the requesting slot. Kept separate from [`Holds`] because it is keyed by *who
/// asked*, not *who dropped*.
type RequestLimiters = Arc<Mutex<HashMap<(SessionKey, SlotId), RequestBucket>>>;

/// The map of live abandoned-session timers: one per session that has gone empty
/// session-wide with an undecided departure. The value is the timer task's cancel
/// handle — dropping it (via [`DropHolds::cancel_abandon`], or when the timer fires
/// and removes its own entry) sends the task down its cancel branch. A present
/// entry means a timer is running for that session.
type AbandonTimers = Arc<Mutex<HashMap<SessionKey, oneshot::Sender<()>>>>;

/// How long a dropped slot's hold must stand before the session's authority relay
/// will honor a manual request to drop it.
///
/// This is the anti-grief *minimum*, not the normal-play experience: even a
/// modified or malicious client cannot force a slot's removal before 30 s of
/// sustained disconnection, no matter how fast it fires `RequestDrop`. The game
/// client's own Drop button is a separate, higher bar — disabled and greyed out
/// until 45 s from when *it* learned of the disconnect — so in ordinary play a
/// legitimate click always lands comfortably past this floor. The 15 s gap between
/// the two is deliberate margin, not slack this floor is tuned against: it exists
/// so observation skew or a clock difference between the client and the relay can
/// never make an already-enabled button's click bounce off a floor it should
/// already have cleared.
pub const DROP_UNLOCK: Duration = Duration::from_secs(30);

/// The drop-request rate cap's burst size: a requesting slot may send this many
/// requests back-to-back before the limiter starts rejecting. Small, because a
/// legitimate survivor clicks the drop button once (or twice, impatiently) — the
/// cap exists only so a stuck or hostile client cannot flood the mesh with
/// request broadcasts.
const DROP_REQUEST_BURST: u32 = 2;

/// The drop-request rate cap's refill: one additional token every this long, up to
/// [`DROP_REQUEST_BURST`]. Loose enough for an impatient double-click, tight enough
/// that a flooding client is throttled to one request every couple of seconds.
const DROP_REQUEST_REFILL_INTERVAL: Duration = Duration::from_secs(2);

/// How long a session with no live slots anywhere — every player's link dead — may
/// stay held with undecided departures before those departures are decided
/// automatically, closing the session out.
///
/// This is the one place a drop is decided without a human asking, and it is
/// deliberately narrow: the no-auto-drop policy exists to protect a disconnected
/// player *while other players remain* to make the call — a drop is their decision
/// to keep waiting or to move on. With nobody connected there is no one to wrong
/// and no one to ask; the game cannot resume, so the departures are decided and the
/// session torn down rather than held forever. An occupied session never
/// auto-decides — only a request does — no matter how long a slot has been gone.
///
/// Unlike a single-player drop, there is no surviving human here to deliberately
/// keep waiting, so the window only has to outlast a realistic *shared* or
/// *transient* blip — a relay restart, a common uplink hiccup — not a genuine
/// decision to hold out. A reconnect completes within seconds of connectivity
/// actually returning (and any slot re-registering cancels the timer outright), so
/// 45 s is ample margin for that case while cleaning up a truly abandoned session
/// well before it would otherwise sit idle for minutes; it also lines up with the
/// game client's own 45 s drop-unlock, so no session outlives what a player at the
/// keyboard could have decided for it anyway.
pub const ABANDONED_SESSION_TIMEOUT: Duration = Duration::from_secs(45);

/// Per-relay registry of undecided drop holds and the per-requester rate cap on
/// the manual requests that resolve them, keyed by the session and slot each
/// concerns. Cheap to clone (an `Arc` around each shared map plus the unlock
/// duration), so it rides in [`crate::mesh::MeshState`] alongside the other
/// per-session registries and is handed to every task that observes a departure or
/// a drop request.
#[derive(Clone)]
pub struct DropHolds {
    /// Live holds: a present entry means an undecided drop is pending for that
    /// `(session, slot)`, with the instant it was first observed as the value.
    holds: Holds,
    /// Per-requester token buckets for the drop-request rate cap.
    limiters: RequestLimiters,
    /// Live abandoned-session timers, one per fully-empty session that still has an
    /// undecided departure. Deliberately kept out of [`end_session`](Self::end_session)'s
    /// sweep: a timer arms exactly when this relay's last local slot leaves, so the
    /// same teardown that sweeps holds must not also cancel the timer — the timer
    /// self-removes on fire or is cancelled by a re-register.
    abandon_timers: AbandonTimers,
    /// How long a hold must stand before the authority will honor a request to
    /// drop it. A field rather than a bare use of [`DROP_UNLOCK`] so a test can
    /// inject a tiny floor and drive the honor path without a real 30-second wait;
    /// production builds it with [`DROP_UNLOCK`].
    unlock: Duration,
    /// How long a session may stay empty session-wide with undecided departures
    /// before they are decided automatically. A field for the same reason `unlock`
    /// is — a test injects a tiny window rather than waiting the production 45 s;
    /// production builds it with [`ABANDONED_SESSION_TIMEOUT`].
    abandon_timeout: Duration,
}

impl DropHolds {
    /// A registry whose holds unlock for a manual drop after `unlock`, and whose
    /// abandoned sessions are closed out after `abandon_timeout`.
    pub fn new(unlock: Duration, abandon_timeout: Duration) -> Self {
        Self {
            holds: Arc::new(Mutex::new(HashMap::new())),
            limiters: Arc::new(Mutex::new(HashMap::new())),
            abandon_timers: Arc::new(Mutex::new(HashMap::new())),
            unlock,
            abandon_timeout,
        }
    }

    /// The unlock floor a hold must exceed before the authority honors a request
    /// to drop it — [`held_for`](Self::held_for) is compared against this.
    pub fn unlock(&self) -> Duration {
        self.unlock
    }

    /// Marks `(key, slot)` as an undecided drop, stamping now as the observation
    /// instant — unless a hold for the slot already exists, in which case the
    /// original instant is kept (a duplicate drop signal never restarts the
    /// window). Records nothing to decide: a dropped slot is removed only by an
    /// honored `RequestDrop`, or never.
    pub fn hold(&self, key: SessionKey, slot: SlotId) {
        self.holds
            .lock()
            .entry((key, slot))
            .or_insert_with(Instant::now);
    }

    /// Releases the hold on `(key, slot)`, if one is pending, and reports whether
    /// it found one to release. Called when a clean-leave intent supersedes a
    /// drop (where the boolean is informational only — a clean leave decides
    /// either way), when the authority honors a drop request for the slot (where
    /// the boolean gates the decision), and by
    /// [`take_if_pending`](Self::take_if_pending) internally for a re-registering
    /// client.
    ///
    /// The boolean is this hold's claim signal: `true` means *this* call is the
    /// one that removed a still-pending entry, so the caller — and only the
    /// caller — owns whatever happens next for this slot. `false` means the hold
    /// was already gone (a concurrent claimant, or nothing was ever held), so the
    /// caller must not decide (or resurrect) a departure on the strength of a
    /// hold it did not actually win.
    #[must_use]
    pub fn release(&self, key: &SessionKey, slot: SlotId) -> bool {
        // The map key is owned; clone the session key to look it up.
        self.holds.lock().remove(&(key.clone(), slot)).is_some()
    }

    /// Atomically decides a re-registering slot's fate against its hold: if a
    /// hold is pending, runs `reinstate` (the caller's `consensus::reinstate_slot`)
    /// and removes the hold entry, all inside one acquisition of the holds lock,
    /// then returns whatever `reinstate` reported. Returns `false` outright, never
    /// calling `reinstate`, when no hold is pending.
    ///
    /// This is the single linearization point a reconnect races every decide path
    /// against: whichever side observes the hold present — this call, an honored
    /// `RequestDrop`'s [`release`](Self::release), or the abandoned-session
    /// force-decide — is the one, and only one, side that acts on it, because the
    /// removal happens under the same lock the presence check ran under, so no
    /// concurrent caller can find the hold still pending once it is gone.
    ///
    /// Running `reinstate` *inside* the lock, before the entry is removed, is
    /// what closes the narrower window the module docs describe: an external
    /// reader of [`pending_slots`](Self::pending_slots) (an authority promotion's
    /// re-derive) takes the same lock, so it can never observe "hold gone,
    /// departure record still present" — it either reads before this call (hold
    /// present, record present: an ordinary undecided drop) or after (hold gone,
    /// and — because `reinstate` already ran — the record gone too).
    ///
    /// `reinstate` returning `false` (the slot's leave was already decided under
    /// `consensus`'s own lock — a concurrent `RequestDrop` or abandoned-session
    /// force-decide won a photo finish) still removes the hold: a hold whose slot
    /// just got decided against it is exactly as resolved as one this call
    /// reinstated, and nothing should ever act on it again.
    #[must_use]
    pub fn take_if_pending(
        &self,
        key: &SessionKey,
        slot: SlotId,
        reinstate: impl FnOnce() -> bool,
    ) -> bool {
        let map_key = (key.clone(), slot);
        let mut holds = self.holds.lock();
        if !holds.contains_key(&map_key) {
            return false;
        }
        let reinstated = reinstate();
        holds.remove(&map_key);
        reinstated
    }

    /// Whether an undecided drop is currently held for `(key, slot)`. Read at
    /// re-register time to tell a client returning within its hold (a hold is
    /// pending, so release it and resume) from one whose leave was already decided
    /// (no hold, so refuse), and at the client edge to sanity-check a drop request
    /// names a slot this relay actually sees as dropped.
    pub fn is_pending(&self, key: &SessionKey, slot: SlotId) -> bool {
        self.holds.lock().contains_key(&(key.clone(), slot))
    }

    /// The slots of `key` whose drop is currently held on this relay. Read at an
    /// authority promotion so it re-derives leaves only for slots that are *not*
    /// held as undecided drops — a held drop's fate is decided only by a manual
    /// request, never by a promotion.
    pub fn pending_slots(&self, key: &SessionKey) -> HashSet<SlotId> {
        self.holds
            .lock()
            .keys()
            .filter(|(hold_key, _)| hold_key == key)
            .map(|(_, slot)| *slot)
            .collect()
    }

    /// How long the hold on `(key, slot)` has stood, or `None` when no hold is
    /// pending. The authority compares this against [`unlock`](Self::unlock)
    /// before honoring a manual drop request: a request past the floor is honored,
    /// one before it is refused (the drop may still be a recoverable blip).
    pub fn held_for(&self, key: &SessionKey, slot: SlotId) -> Option<Duration> {
        self.holds
            .lock()
            .get(&(key.clone(), slot))
            .map(Instant::elapsed)
    }

    /// Charges one drop-request token to `requester` in `key`'s session, returning
    /// whether the request may proceed. A fresh requester starts with a full burst;
    /// over-cap requests return `false` and are dropped by the caller without ever
    /// closing the link. Mirrors the game-chat rate cap ([`crate::chat`]).
    pub fn admit_request(&self, key: &SessionKey, requester: SlotId) -> bool {
        self.limiters
            .lock()
            .entry((key.clone(), requester))
            .or_insert_with(RequestBucket::new)
            .try_take()
    }

    /// Arms an abandoned-session timer for `key`: after `abandon_timeout`, `on_expire`
    /// runs — unless [`cancel_abandon`](Self::cancel_abandon) removed it first (a slot
    /// re-registered). Idempotent per session: if a timer is already running, the
    /// existing one is kept, so a second empty-presence observation does not restart
    /// the window. Must be called from within a Tokio runtime — it spawns the timer.
    ///
    /// `on_expire` is the decide-and-broadcast step; it runs once, at expiry, on the
    /// timer task. It is synchronous (a force-decide plus channel sends, no awaits)
    /// so the timer needs no borrowed state past the fire.
    pub fn arm_abandon<F>(&self, key: SessionKey, on_expire: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let (cancel_tx, cancel_rx) = oneshot::channel();
        {
            let mut timers = self.abandon_timers.lock();
            if timers.contains_key(&key) {
                // A timer is already running for this session; keep it, so a
                // redundant empty-presence observation cannot push the deadline out.
                return;
            }
            timers.insert(key.clone(), cancel_tx);
        }
        let timers = Arc::clone(&self.abandon_timers);
        let timeout = self.abandon_timeout;
        tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(timeout) => {
                    // The window elapsed: remove our own entry (so a later
                    // abandonment can arm afresh) and decide. Removing under the lock
                    // before deciding means a concurrent `cancel_abandon` either
                    // already won (our entry is gone) or loses (it finds nothing) —
                    // either way the force-decide is idempotent, so a race cannot
                    // double-decide.
                    timers.lock().remove(&key);
                    on_expire();
                }
                _ = cancel_rx => {
                    // Cancelled (a slot re-registered). The canceller already removed
                    // the entry; nothing to decide here.
                }
            }
        });
    }

    /// Cancels `key`'s abandoned-session timer, if one is running — a slot
    /// re-registered, so the session is no longer empty. A no-op when none is armed.
    /// Removing the entry drops its cancel sender, sending the timer task down its
    /// cancel branch.
    pub fn cancel_abandon(&self, key: &SessionKey) {
        self.abandon_timers.lock().remove(key);
    }

    /// Whether an abandoned-session timer is currently armed for `key` — for tests
    /// (including this crate's own integration tests, which link against this
    /// crate as an external dependency and so cannot see a `#[cfg(test)]` item).
    pub fn abandon_armed(&self, key: &SessionKey) -> bool {
        self.abandon_timers.lock().contains_key(key)
    }

    /// Drops request limiters for `key` unconditionally, and holds whose slot's
    /// leave is in `decided` — called when the relay's last local slot for the
    /// session leaves, mirroring how the roster group, lobby, chat, and turn-ring
    /// state are dropped then. Idempotent.
    ///
    /// **Deliberately does not sweep a hold for a slot not in `decided`.** Every
    /// disconnect on a session split across relays empties that relay's *local*
    /// roster (each relay is home to only its own slots), which is exactly the
    /// moment this fires — including the disconnect that just marked the hold this
    /// call would otherwise erase before anything ever decided it. `decided` is the
    /// caller's read of which slots' leaves are already committed (see
    /// [`crate::consensus::decided_slots`]); a hold outside that set still gates an
    /// undecided drop and must survive to keep serving as the reconnect-admission
    /// check and the unlock clock. See the module docs for why this is still
    /// memory-bounded rather than a leak.
    ///
    /// The abandoned-session timer is, separately, never swept here either: it
    /// arms at the very moment this relay's last local slot leaves (a fully-empty
    /// session), so cancelling it in the same teardown would defeat its whole
    /// purpose. It self-removes when it fires, or is cancelled by a re-register.
    pub fn end_session(&self, key: &SessionKey, decided: &HashSet<SlotId>) {
        self.holds
            .lock()
            .retain(|(hold_key, slot), _| hold_key != key || !decided.contains(slot));
        self.limiters
            .lock()
            .retain(|(limiter_key, _), _| limiter_key != key);
    }
}

/// A per-requester token bucket for the drop-request rate cap. A whole-token
/// counter plus a last-refill instant, matching the game-chat limiter: drop
/// requests are far rarer than chat, so whole-token granularity costs nothing and
/// integer refill counts avoid floating-point drift over a long session.
struct RequestBucket {
    /// Tokens currently available, capped at [`DROP_REQUEST_BURST`].
    tokens: u32,
    /// The instant the tokens above were last refilled up to.
    last_refill: Instant,
}

impl RequestBucket {
    /// A fresh bucket starts with a full burst — a survivor's first drop requests
    /// are not penalized.
    fn new() -> Self {
        Self {
            tokens: DROP_REQUEST_BURST,
            last_refill: Instant::now(),
        }
    }

    /// Refills whole elapsed [`DROP_REQUEST_REFILL_INTERVAL`]s since the last
    /// refill (capped at the burst), then attempts to take one token. Returns
    /// `false` — taking nothing — when the bucket is still empty after refilling.
    fn try_take(&mut self) -> bool {
        let elapsed = self.last_refill.elapsed();
        let interval_ms = DROP_REQUEST_REFILL_INTERVAL.as_millis().max(1);
        let intervals = elapsed.as_millis() / interval_ms;
        if intervals > 0 {
            let intervals = u32::try_from(intervals).unwrap_or(DROP_REQUEST_BURST);
            self.tokens = self
                .tokens
                .saturating_add(intervals)
                .min(DROP_REQUEST_BURST);
            self.last_refill += DROP_REQUEST_REFILL_INTERVAL * intervals;
        }
        if self.tokens == 0 {
            false
        } else {
            self.tokens -= 1;
            true
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
            tenant: TenantId("t".to_owned()),
            session: SessionId(1),
        }
    }

    #[test]
    fn a_hold_is_pending_and_records_its_elapsed() {
        let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
        assert!(!holds.is_pending(&key(), SlotId(3)));
        assert!(holds.held_for(&key(), SlotId(3)).is_none());

        holds.hold(key(), SlotId(3));
        assert!(holds.is_pending(&key(), SlotId(3)));
        assert!(
            holds.held_for(&key(), SlotId(3)).is_some(),
            "a held slot reports how long it has stood",
        );
        assert_eq!(
            holds.pending_slots(&key()),
            [SlotId(3)].into_iter().collect()
        );
    }

    #[test]
    fn releasing_a_hold_clears_it() {
        let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
        holds.hold(key(), SlotId(3));
        assert!(
            holds.release(&key(), SlotId(3)),
            "the first release claims a genuinely pending hold",
        );
        assert!(!holds.is_pending(&key(), SlotId(3)));
        assert!(holds.held_for(&key(), SlotId(3)).is_none());
        // Releasing an absent hold is a no-op, never a panic.
        assert!(!holds.release(&key(), SlotId(9)));
    }

    #[test]
    fn a_second_release_finds_nothing_to_claim() {
        // The claim semantics that close the split-brain race: once a hold is
        // released, a second release for the same slot -- a concurrent decide
        // path that lost the race -- must see `false`, not silently "succeed"
        // again, so it knows to stand down rather than act a second time.
        let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
        holds.hold(key(), SlotId(3));
        assert!(
            holds.release(&key(), SlotId(3)),
            "the first release claims it"
        );
        assert!(
            !holds.release(&key(), SlotId(3)),
            "a second release for the same slot finds nothing left to claim",
        );
    }

    #[test]
    fn take_if_pending_reinstates_and_removes_the_hold() {
        let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
        holds.hold(key(), SlotId(3));

        let reinstated = holds.take_if_pending(&key(), SlotId(3), || true);
        assert!(reinstated, "reinstate succeeded, so the claim reports true");
        assert!(
            !holds.is_pending(&key(), SlotId(3)),
            "the hold is removed once claimed, regardless of reinstate's outcome",
        );
    }

    #[test]
    fn take_if_pending_still_removes_the_hold_when_reinstate_loses_the_photo_finish() {
        // `reinstate` returning false models `consensus::reinstate_slot` finding
        // the slot's leave already decided under its own lock -- a concurrent
        // `RequestDrop` or abandoned-session force-decide won the race. The hold
        // is still removed (it is exactly as resolved as one this call
        // reinstated), but the caller's overall claim reports false so it knows
        // to refuse the reconnect rather than admit it.
        let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
        holds.hold(key(), SlotId(3));

        let reinstated = holds.take_if_pending(&key(), SlotId(3), || false);
        assert!(!reinstated, "reinstate lost the photo finish");
        assert!(
            !holds.is_pending(&key(), SlotId(3)),
            "the hold is still removed even though reinstate reported false",
        );
    }

    #[test]
    fn take_if_pending_never_calls_reinstate_when_nothing_is_pending() {
        let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
        let mut called = false;
        let reinstated = holds.take_if_pending(&key(), SlotId(3), || {
            called = true;
            true
        });
        assert!(
            !reinstated,
            "no hold was pending, so there is nothing to claim"
        );
        assert!(
            !called,
            "reinstate must never run when there was no hold to claim it against",
        );
    }

    #[test]
    fn concurrent_claims_on_the_same_hold_have_exactly_one_winner() {
        // The property every decide path (an honored `RequestDrop`, the
        // abandoned-session force-decide) and every reconnect's `take_if_pending`
        // rests on: whichever thread's `release`/`take_if_pending` call actually
        // acquires the holds lock first wins the claim, and every other
        // concurrent claimant on the exact same `(key, slot)` must lose. This
        // drives genuine OS-thread contention (not just async interleaving) at
        // the primitive level, since the higher-level routing functions this
        // backs (`honor_drop_request`, `serve_connection`'s admission) have no
        // seam to inject a race into deterministically.
        use std::sync::Barrier;

        let holds = Arc::new(DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT));
        holds.hold(key(), SlotId(3));

        const CLAIMANTS: usize = 8;
        let barrier = Arc::new(Barrier::new(CLAIMANTS));
        let handles: Vec<_> = (0..CLAIMANTS)
            .map(|_| {
                let holds = Arc::clone(&holds);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    holds.release(&key(), SlotId(3))
                })
            })
            .collect();

        let wins: usize = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|&won| won)
            .count();
        assert_eq!(wins, 1, "exactly one concurrent claimant wins the hold");
        assert!(
            !holds.is_pending(&key(), SlotId(3)),
            "the hold is gone either way"
        );
    }

    #[test]
    fn a_duplicate_hold_keeps_the_original_instant() {
        let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
        holds.hold(key(), SlotId(3));
        std::thread::sleep(Duration::from_millis(30));
        let after_first = holds.held_for(&key(), SlotId(3)).unwrap();
        // A second hold for the same slot must not restart the window.
        holds.hold(key(), SlotId(3));
        let after_second = holds.held_for(&key(), SlotId(3)).unwrap();
        assert!(
            after_second >= after_first,
            "a duplicate hold kept the original, older instant rather than resetting it",
        );
    }

    #[test]
    fn a_never_requested_hold_never_decides_on_its_own() {
        // The core policy: a hold is a marker, not a timer. Even an unlock of zero —
        // "past the floor from the first instant" — decides nothing by itself; a
        // hold only clears when something explicitly releases it. There is no task
        // to observe, so the invariant is simply that the hold stays pending.
        let holds = DropHolds::new(Duration::ZERO, ABANDONED_SESSION_TIMEOUT);
        holds.hold(key(), SlotId(3));
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            holds.is_pending(&key(), SlotId(3)),
            "nothing removes a hold without an explicit release — no auto-drop",
        );
    }

    #[test]
    fn end_session_sweeps_only_decided_holds_keeping_undecided_ones_and_other_sessions() {
        let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
        // Slot 0's drop is undecided (the common case: the last local slot's own
        // hold, freshly marked in the very teardown that empties the roster and
        // triggers this sweep). Slot 1's was already decided elsewhere (an earlier
        // honored request or force-decide) and its hold should have been released
        // then, but this proves the sweep is still correct as a defensive backstop
        // if it somehow wasn't.
        holds.hold(key(), SlotId(0));
        holds.hold(key(), SlotId(1));
        let other = SessionKey {
            tenant: TenantId("t".to_owned()),
            session: SessionId(2),
        };
        holds.hold(other.clone(), SlotId(0));

        let decided = [SlotId(1)].into_iter().collect();
        holds.end_session(&key(), &decided);
        assert!(
            holds.is_pending(&key(), SlotId(0)),
            "the undecided hold survives the sweep -- it's still the reconnect token",
        );
        assert!(
            !holds.is_pending(&key(), SlotId(1)),
            "the already-decided hold is swept",
        );
        assert!(
            holds.is_pending(&other, SlotId(0)),
            "another session's holds are untouched",
        );
    }

    #[test]
    fn end_session_with_no_decided_slots_keeps_every_hold_for_the_session() {
        // The common case: nothing decided yet, so a session-emptied teardown must
        // not erase any hold -- every one of them is still the sole path back to
        // this drop being resolved.
        let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
        holds.hold(key(), SlotId(0));
        holds.hold(key(), SlotId(1));

        holds.end_session(&key(), &HashSet::new());
        assert_eq!(
            holds.pending_slots(&key()),
            [SlotId(0), SlotId(1)].into_iter().collect(),
            "no undecided hold is swept when nothing is decided",
        );
    }

    #[test]
    fn a_burst_past_the_request_cap_is_rejected_then_recovers_after_refill() {
        let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
        let requester = SlotId(2);
        // The first DROP_REQUEST_BURST requests in a burst are all admitted.
        for _ in 0..DROP_REQUEST_BURST {
            assert!(holds.admit_request(&key(), requester));
        }
        // The next, still within the burst window, is rejected — a double-click
        // storm is throttled, not honored repeatedly.
        assert!(!holds.admit_request(&key(), requester));

        // After a refill interval passes, at least one more token is available.
        std::thread::sleep(DROP_REQUEST_REFILL_INTERVAL + Duration::from_millis(50));
        assert!(holds.admit_request(&key(), requester));
    }

    #[test]
    fn each_requester_has_its_own_budget() {
        let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
        for _ in 0..DROP_REQUEST_BURST {
            assert!(holds.admit_request(&key(), SlotId(2)));
        }
        assert!(!holds.admit_request(&key(), SlotId(2)));
        // A different requester still has its full burst — the cap is per-slot.
        assert!(holds.admit_request(&key(), SlotId(5)));
    }
}
