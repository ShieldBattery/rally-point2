//! Session lifecycle: per-session ordered webhook dispatch, the final
//! `sessionClosed` signal, and the reap policies.
//!
//! The coordinator sees three per-session facts flow up the relay control
//! connections — a slot's result, a slot's departure, and a relay's
//! `SessionClosed` — and holds the global picture of a game's end. This module
//! owns what it does with that picture:
//!
//! - **Ordered dispatch.** Every webhook for one `(tenant, session)` drains from
//!   a single FIFO queue, one at a time; a notice's retry loop blocks the ones
//!   behind it. Because `sessionClosed` is enqueued only after the all-relays-
//!   closed condition, queue order alone guarantees a delivered `sessionClosed`
//!   implies every earlier notice for the session was delivered or exhausted.
//!
//! - **`sessionClosed`.** The coordinator assigned each session's serving relay
//!   set; when every one of them has reported `SessionClosed`, the final
//!   `sessionClosed` webhook is enqueued (and the session's state is reaped).
//!
//! - **Reap policies.** From the accounting it already holds — a player slot is
//!   *accounted* once it has a result or a departure — a **holdout reap** closes
//!   the last silent player's link and a **linger reap** closes links left after
//!   every player is accounted. Two slower bounds cover sessions that cannot
//!   enter either path: one created but never joined, and one whose complete,
//!   fresh relay heartbeats continuously prove every assigned roster empty. The
//!   latter paths retire membership directly so stale descriptors cannot pin an
//!   otherwise idle relay fleet above zero.
//!
//! Coordinator-restart amnesia is accepted: this state is in-memory, so a restart
//! forgets a session's accounting and serving set. A departure/result webhook for
//! a forgotten session still delivers (a webhook-only queue is created lazily),
//! but its `sessionClosed` and reaps do not fire — the tenant's batch liveness
//! probe is the backstop for those.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::{Mutex, MutexGuard};
use rally_point_proto::control::{DepartedSlot, DepartureKind, SessionPresence, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::descriptors::SlotClose;
use crate::notify::{self, NoticeDedup};
use crate::session::SessionSetup;
use crate::tenant::{NotifyConfig, TenantStore};

/// How long a holdout slot may stay silent on a live link — all-but-one player
/// accounted — before the coordinator closes its link.
pub const HOLDOUT_REAP_GRACE: Duration = Duration::from_secs(60);

/// How long a session's stragglers may linger — all players accounted but links
/// still open (`sessionClosed` not yet fired) — before the coordinator closes the
/// slots with no departure record.
pub const LINGER_REAP_GRACE: Duration = Duration::from_secs(60);

/// How long a webhook-only lifecycle state — one lazily created for a session
/// this coordinator lifetime never registered (restart amnesia), so it has no
/// serving relays and never receives a `SessionClosed` — may sit idle before it
/// is reaped. Measured from the last webhook enqueued onto it, so a burst of a
/// game's tail notices keeps it alive until they quiesce. Comfortably longer than
/// a single webhook's whole retry span, so the entry's ordered queue has drained
/// before it is removed. Without this such an entry (and its parked drain task)
/// would leak for the process lifetime, one per in-flight game across a restart.
pub const WEBHOOK_ONLY_REAP_GRACE: Duration = Duration::from_secs(300);

/// How long a freshly created session may sit with **no client ever having
/// connected** — no relay heartbeat naming a connected slot for it, no
/// accounting event — before the coordinator concludes nobody ever will and
/// retires it. Comfortably covers realistic matchmaking-to-dial latency
/// (queueing, retries, a slow client) while bounding an abandoned create's
/// footprint — its lifecycle entry, its descriptors on every assigned relay,
/// and the warm-relay demand those imply — to a bounded span rather than
/// forever.
///
/// Deliberately NOT extended to the session's token lifetime. Tokens stay
/// valid for hours so an active session can authenticate a later reconnect, but
/// a client that connected has *started* the session (its first presence
/// permanently disarms this particular reap), so this window never governs it.
/// A separate all-relays-empty grace bounds fully abandoned started sessions.
/// A session nothing ever dialed has no such client to protect, and holding
/// its state for the token lifetime instead would pin its descriptors (and
/// keep its assigned relays looking busy, blocking their scale-down) for
/// hours per abandoned create. A straggler whose first-ever dial lands after
/// this window finds the session gone — its still-valid token buys nothing —
/// and falls back to its caller's create path, exactly as if the create had
/// never happened.
pub const NEVER_STARTED_REAP_GRACE: Duration = Duration::from_secs(15 * 60);

/// How long a session that previously started may remain continuously empty on
/// every assigned relay before the coordinator retires it. Relays normally close
/// an abandoned session themselves within seconds; this longer window is a
/// defense-in-depth bound for a missed close notice or a relay whose assigned
/// slot never connected and therefore never produced a local roster transition.
///
/// Emptiness is accepted only from complete, generation-fenced heartbeat rosters
/// and is re-checked when this timer fires. A reconnect, a partial/legacy roster,
/// a re-home, any occupied roster, or a stale heartbeat resets the proof.
pub const EMPTY_SESSION_REAP_GRACE: Duration = Duration::from_secs(15 * 60);

/// The longest gap between complete heartbeat rosters that may still count as
/// continuous emptiness. This matches the active-presence freshness window and
/// is comfortably above the relay's 10-second heartbeat cadence. Silence is
/// unknown, never proof that a session is empty.
pub const EMPTY_ROSTER_FRESHNESS: Duration = Duration::from_secs(35);

/// One session's ordered dispatch queue's capacity. A session's genuine
/// notice volume is small and bounded by its slot count: at most one
/// departure and one result per slot (12 slots, BW's cap), a handful of
/// desyncs, and the one terminal `sessionClosed`. This is sized with wide
/// headroom over that — reachable only by a bug or abuse, never by an
/// honest game — so [`Lifecycle::enqueue_webhook`]'s overflow drop (see its
/// own doc) is a backstop, not a limit real traffic ever brushes against.
/// One slot is implicitly reserved for the terminal job: an ordinary notice
/// only ever fills the queue to `NOTICE_QUEUE_CAPACITY - 1`, so
/// `sessionClosed` always finds room (see [`Lifecycle::push_terminal`]).
const NOTICE_QUEUE_CAPACITY: usize = 128;

/// How many non-terminal notices this coordinator has ever dropped from a
/// full session queue — process-wide, not per-session. Expected to stay at
/// zero in production; a nonzero value means [`NOTICE_QUEUE_CAPACITY`] was
/// actually reached, which given its headroom is itself worth alerting on.
/// Exposed through [`dropped_notice_count`] so the metrics exposition and tests
/// can observe drops without scraping logs.
static DROPPED_NOTICE_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The process-wide count of non-terminal notices dropped from a full session
/// queue, for metrics exposition. See [`DROPPED_NOTICE_COUNT`].
pub(crate) fn dropped_notice_count() -> u64 {
    DROPPED_NOTICE_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

/// A `(tenant, session)` key for the per-session lifecycle map.
type SessionRef = (TenantId, SessionId);

/// What the coordinator knows about one session's load progress, as
/// [`Lifecycle::load_state`] reports it.
///
/// The accumulated facts are never a live view: the slot sets record that a slot
/// *ever* connected or *ever* reported its game loop, so a slot that arrived and
/// then dropped still appears. That is what makes the answer useful for
/// attributing a failed load — the caller wants "who never got here", not "who is
/// here right now" (which is what the presence store answers).
///
/// They are also only ever *positive* evidence, and always safe to merge. What
/// takes qualifying is reading a slot's **absence** as proof it never arrived,
/// which needs the record to be complete. Two of these fields are the coordinator's
/// half of that question; the other half — whether every serving relay just
/// attested — belongs to whoever asked them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLoadState {
    /// Whether `register_session` created this state: the session was set up
    /// against *this* coordinator process, so the sets start at the session's
    /// beginning rather than wherever a restarted process came up.
    pub created_here: bool,
    /// Whether an unbroken chain of relay memory still covers the session's whole
    /// life, so a snapshot the serving relays produce today can still speak for
    /// what happened at its beginning. Cleared permanently once a serving relay is
    /// replaced or restarts its process, since whatever that process saw and had
    /// not restated is then unrecoverable.
    pub attestable: bool,
    /// The relays currently assigned to serve the session; empty for a state no
    /// registration ever gave a serving set. Every one of them must produce a
    /// snapshot for a completeness claim to stand.
    pub serving_relays: Vec<RelayId>,
    /// Relay wall-clock (unix epoch ms) of the session's start — the earliest
    /// instant any relay reported for it. `None` when no relay has reported the
    /// session started.
    pub started_at_ms: Option<u64>,
    /// Slots whose links ever activated, ascending.
    pub connected_slots: Vec<SlotId>,
    /// Slots that ever reported their game loop running, ascending.
    pub started_slots: Vec<SlotId>,
}

/// A slot set as an ascending vector, so a load-state answer is deterministic
/// rather than following the hash set's iteration order.
fn sorted_slots(slots: &HashSet<SlotId>) -> Vec<SlotId> {
    let mut sorted: Vec<SlotId> = slots.iter().copied().collect();
    sorted.sort_unstable();
    sorted
}

/// One assigned relay's continuous proof that a session is empty.
#[derive(Debug, Clone, Copy)]
struct EmptyRosterEvidence {
    /// The control-connection generation that supplied the proof.
    generation: u64,
    /// When the most recent complete empty roster refreshed the proof.
    last_seen: Instant,
}

/// The control connection epoch currently recognized by lifecycle bookkeeping.
/// Enrollment, disconnect, heartbeat, and terminal-close handling serialize on
/// the map's mutex so an old connection cannot cross a reconnect boundary between
/// its registry check and its lifecycle mutation.
#[derive(Debug, Clone, Copy)]
struct RelayEpoch {
    generation: u64,
    connected: bool,
}

/// One armed globally-empty timer. `token` prevents an aborted task that already
/// passed its sleep from consuming a newer timer's freshly-established evidence.
struct EmptyTimer {
    token: u64,
    abort: AbortHandle,
}

/// One webhook ready to sign and POST — enqueued onto a session's ordered queue.
struct WebhookJob {
    tenant: TenantId,
    config: NotifyConfig,
    body: Bytes,
    kind: &'static str,
}

/// The retained data one departed slot's rehome seed carries — everything a
/// [`DepartedSlot`] needs beyond the slot id itself, taken from the departure
/// notice when the slot departed.
#[derive(Debug, Clone, Copy)]
struct DepartureSeed {
    /// The relay's left-vs-dropped classification.
    kind: DepartureKind,
    /// The leave directive's exact turn count, `None` when it carried none.
    final_turn_count: Option<u64>,
    /// Whether a dropped count carries the home-finalization proof
    /// ([`DepartureNotice::finalized`]) — without it a dropped count is
    /// stripped at this ingress, and with it the proof rides back out through
    /// [`DepartedSlot::finalized`] on a rehome seed.
    finalized: bool,
}

/// One session's lifecycle state.
struct SessionState {
    /// The relays the coordinator assigned to serve the session — the distinct
    /// home relays of its slots — or empty for a webhook-only state lazily created
    /// for a session this coordinator lifetime never created (restart amnesia). The
    /// reap fans a `CloseSlot` out to all of these.
    serving_relays: Vec<RelayId>,
    /// Whether `register_session` created this state — the session was set up
    /// against *this* coordinator process, so everything it has accumulated since
    /// covers the session's whole life. `false` for a state lazily created by an
    /// arriving notice or heartbeat for a session this process never created
    /// (restart amnesia), where the accumulated sets start wherever the coordinator
    /// happened to come up. Only the load-state read distinguishes the two: an
    /// absent slot is evidence of a no-show only in the first case.
    created_here: bool,
    /// The session's player (non-observer) slots — the reap accounting universe.
    player_slots: HashSet<SlotId>,
    /// The session's observer slots — never accounted (they don't report), reaped
    /// like stragglers at session end.
    observer_slots: HashSet<SlotId>,
    /// Player slots that have a result or a departure — the accounted set. Grows
    /// monotonically (a slot never un-accounts).
    accounted: HashSet<SlotId>,
    /// Slots (player or observer) whose links have ever activated on a serving
    /// relay, from the relays' slot-connected notices. Grows monotonically — the
    /// question it answers is "did this player ever arrive", so a later
    /// disconnect never removes an entry (live connectivity is the presence
    /// store's job, not this set's).
    connected_slots: HashSet<SlotId>,
    /// Slots that have ever reported their game loop running. Grows
    /// monotonically for the same reason as `connected_slots`.
    started_slots: HashSet<SlotId>,
    /// Whether an unbroken chain of relay memory still covers this session's whole
    /// life, so a snapshot the serving relays produce today can still speak for
    /// what happened at its beginning.
    ///
    /// A relay's load state lives in its process memory. When a serving relay is
    /// replaced (a re-home) or its process restarts, whatever it observed since its
    /// last restatement is gone, and no relay that comes after can vouch for that
    /// interval — the facts are simply unrecoverable, however promptly everyone
    /// answers afterwards. So this starts `true` at registration and is cleared
    /// **permanently** the first time such a break is observed: nothing later
    /// restores it, because nothing later can recover what was lost. A cleared flag
    /// costs only the negative inference; every fact the record holds still stands.
    attestable: bool,
    /// Relay wall-clock (unix epoch ms) of the session's start, from the authority
    /// relay's session-started notice or any relay's heartbeat restatement. First
    /// report wins — an at-least-once re-send, a second authority after a
    /// promotion, or a peer's later adoption instant must not move an instant the
    /// tenant may already have recorded.
    started_at_ms: Option<u64>,
    /// Slots (player or observer) that have a departure record, each with the
    /// data a coordinator-mediated re-home seeds into a fresh relay's consensus
    /// ([`Lifecycle::departed_slots`]): the left-vs-dropped classification and
    /// the leave directive's exact turn count. The first record for a slot wins
    /// (a slot never departs twice). The linger reap closes the slots *not* in
    /// this map.
    departures: HashMap<SlotId, DepartureSeed>,
    /// Serving relays that have reported `SessionClosed`, scoped to the control
    /// connection generation that supplied the terminal notice.
    closed_relays: HashMap<RelayId, u64>,
    /// Whether the final `sessionClosed` webhook has been enqueued, so it fires
    /// exactly once.
    session_closed_enqueued: bool,
    /// The sender onto the session's ordered dispatch queue, bounded to
    /// [`NOTICE_QUEUE_CAPACITY`] (see [`Lifecycle::enqueue_webhook`] and
    /// [`Lifecycle::push_terminal`] for how the two kinds of push treat it
    /// differently).
    queue: mpsc::Sender<WebhookJob>,
    /// The armed holdout-reap timer, if any (aborted on disarm/re-arm).
    holdout_timer: Option<AbortHandle>,
    /// The armed linger-reap timer, if any.
    linger_timer: Option<AbortHandle>,
    /// The armed webhook-only reap timer, if any — set only while this is a
    /// webhook-only state (empty serving set). Reset on every webhook enqueued, so
    /// it measures idle time since the last one; disarmed if the state ever gains a
    /// serving relay (it then has the normal all-relays-closed removal path).
    webhook_timer: Option<AbortHandle>,
    /// Whether this session has been observed to have actually started: a
    /// relay's heartbeat reported a connected slot for it
    /// ([`Lifecycle::on_presence_seen`]), or some accounting event
    /// (departure/result) arrived — either only possible once a real client
    /// has dialed in. Distinguishes "created but no client ever showed up"
    /// from "legitimately still setting up" so [`fire_never_started`] can
    /// re-check this under the lock rather than trusting its timer's abort
    /// alone to have won the race against a client dialing in right at the
    /// edge of the grace window.
    started: bool,
    /// The armed never-started reap timer, if any — set at
    /// [`Lifecycle::register_session`] and disarmed the moment `started`
    /// becomes true. `None` once the session has started (or been reaped);
    /// never re-armed after that.
    never_started_timer: Option<AbortHandle>,
    /// Per-serving-relay complete-roster evidence that this session is empty.
    /// Missing means unknown or occupied. A relay that reported `SessionClosed`
    /// is terminal evidence and need not appear here.
    empty_relays: HashMap<RelayId, EmptyRosterEvidence>,
    /// The armed globally-empty reap timer, if every serving relay currently has
    /// fresh empty evidence (or has already reported `SessionClosed`).
    empty_timer: Option<EmptyTimer>,
}

impl SessionState {
    /// Whether every assigned serving relay has reported closed. `false` for a
    /// webhook-only state (no serving set), so its `sessionClosed` never fires.
    fn all_relays_closed(&self) -> bool {
        !self.serving_relays.is_empty()
            && self
                .serving_relays
                .iter()
                .all(|r| self.closed_relays.contains_key(r))
    }

    /// The player slots not yet accounted (no result and no departure).
    fn unaccounted_players(&self) -> Vec<SlotId> {
        self.player_slots
            .iter()
            .filter(|s| !self.accounted.contains(s))
            .copied()
            .collect()
    }

    /// Whether every assigned relay is freshly known empty at `now`. A normal
    /// `SessionClosed` is stronger than a heartbeat omission and remains valid
    /// even after that relay disconnects.
    fn all_relays_confirmed_empty(&self, now: Instant, freshness: Duration) -> bool {
        !self.serving_relays.is_empty()
            && self.serving_relays.iter().all(|relay| {
                self.closed_relays.contains_key(relay)
                    || self.empty_relays.get(relay).is_some_and(|evidence| {
                        now.saturating_duration_since(evidence.last_seen) <= freshness
                    })
            })
    }

    /// Whether every heartbeat-based proof belongs to the still-current control
    /// connection. Closed relays are terminal within an epoch and are cleared by
    /// the next enrollment while the same epoch gate is held.
    fn empty_evidence_matches_epochs(&self, epochs: &HashMap<RelayId, RelayEpoch>) -> bool {
        self.serving_relays.iter().all(|relay| {
            self.closed_relays.contains_key(relay)
                || self.empty_relays.get(relay).is_some_and(|evidence| {
                    epochs.get(relay).is_some_and(|epoch| {
                        epoch.connected && epoch.generation == evidence.generation
                    })
                })
        })
    }
}

/// The coordinator's per-session lifecycle tracker. Cloned cheaply (one `Arc`) so
/// the api layer, the dispatch queues, and the reap timers all share one map.
#[derive(Clone)]
pub struct Lifecycle {
    inner: Arc<Inner>,
}

struct Inner {
    setup: SessionSetup,
    sessions: Mutex<HashMap<SessionRef, SessionState>>,
    /// Also serves as the connection-epoch linearization gate. Every production
    /// registry enrollment/removal is committed while this lock is held.
    relay_epochs: Mutex<HashMap<RelayId, RelayEpoch>>,
    /// Process-wide timer identities prevent a callback from an already-retired
    /// session key matching a timer on a later state with the same key.
    next_empty_timer_token: AtomicU64,
    holdout_grace: Duration,
    linger_grace: Duration,
    webhook_grace: Duration,
    /// Each new session's dispatch queue capacity — [`NOTICE_QUEUE_CAPACITY`]
    /// in production; injectable ([`Lifecycle::with_test_tunables`]) so a
    /// queue-overflow test doesn't need to push the full production headroom
    /// through a fake endpoint to observe the drop policy.
    queue_capacity: usize,
    /// The never-started reap's grace window — [`NEVER_STARTED_REAP_GRACE`]
    /// in production; injectable ([`Lifecycle::with_test_tunables`]) for the
    /// same reason as `queue_capacity`.
    never_started_grace: Duration,
    /// A started session's globally-empty grace and the maximum accepted gap
    /// between the complete rosters proving that emptiness.
    empty_session_grace: Duration,
    empty_roster_freshness: Duration,
    /// The notice dedup sets to prune when a session's state is removed, wired in
    /// once at startup ([`Lifecycle::attach_dedup`]). Optional so a lifecycle
    /// built without one (a test that never exercises dedup) simply skips pruning.
    dedup: OnceLock<NoticeDedup>,
}

/// A scrape-time census of the lifecycle map, produced by
/// [`Lifecycle::metrics_census`] for the metrics exporter.
#[derive(Debug, Default)]
pub(crate) struct LifecycleMetrics {
    /// Per-tenant counts of sessions with an assigned serving relay, split by
    /// whether a client has been observed.
    pub(crate) sessions: HashMap<TenantId, SessionCensus>,
    /// Per-tenant total depth of pending webhook queues across all of the
    /// tenant's lifecycle states (serving and webhook-only alike).
    pub(crate) notices_pending: HashMap<TenantId, u64>,
}

/// One tenant's serving-session counts, split by whether a real client has been
/// seen for the session yet.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SessionCensus {
    /// Sessions registered with a serving relay but not yet observed to have a
    /// client present.
    pub(crate) loading: u64,
    /// Sessions a client has been observed to have dialed into.
    pub(crate) started: u64,
    /// Started sessions currently inside the globally-confirmed-empty grace.
    pub(crate) empty_grace: u64,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
struct EmptyReapTunables {
    grace: Duration,
    freshness: Duration,
}

impl Lifecycle {
    /// Creates a lifecycle tracker over `setup` with the production reap graces.
    pub fn new(setup: SessionSetup) -> Self {
        Self::with_graces(
            setup,
            HOLDOUT_REAP_GRACE,
            LINGER_REAP_GRACE,
            WEBHOOK_ONLY_REAP_GRACE,
        )
    }

    /// Creates a lifecycle tracker with the reap graces injected, so a test need
    /// not wait the production minute.
    pub fn with_graces(
        setup: SessionSetup,
        holdout_grace: Duration,
        linger_grace: Duration,
        webhook_grace: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                setup,
                sessions: Mutex::new(HashMap::new()),
                relay_epochs: Mutex::new(HashMap::new()),
                next_empty_timer_token: AtomicU64::new(1),
                holdout_grace,
                linger_grace,
                webhook_grace,
                queue_capacity: NOTICE_QUEUE_CAPACITY,
                never_started_grace: NEVER_STARTED_REAP_GRACE,
                empty_session_grace: EMPTY_SESSION_REAP_GRACE,
                empty_roster_freshness: EMPTY_ROSTER_FRESHNESS,
                dedup: OnceLock::new(),
            }),
        }
    }

    /// [`with_graces`](Self::with_graces) plus every other production
    /// constant a test might need to shrink: the per-session queue capacity,
    /// the never-started grace, and the empty-roster policy. Each defaults to
    /// its production value in [`with_graces`](Self::with_graces); this exists
    /// only so a test can override the ones it actually cares about without
    /// waiting out the real windows.
    #[cfg(test)]
    fn with_test_tunables(
        setup: SessionSetup,
        holdout_grace: Duration,
        linger_grace: Duration,
        webhook_grace: Duration,
        queue_capacity: usize,
        never_started_grace: Duration,
        empty_reap: EmptyReapTunables,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                setup,
                sessions: Mutex::new(HashMap::new()),
                relay_epochs: Mutex::new(HashMap::new()),
                next_empty_timer_token: AtomicU64::new(1),
                holdout_grace,
                linger_grace,
                webhook_grace,
                queue_capacity,
                never_started_grace,
                empty_session_grace: empty_reap.grace,
                empty_roster_freshness: empty_reap.freshness,
                dedup: OnceLock::new(),
            }),
        }
    }

    /// Wires in the notice dedup sets this lifecycle prunes when it removes a
    /// session's state, so they don't grow for the process lifetime. Called once
    /// at startup, after both are constructed; a second call is ignored.
    pub fn attach_dedup(&self, dedup: NoticeDedup) {
        let _ = self.inner.dedup.set(dedup);
    }
}

/// Aborts every armed reap timer on a state being removed, so no timer fires
/// against a session id that no longer exists.
fn abort_timers(state: &SessionState) {
    if let Some(timer) = &state.holdout_timer {
        timer.abort();
    }
    if let Some(timer) = &state.linger_timer {
        timer.abort();
    }
    if let Some(timer) = &state.webhook_timer {
        timer.abort();
    }
    if let Some(timer) = &state.never_started_timer {
        timer.abort();
    }
    if let Some(timer) = &state.empty_timer {
        timer.abort.abort();
    }
}

/// Drains one session's ordered dispatch queue, delivering each webhook to
/// completion (its full retry span) before the next. Exits when every sender is
/// dropped — the session state was reaped — after the last job is delivered.
async fn drain_queue(mut rx: mpsc::Receiver<WebhookJob>, tenants: TenantStore) {
    while let Some(job) = rx.recv().await {
        notify::dispatch(tenants.clone(), job.tenant, job.config, job.body, job.kind).await;
    }
}

mod close;
mod reaps;
mod relays;
mod sessions;

#[cfg(test)]
mod tests;
