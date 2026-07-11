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
//!   *accounted* once it has a result or a departure — two timers keep a session
//!   from dangling: a **holdout reap** (all-but-one player accounted, the last one
//!   silent on a live link → close its link after a grace) and a **linger reap**
//!   (all players accounted but links remain → close the reported-but-still-linked
//!   stragglers, observers included). Both close slots via a `CloseSlot` directive
//!   down the relay control connection; the closed link then flows through the
//!   normal link-death path, which is what makes the reap self-resolving.
//!
//! Coordinator-restart amnesia is accepted: this state is in-memory, so a restart
//! forgets a session's accounting and serving set. A departure/result webhook for
//! a forgotten session still delivers (a webhook-only queue is created lazily),
//! but its `sessionClosed` and reaps do not fire — the tenant's batch liveness
//! probe is the backstop for those.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use rally_point_proto::control::{DepartedSlot, DepartureKind, TenantId};
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

/// A `(tenant, session)` key for the per-session lifecycle map.
type SessionRef = (TenantId, SessionId);

/// One webhook ready to sign and POST — enqueued onto a session's ordered queue.
struct WebhookJob {
    tenant: TenantId,
    config: NotifyConfig,
    body: Bytes,
    kind: &'static str,
}

/// One session's lifecycle state.
struct SessionState {
    /// The relays the coordinator assigned to serve the session — the distinct
    /// home relays of its slots — or empty for a webhook-only state lazily created
    /// for a session this coordinator lifetime never created (restart amnesia). The
    /// reap fans a `CloseSlot` out to all of these.
    serving_relays: Vec<RelayId>,
    /// The session's player (non-observer) slots — the reap accounting universe.
    player_slots: HashSet<SlotId>,
    /// The session's observer slots — never accounted (they don't report), reaped
    /// like stragglers at session end.
    observer_slots: HashSet<SlotId>,
    /// Player slots that have a result or a departure — the accounted set. Grows
    /// monotonically (a slot never un-accounts).
    accounted: HashSet<SlotId>,
    /// Slots (player or observer) that have a departure record. The linger reap
    /// closes the slots *not* in this set.
    departed: HashSet<SlotId>,
    /// Each departed slot's left-vs-dropped classification, retained so a
    /// coordinator-mediated re-home can seed a fresh relay's consensus with the
    /// already-decided departures ([`Lifecycle::departed_slots`]). Grows with
    /// `departed`; the first classification for a slot wins (a slot never departs
    /// twice with a different kind).
    departed_kinds: HashMap<SlotId, DepartureKind>,
    /// Serving relays that have reported `SessionClosed`.
    closed_relays: HashSet<RelayId>,
    /// Whether the final `sessionClosed` webhook has been enqueued, so it fires
    /// exactly once.
    session_closed_enqueued: bool,
    /// The sender onto the session's ordered dispatch queue.
    queue: mpsc::UnboundedSender<WebhookJob>,
    /// The armed holdout-reap timer, if any (aborted on disarm/re-arm).
    holdout_timer: Option<AbortHandle>,
    /// The armed linger-reap timer, if any.
    linger_timer: Option<AbortHandle>,
    /// The armed webhook-only reap timer, if any — set only while this is a
    /// webhook-only state (empty serving set). Reset on every webhook enqueued, so
    /// it measures idle time since the last one; disarmed if the state ever gains a
    /// serving relay (it then has the normal all-relays-closed removal path).
    webhook_timer: Option<AbortHandle>,
}

impl SessionState {
    /// Whether every assigned serving relay has reported closed. `false` for a
    /// webhook-only state (no serving set), so its `sessionClosed` never fires.
    fn all_relays_closed(&self) -> bool {
        !self.serving_relays.is_empty()
            && self
                .serving_relays
                .iter()
                .all(|r| self.closed_relays.contains(r))
    }

    /// The player slots not yet accounted (no result and no departure).
    fn unaccounted_players(&self) -> Vec<SlotId> {
        self.player_slots
            .iter()
            .filter(|s| !self.accounted.contains(s))
            .copied()
            .collect()
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
    holdout_grace: Duration,
    linger_grace: Duration,
    webhook_grace: Duration,
    /// The notice dedup sets to prune when a session's state is removed, wired in
    /// once at startup ([`Lifecycle::attach_dedup`]). Optional so a lifecycle
    /// built without one (a test that never exercises dedup) simply skips pruning.
    dedup: OnceLock<NoticeDedup>,
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
                holdout_grace,
                linger_grace,
                webhook_grace,
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

    /// Records a freshly created session's serving relays and its player/observer
    /// slot split, spawning its ordered dispatch queue. Called from
    /// `create_session`. A repeat call (a session id collision, or a re-create)
    /// replaces the accounting inputs while keeping the existing queue.
    pub fn register_session(
        &self,
        tenant: TenantId,
        session: SessionId,
        serving_relays: Vec<RelayId>,
        player_slots: HashSet<SlotId>,
        observer_slots: HashSet<SlotId>,
    ) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant, session))
            .or_insert_with(|| self.new_state(Vec::new()));
        state.serving_relays = serving_relays;
        state.player_slots = player_slots;
        state.observer_slots = observer_slots;
        // If this state existed only as a webhook-only entry (a departure/result
        // arrived before its registration), it now has the normal all-relays-
        // closed removal path, so its idle reap no longer applies.
        if !state.serving_relays.is_empty()
            && let Some(timer) = state.webhook_timer.take()
        {
            timer.abort();
        }
    }

    /// Swaps `dead` for `r_new` in the session's cached serving-relay set, so a
    /// later `SessionClosed` from the replacement (or from any other surviving
    /// relay) can still satisfy the all-relays-closed condition — without this, a
    /// re-home leaves the cached set naming a relay that will never report
    /// closed, and the session's final `sessionClosed` webhook, state, and drain
    /// queue task never retire.
    ///
    /// A same-id swap (`dead == r_new`, a relay that restarted in place under a
    /// new cert) is a no-op: the id was never removed from the cached set, so
    /// there is nothing to swap. Otherwise, if `r_new` is already present, `dead`
    /// is simply dropped from the set rather than producing a duplicate entry. A
    /// session with no cached state, or one whose cached set no longer names
    /// `dead` (an already-applied swap, or an id unrelated to this session), is
    /// left untouched — the call is idempotent, so a caller need not track
    /// whether it already applied a given swap.
    pub fn on_rehome(&self, tenant: &TenantId, session: SessionId, dead: RelayId, r_new: RelayId) {
        if dead == r_new {
            return;
        }
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant.clone(), session)) else {
            return;
        };
        let Some(pos) = state.serving_relays.iter().position(|&id| id == dead) else {
            return;
        };
        if state.serving_relays.contains(&r_new) {
            state.serving_relays.remove(pos);
        } else {
            state.serving_relays[pos] = r_new;
        }
    }

    /// Records a slot's departure: accounts the slot (if a player), notes it
    /// departed with its left-vs-dropped classification, and re-evaluates the reap
    /// timers. The `kind` is retained so a coordinator-mediated re-home can seed a
    /// fresh relay with the already-decided departure ([`departed_slots`](Self::departed_slots)).
    pub fn on_departure(
        &self,
        tenant: TenantId,
        session: SessionId,
        slot: SlotId,
        kind: DepartureKind,
    ) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        state.departed.insert(slot);
        // First classification for a slot wins — a slot never departs twice.
        state.departed_kinds.entry(slot).or_insert(kind);
        if state.player_slots.contains(&slot) {
            state.accounted.insert(slot);
        }
        self.reevaluate_reaps(&tenant, session, state);
        self.arm_webhook_reap_if_orphan(&tenant, session, state);
    }

    /// The slots this coordinator has recorded as departed for `session`, each
    /// with its left-vs-dropped classification — the seed a coordinator-mediated
    /// re-home carries in the rebuilt descriptors so a fresh relay's consensus
    /// treats the departures as already decided. Empty for a session with no
    /// recorded departures (or one this coordinator lifetime never registered).
    pub fn departed_slots(&self, tenant: &TenantId, session: SessionId) -> Vec<DepartedSlot> {
        self.inner
            .sessions
            .lock()
            .get(&(tenant.clone(), session))
            .map(|state| {
                state
                    .departed_kinds
                    .iter()
                    .map(|(&slot, &kind)| DepartedSlot { slot, kind })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Records a slot's result: accounts the slot (if a player) and re-evaluates
    /// the reap timers. A result does not mark the slot departed — a reported
    /// player may still be watching live.
    pub fn on_result(&self, tenant: TenantId, session: SessionId, slot: SlotId) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        if state.player_slots.contains(&slot) {
            state.accounted.insert(slot);
        }
        self.reevaluate_reaps(&tenant, session, state);
        self.arm_webhook_reap_if_orphan(&tenant, session, state);
    }

    /// Records a relay's `SessionClosed`. When every assigned serving relay has
    /// closed, enqueues the final `sessionClosed` webhook (behind every prior
    /// notice in queue order) and reaps the session's state.
    pub fn on_session_closed(&self, tenant: TenantId, session: SessionId, relay_id: RelayId) {
        let key = (tenant.clone(), session);
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&key) else {
            return; // an unknown session (restart amnesia): no serving set to close
        };
        state.closed_relays.insert(relay_id);
        if !state.all_relays_closed() || state.session_closed_enqueued {
            return;
        }
        state.session_closed_enqueued = true;
        // Build the sessionClosed job, enqueue it behind everything already in the
        // queue, then reap the state: the queue's own sender lives on in the
        // detached drain task, which delivers the final job and then exits.
        if let Some((config, body)) =
            notify::session_closed_dispatch(&self.inner.setup, &tenant, session)
        {
            let _ = state.queue.send(WebhookJob {
                tenant: tenant.clone(),
                config,
                body,
                kind: "sessionClosed",
            });
        }
        let state = sessions.remove(&key).expect("just held it");
        drop(sessions);
        abort_timers(&state);
        // The session is done: drop its dedup entries so they don't accumulate for
        // the process lifetime, and retire any pending reap directives so they are
        // not replayed to a relay that reconnects after this.
        self.prune_dedup(&tenant, session);
        self.inner.setup.reaps().retire(&tenant, session);
        // Take (remove-and-return) the session's relay membership FIRST, atomically
        // with the serving-set snapshot, then drop each serving relay's descriptor
        // and only afterward clear the recorded rehomes. Ordering matters against a
        // concurrent `session::rehome`, which re-validates membership under the same
        // `session_relays` lock this take acquires:
        //
        // - Once the membership is gone (after this take), any racing rehome fails
        //   its under-lock re-validation: it can neither push a descriptor nor record
        //   a rehome, so there is nothing of its left to clean up.
        // - A rehome that completed BEFORE this take had already added its target
        //   relay to the membership, so that relay is in `serving` here — the
        //   descriptor removal below therefore covers the resumed descriptor it
        //   pushed, and `forget_rehomes` (run after the take) clears the idempotency
        //   entry it recorded.
        //
        // Every interleaving is thus covered. Removing the descriptor also stops a
        // relay reconnecting after the close from being re-synced the dead session's
        // stale descriptor and re-applying it — the relay-side reconciler only ends
        // sessions ABSENT from the pushed set, so a present-but-dead descriptor would
        // otherwise resurrect the session on that relay. Retiring the membership is
        // also what makes every subsequent re-home ask honestly answer `Unavailable`
        // (the empty serving set trips `session::rehome`'s guard), and dropping the
        // rate-limit bucket keeps that map bounded by live sessions.
        let serving = self.inner.setup.take_session_membership(&tenant, session);
        for relay_id in serving {
            self.inner
                .setup
                .descriptors()
                .remove(relay_id, &tenant, session);
        }
        self.inner.setup.forget_rehomes(&tenant, session);
        self.inner.setup.rehome_limiter().forget(&tenant, session);
        tracing::info!(
            tenant = tenant.as_ref(),
            session = session.0,
            "session fully closed; sessionClosed enqueued",
        );
    }

    /// Enqueues a webhook onto the session's ordered dispatch queue, creating a
    /// webhook-only queue on the fly for a session this coordinator lifetime never
    /// created (restart amnesia — the departure still delivers, serialized).
    pub fn enqueue_webhook(
        &self,
        tenant: TenantId,
        session: SessionId,
        config: NotifyConfig,
        body: Bytes,
        kind: &'static str,
    ) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        let _ = state.queue.send(WebhookJob {
            tenant: tenant.clone(),
            config,
            body,
            kind,
        });
        self.arm_webhook_reap_if_orphan(&tenant, session, state);
    }

    /// Whether the coordinator currently holds live state for `session` — it was
    /// created this coordinator lifetime and has not fully closed. The batch
    /// liveness endpoint reports exactly this; a session unknown, closed, or
    /// created only as a webhook-only queue (restart amnesia) reads as not alive,
    /// so the caller force-reconciles it.
    pub fn is_alive(&self, tenant: &TenantId, session: SessionId) -> bool {
        self.inner
            .sessions
            .lock()
            .get(&(tenant.clone(), session))
            .is_some_and(|state| !state.serving_relays.is_empty() && !state.all_relays_closed())
    }

    /// Builds a fresh `SessionState` with an ordered dispatch queue whose detached
    /// drain task delivers jobs one at a time (each retry blocking the next).
    fn new_state(&self, serving_relays: Vec<RelayId>) -> SessionState {
        let (tx, rx) = mpsc::unbounded_channel::<WebhookJob>();
        let tenants = self.inner.setup.tenants().clone();
        tokio::spawn(drain_queue(rx, tenants));
        SessionState {
            serving_relays,
            player_slots: HashSet::new(),
            observer_slots: HashSet::new(),
            accounted: HashSet::new(),
            departed: HashSet::new(),
            departed_kinds: HashMap::new(),
            closed_relays: HashSet::new(),
            session_closed_enqueued: false,
            queue: tx,
            holdout_timer: None,
            linger_timer: None,
            webhook_timer: None,
        }
    }

    /// Arms (or re-arms) a webhook-only state's idle reap, but only while it is
    /// webhook-only — a state with a serving relay has the normal all-relays-closed
    /// removal path and needs no idle reap. Called after every webhook enqueued, so
    /// the grace measures idle time since the last one and a game's tail notices
    /// keep the entry alive until they stop arriving.
    fn arm_webhook_reap_if_orphan(
        &self,
        tenant: &TenantId,
        session: SessionId,
        state: &mut SessionState,
    ) {
        if !state.serving_relays.is_empty() {
            return;
        }
        if let Some(timer) = state.webhook_timer.take() {
            timer.abort();
        }
        let this = self.clone();
        let tenant = tenant.clone();
        let grace = self.inner.webhook_grace;
        state.webhook_timer = Some(
            tokio::spawn(async move {
                tokio::time::sleep(grace).await;
                this.fire_webhook_reap(tenant, session);
            })
            .abort_handle(),
        );
    }

    /// The webhook-only reap timer firing: if the state is still webhook-only (no
    /// serving relay was recorded during the grace), remove it. Removing it drops
    /// the ordered queue's sender, so its detached drain task delivers whatever is
    /// still queued and then exits — no parked task is left behind — and its dedup
    /// entries are pruned.
    fn fire_webhook_reap(&self, tenant: TenantId, session: SessionId) {
        let key = (tenant.clone(), session);
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get(&key) else {
            return;
        };
        if !state.serving_relays.is_empty() {
            return; // it gained a serving set: the normal close path owns it now
        }
        let state = sessions.remove(&key).expect("just held it");
        drop(sessions);
        abort_timers(&state);
        // Dropping `state` drops the queue sender; the drain task finishes any
        // buffered job, then exits.
        drop(state);
        self.prune_dedup(&tenant, session);
        // Retire any pending reap directives for the removed session (a webhook-only
        // state normally has none, but this keeps the pending set bounded either way).
        self.inner.setup.reaps().retire(&tenant, session);
        // A webhook-only state has no relay membership (this coordinator lifetime
        // never created the session), so the take returns an empty serving set, the
        // removal loop is empty, and forget_rehomes a harmless no-op. The steps run
        // anyway in the same take-first order as `on_session_closed` above, so the two
        // close paths stay uniform (see that path for why the take must come first).
        let serving = self.inner.setup.take_session_membership(&tenant, session);
        for relay_id in serving {
            self.inner
                .setup
                .descriptors()
                .remove(relay_id, &tenant, session);
        }
        self.inner.setup.forget_rehomes(&tenant, session);
        self.inner.setup.rehome_limiter().forget(&tenant, session);
        tracing::debug!(
            tenant = tenant.as_ref(),
            session = session.0,
            "webhook-only session state reaped after its idle grace",
        );
    }

    /// Drops the notice dedup entries for `(tenant, session)`, if a dedup set was
    /// wired in. A no-op for a lifecycle built without one.
    fn prune_dedup(&self, tenant: &TenantId, session: SessionId) {
        if let Some(dedup) = self.inner.dedup.get() {
            dedup.prune_session(tenant, session);
        }
    }

    /// Whether a lifecycle state currently exists for `(tenant, session)` — a test
    /// hook for asserting a state was reaped (its map entry removed).
    #[cfg(test)]
    fn contains_state(&self, tenant: &TenantId, session: SessionId) -> bool {
        self.inner
            .sessions
            .lock()
            .contains_key(&(tenant.clone(), session))
    }

    /// Re-arms or disarms the two reap timers for `state` after its accounting
    /// changed. Arming is idempotent — an already-armed timer is left running
    /// rather than reset, so the grace measures from when the condition first held.
    fn reevaluate_reaps(&self, tenant: &TenantId, session: SessionId, state: &mut SessionState) {
        let unaccounted = state.unaccounted_players();

        // Holdout: all-but-one player accounted, the last one silent on a live
        // link. Only meaningful for a real multi-player session.
        if state.player_slots.len() >= 2 && unaccounted.len() == 1 {
            let holdout = unaccounted[0];
            if state.holdout_timer.is_none() {
                state.holdout_timer = Some(self.arm_holdout(
                    tenant.clone(),
                    session,
                    holdout,
                    self.inner.holdout_grace,
                ));
            }
        } else if let Some(timer) = state.holdout_timer.take() {
            timer.abort();
        }

        // Linger: every player accounted but links remain (sessionClosed not yet
        // fired). Protects the defeated spectator — not all accounted, no reap.
        if !state.player_slots.is_empty() && unaccounted.is_empty() && !state.all_relays_closed() {
            if state.linger_timer.is_none() {
                state.linger_timer =
                    Some(self.arm_linger(tenant.clone(), session, self.inner.linger_grace));
            }
        } else if let Some(timer) = state.linger_timer.take() {
            timer.abort();
        }
    }

    /// Spawns the holdout-reap timer: after `grace`, if the holdout is still
    /// unaccounted, close its link on every serving relay.
    fn arm_holdout(
        &self,
        tenant: TenantId,
        session: SessionId,
        holdout: SlotId,
        grace: Duration,
    ) -> AbortHandle {
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            this.fire_holdout(tenant, session, holdout);
        })
        .abort_handle()
    }

    /// The holdout timer firing: re-check the condition (accounting can have moved
    /// during the grace), then close the holdout's link on every serving relay.
    fn fire_holdout(&self, tenant: TenantId, session: SessionId, holdout: SlotId) {
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant.clone(), session)) else {
            return;
        };
        state.holdout_timer = None;
        if state.accounted.contains(&holdout) {
            return; // the holdout reported/departed during the grace — resolved
        }
        let relays = state.serving_relays.clone();
        drop(sessions);
        tracing::info!(
            tenant = tenant.as_ref(),
            session = session.0,
            slot = holdout.0,
            "holdout reap: closing the silent slot's link",
        );
        self.close_slots(&tenant, session, vec![holdout], &relays);
    }

    /// Spawns the linger-reap timer: after `grace`, if all players are still
    /// accounted and links remain, close every slot with no departure record.
    fn arm_linger(&self, tenant: TenantId, session: SessionId, grace: Duration) -> AbortHandle {
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            this.fire_linger(tenant, session);
        })
        .abort_handle()
    }

    /// The linger timer firing: re-check the condition, then close every player or
    /// observer slot that has no departure record (reported-but-still-linked
    /// stragglers and observers).
    fn fire_linger(&self, tenant: TenantId, session: SessionId) {
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant.clone(), session)) else {
            return;
        };
        state.linger_timer = None;
        if !state.unaccounted_players().is_empty() || state.all_relays_closed() {
            return; // condition resolved during the grace
        }
        let targets: Vec<SlotId> = state
            .player_slots
            .iter()
            .chain(state.observer_slots.iter())
            .filter(|s| !state.departed.contains(s))
            .copied()
            .collect();
        let relays = state.serving_relays.clone();
        drop(sessions);
        if targets.is_empty() {
            return;
        }
        tracing::info!(
            tenant = tenant.as_ref(),
            session = session.0,
            slots = ?targets,
            "linger reap: closing the non-departed stragglers",
        );
        self.close_slots(&tenant, session, targets, &relays);
    }

    /// Fans a `CloseSlot` directive out to every serving relay. A relay that does
    /// not hold a named slot ignores it, so naming every serving relay is safe.
    fn close_slots(
        &self,
        tenant: &TenantId,
        session: SessionId,
        slots: Vec<SlotId>,
        relays: &[RelayId],
    ) {
        let close = SlotClose {
            tenant: tenant.clone(),
            session,
            slots,
        };
        for relay in relays {
            self.inner.setup.reaps().send(*relay, close.clone());
        }
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
}

/// Drains one session's ordered dispatch queue, delivering each webhook to
/// completion (its full retry span) before the next. Exits when every sender is
/// dropped — the session state was reaped — after the last job is delivered.
async fn drain_queue(mut rx: mpsc::UnboundedReceiver<WebhookJob>, tenants: TenantStore) {
    while let Some(job) = rx.recv().await {
        notify::dispatch(tenants.clone(), job.tenant, job.config, job.body, job.kind).await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc as StdArc;

    use axum::Router;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::token::KeyId;
    use tokio::sync::{Notify as TokioNotify, mpsc as tokio_mpsc};
    use tokio::time::timeout;

    use super::*;
    use crate::registry;
    use crate::tenant;

    const TENANT: &str = "sb-test";
    const HOUR: Duration = Duration::from_secs(3600);
    const SHORT: Duration = Duration::from_millis(80);

    fn tid() -> TenantId {
        TenantId(TENANT.to_owned())
    }

    /// A bare setup with a tenant enrolled (its signing key), no notify config —
    /// enough for reap tests, which never POST a webhook.
    fn bare_setup() -> SessionSetup {
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("k1".to_owned()),
            tid(),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        SessionSetup::new(registry::new_registry(), tenants)
    }

    /// One webhook the stand-in tenant received: its `event` discriminator.
    #[derive(Clone, Debug)]
    struct Received {
        event: String,
    }

    /// The stand-in receiver's axum state: the record channel, the optional
    /// first-request gate, and the "have we seen the first request" flag.
    type ReceiverState = (
        tokio_mpsc::UnboundedSender<Received>,
        Option<StdArc<TokioNotify>>,
        StdArc<std::sync::atomic::AtomicBool>,
    );

    /// A stand-in tenant receiver recording each POST's `event` in order. If
    /// `gate` is set, the *first* request blocks on it until the test releases it —
    /// so a test can prove a stuck notice blocks the queue behind it.
    async fn spawn_receiver(
        gate: Option<StdArc<TokioNotify>>,
    ) -> (String, tokio_mpsc::UnboundedReceiver<Received>) {
        let (tx, rx) = tokio_mpsc::unbounded_channel::<Received>();
        let first = StdArc::new(std::sync::atomic::AtomicBool::new(true));
        let app = Router::new()
            .route(
                "/hook",
                post(
                    move |State((tx, gate, first)): State<ReceiverState>,
                          body: axum::body::Bytes| async move {
                        let is_first = first.swap(false, std::sync::atomic::Ordering::SeqCst);
                        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let event = value["event"].as_str().unwrap_or_default().to_owned();
                        let _ = tx.send(Received { event });
                        if is_first && let Some(gate) = gate {
                            gate.notified().await;
                        }
                        StatusCode::OK
                    },
                ),
            )
            .with_state((tx, gate, first));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/hook"), rx)
    }

    fn setup_with_notify(url: String) -> SessionSetup {
        let setup = bare_setup();
        tenant::set_notify(setup.tenants(), &tid(), Some(NotifyConfig { url }));
        setup
    }

    #[tokio::test]
    async fn holdout_reap_closes_the_silent_slot_after_grace_not_before() {
        let setup = bare_setup();
        let mut reaps = setup.reaps().subscribe(RelayId(1));
        let lc = Lifecycle::with_graces(setup, SHORT, HOUR, HOUR);
        let s = SessionId(1);
        lc.register_session(
            tid(),
            s,
            vec![RelayId(1)],
            HashSet::from([SlotId(0), SlotId(1)]),
            HashSet::new(),
        );

        // Slot 0 accounts (departs); slot 1 is the lone holdout → holdout timer arms.
        lc.on_departure(tid(), s, SlotId(0), DepartureKind::Dropped);
        assert!(reaps.try_recv().is_err(), "nothing closes before the grace");
        tokio::time::sleep(SHORT / 2).await;
        assert!(reaps.try_recv().is_err(), "still nothing mid-grace");

        let close = timeout(SHORT * 4, reaps.recv())
            .await
            .expect("the holdout is reaped after the grace")
            .unwrap();
        assert_eq!(close.session, s);
        assert_eq!(close.slots, vec![SlotId(1)], "only the holdout is closed");
    }

    #[tokio::test]
    async fn holdout_reap_disarms_when_the_holdout_reports() {
        let setup = bare_setup();
        let mut reaps = setup.reaps().subscribe(RelayId(1));
        let lc = Lifecycle::with_graces(setup, SHORT, HOUR, HOUR);
        let s = SessionId(1);
        lc.register_session(
            tid(),
            s,
            vec![RelayId(1)],
            HashSet::from([SlotId(0), SlotId(1)]),
            HashSet::new(),
        );

        lc.on_departure(tid(), s, SlotId(0), DepartureKind::Dropped); // arms holdout for slot 1
        lc.on_departure(tid(), s, SlotId(1), DepartureKind::Dropped); // the holdout reports → disarm

        // Past the holdout grace, nothing was reaped (the linger grace is an hour).
        tokio::time::sleep(SHORT * 2).await;
        assert!(
            reaps.try_recv().is_err(),
            "a holdout that reports before the grace is not reaped",
        );
    }

    #[tokio::test]
    async fn linger_reap_closes_non_departed_slots_including_observers() {
        let setup = bare_setup();
        let mut r1 = setup.reaps().subscribe(RelayId(1));
        let mut r2 = setup.reaps().subscribe(RelayId(2));
        let lc = Lifecycle::with_graces(setup, HOUR, SHORT, HOUR);
        let s = SessionId(1);
        lc.register_session(
            tid(),
            s,
            vec![RelayId(1), RelayId(2)],
            HashSet::from([SlotId(0), SlotId(1)]),
            HashSet::from([SlotId(2)]),
        );

        // Both players report a result (accounted, but not departed) → linger arms.
        lc.on_result(tid(), s, SlotId(0));
        lc.on_result(tid(), s, SlotId(1));

        let close = timeout(SHORT * 4, r1.recv())
            .await
            .expect("the stragglers are reaped after the linger grace")
            .unwrap();
        let closed: HashSet<SlotId> = close.slots.into_iter().collect();
        assert_eq!(
            closed,
            HashSet::from([SlotId(0), SlotId(1), SlotId(2)]),
            "every non-departed slot, observer included, is closed",
        );
        // The reap fans out to every serving relay.
        let close2 = timeout(SHORT * 4, r2.recv())
            .await
            .expect("the second serving relay is reaped too")
            .unwrap();
        assert_eq!(close2.session, s);
    }

    #[tokio::test]
    async fn session_closed_fires_only_after_all_serving_relays_closed() {
        let (url, mut rx) = spawn_receiver(None).await;
        let setup = setup_with_notify(url);
        let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
        let s = SessionId(1);
        lc.register_session(
            tid(),
            s,
            vec![RelayId(1), RelayId(2)],
            HashSet::from([SlotId(0)]),
            HashSet::new(),
        );

        // The first serving relay closes: no sessionClosed yet, and still alive.
        lc.on_session_closed(tid(), s, RelayId(1));
        assert!(lc.is_alive(&tid(), s), "one relay closed is not the end");
        assert!(
            timeout(Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "sessionClosed must not fire while a serving relay is still open",
        );

        // The last serving relay closes: sessionClosed fires, and it is no longer
        // alive (its state was reaped).
        lc.on_session_closed(tid(), s, RelayId(2));
        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("sessionClosed is delivered once every relay closed")
            .unwrap();
        assert_eq!(got.event, "sessionClosed");
        assert!(
            !lc.is_alive(&tid(), s),
            "a fully-closed session is not alive"
        );
    }

    #[tokio::test]
    async fn a_retrying_notice_blocks_session_closed_behind_it() {
        // A departure whose delivery hangs blocks the queue: sessionClosed, enqueued
        // after it, cannot be delivered until the departure completes — the ordering
        // guarantee the sessionClosed signal rests on.
        let gate = StdArc::new(TokioNotify::new());
        let (url, mut rx) = spawn_receiver(Some(gate.clone())).await;
        let setup = setup_with_notify(url.clone());
        let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
        let s = SessionId(1);
        lc.register_session(
            tid(),
            s,
            vec![RelayId(1)],
            HashSet::from([SlotId(0)]),
            HashSet::new(),
        );

        // Enqueue a departure webhook (its delivery will hang at the receiver).
        lc.enqueue_webhook(
            tid(),
            s,
            NotifyConfig { url },
            bytes::Bytes::from_static(br#"{"event":"departure"}"#),
            "departure",
        );
        // The last (only) serving relay closes → sessionClosed enqueued behind it.
        lc.on_session_closed(tid(), s, RelayId(1));

        // The departure request reaches the receiver and hangs; sessionClosed is
        // stuck behind it in the queue.
        let first = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("the departure request reaches the receiver")
            .unwrap();
        assert_eq!(first.event, "departure");
        assert!(
            timeout(Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "sessionClosed is blocked behind the stuck departure",
        );

        // Release the departure: it completes, then sessionClosed is delivered.
        gate.notify_one();
        let next = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("sessionClosed is delivered once the departure completes")
            .unwrap();
        assert_eq!(next.event, "sessionClosed");
    }

    #[tokio::test]
    async fn is_alive_reports_live_gone_and_unknown() {
        let setup = bare_setup();
        let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
        let live = SessionId(1);
        lc.register_session(
            tid(),
            live,
            vec![RelayId(1)],
            HashSet::from([SlotId(0)]),
            HashSet::new(),
        );
        assert!(lc.is_alive(&tid(), live), "a created session is alive");

        // Unknown (never created) reads as not alive.
        assert!(
            !lc.is_alive(&tid(), SessionId(999)),
            "an unknown session is not alive"
        );

        // Fully closed reads as not alive.
        lc.on_session_closed(tid(), live, RelayId(1));
        assert!(!lc.is_alive(&tid(), live), "a closed session is not alive");
    }

    #[tokio::test]
    async fn a_webhook_only_state_is_reaped_and_prunes_its_dedup_after_the_idle_grace() {
        // A departure/result webhook for a session this lifetime never registered
        // (restart amnesia) lazily creates a webhook-only state — no serving relays,
        // so it never receives a `SessionClosed` and the all-relays-closed removal
        // never fires. Its own idle reap must remove it (ending its drain task) and
        // prune its dedup entries, else it leaks for the process lifetime.
        let (url, mut rx) = spawn_receiver(None).await;
        let setup = setup_with_notify(url.clone());
        // Only the webhook-only idle grace is short; the others don't apply here.
        let lc = Lifecycle::with_graces(setup, HOUR, HOUR, SHORT);
        let dedup = notify::new_dedup();
        lc.attach_dedup(dedup.clone());
        let s = SessionId(1);

        // Seed a dedup entry for this session, as the notice handler would have.
        dedup.departures.lock().insert((tid(), s, SlotId(0)));

        lc.enqueue_webhook(
            tid(),
            s,
            NotifyConfig { url },
            bytes::Bytes::from_static(br#"{"event":"departure"}"#),
            "departure",
        );
        assert!(
            lc.contains_state(&tid(), s),
            "the webhook-only state exists after the lazy insert",
        );

        // Its queued webhook still delivers before the state is reaped.
        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("the webhook-only queue delivers its job")
            .unwrap();
        assert_eq!(got.event, "departure");

        // After the idle grace with no further webhooks, the state is removed and
        // its dedup entry pruned.
        timeout(SHORT * 20, async {
            loop {
                if !lc.contains_state(&tid(), s) {
                    break;
                }
                tokio::time::sleep(SHORT / 4).await;
            }
        })
        .await
        .expect("the webhook-only state is reaped after its idle grace");
        assert!(
            !dedup.departures.lock().contains(&(tid(), s, SlotId(0))),
            "the reaped session's dedup entry was pruned",
        );
    }

    #[tokio::test]
    async fn a_fresh_webhook_re_arms_the_idle_reap() {
        // The idle reap measures from the last webhook, so a later webhook pushes
        // it out — a game's tail notices keep the webhook-only state alive until
        // they stop arriving, rather than a fixed window from the first one.
        let (url, mut rx) = spawn_receiver(None).await;
        let setup = setup_with_notify(url.clone());
        let lc = Lifecycle::with_graces(setup, HOUR, HOUR, SHORT * 4);
        let s = SessionId(1);

        let enqueue = |lc: &Lifecycle| {
            lc.enqueue_webhook(
                tid(),
                s,
                NotifyConfig { url: url.clone() },
                bytes::Bytes::from_static(br#"{"event":"departure"}"#),
                "departure",
            );
        };

        enqueue(&lc);
        // Half a grace later, a second webhook re-arms the timer.
        tokio::time::sleep(SHORT * 2).await;
        enqueue(&lc);
        // Past the *original* grace but inside the re-armed one: still present.
        tokio::time::sleep(SHORT * 3).await;
        assert!(
            lc.contains_state(&tid(), s),
            "a fresh webhook re-armed the idle reap, so the state is still held",
        );

        // Drain the two delivered webhooks so the receiver doesn't wedge on drop.
        let _ = timeout(Duration::from_secs(1), rx.recv()).await;
        let _ = timeout(Duration::from_secs(1), rx.recv()).await;

        // Eventually, with no more webhooks, it is reaped.
        timeout(SHORT * 20, async {
            loop {
                if !lc.contains_state(&tid(), s) {
                    break;
                }
                tokio::time::sleep(SHORT / 4).await;
            }
        })
        .await
        .expect("the state is reaped once the idle grace elapses with no new webhook");
    }

    #[tokio::test]
    async fn closing_a_session_retires_its_pending_reap_directives() {
        // A reap armed for a session must not linger in the reap outbox after the
        // session fully closes: a relay reconnecting afterward would otherwise be
        // re-synced with a stale close for a session it no longer serves.
        let setup = bare_setup();
        let reaps = setup.reaps().clone();
        let lc = Lifecycle::with_graces(setup, SHORT, HOUR, HOUR);
        let s = SessionId(1);
        lc.register_session(
            tid(),
            s,
            vec![RelayId(1)],
            HashSet::from([SlotId(0), SlotId(1)]),
            HashSet::new(),
        );

        // Arm and fire the holdout reap so a directive is pending for relay 1.
        lc.on_departure(tid(), s, SlotId(0), DepartureKind::Dropped);
        let mut rx = reaps.subscribe(RelayId(1));
        let close = timeout(SHORT * 4, rx.recv())
            .await
            .expect("the holdout is reaped")
            .unwrap();
        assert_eq!(close.slots, vec![SlotId(1)]);

        // The session fully closes → its pending reap is retired. A relay
        // reconnecting after the close gets no stale directive replayed.
        lc.on_session_closed(tid(), s, RelayId(1));
        let mut reconnect = reaps.subscribe(RelayId(1));
        assert!(
            reconnect.try_recv().is_err(),
            "a closed session's reap is not replayed to a reconnecting relay",
        );
    }

    #[tokio::test]
    async fn closing_a_session_prunes_its_dedup_entries_only() {
        // The normal all-relays-closed removal must also prune the session's dedup
        // entries (across all three sets), without touching another session's.
        let setup = bare_setup();
        let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
        let dedup = notify::new_dedup();
        lc.attach_dedup(dedup.clone());
        let s = SessionId(1);
        let other = SessionId(2);
        lc.register_session(
            tid(),
            s,
            vec![RelayId(1)],
            HashSet::from([SlotId(0)]),
            HashSet::new(),
        );

        dedup.departures.lock().insert((tid(), s, SlotId(0)));
        dedup.results.lock().insert((tid(), s, SlotId(0)));
        dedup.desyncs.lock().insert((tid(), s, 7));
        // A different session's entry, which must survive.
        dedup.departures.lock().insert((tid(), other, SlotId(0)));

        lc.on_session_closed(tid(), s, RelayId(1));

        assert!(!dedup.departures.lock().contains(&(tid(), s, SlotId(0))));
        assert!(!dedup.results.lock().contains(&(tid(), s, SlotId(0))));
        assert!(!dedup.desyncs.lock().contains(&(tid(), s, 7)));
        assert!(
            dedup.departures.lock().contains(&(tid(), other, SlotId(0))),
            "another session's dedup entry is untouched",
        );
    }

    /// A setup with relay 1 enrolled and the test tenant, plus a real two-player
    /// session created on it — so its `session_relays`/`session_refs` membership is
    /// recorded, the way a lifecycle full-close later retires. Returns the setup and
    /// the created session id.
    fn setup_with_relay_and_session() -> (SessionSetup, SessionId) {
        use rally_point_proto::control::{PlayerHandoff, RelayHello, SessionRequest};
        use rally_point_proto::token::{ClientPublicKey, ExpiresAt};
        use rally_point_proto::version::ProtocolVersion;

        let reg = registry::new_registry();
        registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(1),
                std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                ProtocolVersion::CURRENT,
                vec![1u8; 4],
            ),
        );
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("k1".to_owned()),
            tid(),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = SessionSetup::new(reg, tenants);
        let resp = crate::session::create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: vec![
                    PlayerHandoff {
                        slot: SlotId(0),
                        client_pubkey: ClientPublicKey([0xAA; 32]),
                        external_ref: None,
                        observer: false,
                    },
                    PlayerHandoff {
                        slot: SlotId(1),
                        client_pubkey: ClientPublicKey([0xBB; 32]),
                        external_ref: None,
                        observer: false,
                    },
                ],
                external_id: None,
                dev_relay_split: Vec::new(),
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
        (setup, resp.session)
    }

    #[tokio::test]
    async fn closing_a_session_retires_membership_and_limiter_bucket() {
        // A full close must retire the session's relay membership and drop its
        // rate-limit bucket, so a straggler cannot re-home (and thus resurrect) a
        // dead session and the bucket map stays bounded.
        use crate::rehome::REHOME_BURST;
        use crate::session::{self, RehomeOutcome};

        let (setup, s) = setup_with_relay_and_session();
        let lc = Lifecycle::with_graces(setup.clone(), HOUR, HOUR, HOUR);
        lc.register_session(
            tid(),
            s,
            setup.serving_relays(&tid(), s),
            HashSet::from([SlotId(0), SlotId(1)]),
            HashSet::new(),
        );

        // Membership is recorded; exhaust the session's limiter bucket so its later
        // reset is observable.
        assert!(
            !setup.serving_relays(&tid(), s).is_empty(),
            "membership is recorded before close",
        );
        for _ in 0..REHOME_BURST {
            assert!(setup.rehome_limiter().check(&tid(), s));
        }
        assert!(
            !setup.rehome_limiter().check(&tid(), s),
            "the bucket is exhausted before close",
        );

        // The single serving relay reports closed → full close.
        lc.on_session_closed(tid(), s, RelayId(1));

        assert!(
            setup.serving_relays(&tid(), s).is_empty(),
            "close retired the session→relay membership",
        );
        // Relay 1 is still enrolled, yet the closed session's empty serving set trips
        // the guard: the honest terminal answer is Unavailable, not a resurrection.
        assert_eq!(
            session::rehome(&setup, &tid(), s, RelayId(1), vec![]),
            RehomeOutcome::Unavailable,
            "a closed session refuses re-home even while a relay is live",
        );
        assert!(
            setup.rehome_limiter().check(&tid(), s),
            "close dropped the limiter bucket, so a fresh burst is available",
        );
    }

    #[tokio::test]
    async fn closing_a_session_removes_its_descriptor_from_each_serving_relay() {
        // A full close must drop the session's descriptor from every serving relay's
        // latest-wins outbox. Otherwise a relay reconnecting after the close is
        // re-synced the stale descriptor and re-applies the dead session (its
        // reconciler only leaves sessions absent from the pushed set).
        let (setup, s) = setup_with_relay_and_session();
        let lc = Lifecycle::with_graces(setup.clone(), HOUR, HOUR, HOUR);
        lc.register_session(
            tid(),
            s,
            setup.serving_relays(&tid(), s),
            HashSet::from([SlotId(0), SlotId(1)]),
            HashSet::new(),
        );

        // create_session staged a descriptor for the sole serving relay.
        assert!(
            setup
                .descriptors()
                .current_for(RelayId(1))
                .iter()
                .any(|d| d.session == s),
            "the session's descriptor is staged before the close",
        );

        lc.on_session_closed(tid(), s, RelayId(1));

        // A relay reconnecting after the close subscribes to a set that no longer
        // carries the closed session's descriptor.
        let rx = setup.descriptors().subscribe(RelayId(1));
        assert!(
            !rx.borrow().iter().any(|d| d.session == s),
            "the closed session's descriptor is gone from the serving relay's outbox",
        );
        assert!(
            setup
                .descriptors()
                .current_for(RelayId(1))
                .iter()
                .all(|d| d.session != s),
        );
    }

    /// A two-relay setup — both enrolled, only relay 1 serving (the session's
    /// default, unsplit assignment) — with the tenant's notify URL wired to
    /// `url`, so a test can observe the final `sessionClosed` webhook.
    fn setup_with_two_relays_and_session(url: String) -> (SessionSetup, SessionId) {
        use rally_point_proto::control::{PlayerHandoff, RelayHello, SessionRequest};
        use rally_point_proto::token::{ClientPublicKey, ExpiresAt};
        use rally_point_proto::version::ProtocolVersion;

        let reg = registry::new_registry();
        for (id, port) in [(1u64, 14900u16), (2, 14901)] {
            registry::enroll(
                &reg,
                RelayHello::new(
                    RelayId(id),
                    std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                    ProtocolVersion::CURRENT,
                    vec![id as u8; 4],
                ),
            );
        }
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("k1".to_owned()),
            tid(),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        tenant::set_notify(&tenants, &tid(), Some(NotifyConfig { url }));
        let setup = SessionSetup::new(reg, tenants);
        let resp = crate::session::create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: vec![
                    PlayerHandoff {
                        slot: SlotId(0),
                        client_pubkey: ClientPublicKey([0xAA; 32]),
                        external_ref: None,
                        observer: false,
                    },
                    PlayerHandoff {
                        slot: SlotId(1),
                        client_pubkey: ClientPublicKey([0xBB; 32]),
                        external_ref: None,
                        observer: false,
                    },
                ],
                external_id: None,
                dev_relay_split: Vec::new(),
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
        (setup, resp.session)
    }

    #[tokio::test]
    async fn rehome_then_the_replacements_close_satisfies_all_relays_closed_and_reaps_the_state() {
        // A rehome must keep the lifecycle's cached serving set in step with the
        // mutation `session::rehome` applies to the session's real membership --
        // otherwise the relay it swapped onto is never recognized as needing to
        // report closed, `all_relays_closed` can never be satisfied, and the
        // session's state (and its drain queue task) leaks for the process
        // lifetime instead of being reaped here.
        use crate::session::{self, RehomeOutcome};

        let (url, mut rx) = spawn_receiver(None).await;
        let (setup, s) = setup_with_two_relays_and_session(url);
        let lc = Lifecycle::with_graces(setup.clone(), HOUR, HOUR, HOUR);
        lc.register_session(
            tid(),
            s,
            setup.serving_relays(&tid(), s),
            HashSet::from([SlotId(0), SlotId(1)]),
            HashSet::new(),
        );
        assert_eq!(setup.serving_relays(&tid(), s), vec![RelayId(1)]);

        registry::remove(setup.registry(), RelayId(1));
        let RehomeOutcome::NewTarget(endpoint) =
            session::rehome(&setup, &tid(), s, RelayId(1), vec![])
        else {
            panic!("expected a NewTarget re-home decision");
        };
        assert_eq!(endpoint.relay_id, RelayId(2));
        lc.on_rehome(&tid(), s, RelayId(1), RelayId(2));

        // The replacement's own close satisfies all-relays-closed (the cached set
        // now names only relay 2) and reaps the state: the final webhook fires, and
        // the session is no longer alive or tracked at all.
        lc.on_session_closed(tid(), s, RelayId(2));
        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("sessionClosed is delivered once the swapped-in relay closes")
            .unwrap();
        assert_eq!(got.event, "sessionClosed");
        assert!(!lc.is_alive(&tid(), s), "a fully-closed session is not alive");
        assert!(
            !lc.contains_state(&tid(), s),
            "the session's lifecycle state and drain queue are reaped, not left immortal",
        );
    }

    #[tokio::test]
    async fn a_late_close_from_the_swapped_out_dead_relay_is_ignored() {
        // A dead relay can briefly reconnect after a partition and flush a stale
        // SessionClosed for a session a rehome already swapped it out of. That
        // late report must not satisfy all-relays-closed on its own, and must not
        // disturb the real serving relay's own close finishing the session
        // normally afterward.
        use crate::session::{self, RehomeOutcome};

        let (url, mut rx) = spawn_receiver(None).await;
        let (setup, s) = setup_with_two_relays_and_session(url);
        let lc = Lifecycle::with_graces(setup.clone(), HOUR, HOUR, HOUR);
        lc.register_session(
            tid(),
            s,
            setup.serving_relays(&tid(), s),
            HashSet::from([SlotId(0), SlotId(1)]),
            HashSet::new(),
        );

        registry::remove(setup.registry(), RelayId(1));
        let RehomeOutcome::NewTarget(endpoint) =
            session::rehome(&setup, &tid(), s, RelayId(1), vec![])
        else {
            panic!("expected a NewTarget re-home decision");
        };
        assert_eq!(endpoint.relay_id, RelayId(2));
        lc.on_rehome(&tid(), s, RelayId(1), RelayId(2));

        lc.on_session_closed(tid(), s, RelayId(1)); // the swapped-out dead relay's late report
        assert!(
            lc.is_alive(&tid(), s),
            "a close from a relay no longer in the cached serving set does not finish the session",
        );
        assert!(
            timeout(Duration::from_millis(300), rx.recv())
                .await
                .is_err(),
            "no sessionClosed fires from the stale close alone",
        );

        lc.on_session_closed(tid(), s, RelayId(2));
        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("the real serving relay's close still finishes the session")
            .unwrap();
        assert_eq!(got.event, "sessionClosed");
    }

    #[tokio::test]
    async fn rehome_swap_composes_with_a_surviving_relay_that_was_already_serving() {
        // A split session on relays 1 (home) and 2 (secondary). Relay 2 asks to
        // drain -- still a serving member, but excluded from the replacement pick
        // -- so when the home dies the group moves onto the idle relay 3 instead,
        // leaving BOTH 3 (the replacement) and 2 (the drained-but-still-serving
        // survivor) in the cached set. Both must report closed before the session
        // finishes.
        use crate::session::{self, RehomeOutcome};
        use rally_point_proto::control::{PlayerHandoff, RelayHello, SessionRequest};
        use rally_point_proto::token::{ClientPublicKey, ExpiresAt};
        use rally_point_proto::version::ProtocolVersion;

        let (url, mut rx) = spawn_receiver(None).await;
        let reg = registry::new_registry();
        registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(1),
                std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                ProtocolVersion::CURRENT,
                vec![1u8; 4],
            ),
        );
        let gen2 = registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(2),
                std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
                ProtocolVersion::CURRENT,
                vec![2u8; 4],
            ),
        );
        registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(3),
                std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 14902)),
                ProtocolVersion::CURRENT,
                vec![3u8; 4],
            ),
        );
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("k1".to_owned()),
            tid(),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        tenant::set_notify(&tenants, &tid(), Some(NotifyConfig { url }));
        let setup = SessionSetup::new(reg, tenants);

        let resp = crate::session::create_session(
            &setup,
            SessionRequest {
                tenant: tid(),
                players: vec![
                    PlayerHandoff {
                        slot: SlotId(0),
                        client_pubkey: ClientPublicKey([0xAA; 32]),
                        external_ref: None,
                        observer: false,
                    },
                    PlayerHandoff {
                        slot: SlotId(1),
                        client_pubkey: ClientPublicKey([0xBB; 32]),
                        external_ref: None,
                        observer: false,
                    },
                ],
                external_id: None,
                dev_relay_split: vec![SlotId(1)],
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
        let s = resp.session;
        assert_eq!(setup.serving_relays(&tid(), s), vec![RelayId(1), RelayId(2)]);

        let lc = Lifecycle::with_graces(setup.clone(), HOUR, HOUR, HOUR);
        lc.register_session(
            tid(),
            s,
            setup.serving_relays(&tid(), s),
            HashSet::from([SlotId(0), SlotId(1)]),
            HashSet::new(),
        );

        assert!(registry::mark_draining(setup.registry(), RelayId(2), gen2));
        registry::remove(setup.registry(), RelayId(1));

        let RehomeOutcome::NewTarget(endpoint) =
            session::rehome(&setup, &tid(), s, RelayId(1), vec![])
        else {
            panic!("expected a NewTarget re-home decision");
        };
        assert_eq!(
            endpoint.relay_id,
            RelayId(3),
            "the draining relay 2 is skipped for the idle live relay 3",
        );
        assert_eq!(
            setup.serving_relays(&tid(), s),
            vec![RelayId(3), RelayId(2)],
        );
        lc.on_rehome(&tid(), s, RelayId(1), RelayId(3));

        lc.on_session_closed(tid(), s, RelayId(3));
        assert!(lc.is_alive(&tid(), s), "relay 2 hasn't closed yet");

        lc.on_session_closed(tid(), s, RelayId(2));
        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("sessionClosed fires once both the replacement and the surviving relay close")
            .unwrap();
        assert_eq!(got.event, "sessionClosed");
    }

    #[tokio::test]
    async fn on_rehome_is_a_no_op_for_a_same_id_swap() {
        // A same-id restart's `NewTarget` names the relay's own id as both dead
        // and replacement. The cached serving set never dropped the id in the
        // first place, so composing `on_rehome` with it must leave the set
        // untouched rather than dropping the relay entirely.
        let setup = bare_setup();
        let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
        let s = SessionId(1);
        lc.register_session(
            tid(),
            s,
            vec![RelayId(1), RelayId(2)],
            HashSet::from([SlotId(0)]),
            HashSet::new(),
        );

        lc.on_rehome(&tid(), s, RelayId(1), RelayId(1));

        // Close ONLY relay 2. If the same-id swap had wrongly dropped relay 1 from
        // the cached set (treating it as removed rather than unchanged), this
        // alone would satisfy all-relays-closed; it must not.
        lc.on_session_closed(tid(), s, RelayId(2));
        assert!(
            lc.is_alive(&tid(), s),
            "relay 1 hasn't closed yet -- the same-id swap did not drop it from the set",
        );

        lc.on_session_closed(tid(), s, RelayId(1));
        assert!(!lc.is_alive(&tid(), s), "both original members closing finishes it");
    }

    #[tokio::test]
    async fn webhook_only_reap_retires_membership_harmlessly() {
        // A webhook-only state (restart amnesia) has no membership to begin with, so
        // its idle reap runs the same retirement as a no-op. It must not panic, and
        // the session stays unavailable to re-home afterward.
        use crate::session::{self, RehomeOutcome};

        let (url, mut rx) = spawn_receiver(None).await;
        let setup = setup_with_notify(url.clone());
        let lc = Lifecycle::with_graces(setup.clone(), HOUR, HOUR, SHORT);
        let s = SessionId(1);

        lc.enqueue_webhook(
            tid(),
            s,
            NotifyConfig { url },
            Bytes::from_static(br#"{"event":"departure"}"#),
            "departure",
        );
        assert!(
            setup.serving_relays(&tid(), s).is_empty(),
            "a webhook-only session never had membership",
        );

        // Let its queued webhook deliver, then wait for the idle reap to remove it.
        let _ = timeout(Duration::from_secs(2), rx.recv()).await;
        timeout(SHORT * 20, async {
            loop {
                if !lc.contains_state(&tid(), s) {
                    break;
                }
                tokio::time::sleep(SHORT / 4).await;
            }
        })
        .await
        .expect("the webhook-only state is reaped after its idle grace");

        assert!(setup.serving_relays(&tid(), s).is_empty());
        assert_eq!(
            session::rehome(&setup, &tid(), s, RelayId(1), vec![]),
            RehomeOutcome::Unavailable,
            "still unavailable after the no-op membership retirement",
        );
    }
}
