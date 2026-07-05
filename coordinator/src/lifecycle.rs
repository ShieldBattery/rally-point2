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
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::descriptors::SlotClose;
use crate::notify;
use crate::session::SessionSetup;
use crate::tenant::{NotifyConfig, TenantStore};

/// How long a holdout slot may stay silent on a live link — all-but-one player
/// accounted — before the coordinator closes its link.
pub const HOLDOUT_REAP_GRACE: Duration = Duration::from_secs(60);

/// How long a session's stragglers may linger — all players accounted but links
/// still open (`sessionClosed` not yet fired) — before the coordinator closes the
/// slots with no departure record.
pub const LINGER_REAP_GRACE: Duration = Duration::from_secs(60);

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
}

impl Lifecycle {
    /// Creates a lifecycle tracker over `setup` with the production reap graces.
    pub fn new(setup: SessionSetup) -> Self {
        Self::with_graces(setup, HOLDOUT_REAP_GRACE, LINGER_REAP_GRACE)
    }

    /// Creates a lifecycle tracker with the reap graces injected, so a test need
    /// not wait the production minute.
    pub fn with_graces(
        setup: SessionSetup,
        holdout_grace: Duration,
        linger_grace: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                setup,
                sessions: Mutex::new(HashMap::new()),
                holdout_grace,
                linger_grace,
            }),
        }
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
    }

    /// Records a slot's departure: accounts the slot (if a player), notes it
    /// departed, and re-evaluates the reap timers. `relay_id` is unused here (a
    /// departure names the slot, not who closes) but kept for call-site symmetry
    /// with [`on_session_closed`](Self::on_session_closed).
    pub fn on_departure(&self, tenant: TenantId, session: SessionId, slot: SlotId) {
        let mut sessions = self.inner.sessions.lock();
        let state = sessions
            .entry((tenant.clone(), session))
            .or_insert_with(|| self.new_state(Vec::new()));
        state.departed.insert(slot);
        if state.player_slots.contains(&slot) {
            state.accounted.insert(slot);
        }
        self.reevaluate_reaps(&tenant, session, state);
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
        if let Some(timer) = state.holdout_timer {
            timer.abort();
        }
        if let Some(timer) = state.linger_timer {
            timer.abort();
        }
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
            tenant,
            config,
            body,
            kind,
        });
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
            closed_relays: HashSet::new(),
            session_closed_enqueued: false,
            queue: tx,
            holdout_timer: None,
            linger_timer: None,
        }
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
        let lc = Lifecycle::with_graces(setup, SHORT, HOUR);
        let s = SessionId(1);
        lc.register_session(
            tid(),
            s,
            vec![RelayId(1)],
            HashSet::from([SlotId(0), SlotId(1)]),
            HashSet::new(),
        );

        // Slot 0 accounts (departs); slot 1 is the lone holdout → holdout timer arms.
        lc.on_departure(tid(), s, SlotId(0));
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
        let lc = Lifecycle::with_graces(setup, SHORT, HOUR);
        let s = SessionId(1);
        lc.register_session(
            tid(),
            s,
            vec![RelayId(1)],
            HashSet::from([SlotId(0), SlotId(1)]),
            HashSet::new(),
        );

        lc.on_departure(tid(), s, SlotId(0)); // arms holdout for slot 1
        lc.on_departure(tid(), s, SlotId(1)); // the holdout reports → disarm

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
        let lc = Lifecycle::with_graces(setup, HOUR, SHORT);
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
        let lc = Lifecycle::with_graces(setup, HOUR, HOUR);
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
        let lc = Lifecycle::with_graces(setup, HOUR, HOUR);
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
        let lc = Lifecycle::with_graces(setup, HOUR, HOUR);
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
}
