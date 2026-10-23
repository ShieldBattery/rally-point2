//! The lifecycle's half of surviving a coordinator restart: the accumulated
//! per-session facts captured for `crate::persist` and restored from it, and the
//! bounded wait a shutdown makes for queued webhooks to deliver.
//!
//! Accumulated facts and connection observations are persisted, including the
//! assignment, process, and activation fences that scope those observations.
//! Timers and transient liveness evidence (empty rosters, close marks) are not.
//! The serving set and player/observer split are re-derived from the setup record,
//! every reap timer is re-armed from the restored facts, and the relays' next beats
//! rebuild liveness evidence. A relay re-enrolling reopens its close evidence,
//! and silence is never proof.
//!
//! [`LifecycleFacts`] is a persisted format: a field added later must deserialize
//! from a record written before it existed (the container-level `serde(default)`).

use serde::{Deserialize, Serialize};

use super::*;

/// One registered session's accumulated facts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct LifecycleFacts {
    evidence: Vec<(SlotId, evidence::StoredEvidence)>,
    periodic_evidence: Vec<(SlotId, periodic::StoredPeriodic)>,
    /// Whether a client was ever observed for the session.
    started: bool,
    /// The relay-reported session start instant (unix epoch ms).
    started_at_ms: Option<u64>,
    /// Whether an unbroken chain of relay memory still covers the session's whole
    /// life. Absent reads as `false`: claiming completeness nothing vouched for is
    /// the unsafe direction.
    attestable: bool,
    /// Player slots with a result or a departure, ascending.
    accounted: Vec<SlotId>,
    /// Slots whose links ever activated, ascending.
    connected_slots: Vec<SlotId>,
    /// Slots that ever reported their game loop running, ascending.
    started_slots: Vec<SlotId>,
    /// Slots whose home relay ever forwarded one of their turns, ascending.
    forwarded_slots: Vec<SlotId>,
    /// Slots whose home relay observed a lobby policy violation, ascending.
    lobby_violation_slots: Vec<SlotId>,
    /// Each departed slot's rehome seed, ascending by slot.
    departures: Vec<PersistedDeparture>,
}

/// One departed slot's rehome seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedDeparture {
    slot: SlotId,
    kind: DepartureKind,
    final_turn_count: Option<u64>,
    finalized: bool,
}

impl Lifecycle {
    /// Captures the facts of every session registered with a serving set. A
    /// webhook-only state (restart amnesia, or a notice that beat its session's
    /// registration) is skipped: it has nothing a restart could restore into.
    pub(crate) fn export_facts(&self) -> HashMap<SessionRef, LifecycleFacts> {
        self.inner
            .sessions
            .lock()
            .iter()
            .filter(|(_, state)| state.created_here && !state.serving_relays.is_empty())
            .map(|(key, state)| {
                let mut departures: Vec<PersistedDeparture> = state
                    .departures
                    .iter()
                    .map(|(&slot, seed)| PersistedDeparture {
                        slot,
                        kind: seed.kind,
                        final_turn_count: seed.final_turn_count,
                        finalized: seed.finalized,
                    })
                    .collect();
                departures.sort_by_key(|d| d.slot);
                let facts = LifecycleFacts {
                    evidence: state
                        .evidence
                        .iter()
                        .map(|(&slot, value)| (slot, value.clone()))
                        .collect(),
                    periodic_evidence: state
                        .periodic_evidence
                        .iter()
                        .map(|(&slot, value)| (slot, value.clone()))
                        .collect(),
                    started: state.started,
                    started_at_ms: state.started_at_ms,
                    attestable: state.attestable,
                    accounted: sorted_slots(&state.accounted),
                    connected_slots: sorted_slots(&state.connected_slots),
                    started_slots: sorted_slots(&state.started_slots),
                    forwarded_slots: sorted_slots(&state.forwarded_slots),
                    lobby_violation_slots: sorted_slots(&state.lobby_violation_slots),
                    departures,
                };
                (key.clone(), facts)
            })
            .collect()
    }

    /// Re-registers a session restored from a previous coordinator lifetime and
    /// overlays its persisted facts, then re-evaluates its reaps. Every timer
    /// starts its grace fresh from now: the restart is not counted against a
    /// window that was running when the old process stopped.
    pub(crate) fn restore_session(
        &self,
        tenant: TenantId,
        session: SessionId,
        serving_relays: Vec<RelayId>,
        player_slots: HashSet<SlotId>,
        observer_slots: HashSet<SlotId>,
        facts: LifecycleFacts,
    ) {
        self.register_session(
            tenant.clone(),
            session,
            serving_relays,
            player_slots,
            observer_slots,
        );
        let mut sessions = self.inner.sessions.lock();
        let Some(state) = sessions.get_mut(&(tenant.clone(), session)) else {
            return;
        };
        state.attestable = facts.attestable;
        state.started_at_ms = facts.started_at_ms;
        state.accounted.extend(facts.accounted);
        state.connected_slots.extend(facts.connected_slots);
        state.evidence.extend(facts.evidence);
        state.periodic_evidence.extend(facts.periodic_evidence);
        state.started_slots.extend(facts.started_slots);
        state.forwarded_slots.extend(facts.forwarded_slots);
        state
            .lobby_violation_slots
            .extend(facts.lobby_violation_slots);
        for departure in facts.departures {
            state.departures.insert(
                departure.slot,
                DepartureSeed {
                    kind: departure.kind,
                    final_turn_count: departure.final_turn_count,
                    finalized: departure.finalized,
                },
            );
        }
        if facts.started {
            self.mark_started(state);
        }
        self.reevaluate_reaps(&tenant, session, state);
    }

    /// Waits up to `deadline` for every queued webhook to be delivered or given
    /// up on, returning how many were still pending when it stopped waiting (0 on
    /// a clean drain). A shutdown calls this after its control connections have
    /// closed, so no new relay notice can keep refilling the queues; whatever the
    /// deadline cuts off is lost, as the webhooks are an optimization feed whose
    /// correctness backstops live on the tenant side.
    pub async fn drain_webhooks(&self, deadline: Duration) -> usize {
        const POLL: Duration = Duration::from_millis(50);
        let give_up = tokio::time::Instant::now() + deadline;
        loop {
            let pending = self.inner.pending_webhooks.load(Ordering::Acquire);
            if pending == 0 || tokio::time::Instant::now() >= give_up {
                return pending;
            }
            tokio::time::sleep(POLL).await;
        }
    }
}
