//! The coordinator's per-relay outboxes — everything the control connection has
//! queued for a relay to receive.
//!
//! Two live here. [`RelayDescriptors`] holds each relay's current session
//! descriptor set; [`RelayReaps`] holds each relay's pending slot-close
//! directives. They are together because they are the same shape: per-relay
//! state a session-side caller edits and a connection task pushes, both
//! re-synced whole on reconnect, both safe to re-deliver. The sections below
//! describe the descriptor outbox; [`RelayReaps`]' own docs cover how a reap
//! directive is armed, coalesced and retired.
//!
//! When a session is created, the coordinator records — per relay serving it —
//! the [`SessionDescriptor`] that relay should apply, naming its mesh peers for
//! that session. Each relay holds one control connection open to the coordinator;
//! the connection task watches that relay's set here and pushes it down the
//! connection whenever it changes. The relay applies each descriptor through its
//! idempotent Join source, which turns it into targeted mesh `Join`/`Leave`.
//!
//! # Declarative current-state, pushed on change
//!
//! Each relay's entry holds its *current* descriptor set — the descriptor for
//! every session it should serve, replaced in place when a session's topology
//! changes, dropped when the session ends. The set lives in a
//! [`watch`] channel: a connected relay's task subscribes,
//! and a change wakes it to push the new set. `watch` keeps only the latest
//! value, which is exactly right for declarative state — a relay that was briefly
//! slow or disconnected re-syncs to the current truth rather than replaying a
//! backlog of intermediate edits.
//!
//! Reading is non-destructive and re-pushing is a no-op on the relay (applying a
//! descriptor already in effect changes nothing), so the channel never has to
//! guarantee exactly-once delivery: a relay that reconnects is sent its whole
//! current set and converges, rather than losing membership to a dropped message.
//! The one thing the relay must do that a pure delta would carry explicitly is
//! detect *removals* — a session gone from the set is one to leave — which it does
//! by diffing against what it last applied.
//!
//! A plain (non-async) mutex guards the registry of per-relay channels: every
//! critical section is a short, await-free channel lookup, create, or in-place
//! set edit — never held across the push itself, which happens on the connection
//! task. Clone the outbox cheaply (the state is behind one `Arc`) to share it
//! between session setup and the control-connection handler.
//!
//! # Reaps
//!
//! A reap directive is a *queued* close rather than current state, so
//! [`RelayReaps`] uses an mpsc channel primed from a pending set instead of a
//! `watch`: the relay must see each armed close, not merely the latest snapshot.
//! It shares the descriptor outbox's disconnect behaviour — a fresh subscribe is
//! primed with the whole pending set — and its own idempotence (a slot the relay
//! no longer holds is a no-op) is what makes that re-delivery safe.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use rally_point_proto::control::{DescriptorKey, SessionDescriptor, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use tokio::sync::{mpsc, watch};

/// One relay's current descriptor set, behind a `watch` so a connected relay's
/// control task is woken to push it on every change.
type RelayChannel = watch::Sender<Vec<SessionDescriptor>>;

/// A coordinator-armed reap directive for one relay: close these slots' links so
/// their normal link-death path runs. Carried down the relay's control connection
/// as a [`CoordinatorToRelay::CloseSlot`](rally_point_proto::control::CoordinatorToRelay::CloseSlot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotClose {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session whose slots to close.
    pub session: SessionId,
    /// The slots to close (a slot a relay does not hold is a no-op there).
    pub slots: Vec<SlotId>,
}

/// The per-relay outbox for reap directives — the declarative sibling of
/// [`RelayDescriptors`], and shaped the same way for the same reason. Descriptors
/// are latest-wins current state a reconnecting relay re-syncs to in full; reaps
/// are the same kind of state expressed as a set of pending slot-closes rather
/// than one replaceable value.
///
/// # Pending set, re-synced on reconnect
///
/// Each relay holds a persistent *pending set* of slot-closes. A directive is
/// recorded there and also nudged down the relay's live control connection, if it
/// has one; a directive armed while the relay is disconnected simply stays pending
/// with no live connection to nudge. On every (re)`subscribe` the fresh receiver
/// is primed with the whole pending set, so a relay whose connection dropped
/// during the reconnect gap re-syncs its reaps exactly as it re-syncs descriptors,
/// rather than losing a directive that raced the disconnect.
///
/// Re-delivery is safe because a `CloseSlot` is idempotent on the relay: a slot it
/// no longer holds is a no-op, so replaying the pending set changes nothing that
/// is already in effect. Repeats for one session union their slots (keyed by
/// `(tenant, session)`) rather than accumulate, so the set stays one entry per
/// session. A directive is retired only when its session is done from the
/// coordinator's view — [`retire`](Self::retire), called wherever the lifecycle
/// removes the session's state — which bounds each relay's pending set to its live
/// sessions.
///
/// A plain (non-async) mutex guards the per-relay states; every critical section
/// is a short, await-free set edit plus a non-blocking channel send. Clone the
/// outbox cheaply (state is behind one `Arc`) to share it between the reap
/// policies and the control-connection handler.
#[derive(Clone, Default)]
pub struct RelayReaps {
    /// Each relay's reap state — its pending directives and its live sender.
    relays: Arc<Mutex<HashMap<RelayId, RelayReapState>>>,
}

/// One relay's reap state: the slot-closes still pending for it, plus the sender
/// for its current control connection when one is subscribed.
#[derive(Default)]
struct RelayReapState {
    /// The pending slot-closes for this relay, keyed by `(tenant, session)` so
    /// repeats for one session union their slots into a single entry. Replayed in
    /// full to each (re)subscribe; an entry is dropped when the session retires.
    pending: HashMap<(TenantId, SessionId), Vec<SlotId>>,
    /// The current control connection's sender, replaced on each (re)subscribe and
    /// cleared when a send fails (the connection dropped). `None` while the relay
    /// is disconnected — its directives stay pending until it reconnects.
    sender: Option<mpsc::UnboundedSender<SlotClose>>,
}

impl RelayReaps {
    /// Creates an empty reap outbox.
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribes `relay_id`'s control connection to its reap directives, creating
    /// a fresh channel (replacing any prior sender, so a reconnect owns the live
    /// receiver). The fresh receiver is primed with the relay's whole pending set,
    /// so a reconnecting relay re-syncs directives armed while it was gone. Returns
    /// the receiver the control task drains.
    pub fn subscribe(&self, relay_id: RelayId) -> mpsc::UnboundedReceiver<SlotClose> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut relays = self.relays.lock();
        let state = relays.entry(relay_id).or_default();
        for ((tenant, session), slots) in &state.pending {
            let _ = tx.send(SlotClose {
                tenant: tenant.clone(),
                session: *session,
                slots: slots.clone(),
            });
        }
        state.sender = Some(tx);
        rx
    }

    /// Records a reap directive for `relay_id` into its pending set — unioning the
    /// slots with any already pending for the same session — and nudges the relay's
    /// live control connection with the merged directive. A relay that is
    /// disconnected keeps the directive pending until its next subscribe; a send
    /// that fails means the connection just dropped, so its sender is cleared.
    pub fn send(&self, relay_id: RelayId, close: SlotClose) {
        let mut relays = self.relays.lock();
        let state = relays.entry(relay_id).or_default();
        let slots = state
            .pending
            .entry((close.tenant.clone(), close.session))
            .or_default();
        for slot in &close.slots {
            if !slots.contains(slot) {
                slots.push(*slot);
            }
        }
        let merged = SlotClose {
            tenant: close.tenant,
            session: close.session,
            slots: slots.clone(),
        };
        if let Some(tx) = &state.sender
            && tx.send(merged).is_err()
        {
            state.sender = None;
        }
    }

    /// Retires every pending directive for `session` across all relays — called
    /// when the session's lifecycle state is removed. A directive already delivered
    /// stays applied on the relay (a closed link does not reopen); retiring only
    /// stops replaying it on a future reconnect, keeping each relay's pending set
    /// bounded by its live sessions.
    pub fn retire(&self, tenant: &TenantId, session: SessionId) {
        let mut relays = self.relays.lock();
        for state in relays.values_mut() {
            state.pending.remove(&(tenant.clone(), session));
        }
    }

    /// Drops `relay_id`'s whole entry — pending directives and live sender alike.
    ///
    /// Reserved for a relay id that has been **permanently** retired (a ledger
    /// tombstone that refuses the id from ever enrolling again): only then is it
    /// certain nothing will ever subscribe under the id again, so nothing is lost
    /// by dropping its shell. Calling this for a relay that merely disconnected —
    /// and could legitimately reconnect and re-enroll under the same id — would
    /// discard reap directives it still needs replayed on that reconnect. Idempotent:
    /// forgetting an id with no entry (or already forgotten) is a no-op.
    pub fn forget(&self, relay_id: RelayId) {
        self.relays.lock().remove(&relay_id);
    }

    /// How many relay ids the outbox currently holds state for. Exists for
    /// regression coverage of [`forget`](Self::forget) — a coordinator with a
    /// long uptime and a steady stream of scale-to-zero churn depends on this
    /// count staying bounded by the fleet's live relays rather than growing with
    /// every relay id ever minted.
    pub fn relay_count(&self) -> usize {
        self.relays.lock().len()
    }
}

/// The coordinator's per-relay descriptor outbox.
#[derive(Clone, Default)]
pub struct RelayDescriptors {
    /// The control channel for each relay, created on first record or subscribe
    /// and kept thereafter (a relay's channel outlives any single connection, so
    /// a reconnect re-subscribes to the same current set).
    channels: Arc<Mutex<HashMap<RelayId, RelayChannel>>>,
}

impl RelayDescriptors {
    /// Creates an empty outbox for a coordinator with no sessions yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the descriptor `relay_id` should serve for one session, replacing
    /// any prior descriptor for the same `(relay, session)`. Pushes to a
    /// connected relay only when the set actually changed (an identical re-record
    /// is a no-op, so it wakes no connection).
    pub fn record(&self, relay_id: RelayId, descriptor: SessionDescriptor) {
        let mut channels = self.channels.lock();
        let channel = channels
            .entry(relay_id)
            .or_insert_with(|| watch::channel(Vec::new()).0);
        channel.send_if_modified(|set| upsert(set, descriptor));
    }

    /// Drops `relay_id`'s descriptor for one session (the session ended), pushing
    /// the shrunk set to a connected relay so it leaves that session. Idempotent:
    /// removing an absent session changes nothing and wakes no connection.
    pub fn remove(&self, relay_id: RelayId, tenant: &TenantId, session: SessionId) {
        let channels = self.channels.lock();
        if let Some(channel) = channels.get(&relay_id) {
            channel.send_if_modified(|set| {
                let before = set.len();
                set.retain(|d| !(d.tenant == *tenant && d.session == session));
                set.len() != before
            });
        }
    }

    /// Subscribes to `relay_id`'s descriptor set for a control connection,
    /// creating the channel if this is the relay's first contact. The receiver's
    /// initial value is the relay's current set, so a freshly connected relay is
    /// re-synced before it waits for changes.
    pub fn subscribe(&self, relay_id: RelayId) -> watch::Receiver<Vec<SessionDescriptor>> {
        self.channels
            .lock()
            .entry(relay_id)
            .or_insert_with(|| watch::channel(Vec::new()).0)
            .subscribe()
    }

    /// The current descriptor set `relay_id` should serve, in a stable order (by
    /// session, then tenant). Non-consuming; an unknown relay yields an empty set.
    pub fn current_for(&self, relay_id: RelayId) -> Vec<SessionDescriptor> {
        self.channels
            .lock()
            .get(&relay_id)
            .map(|channel| channel.borrow().clone())
            .unwrap_or_default()
    }

    /// The keys of the sessions currently assigned to `relay_id`, without
    /// cloning their token- and topology-heavy descriptors. Used by control-plane
    /// bookkeeping that needs to reconcile one relay's declarative assignment.
    pub fn current_keys_for(&self, relay_id: RelayId) -> Vec<DescriptorKey> {
        self.channels
            .lock()
            .get(&relay_id)
            .map(|channel| {
                channel
                    .borrow()
                    .iter()
                    .map(|descriptor| DescriptorKey {
                        tenant: descriptor.tenant.clone(),
                        session: descriptor.session,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Drops `relay_id`'s whole channel — closing any subscriber still attached.
    ///
    /// Reserved for a relay id that has been **permanently** retired (a ledger
    /// tombstone that refuses the id from ever enrolling again): only then is it
    /// certain no control connection will ever subscribe under the id again, so
    /// dropping the channel loses nothing a future reconnect would need. Calling
    /// this for a relay that merely disconnected — and could legitimately reconnect
    /// under the same id — would force its next subscribe to recreate the channel
    /// from an empty set instead of the descriptors it should still be serving.
    /// Idempotent: forgetting an id with no channel (or already forgotten) is a
    /// no-op.
    pub fn forget(&self, relay_id: RelayId) {
        self.channels.lock().remove(&relay_id);
    }

    /// How many relay ids the outbox currently holds a channel for. Exists for
    /// regression coverage of [`forget`](Self::forget) — a coordinator with a
    /// long uptime and a steady stream of scale-to-zero churn depends on this
    /// count staying bounded by the fleet's live relays rather than growing with
    /// every relay id ever minted.
    pub fn relay_count(&self) -> usize {
        self.channels.lock().len()
    }
}

/// Inserts or replaces `descriptor` in `set`, keeping the set ordered by session
/// then tenant. Returns whether the set actually changed — re-inserting an
/// identical descriptor is a no-op so it pushes nothing to a connected relay.
fn upsert(set: &mut Vec<SessionDescriptor>, descriptor: SessionDescriptor) -> bool {
    if let Some(slot) = set
        .iter_mut()
        .find(|d| d.tenant == descriptor.tenant && d.session == descriptor.session)
    {
        if *slot == descriptor {
            return false;
        }
        // Same key, so order is unchanged — replace in place.
        *slot = descriptor;
        return true;
    }
    set.push(descriptor);
    set.sort_by(|a, b| (a.session.0, a.tenant.as_ref()).cmp(&(b.session.0, b.tenant.as_ref())));
    true
}

#[cfg(test)]
mod tests;
