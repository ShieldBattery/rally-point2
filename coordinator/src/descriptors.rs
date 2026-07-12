//! The per-relay descriptor outbox: the coordinator's side of the persistent
//! control connection that delivers session descriptors to each relay.
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

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use rally_point_proto::control::{SessionDescriptor, TenantId};
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
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use rally_point_proto::control::{BufferBounds, RelayPeer};

    fn descriptor(tenant: &str, session: u64, peers: &[u64]) -> SessionDescriptor {
        SessionDescriptor {
            tenant: TenantId(tenant.to_owned()),
            session: SessionId(session),
            peers: peers
                .iter()
                .map(|&id| RelayPeer {
                    relay_id: RelayId(id),
                    relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900 + id as u16)),
                    cert_der: vec![id as u8; 4],
                    relay_addrs: vec![],
                })
                .collect(),
            bounds: BufferBounds::new(1, 6).unwrap(),
            authority_order: vec![],
            external_id: None,
            slot_refs: vec![],
            observer_slots: vec![],
            expected_slots: vec![],
            homed_slots: vec![],
            resumed: false,
            departed_slots: vec![],
            latency_estimate_ms: None,
        }
    }

    #[test]
    fn records_and_reads_back_per_relay() {
        let outbox = RelayDescriptors::new();
        outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
        outbox.record(RelayId(2), descriptor("sb-test", 1, &[1]));

        let for_1 = outbox.current_for(RelayId(1));
        assert_eq!(for_1.len(), 1);
        assert_eq!(for_1[0].peers[0].relay_id, RelayId(2));

        let for_2 = outbox.current_for(RelayId(2));
        assert_eq!(for_2.len(), 1);
        assert_eq!(for_2[0].peers[0].relay_id, RelayId(1));
    }

    #[test]
    fn unknown_relay_has_no_descriptors() {
        let outbox = RelayDescriptors::new();
        assert!(outbox.current_for(RelayId(99)).is_empty());
    }

    #[test]
    fn recording_same_session_replaces_rather_than_accumulates() {
        let outbox = RelayDescriptors::new();
        outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
        // The session's topology changes: peer 3 replaces peer 2.
        outbox.record(RelayId(1), descriptor("sb-test", 1, &[3]));

        let set = outbox.current_for(RelayId(1));
        assert_eq!(set.len(), 1, "same (relay, session) overwrites");
        assert_eq!(set[0].peers[0].relay_id, RelayId(3));
    }

    #[test]
    fn distinct_sessions_for_one_relay_coexist() {
        let outbox = RelayDescriptors::new();
        outbox.record(RelayId(1), descriptor("sb-test", 2, &[2]));
        outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));

        let set = outbox.current_for(RelayId(1));
        assert_eq!(set.len(), 2);
        // Stable order: sorted by session id.
        assert_eq!(set[0].session, SessionId(1));
        assert_eq!(set[1].session, SessionId(2));
    }

    #[test]
    fn same_session_id_across_tenants_does_not_collide() {
        let outbox = RelayDescriptors::new();
        outbox.record(RelayId(1), descriptor("tenant-a", 1, &[2]));
        outbox.record(RelayId(1), descriptor("tenant-b", 1, &[2]));

        let set = outbox.current_for(RelayId(1));
        assert_eq!(
            set.len(),
            2,
            "the (tenant, session) key keeps them distinct"
        );
    }

    #[test]
    fn remove_drops_one_session_and_leaves_the_rest() {
        let outbox = RelayDescriptors::new();
        outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
        outbox.record(RelayId(1), descriptor("sb-test", 2, &[2]));

        outbox.remove(RelayId(1), &TenantId("sb-test".to_owned()), SessionId(1));
        let set = outbox.current_for(RelayId(1));
        assert_eq!(set.len(), 1);
        assert_eq!(set[0].session, SessionId(2));

        // Removing the last session leaves the set empty.
        outbox.remove(RelayId(1), &TenantId("sb-test".to_owned()), SessionId(2));
        assert!(outbox.current_for(RelayId(1)).is_empty());
    }

    #[test]
    fn remove_on_unknown_relay_or_session_is_a_no_op() {
        let outbox = RelayDescriptors::new();
        outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
        outbox.remove(RelayId(9), &TenantId("sb-test".to_owned()), SessionId(1));
        outbox.remove(RelayId(1), &TenantId("sb-test".to_owned()), SessionId(9));
        assert_eq!(outbox.current_for(RelayId(1)).len(), 1);
    }

    #[test]
    fn a_subscriber_is_woken_on_record_and_sees_the_current_set() {
        let outbox = RelayDescriptors::new();
        let mut rx = outbox.subscribe(RelayId(1));
        // Initial value is the (empty) current set.
        assert!(rx.borrow_and_update().is_empty());

        // A record marks the channel changed, so the connection task wakes.
        outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
        assert!(rx.has_changed().unwrap());
        let set = rx.borrow_and_update().clone();
        assert_eq!(set.len(), 1);
        assert_eq!(set[0].session, SessionId(1));
    }

    #[test]
    fn an_identical_re_record_does_not_wake_the_subscriber() {
        let outbox = RelayDescriptors::new();
        outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
        let mut rx = outbox.subscribe(RelayId(1));
        rx.borrow_and_update(); // mark current as seen

        // Re-recording the identical descriptor changes nothing — no wake.
        outbox.record(RelayId(1), descriptor("sb-test", 1, &[2]));
        assert!(
            !rx.has_changed().unwrap(),
            "an unchanged set must not wake the relay"
        );
    }

    #[test]
    fn a_record_after_subscribe_for_a_new_relay_still_wakes() {
        // Subscribing creates the channel; a later record on that relay wakes it.
        let outbox = RelayDescriptors::new();
        let mut rx = outbox.subscribe(RelayId(7));
        assert!(rx.borrow_and_update().is_empty());
        outbox.record(RelayId(7), descriptor("sb-test", 3, &[8]));
        assert!(rx.has_changed().unwrap());
    }

    fn slot_close(tenant: &str, session: u64, slots: &[u8]) -> SlotClose {
        SlotClose {
            tenant: TenantId(tenant.to_owned()),
            session: SessionId(session),
            slots: slots.iter().map(|&s| SlotId(s)).collect(),
        }
    }

    #[test]
    fn a_reap_armed_while_disconnected_is_delivered_on_the_next_subscribe() {
        // The core fix: a directive sent while the relay has no live control
        // connection is not lost — it stays pending and rides the next subscribe.
        let reaps = RelayReaps::new();
        reaps.send(RelayId(1), slot_close("sb-test", 1, &[3]));

        let mut rx = reaps.subscribe(RelayId(1));
        let close = rx
            .try_recv()
            .expect("the pending directive re-syncs on connect");
        assert_eq!(close.session, SessionId(1));
        assert_eq!(close.slots, vec![SlotId(3)]);
    }

    #[test]
    fn a_reap_sent_while_connected_is_delivered_and_also_replayed_on_resubscribe() {
        // A connected relay gets the directive immediately; because re-delivery is
        // idempotent, a reconnect (fresh subscribe) is re-synced with it too, until
        // the session retires.
        let reaps = RelayReaps::new();
        let mut rx = reaps.subscribe(RelayId(1));
        reaps.send(RelayId(1), slot_close("sb-test", 1, &[2]));
        let live = rx
            .try_recv()
            .expect("a connected relay is nudged immediately");
        assert_eq!(live.slots, vec![SlotId(2)]);

        // A reconnect re-subscribes and is primed with the still-pending directive.
        let mut rx2 = reaps.subscribe(RelayId(1));
        let replayed = rx2
            .try_recv()
            .expect("the pending directive replays on reconnect");
        assert_eq!(replayed.session, SessionId(1));
        assert_eq!(replayed.slots, vec![SlotId(2)]);
        // The replaced subscription's channel is closed.
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn retiring_a_session_drops_its_pending_directives() {
        let reaps = RelayReaps::new();
        reaps.send(RelayId(1), slot_close("sb-test", 1, &[2]));
        reaps.send(RelayId(1), slot_close("sb-test", 2, &[4]));

        // Retire session 1: only session 2 should replay on a fresh subscribe.
        reaps.retire(&TenantId("sb-test".to_owned()), SessionId(1));
        let mut rx = reaps.subscribe(RelayId(1));
        let mut got: Vec<SlotClose> = Vec::new();
        while let Ok(close) = rx.try_recv() {
            got.push(close);
        }
        assert_eq!(got.len(), 1, "the retired session no longer replays");
        assert_eq!(got[0].session, SessionId(2));
        assert_eq!(got[0].slots, vec![SlotId(4)]);
    }

    #[test]
    fn retiring_a_session_leaves_another_relays_pending_for_it_only_by_key() {
        // Retire fans across every relay: a session retired removes its pending
        // entry from all relays that held one, not just one.
        let reaps = RelayReaps::new();
        reaps.send(RelayId(1), slot_close("sb-test", 1, &[0]));
        reaps.send(RelayId(2), slot_close("sb-test", 1, &[0]));
        reaps.send(RelayId(2), slot_close("sb-test", 3, &[1]));

        reaps.retire(&TenantId("sb-test".to_owned()), SessionId(1));

        assert!(
            reaps.subscribe(RelayId(1)).try_recv().is_err(),
            "relay 1's only (retired) directive is gone",
        );
        let mut rx2 = reaps.subscribe(RelayId(2));
        let close = rx2.try_recv().expect("relay 2 still has session 3 pending");
        assert_eq!(close.session, SessionId(3));
        assert!(
            rx2.try_recv().is_err(),
            "session 1 was retired for relay 2 too"
        );
    }

    #[test]
    fn repeats_for_one_session_union_their_slots() {
        // Two directives for the same session merge into one pending entry whose
        // slots are the union — repeats don't accumulate separate entries.
        let reaps = RelayReaps::new();
        reaps.send(RelayId(1), slot_close("sb-test", 1, &[2]));
        reaps.send(RelayId(1), slot_close("sb-test", 1, &[5, 2]));

        let mut rx = reaps.subscribe(RelayId(1));
        let close = rx.try_recv().expect("the single merged directive replays");
        assert_eq!(close.session, SessionId(1));
        assert_eq!(
            close.slots,
            vec![SlotId(2), SlotId(5)],
            "slots union, the duplicate is not re-added",
        );
        assert!(
            rx.try_recv().is_err(),
            "one entry per session, not one per send"
        );
    }

    #[test]
    fn a_disconnected_sender_is_cleared_so_a_send_does_not_wedge() {
        // Dropping the receiver (the connection ended) makes the next send's nudge
        // fail; the stale sender is cleared and the directive stays pending for the
        // next subscribe rather than being silently swallowed by a dead channel.
        let reaps = RelayReaps::new();
        let rx = reaps.subscribe(RelayId(1));
        drop(rx); // the control connection ended without a re-subscribe

        reaps.send(RelayId(1), slot_close("sb-test", 1, &[7]));
        let mut rx2 = reaps.subscribe(RelayId(1));
        let close = rx2
            .try_recv()
            .expect("the directive survived the dead connection and replays");
        assert_eq!(close.slots, vec![SlotId(7)]);
    }
}
