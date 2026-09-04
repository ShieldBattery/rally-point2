//! The load-state fence: proving that no slot this relay serves is about to
//! tell it something the snapshot it is building says never happened.
//!
//! # Why observing the relay is not enough
//!
//! A load-state snapshot answers "which of this session's slots have reported
//! their game loop running here". The relay learns that from a `GameStarted`
//! frame the client writes on its own reliable control stream — a channel that
//! runs entirely independently of the coordinator's question. So the relay can
//! honestly snapshot "slot 3 has not started" while slot 3's report is queued in
//! its client's driver, in flight on the wire, or parked waiting for the
//! driver's next stream. The coordinator would then vouch for a record that is
//! wrong about slot 3, and a tenant reading that absence as "this player never
//! loaded" would blame the wrong person.
//!
//! # The fence
//!
//! Before snapshotting, the relay sends each slot it is unsure about a probe
//! down that slot's own control stream and waits for the echoed
//! acknowledgement. The stream is ordered and the client writes any report it
//! owes *ahead* of the ack, so an ack that arrives proves nothing of that slot's
//! is still behind it: whatever the game had signalled before the probe was
//! handled is already on the relay's side of the wire. Everything after the ack
//! is genuinely after the question, which is exactly the boundary the
//! coordinator's completeness claim needs.
//!
//! A slot that does not ack in time is simply unfenced. So is a slot that
//! connected earlier and is disconnected now: there is no stream to probe, and
//! its client may be holding a report for the stream it opens next. A slot that
//! never connected here holds nothing to fence — no client ever had a stream to
//! this relay for it — so its absence needs no probe to be attestable.
//!
//! # Shape
//!
//! One map of outstanding probes keyed by probe id, behind a plain (non-async)
//! mutex: every critical section is a short, await-free insert or lookup. Clone
//! the fence cheaply (state is behind one `Arc`) to share it between the
//! coordinator connection that probes and the slot-link tasks that resolve.
//!
//! Nothing here is retried or replayed: a probe is meaningful only to the
//! snapshot still waiting on it, and that snapshot's own deadline outlives no
//! reconnect worth speaking of.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use rally_point_proto::ids::SlotId;
use tokio::sync::oneshot;

use crate::routing::SessionKey;

/// The relay's load-state fence broker.
#[derive(Clone, Default)]
pub struct LoadStateFence {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    /// Mints probe ids, strictly increasing for the relay process's lifetime so
    /// an id is never reused and a late ack can never match a later probe.
    next_probe_id: AtomicU64,
    pending: Mutex<HashMap<u64, PendingProbe>>,
}

/// One outstanding probe: who it was sent to, and where the ack goes.
struct PendingProbe {
    /// The session the probed slot belongs to. An ack from a slot serving a
    /// different session is discarded — a probe id is a handle to *one* slot's
    /// answer, and no client can see another's id except by guessing.
    key: SessionKey,
    /// The probed slot, as the relay authenticated it on the link the probe went
    /// down.
    slot: SlotId,
    ack: oneshot::Sender<()>,
}

/// A probe in flight, held by the snapshot waiting on its ack.
///
/// Dropping it retires the probe: an ack arriving afterwards finds no entry and
/// is discarded, exactly as a stale one is. That is what keeps the pending map
/// bounded by the fences running right now rather than by every probe ever sent,
/// however the waiter leaves — acked, timed out, or abandoned with the read that
/// asked.
pub struct PendingAck {
    probe_id: u64,
    inner: Arc<Inner>,
    ack: oneshot::Receiver<()>,
}

impl PendingAck {
    /// The probe's id, to write into the frame that goes down the slot's stream.
    pub fn probe_id(&self) -> u64 {
        self.probe_id
    }

    /// Waits for this slot's acknowledgement. `false` when it can no longer come
    /// — the slot's link ended, or the fence dropped the probe — which the
    /// caller reads as this slot being unfenced. Bound the wait with a deadline:
    /// nothing here times out on its own.
    pub async fn recv(&mut self) -> bool {
        (&mut self.ack).await.is_ok()
    }
}

impl Drop for PendingAck {
    fn drop(&mut self) {
        self.inner.pending.lock().remove(&self.probe_id);
    }
}

impl LoadStateFence {
    /// Creates a fence with nothing outstanding.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a probe for `slot` in `key`, returning the handle that carries
    /// its id and waits for its ack. The caller sends the frame itself; nothing
    /// is reserved on the slot's link here.
    pub fn probe(&self, key: &SessionKey, slot: SlotId) -> PendingAck {
        let probe_id = self.inner.next_probe_id.fetch_add(1, Ordering::Relaxed);
        let (ack_tx, ack_rx) = oneshot::channel();
        self.inner.pending.lock().insert(
            probe_id,
            PendingProbe {
                key: key.clone(),
                slot,
                ack: ack_tx,
            },
        );
        PendingAck {
            probe_id,
            inner: self.inner.clone(),
            ack: ack_rx,
        }
    }

    /// Delivers a slot's acknowledgement to whoever probed it, returning whether
    /// it matched an outstanding probe.
    ///
    /// An ack is accepted only when its id names a probe that is still
    /// outstanding **and** that probe went to this exact slot of this exact
    /// session. Anything else — an id already acked, an id from an earlier
    /// fence, an id another slot's probe owns — is discarded rather than
    /// honored: the fence's whole value is that each slot answered for itself,
    /// so one client must never be able to ack in another's name. `key` and
    /// `slot` are the values the relay authenticated on the link the ack arrived
    /// on, never anything the frame carried.
    pub fn resolve(&self, probe_id: u64, key: &SessionKey, slot: SlotId) -> bool {
        let mut pending = self.inner.pending.lock();
        let matches = pending
            .get(&probe_id)
            .is_some_and(|probe| probe.key == *key && probe.slot == slot);
        if !matches {
            return false;
        }
        let probe = pending
            .remove(&probe_id)
            .expect("the entry was just matched under this lock");
        drop(pending);
        // A dropped receiver means the fence already gave up on this slot; the
        // ack is simply not needed, which is not a mismatch to report.
        let _ = probe.ack.send(());
        true
    }

    /// How many probes are outstanding. Exists so the pending map's bound —
    /// running fences, not fences ever run — is actually asserted rather than
    /// assumed.
    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> usize {
        self.inner.pending.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use rally_point_proto::control::TenantId;
    use rally_point_proto::ids::SessionId;

    use super::*;

    fn key(session: u64) -> SessionKey {
        SessionKey {
            tenant: TenantId("sb-test".to_owned()),
            session: SessionId(session),
        }
    }

    #[tokio::test]
    async fn an_ack_from_the_probed_slot_releases_its_waiter() {
        let fence = LoadStateFence::new();
        let mut pending = fence.probe(&key(5), SlotId(2));
        assert!(fence.resolve(pending.probe_id(), &key(5), SlotId(2)));
        assert!(pending.recv().await);
    }

    #[tokio::test]
    async fn an_ack_never_matches_another_slot_session_or_fence() {
        let fence = LoadStateFence::new();
        let mut pending = fence.probe(&key(5), SlotId(2));
        let probe_id = pending.probe_id();

        // Another slot on the same session acking in slot 2's name.
        assert!(!fence.resolve(probe_id, &key(5), SlotId(3)));
        // The right slot, the wrong session.
        assert!(!fence.resolve(probe_id, &key(6), SlotId(2)));
        // An id nobody is waiting on.
        assert!(!fence.resolve(probe_id.wrapping_add(1), &key(5), SlotId(2)));
        // None of that consumed the probe, and the real ack still lands.
        assert!(fence.resolve(probe_id, &key(5), SlotId(2)));
        assert!(pending.recv().await);
        // A second ack for the same id is stale: the probe is consumed.
        assert!(!fence.resolve(probe_id, &key(5), SlotId(2)));
    }

    #[tokio::test]
    async fn a_waiter_that_gives_up_retires_its_probe() {
        let fence = LoadStateFence::new();
        let pending = fence.probe(&key(5), SlotId(2));
        let probe_id = pending.probe_id();
        assert_eq!(fence.pending_count(), 1);

        drop(pending);
        assert_eq!(
            fence.pending_count(),
            0,
            "the map tracks running fences only"
        );
        assert!(
            !fence.resolve(probe_id, &key(5), SlotId(2)),
            "an ack for an abandoned fence is discarded",
        );
    }
}
