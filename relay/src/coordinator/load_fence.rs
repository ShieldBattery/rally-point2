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
//! # A probe names a connection, not a seat
//!
//! Everything above is a claim about one *stream*, so every probe is bound to the
//! link generation it went down: the session, the slot, and that connection's
//! lifecycle epoch. A client that reconnects takes the same slot back on a fresh
//! stream whose queue of owed reports the old stream's ack says nothing about, so
//! an ack that comes up on a different epoch is discarded exactly like one from a
//! different slot. Whoever fences compares the same triple on both sides of the
//! wait: a slot present before and after with the same epoch was the same link
//! throughout, and any other pairing is a membership change the fence cannot
//! vouch across.
//!
//! # Shape
//!
//! One map of outstanding probes keyed by probe id, behind a plain (non-async)
//! mutex: every critical section is a short, await-free insert or lookup, plus a
//! semaphore capping how many fences run at once ([`MAX_ACTIVE_LOAD_FENCES`]).
//! Clone the fence cheaply (state is behind one `Arc`) to share it between the
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
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

use crate::routing::SessionKey;

/// How many load-state fences this relay runs at once.
///
/// A fence occupies a task for up to its whole timeout while it waits on game
/// clients, so without a cap the only thing between a burst of reads and an
/// unbounded pile of waiting tasks is how fast the coordinator asks. A permit is
/// taken *before* a fence starts and held for its whole life, so what this bounds
/// is the probing in flight, not the answers already finished. Sized well above the
/// sessions one relay serves at once, so reaching it means reads are arriving
/// faster than clients answer them — at which point shedding is the honest
/// response: an unanswered question reads as "did not attest", exactly like a relay
/// that is slow or gone, and the caller's next read gets a fresh chance.
pub const MAX_ACTIVE_LOAD_FENCES: usize = 32;

/// The relay's load-state fence broker.
#[derive(Clone)]
pub struct LoadStateFence {
    inner: Arc<Inner>,
}

impl Default for LoadStateFence {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                next_probe_id: AtomicU64::new(0),
                pending: Mutex::new(HashMap::new()),
                active: Arc::new(Semaphore::new(MAX_ACTIVE_LOAD_FENCES)),
            }),
        }
    }
}

struct Inner {
    /// Mints probe ids, strictly increasing for the relay process's lifetime so
    /// an id is never reused and a late ack can never match a later probe.
    next_probe_id: AtomicU64,
    pending: Mutex<HashMap<u64, PendingProbe>>,
    /// One permit per fence allowed to run at once (see
    /// [`MAX_ACTIVE_LOAD_FENCES`]). Held for the fence's whole life, so a fence
    /// whose asker has already given up still occupies its permit until it
    /// actually finishes — which is the point: the cost being bounded is the
    /// waiting, and abandoned waiting costs the same as awaited waiting.
    active: Arc<Semaphore>,
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
    /// The lifecycle epoch of the link the probe went down. A probe asks about one
    /// client stream's position, and a reconnect opens a *new* stream with its own
    /// queue of owed reports, so an ack arriving on a different connection answers
    /// a different question and is discarded.
    connection_epoch: u64,
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

    /// Takes one of the [`MAX_ACTIVE_LOAD_FENCES`] permits, or `None` when they
    /// are all held. Hold the returned permit for the fence's whole life — it is
    /// what bounds the probing in flight — and shed the ask when it is `None`.
    pub fn try_start(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.inner.active).try_acquire_owned().ok()
    }

    /// Registers a probe for `slot` in `key` on link generation
    /// `connection_epoch`, returning the handle that carries its id and waits for
    /// its ack. The caller sends the frame itself; nothing is reserved on the
    /// slot's link here.
    pub fn probe(&self, key: &SessionKey, slot: SlotId, connection_epoch: u64) -> PendingAck {
        let probe_id = self.inner.next_probe_id.fetch_add(1, Ordering::Relaxed);
        let (ack_tx, ack_rx) = oneshot::channel();
        self.inner.pending.lock().insert(
            probe_id,
            PendingProbe {
                key: key.clone(),
                slot,
                connection_epoch,
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
    /// outstanding **and** that probe went down this exact link: the same
    /// session, the same slot, and the same connection epoch. Anything else — an
    /// id already acked, an id from an earlier fence, an id another slot's probe
    /// owns, an id acked on the connection that replaced the probed one — is
    /// discarded rather than honored: the fence's whole value is that each client
    /// stream answered for its own position, so neither another client nor a
    /// later connection of the same client may ack in its name. `key`, `slot` and
    /// `connection_epoch` are the values the relay authenticated on the link the
    /// ack arrived on, never anything the frame carried.
    pub fn resolve(
        &self,
        probe_id: u64,
        key: &SessionKey,
        slot: SlotId,
        connection_epoch: u64,
    ) -> bool {
        let mut pending = self.inner.pending.lock();
        let matches = pending.get(&probe_id).is_some_and(|probe| {
            probe.key == *key && probe.slot == slot && probe.connection_epoch == connection_epoch
        });
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

    /// A link generation to probe on. Any two distinct values would do — the
    /// epoch is an equality fence, not an ordering key.
    const EPOCH: u64 = 0xa1;
    const REPLACEMENT_EPOCH: u64 = 0xb2;

    #[tokio::test]
    async fn an_ack_from_the_probed_slot_releases_its_waiter() {
        let fence = LoadStateFence::new();
        let mut pending = fence.probe(&key(5), SlotId(2), EPOCH);
        assert!(fence.resolve(pending.probe_id(), &key(5), SlotId(2), EPOCH));
        assert!(pending.recv().await);
    }

    #[tokio::test]
    async fn an_ack_never_matches_another_slot_session_fence_or_connection() {
        let fence = LoadStateFence::new();
        let mut pending = fence.probe(&key(5), SlotId(2), EPOCH);
        let probe_id = pending.probe_id();

        // Another slot on the same session acking in slot 2's name.
        assert!(!fence.resolve(probe_id, &key(5), SlotId(3), EPOCH));
        // The right slot, the wrong session.
        assert!(!fence.resolve(probe_id, &key(6), SlotId(2), EPOCH));
        // The right slot of the right session, on the connection that replaced
        // the probed one: a different stream, holding whatever the game signalled
        // since, so it cannot answer for the stream that was asked.
        assert!(!fence.resolve(probe_id, &key(5), SlotId(2), REPLACEMENT_EPOCH));
        // An id nobody is waiting on.
        assert!(!fence.resolve(probe_id.wrapping_add(1), &key(5), SlotId(2), EPOCH));
        // None of that consumed the probe, and the real ack still lands.
        assert!(fence.resolve(probe_id, &key(5), SlotId(2), EPOCH));
        assert!(pending.recv().await);
        // A second ack for the same id is stale: the probe is consumed.
        assert!(!fence.resolve(probe_id, &key(5), SlotId(2), EPOCH));
    }

    #[tokio::test]
    async fn a_waiter_that_gives_up_retires_its_probe() {
        let fence = LoadStateFence::new();
        let pending = fence.probe(&key(5), SlotId(2), EPOCH);
        let probe_id = pending.probe_id();
        assert_eq!(fence.pending_count(), 1);

        drop(pending);
        assert_eq!(
            fence.pending_count(),
            0,
            "the map tracks running fences only"
        );
        assert!(
            !fence.resolve(probe_id, &key(5), SlotId(2), EPOCH),
            "an ack for an abandoned fence is discarded",
        );
    }

    #[tokio::test]
    async fn only_the_capped_number_of_fences_may_run_at_once() {
        // The bound is on fences *running*, so a permit is unavailable while its
        // fence is alive however long that fence waits, and is free again the
        // moment it finishes.
        let fence = LoadStateFence::new();
        let permits: Vec<_> = (0..MAX_ACTIVE_LOAD_FENCES)
            .map(|_| fence.try_start().expect("a fence under the cap starts"))
            .collect();
        assert!(
            fence.try_start().is_none(),
            "a fence over the cap is shed rather than queued",
        );

        drop(permits);
        assert!(
            fence.try_start().is_some(),
            "a finished fence frees its permit for the next ask",
        );
    }
}
