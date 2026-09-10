//! One slot's forward queue: the sink fan-out offers payloads to, the receiver
//! its link task drains, and the resident-byte accounting the two share. Also
//! holds the game-result ingress predicate, the other place a client-supplied
//! payload is measured before it is allowed any further in.

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::consensus::MAX_GAME_RESULT_PAYLOAD_LEN;

/// The channel sink delivering payloads to one slot's link task.
type ForwardTx = mpsc::Sender<Payload>;

/// The bytes a queued payload counts against a slot's resident forward budget.
/// Only the command stream varies in size; the envelope's fixed fields are
/// negligible and constant, so — like the per-turn oversize cap — the measure is
/// the command length. The enqueue reservation and the drain release share this
/// one definition so they can never disagree on a payload's cost.
fn forward_bytes(payload: &Payload) -> usize {
    payload.commands.len()
}

/// The outcome of offering a payload to a slot's [`ForwardSink`].
pub(super) enum ForwardOutcome {
    /// Enqueued; its bytes are counted resident until the link task drains it.
    Delivered,
    /// The slot's queue is at the payload-count bound ([`FORWARD_CAPACITY`]).
    QueueFull,
    /// Accepting the payload would push the slot's resident forward bytes over
    /// [`FORWARD_BYTE_BUDGET`]; the payload was not enqueued.
    OverBudget,
    /// The slot's link task already exited and dropped its receiver.
    Gone,
}

/// One slot's forward channel paired with a live count of the payload bytes
/// resident in it. The channel bounds how many payloads may queue
/// ([`FORWARD_CAPACITY`]); the count bounds their aggregate size
/// ([`FORWARD_BYTE_BUDGET`]), because one oversize turn costs far more than a
/// normal one and a queue full of them pins far more memory than the count bound
/// alone implies.
///
/// Cloneable and shared: [`fan_out`] holds a producer clone per send, the link
/// task's [`SlotInbox`] holds the matching [`ForwardRx`] over the same counter,
/// and every producer's reservation and the consumer's release act on that one
/// shared count. The queue is many-producer (a turn from any local sibling slot
/// and a turn arriving over any mesh link both fan out to it), so the count is an
/// atomic and the reservation is taken before the payload is enqueued.
#[derive(Clone)]
pub(super) struct ForwardSink {
    pub(super) tx: ForwardTx,
    pub(super) resident_bytes: Arc<AtomicUsize>,
}

impl ForwardSink {
    /// Offers `payload` to the slot without blocking, reporting whether it landed
    /// or the slot is too far behind to take it (its count bound or its byte
    /// budget).
    ///
    /// The byte reservation is taken *before* the payload is enqueued, so it is
    /// visible to the draining [`ForwardRx`] before the payload is: the drain's
    /// matching release can then never observe an un-reserved payload and underflow
    /// the count, which keeps the count sound even under the many producers that
    /// concurrently fan out to one slot. A reservation that would breach the budget,
    /// or a send that finds the queue full or the receiver gone, is backed out so
    /// only genuinely resident bytes stay counted.
    pub(super) fn offer(&self, payload: &Payload) -> ForwardOutcome {
        let bytes = forward_bytes(payload);
        let resident = self.resident_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if resident > FORWARD_BYTE_BUDGET {
            self.resident_bytes.fetch_sub(bytes, Ordering::Relaxed);
            return ForwardOutcome::OverBudget;
        }
        match self.tx.try_send(payload.clone()) {
            Ok(()) => ForwardOutcome::Delivered,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.resident_bytes.fetch_sub(bytes, Ordering::Relaxed);
                ForwardOutcome::QueueFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.resident_bytes.fetch_sub(bytes, Ordering::Relaxed);
                ForwardOutcome::Gone
            }
        }
    }
}

/// The receiving half of a slot's forward channel, paired with the same resident-
/// byte count [`ForwardSink`] reserves against. Draining a payload releases its
/// bytes from the count, so the count tracks only what is still buffered.
pub(super) struct ForwardRx {
    pub(super) rx: mpsc::Receiver<Payload>,
    pub(super) resident_bytes: Arc<AtomicUsize>,
}

impl ForwardRx {
    /// Waits for the next forwarded payload, releasing its reserved bytes from the
    /// resident count as it hands it over. `None` once every sender is dropped.
    ///
    /// Cancel-safe for `tokio::select!`: the only await is the inner `recv`, itself
    /// cancel-safe, and the release runs synchronously once a payload is in hand, so
    /// a cancelled poll neither takes a payload nor releases bytes.
    pub(super) async fn recv(&mut self) -> Option<Payload> {
        let payload = self.rx.recv().await?;
        self.resident_bytes
            .fetch_sub(forward_bytes(&payload), Ordering::Relaxed);
        Some(payload)
    }

    /// Non-blockingly pulls the next forwarded payload, releasing its reserved
    /// bytes as [`recv`](Self::recv) does. `None` when the queue is empty.
    #[cfg(test)]
    pub(super) fn try_recv(&mut self) -> Option<Payload> {
        let payload = self.rx.try_recv().ok()?;
        self.resident_bytes
            .fetch_sub(forward_bytes(&payload), Ordering::Relaxed);
        Some(payload)
    }
}

/// Whether a client's `GameResult` control frame should be forwarded to
/// `consensus::record_result`, or dropped at ingress before it ever reaches the
/// decision-maker. A zero-length payload is the wire sentinel a `SlotDeparted`
/// uses to mean "no result reported" (see `wire.proto`), so recording one as a
/// genuine report would make a real empty result indistinguishable from no
/// result at all once the slot departs; an over-cap payload is simply an
/// ill-formed report. Pulled out as its own predicate — returning the reason
/// for a caller to log — so the ingress rule is unit-testable without standing
/// up the control-stream serve loop.
pub(super) fn game_result_admissible(payload: &[u8]) -> Result<(), &'static str> {
    if payload.is_empty() {
        Err("empty")
    } else if payload.len() > MAX_GAME_RESULT_PAYLOAD_LEN {
        Err("oversize")
    } else {
        Ok(())
    }
}
