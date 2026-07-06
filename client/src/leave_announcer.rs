//! Announcing this client's own clean departure to the relay.
//!
//! When the game decides to leave (F10 quit, game over) it signals the driver,
//! but the driver must not announce that immediately: the relay has to see every
//! turn this client already produced before it decides the leave. So the
//! announcement waits until the outbound queue and the unacked window have both
//! drained — every produced turn sent, every sent turn acked — or a short safety
//! timeout passes, then a `LeaveIntent` control frame goes out and the relay's
//! subsequent close of the link counts as a clean shutdown rather than a failure.
//!
//! [`LeaveAnnouncer`] owns that little state machine. Three states make the
//! impossible combinations unrepresentable:
//!
//! - `Idle` — the game has not signaled departure. Nothing to announce.
//! - `Pending { deadline }` — the game signaled; the announcement is held until
//!   the drain condition is met, but no later than `deadline` (the safety
//!   timeout).
//! - `Sent` — the frame has gone out. From here on, the relay closing the link is
//!   the expected confirmation it processed the leave, not a fault.
//!
//! When the game marked a result report expected, the announcement is
//! additionally held until that report has been sent, so the result frame
//! precedes the intent on the single ordered control stream. That hold is still
//! bounded by the safety timeout — a missing or late result is harmless.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rally_point_proto::messages::Payload;
use rally_point_transport::Link;
use rally_point_transport::control::{ControlSendError, send_control_leave_intent};
use rally_point_transport::quinn;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// The leave-intent state machine. `Idle` before the game signals departure,
/// `Pending` while the announcement is held for the drain (or result) condition,
/// `Sent` once the frame is on the wire.
enum LeaveState {
    /// The game has not signaled its departure. No announcement is owed.
    Idle,
    /// The game signaled departure; the announcement is held until the outbound
    /// queue and unacked window drain (and any expected result has been sent),
    /// but no later than `deadline` — the safety-timeout instant past which the
    /// frame goes out regardless of drain state.
    Pending { deadline: Instant },
    /// The `LeaveIntent` frame has been written. The relay closing the link now
    /// confirms it processed the leave rather than signalling a failure.
    Sent,
}

/// Owns the client's leave-intent announcement: when to write the `LeaveIntent`
/// frame, and how to read the link close that follows it.
///
/// Drive it from the driver loop: [`arm`](Self::arm) on the game's departure
/// signal, [`maybe_send`](Self::maybe_send) after anything that might have
/// changed drain state, [`force_send`](Self::force_send) when the safety timeout
/// fires, and [`absorb_link_close`](Self::absorb_link_close) to classify a
/// send/link failure as the expected post-announce close versus a real fault.
pub(crate) struct LeaveAnnouncer {
    state: LeaveState,
    /// Whether the game will produce an end-of-game result report. When set, a
    /// pending announcement is held until the result frame has been written, so
    /// it precedes the intent on the one ordered control stream. Shared with the
    /// game thread, which sets it synchronously before it can ever signal a
    /// leave.
    result_expected: Arc<AtomicBool>,
    /// Whether that result report has been written to the control stream yet.
    /// Latched once, releasing the intent hold.
    result_sent: bool,
}

impl LeaveAnnouncer {
    /// A fresh announcer in `Idle`, sharing the game's `result_expected` flag.
    pub(crate) fn new(result_expected: Arc<AtomicBool>) -> Self {
        Self {
            state: LeaveState::Idle,
            result_expected,
            result_sent: false,
        }
    }

    /// Records the game's departure signal, arming the announcement with a safety
    /// timeout `timeout` from now. After this, [`maybe_send`](Self::maybe_send)
    /// can write the frame once the drain condition is met, and the timeout
    /// bounds the wait. A no-op once the frame has already been sent (the game
    /// signals its departure at most once, so this is only defensive).
    pub(crate) fn arm(&mut self, timeout: Duration) {
        if !matches!(self.state, LeaveState::Sent) {
            self.state = LeaveState::Pending {
                deadline: Instant::now() + timeout,
            };
        }
    }

    /// The safety-timeout instant while an announcement is pending, or `None`
    /// otherwise. The driver arms its `sleep_until` select branch on this — only
    /// a `Pending` announcer has a live deadline, so the branch stays dormant
    /// before the game signals and after the frame is sent.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        match self.state {
            LeaveState::Pending { deadline } => Some(deadline),
            LeaveState::Idle | LeaveState::Sent => None,
        }
    }

    /// Whether the `LeaveIntent` frame has been written. Once true, the relay
    /// closing the link is the expected confirmation it processed the leave, so
    /// the driver returns `Ok` rather than a failure — see
    /// [`absorb_link_close`](Self::absorb_link_close).
    pub(crate) fn sent(&self) -> bool {
        matches!(self.state, LeaveState::Sent)
    }

    /// Latches that the game's result report has been written, releasing the hold
    /// that keeps a pending announcement behind the result on the wire.
    pub(crate) fn note_result_sent(&mut self) {
        self.result_sent = true;
    }

    /// Whether the game's result report has already been written. The driver
    /// reads this to drop a second result payload rather than send it twice.
    pub(crate) fn result_sent(&self) -> bool {
        self.result_sent
    }

    /// Writes the `LeaveIntent` frame if the game has signaled its departure
    /// *and* both the outbound queue and unacked window have drained (and any
    /// expected result has been sent) — every produced turn sent, every sent turn
    /// acked, so the relay's view of our last frame is final. A no-op before the
    /// game has signaled or once the frame has already gone out, so the driver
    /// can call it unconditionally after anything that might have changed drain
    /// state. Transitions to `Sent` on the write.
    pub(crate) async fn maybe_send(
        &mut self,
        control_send: &mut quinn::SendStream,
        outbound: &mpsc::Receiver<Payload>,
        link: &Link,
    ) -> Result<(), ControlSendError> {
        if self.ready_to_send(outbound.is_empty(), link.payloads_in_flight()) {
            send_control_leave_intent(control_send).await?;
            self.state = LeaveState::Sent;
        }
        Ok(())
    }

    /// Writes the `LeaveIntent` frame regardless of drain state, for the
    /// safety-timeout path: the outbound queue or unacked window never drained,
    /// but holding the announcement longer is pointless — if acks aren't coming
    /// the link is effectively dead, and sending anyway is harmless (the relay
    /// stops forwarding this slot's turns the moment it sees the intent).
    /// Transitions to `Sent`.
    pub(crate) async fn force_send(
        &mut self,
        control_send: &mut quinn::SendStream,
    ) -> Result<(), ControlSendError> {
        send_control_leave_intent(control_send).await?;
        self.state = LeaveState::Sent;
        Ok(())
    }

    /// Classifies a send/link failure once the departure state is known: after
    /// the intent is announced, the relay closing the link (or the control
    /// stream) out from under an in-flight send is the expected confirmation it
    /// processed the leave, so the error becomes a clean stop (`Ok`). Before the
    /// announce, the error is a genuine link failure and passes through
    /// unchanged.
    pub(crate) fn absorb_link_close<E>(&self, result: Result<(), E>) -> Result<(), E> {
        match result {
            Err(_) if self.sent() => Ok(()),
            other => other,
        }
    }

    /// The gate predicate, split out from the IO so it can be exercised directly:
    /// a pending announcement fires only when no expected result is still owed,
    /// the outbound queue is empty, and nothing is in flight.
    fn ready_to_send(&self, outbound_empty: bool, in_flight: usize) -> bool {
        matches!(self.state, LeaveState::Pending { .. })
            && !self.awaiting_result()
            && outbound_empty
            && in_flight == 0
    }

    /// Whether a result report is expected but not yet sent — the extra hold that
    /// keeps a pending announcement behind the result frame on the wire.
    fn awaiting_result(&self) -> bool {
        self.result_expected.load(Ordering::Relaxed) && !self.result_sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn announcer() -> LeaveAnnouncer {
        LeaveAnnouncer::new(Arc::new(AtomicBool::new(false)))
    }

    #[test]
    fn idle_never_sends_and_has_no_deadline() {
        let ann = announcer();
        assert!(!ann.sent());
        assert!(ann.deadline().is_none());
        // Even a fully-drained link doesn't fire before the game signals.
        assert!(!ann.ready_to_send(true, 0));
    }

    #[test]
    fn armed_but_undrained_holds() {
        let mut ann = announcer();
        ann.arm(Duration::from_secs(2));
        assert!(
            ann.deadline().is_some(),
            "a pending announcer has a deadline"
        );
        // Outbound not empty: hold.
        assert!(!ann.ready_to_send(false, 0));
        // In flight: hold.
        assert!(!ann.ready_to_send(true, 3));
    }

    #[test]
    fn armed_and_drained_is_ready() {
        let mut ann = announcer();
        ann.arm(Duration::from_secs(2));
        assert!(
            ann.ready_to_send(true, 0),
            "a signaled departure with a drained link is ready to announce"
        );
    }

    #[test]
    fn an_expected_result_holds_the_announcement_until_it_is_sent() {
        let flag = Arc::new(AtomicBool::new(true));
        let mut ann = LeaveAnnouncer::new(Arc::clone(&flag));
        ann.arm(Duration::from_secs(2));
        // Drained, but the expected result hasn't gone out: still held.
        assert!(
            !ann.ready_to_send(true, 0),
            "the intent must wait behind an expected-but-unsent result"
        );
        ann.note_result_sent();
        assert!(
            ann.ready_to_send(true, 0),
            "once the result is sent the intent may go out"
        );
    }

    #[test]
    fn a_result_not_expected_does_not_hold() {
        // The flag is false, so even without a result the drain condition alone
        // releases the announcement.
        let mut ann = announcer();
        ann.arm(Duration::from_secs(2));
        assert!(ann.ready_to_send(true, 0));
    }

    #[test]
    fn absorb_link_close_swallows_only_after_the_intent_is_sent() {
        let mut ann = announcer();
        ann.arm(Duration::from_secs(2));
        // Before the intent is sent, an error is a genuine failure.
        assert!(ann.absorb_link_close::<()>(Err(())).is_err());

        // Simulate the frame going out via the gate transition path.
        // (force_send would do this over a real stream; drive the state directly
        // for a pure unit test.)
        ann.state = LeaveState::Sent;
        assert!(ann.sent());
        assert!(
            ann.absorb_link_close::<()>(Err(())).is_ok(),
            "a post-announce link close is a clean stop"
        );
        // Ok always stays Ok.
        assert!(ann.absorb_link_close::<()>(Ok(())).is_ok());
    }

    #[test]
    fn deadline_clears_once_sent() {
        let mut ann = announcer();
        ann.arm(Duration::from_secs(2));
        assert!(ann.deadline().is_some());
        ann.state = LeaveState::Sent;
        assert!(
            ann.deadline().is_none(),
            "a sent announcer arms no more safety timeouts"
        );
        // And a ready check no longer fires (not Pending).
        assert!(!ann.ready_to_send(true, 0));
    }
}
