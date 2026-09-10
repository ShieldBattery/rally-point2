//! Waiting without going blind: the non-blocking driver → game push, the
//! backoff and re-home waits that keep servicing the game seam while the link
//! is down, and the jittered backoff schedule they wait on.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};

use super::state::{
    GameSeam, LoopState, OUTAGE_OUTBOUND_BUFFER_CAP, RECONNECT_BACKOFF_CAP,
    RECONNECT_BACKOFF_INITIAL,
};
use super::*;

/// How a non-blocking driver → game push resolved. Every driver → game delivery
/// besides the ordered turn stream goes through [`push_to_game`]: the driver's
/// one loop also carries turns and acks, so it must never park on an embedder
/// channel — a retained-but-undrained receiver would stall the whole session
/// with it. What a `Full` buffer means is the caller's policy: a
/// correctness-critical delivery (a synced leave, a lobby command, the
/// session-start directive) surfaces [`DriverError::GameStalled`], exactly as
/// the turn path does, while a best-effort one (chat, a connectivity display
/// change) is simply dropped.
pub(super) enum GamePush {
    /// The value is in the channel's buffer.
    Sent,
    /// The channel's buffer is full — the game has stopped draining it (the
    /// depths are sized generously past each channel's real traffic).
    Full,
    /// The game dropped its receiver: a clean stop.
    Closed,
}

/// Offers `value` to a driver → game channel without ever awaiting.
pub(super) fn push_to_game<T>(tx: &mpsc::Sender<T>, value: T) -> GamePush {
    match tx.try_send(value) {
        Ok(()) => GamePush::Sent,
        Err(mpsc::error::TrySendError::Full(_)) => GamePush::Full,
        Err(mpsc::error::TrySendError::Closed(_)) => GamePush::Closed,
    }
}

/// The outcome of a backoff wait between reconnect attempts.
pub(super) enum WaitOutcome {
    /// The backoff delay elapsed; time to (re)dial.
    Elapsed,
    /// The game tore down its seam; abandon reconnection.
    GameGone,
    /// The outage buffer crossed [`OUTAGE_OUTBOUND_BUFFER_CAP`]; the driver
    /// stops rather than silently drop a game-produced turn.
    BufferExhausted,
}

/// Waits the next backoff delay before a reconnect attempt, while still servicing
/// the game's outbound turns — buffering them (bounded) so a resumed session can
/// flush them — and watching for the game tearing down (its outbound sender or
/// inbound receiver dropped). Other game→driver channels park in their own buffers
/// during the brief outage and are drained when the session resumes.
///
/// A turn produced past [`OUTAGE_OUTBOUND_BUFFER_CAP`] is not dropped: dropping it
/// here would be silent (the resumed session assigns the survivors gapless origin
/// seqs, so no peer could ever detect the loss), so the caller ends the driver
/// instead — see [`DriverError::OutageBufferExhausted`].
pub(super) async fn wait_backoff(
    backoff: &mut Backoff,
    seam: &mut GameSeam,
    state: &mut LoopState,
) -> WaitOutcome {
    let deadline = Instant::now() + backoff.next_delay();
    loop {
        tokio::select! {
            _ = sleep_until(deadline) => return WaitOutcome::Elapsed,
            // The game dropped its inbound receiver: a teardown.
            _ = seam.inbound.closed() => return WaitOutcome::GameGone,
            produced = seam.outbound.recv() => match produced {
                Some(turn) => {
                    state.outbound_buffer.push_back(turn);
                    if state.outbound_buffer.len() > OUTAGE_OUTBOUND_BUFFER_CAP {
                        return WaitOutcome::BufferExhausted;
                    }
                }
                // The game dropped its outbound sender: a teardown.
                None => return WaitOutcome::GameGone,
            },
        }
    }
}

/// The outcome of awaiting the re-home provider while the seam stays serviced.
pub(super) enum EscalationWait {
    /// The provider answered.
    Answered(RehomeOutcome),
    /// The provider did not answer within the deadline; the caller treats this
    /// exactly as [`RehomeOutcome::Unavailable`] (the pending ask is dropped —
    /// the next escalation asks afresh).
    TimedOut,
    /// The game tore down its seam; abandon reconnection.
    GameGone,
    /// The outage buffer crossed [`OUTAGE_OUTBOUND_BUFFER_CAP`]; the driver
    /// stops rather than silently drop a game-produced turn.
    BufferExhausted,
}

/// Awaits one [`RehomeProvider::rehome`] ask under `deadline`, servicing the
/// game seam exactly as [`wait_backoff`] does — buffering outbound turns
/// (bounded) and watching for the game tearing down. The provider is embedder
/// code awaiting an app-server round-trip; without this the whole reconnect
/// loop would be parked on that future, blind to game teardown and to the
/// outage-buffer cap for as long as it takes — forever, if it hangs.
pub(super) async fn await_rehome(
    provider: &Arc<dyn RehomeProvider>,
    dead_relay_id: u64,
    deadline: Duration,
    seam: &mut GameSeam,
    state: &mut LoopState,
) -> EscalationWait {
    let deadline = Instant::now() + deadline;
    let mut ask = provider.rehome(dead_relay_id);
    loop {
        tokio::select! {
            outcome = &mut ask => return EscalationWait::Answered(outcome),
            _ = sleep_until(deadline) => return EscalationWait::TimedOut,
            // The game dropped its inbound receiver: a teardown.
            _ = seam.inbound.closed() => return EscalationWait::GameGone,
            produced = seam.outbound.recv() => match produced {
                Some(turn) => {
                    state.outbound_buffer.push_back(turn);
                    if state.outbound_buffer.len() > OUTAGE_OUTBOUND_BUFFER_CAP {
                        return EscalationWait::BufferExhausted;
                    }
                }
                // The game dropped its outbound sender: a teardown.
                None => return EscalationWait::GameGone,
            },
        }
    }
}

/// Capped exponential backoff with jitter for the reconnect dial.
///
/// The base schedule doubles from [`RECONNECT_BACKOFF_INITIAL`] to
/// [`RECONNECT_BACKOFF_CAP`]; each delay is then jittered down into `[base/2, base]`
/// so many clients that dropped together don't re-dial in lockstep. The base
/// schedule is a pure function of the attempt count, so its shape is unit-testable
/// independently of the jitter.
pub(super) struct Backoff {
    pub(super) attempt: u32,
    pub(super) rng: u64,
}

impl Backoff {
    pub(super) fn new() -> Self {
        // Seed the jitter PRNG from the clock; only that separate clients diverge
        // matters, not the exact value. Force non-zero for the xorshift.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            | 1;
        Self {
            attempt: 0,
            rng: seed,
        }
    }

    /// Resets to the initial delay after a successful reconnect.
    pub(super) fn reset(&mut self) {
        self.attempt = 0;
    }

    /// The base (un-jittered) delay for `attempt`: the initial delay doubled
    /// `attempt` times, capped. Pure, so the schedule shape is unit-testable.
    pub(super) fn base_delay(attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt).unwrap_or(u32::MAX);
        RECONNECT_BACKOFF_INITIAL
            .saturating_mul(factor)
            .min(RECONNECT_BACKOFF_CAP)
    }

    /// The next delay: the current attempt's base jittered into `[base/2, base]`,
    /// advancing the attempt counter (saturating, so it stays at the cap).
    pub(super) fn next_delay(&mut self) -> Duration {
        let base = Self::base_delay(self.attempt).as_millis() as u64;
        self.attempt = self.attempt.saturating_add(1);
        let half = base / 2;
        let jitter = if half == 0 {
            0
        } else {
            self.next_rand() % (half + 1)
        };
        Duration::from_millis(base - jitter)
    }

    /// One xorshift64 step — a tiny PRNG for jitter, with no external dependency.
    fn next_rand(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }
}
