//! Process shutdown: the OS signal wait, the coordinated drain sequence, and
//! the flight-recorder flush both exit paths (drain and idle self-exit) end
//! with. Split out of `main.rs` so the wiring in `main` isn't interleaved
//! with this sequencing detail.

use std::time::Duration;

use rally_point_relay::coordinator;
use rally_point_relay::observability::flight_recorder::FlightRecorder;
use rally_point_relay::routing::Sessions;

/// How long the drain sequence waits for the coordinator's `DrainAck` before
/// proceeding regardless. A coordinator that is down, or one predating the drain
/// frame, must never wedge shutdown — so this is short and the wait is best-effort.
const DRAIN_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the drain sequence re-checks whether the relay has gone idle. A
/// shutdown path is not latency-critical, so a coarse poll keeps it simple.
const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Flushes whatever flight recordings remain to their sink, bounded by
/// [`flight_recorder::DRAIN_FLUSH_TIMEOUT`](rally_point_relay::observability::flight_recorder::DRAIN_FLUSH_TIMEOUT).
/// Both process-exit paths — the coordinated drain and the idle self-exit — end
/// with this so a session's observability is not lost when the process goes away.
/// Whatever the deadline cuts off is logged and abandoned: flight data is
/// observability, never backpressure, and the rings are size-capped and live
/// sessions bounded, so the volume always fits the timeout, which nests under
/// Fargate's `stopTimeout`.
pub(crate) async fn flush_flight_recordings(flight: &FlightRecorder) {
    flight
        .flush_all(rally_point_relay::observability::flight_recorder::DRAIN_FLUSH_TIMEOUT)
        .await;
}

/// Resolves when the process receives a shutdown signal: `Ctrl-C` everywhere, plus
/// `SIGTERM` on Unix — production runs on Linux/Fargate, which stops a task by
/// sending `SIGTERM` (then `SIGKILL` after `stopTimeout`), so the drain must key on
/// `SIGTERM`, not just an interactive interrupt.
pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing a SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

/// The coordinated-drain sequence, run once a shutdown signal arrives while the
/// server keeps serving: ask the coordinator to stop assigning us new sessions,
/// wait (bounded) for its `DrainAck`, then wait for the relay to go idle before
/// returning so the caller can exit.
///
/// **Idle predicate: no local slot held AND an empty applied descriptor set**
/// ([`coordinator::client::drained_idle`]). The DrainAck contract makes the second
/// half sound: the coordinator pushes our current descriptor set before the ack, so
/// an empty applied set at ack time means we are *provably unassigned* — the
/// truly-idle scale-in case exits immediately (well under a second). A non-empty
/// set names sessions whose clients may not have dialed yet (a session committed
/// just before our drain mark), so we wait: they dial, register slots, and the wait
/// ends when they finish. Slot liveness alone would miss exactly that window and
/// strand those clients dialing a dead relay pre-start, which the client driver
/// cannot recover (it escalates to re-home only after `SessionStart`). The cost of
/// the descriptor half is a *bounded* wait: a session whose clients never dial, or
/// one a peer relay still serves after our players left, holds its descriptor here
/// until the drain timeout — under Fargate's stopTimeout — and is then, like any
/// session still running at the deadline, deliberately abandoned to the
/// coordinator-mediated failover.
pub(crate) async fn drain_and_exit(
    has_coordinator: bool,
    drain_tx: &tokio::sync::watch::Sender<bool>,
    drain_acked_rx: &mut tokio::sync::watch::Receiver<bool>,
    sessions: &Sessions,
    applied: &coordinator::client::AppliedSessions,
    flight: &FlightRecorder,
    drain_timeout: Duration,
) {
    tracing::info!("shutdown signal received; beginning coordinated drain");

    if has_coordinator {
        // Ask the coordinator to stop assigning us new sessions.
        let _ = drain_tx.send(true);
        // Wait for the DrainAck, but never let a down/older coordinator wedge us.
        match tokio::time::timeout(DRAIN_ACK_TIMEOUT, drain_acked_rx.changed()).await {
            Ok(Ok(())) => tracing::info!("coordinator acknowledged drain"),
            Ok(Err(_)) => tracing::warn!("drain-ack channel closed before an ack; proceeding"),
            Err(_) => tracing::warn!("timed out waiting for a drain ack; proceeding"),
        }
    } else {
        tracing::info!("no coordinator configured; skipping the drain handshake");
    }

    // Wait until drained-idle, bounded by the drain timeout.
    let deadline = tokio::time::Instant::now() + drain_timeout;
    loop {
        if coordinator::client::drained_idle(sessions, applied) {
            tracing::info!("relay idle; no local slots held and no session assigned");
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            tracing::warn!(
                "drain timeout reached with sessions still live or assigned; abandoning them to failover",
            );
            break;
        }
        tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
    }

    // Flush whatever flight recordings remain — sessions that never reached their
    // ordinary close-time flush (still running at the deadline, or ended by a
    // descriptor removal with no local slot to close).
    flush_flight_recordings(flight).await;
}
