//! The two loops after this player's own send stream ends: keeping the live
//! link draining until the session's shared delivery result is known, and then
//! waiting out the driver's own teardown.

use tokio::task::JoinError;
use tokio::time::{Duration, Instant as TokioInstant, sleep_until};

use rally_point_client::DriverError;

use crate::lifecycle::{DrainResolution, SessionLifecycle};
use crate::metrics::Ending;

use super::measure::Measurement;
use super::recv_turn;

/// How long a player waits for its driver to end after signaling a clean leave,
/// before abandoning it as an errored ending.
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(15);

/// Keeps the live link draining after this player's exact send stream finishes.
/// Completion is per destination and exact by `(origin, frame)`; the first
/// player to hit the shared deadline releases the whole session together.
pub(super) async fn drain_delivery_phase(
    channels: &mut rally_point_client::TurnChannels,
    measure: &mut Measurement<'_>,
    lifecycle: &SessionLifecycle,
) -> DrainResolution {
    let mut reported_complete = false;
    let mut lifecycle_changes = lifecycle.subscribe();
    loop {
        if measure.deliveries.is_complete() && !reported_complete {
            lifecycle.receiver_done();
            reported_complete = true;
        }

        tokio::select! {
            biased;
            resolution = lifecycle.wait_for_drain_resolution(&mut lifecycle_changes) => {
                return resolution;
            },
            maybe = recv_turn(channels) => {
                match maybe {
                    Some(payload) => measure.observe(&payload),
                    None => {
                        lifecycle.abort();
                        return DrainResolution::Aborted;
                    }
                }
            }
        }
    }
}

/// Waits for the driver to end after a leave, still draining inbound so a late
/// turn can't stall it, and classifies the ending. Bounded by [`TEARDOWN_TIMEOUT`].
pub(super) async fn drain_until_driver_ends(
    channels: &mut rally_point_client::TurnChannels,
    handle: &mut tokio::task::JoinHandle<Result<(), DriverError>>,
    measure: &mut Measurement<'_>,
) -> Ending {
    let deadline = TokioInstant::now() + TEARDOWN_TIMEOUT;
    let mut channels_alive = true;
    loop {
        tokio::select! {
            biased;
            res = &mut *handle => {
                measure.absorb_buffered(&mut channels.inbound);
                return classify_ending(res);
            },
            _ = sleep_until(deadline) => {
                handle.abort();
                let _ = (&mut *handle).await;
                measure.absorb_buffered(&mut channels.inbound);
                return Ending::Errored;
            }
            maybe = recv_turn(channels), if channels_alive => {
                match maybe {
                    Some(payload) => measure.observe(&payload),
                    None => channels_alive = false,
                }
            }
        }
    }
}

/// Maps a joined driver result to an [`Ending`]: a clean `Ok(Ok(()))` is the only
/// clean ending; a driver error or a task join failure is errored.
fn classify_ending(res: Result<Result<(), DriverError>, JoinError>) -> Ending {
    match res {
        Ok(Ok(())) => Ending::Clean,
        Ok(Err(err)) => {
            tracing::debug!(error = %err, "driver ended with an error");
            Ending::Errored
        }
        Err(err) => {
            tracing::debug!(error = %err, "driver task failed to join");
            Ending::Errored
        }
    }
}
