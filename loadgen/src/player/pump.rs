//! The send loop: this player's exact measured turn stream, emitted at game
//! cadence while everything the driver hands back keeps draining.

use rally_point_client::proto::messages::Payload;
use tokio::time::{Duration, Instant as TokioInstant, MissedTickBehavior, interval_at, timeout};

use crate::lifecycle::SessionLifecycle;
use crate::turn::{TurnBuilder, sync_generation};

use super::measure::Measurement;

/// A wedged driver must not strand the other players before the shared drain
/// deadline exists. Normal sends enter the bounded driver queue immediately.
const OUTBOUND_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// The exact send stream one player owes the session: which turns to build, how
/// fast, and from when.
pub(super) struct Workload<'a> {
    pub(super) builder: &'a TurnBuilder,
    pub(super) own_slot: u32,
    pub(super) turn_interval: Duration,
    /// Where this player's ticker is anchored. The deliberate send-phase
    /// stagger rides this anchor, so every turn a staggered player emits sits
    /// its offset later in the cycle than slot 0's.
    pub(super) start: TokioInstant,
    pub(super) measured_turns: u64,
}

/// The steady-state loop: emit the exact measured turn count at the configured
/// interval while draining everything the driver hands back. A driver ending
/// early closes the inbound channel and makes the workload incomplete.
pub(super) async fn pump_turns(
    channels: &mut rally_point_client::TurnChannels,
    workload: &Workload<'_>,
    measure: &mut Measurement<'_>,
    lifecycle: &SessionLifecycle,
) -> bool {
    let mut ticker = interval_at(workload.start, workload.turn_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut lifecycle_changes = lifecycle.subscribe();
    let mut ordinal: u64 = 0;

    while ordinal < workload.measured_turns {
        tokio::select! {
            biased;
            _ = lifecycle.wait_for_abort(&mut lifecycle_changes) => return false,
            _ = ticker.tick() => {
                let frame = ordinal as u32;
                let commands = workload.builder.turn(ordinal);
                // Record the send instant before handing the turn off, so a peer's
                // receipt always finds it.
                if let Ok(mut map) = measure.send_times.lock() {
                    map.insert((workload.own_slot, frame), std::time::Instant::now());
                }
                // seq/slot are left zero: the driver stamps seq, the relay rebinds slot.
                let payload = Payload {
                    seq: 0,
                    slot: 0,
                    commands: commands.into(),
                    game_frame_count: Some(frame),
                    // Exercise both modes in each multi-player session. Keep the
                    // choice stable for this origin throughout its connection.
                    sync_generation: workload
                        .own_slot
                        .is_multiple_of(2)
                        .then_some(sync_generation(ordinal)),
                    buffer_directive: None,
                };
                let send_result = tokio::select! {
                    biased;
                    _ = lifecycle.wait_for_abort(&mut lifecycle_changes) => return false,
                    result = timeout(OUTBOUND_SEND_TIMEOUT, channels.outbound.send(payload)) => result,
                };
                if !matches!(send_result, Ok(Ok(()))) {
                    tracing::warn!(slot = workload.own_slot, frame, "outbound turn send stalled or closed");
                    return false;
                }
                measure.stats.turns_sent += 1;
                ordinal += 1;
            }
            maybe = channels.recv_turn() => {
                match maybe {
                    Some(payload) => measure.observe(&payload),
                    None => return false,
                }
            }
        }
    }
    true
}
