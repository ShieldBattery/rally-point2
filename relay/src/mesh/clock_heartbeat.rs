//! The authority's heartbeat for its rollback sessions' clocks.
//!
//! The clock's frame goes out at once when the authority anchors the clock or a stop ends, but its
//! limit (the newest step whose deadline is final) moves on with every step the session confirms,
//! and another relay measures its own players' turns only up to the limit it has heard of. The
//! heartbeat keeps that copy current, and also repairs any relay that missed a frame.

use std::time::Duration;

use super::MeshState;
use super::fan_out::fan_out_session_clock;

/// How often the authority re-sends each rollback session's clock to every other relay: how long,
/// at most, a turn waits on another relay for the limit to reach it, short next to the half second
/// between a player's lead reports.
pub const SESSION_CLOCK_HEARTBEAT: Duration = Duration::from_millis(250);

/// Every `interval`, sends the clock of each rollback session this relay is the authority for to
/// every peer relay serving it. One task per relay, spawned by the binary; never returns.
pub async fn run_session_clock_heartbeat(mesh: MeshState, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        send_session_clocks(&mesh);
    }
}

/// Sends the clock of each rollback session this relay is the authority for to every peer relay
/// serving it.
pub(super) fn send_session_clocks(mesh: &MeshState) {
    for (key, frame) in mesh.session.decision_makers.session_clock_frames() {
        fan_out_session_clock(&mesh.links, &key, frame);
    }
}
