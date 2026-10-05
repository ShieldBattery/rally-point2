//! Every relay's heartbeat for its copies of rollback sessions' clocks.
//!
//! The authority's copy goes out at once when it anchors the clock or a stop ends, but its limit
//! (the newest step whose deadline is final) moves on with every step the session confirms, and
//! another relay measures its own players' turns only up to the limit it has heard of. Every relay
//! sends its copy on the heartbeat, and every relay merges the copies it gets, so each copy keeps
//! up with the limit, a relay that missed a frame catches up, and a stop that only some relays
//! heard of (from an authority that has since failed, say) reaches the rest.

use std::time::Duration;

use super::MeshState;
use super::fan_out::fan_out_session_clock;

/// How often each relay sends its copy of each rollback session's clock to every other relay: how
/// long, at most, a turn waits on another relay for the limit to reach it, short next to the half
/// second between a player's lead reports.
pub const SESSION_CLOCK_HEARTBEAT: Duration = Duration::from_millis(250);

/// Every `interval`, sends this relay's copy of each rollback session's clock to every peer relay
/// serving it. One task per relay, spawned by the binary; never returns.
pub async fn run_session_clock_heartbeat(mesh: MeshState, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        send_session_clocks(&mesh);
    }
}

/// Sends this relay's copy of each rollback session's clock to every peer relay serving it.
pub(super) fn send_session_clocks(mesh: &MeshState) {
    for (key, frame) in mesh.session.decision_makers.session_clock_frames() {
        fan_out_session_clock(&mesh.links, &key, frame);
    }
}
