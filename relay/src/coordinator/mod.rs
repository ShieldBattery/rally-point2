//! The relay's coordinator-facing half.
//!
//! The control connection the relay dials out to the coordinator, plus the
//! things that connection feeds or is fed by: the region round-trip
//! measurements the heartbeat reports upward, the load-state fence the
//! coordinator consults before placing work here, and the idle-exit countdown
//! that retires a relay the coordinator has stopped using. None of this sits on
//! the per-turn path — a running game survives a coordinator outage.

pub mod client;
pub mod idle_exit;
pub mod load_fence;
pub mod region_ping;
