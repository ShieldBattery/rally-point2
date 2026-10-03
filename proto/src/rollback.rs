//! What a rollback session's game clients and its relays must agree on about time.
//!
//! A rollback session runs against a session clock the relays keep: step `n` is due at the relay
//! `STEP_DURATION_US` after step `n - 1`, starting from the moment the session's lockstep start
//! ends. Each player's home relay reports how early or late that player's turns arrive against
//! it (`LeadReport`), and the client sets its own pacing from those reports. Both ends have to use
//! the same step length and the same start, or every report would read as a drift.

/// How many steps a rollback game runs in lockstep before predicting: the turns for these steps
/// arrive before every client's game loop is running, so stepping them only once every turn is
/// known lines the clients' simulations up. The session clock is anchored where this ends.
pub const LOCKSTEP_START_STEPS: u64 = 24;

/// The interval between game steps at the Fastest game speed, which is also the session clock's
/// step length: one turn per step, one step every 42 ms.
pub const STEP_DURATION_US: u64 = 42_000;
