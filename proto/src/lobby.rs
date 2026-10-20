//! The relay's admission limits on lobby commands, shared because a client must
//! stay inside them to be sure every command it authors is accepted.
//!
//! A relay refuses a lobby command from an author faster than its rate cap, and
//! stops accepting any once the session's log is full. A client re-sends every
//! command it authored on each new control stream, including to a relay that
//! has never seen any of them, so it paces itself against the rate cap (with
//! margin, see the client driver) and stops retaining past the log ceiling,
//! beyond which no relay could accept a command anyway.

use std::time::Duration;

/// How many lobby commands one author may send back-to-back before the relay's
/// per-slot rate cap starts refusing. A full 8-player lobby's setup (slot,
/// color, race and team assignments plus the game-init) is on the order of
/// thirty commands from one author, all emitted at once.
pub const RATE_BURST: u32 = 32;

/// How often the relay's per-slot rate cap regains one lobby command, up to
/// [`RATE_BURST`]: 5 a second sustained, generous for a player clicking through
/// settings and an order of magnitude below anything that could meaningfully
/// grow the relay's queues.
pub const RATE_REFILL: Duration = Duration::from_millis(200);

/// The most lobby commands a relay logs for one session, all authors together.
/// Far above any real lobby; past it the relay accepts no further command.
pub const LOG_MAX_COMMANDS: usize = 1024;

/// The most lobby-command payload bytes a relay logs for one session, all
/// authors together. Stops a few large payloads pinning memory under
/// [`LOG_MAX_COMMANDS`].
pub const LOG_MAX_BYTES: usize = 256 * 1024;
