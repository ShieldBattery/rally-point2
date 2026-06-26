//! `rally-point-relay` — the validating netcode v2 relay (library half).
//!
//! The relay is the transport *below* the game's OUT/IN hooks and the
//! server-side vantage point for everything stateful in netcode v2:
//!
//! - **validation** — bind each turn to the token's slot, bounds-check every
//!   command, allowlist live ids, strip client-originated control commands.
//! - **mesh + dedup** — one QUIC connection per relay-pair, topological fan-out,
//!   topological dedup, degrade-to-single-relay (`C–S–C`).
//! - **consensus** — execute per-turn latency/leave consensus keyed on
//!   `game_frame_count`; the coordinator only sets *policy*.
//! - **turn log** — persist + replicate the per-game turn log; the same
//!   "replay from cursor X" primitive serves failover and (future) observers.
//! - **flight recorder** — per-game turn stream + per-link health + events,
//!   flushed to a durable store *before* scale-to-zero teardown.
//!
//! The modules for these are not built yet; this half currently exposes only
//! shared constants. The binary half ([`main`](../main.rs)) wires up the
//! process.

// TODO: pub mod validation;       // attacker-facing, fuzzed
// TODO: pub mod mesh;             // one conn per relay-pair
// TODO: pub mod consensus;        // keyed on game_frame_count
// TODO: pub mod turn_log;         // replicated, bounded + flushed
// TODO: pub mod flight_recorder;  // tenant/session/slot/turn

/// Default UDP port the relay listens on for client + mesh QUIC connections.
// TODO: reconcile with the Fargate task def + per-game IP rotation.
pub const DEFAULT_PORT: u16 = 14_900;
