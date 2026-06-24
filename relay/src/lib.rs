//! `rally-point-relay` — the validating netcode v2 relay (library half).
//!
//! The relay is the transport *below* the game's OUT/IN hooks and the
//! server-side vantage point for everything stateful in netcode v2:
//!
//! - **validation (D10)** — bind each turn to the token's slot, bounds-check
//!   every command, allowlist live ids, strip client-originated control commands.
//! - **mesh + dedup** — one QUIC connection per relay-pair, topological fan-out,
//!   topological dedup, degrade-to-single-relay (`C–S–C`).
//! - **consensus (D9)** — execute per-turn latency/leave consensus keyed on
//!   `game_frame_count`; the coordinator only sets *policy*.
//! - **turn log (D4/D11)** — persist + replicate the per-game turn log; the same
//!   "replay from cursor X" primitive serves failover and (future) observers.
//! - **flight recorder (D8)** — per-game turn stream + per-leg health + events,
//!   flushed to a durable store *before* scale-to-zero teardown.
//!
//! The modules for these land in Phases 1–2; this half currently exposes only
//! shared constants. The binary half ([`main`](../main.rs)) wires up the
//! process.

// TODO(phase-1): pub mod validation;       // D10 — attacker-facing, fuzzed
// TODO(phase-2): pub mod mesh;             // brief §2.1, one conn per relay-pair
// TODO(phase-3): pub mod consensus;        // D9, keyed on game_frame_count
// TODO(phase-2): pub mod turn_log;         // D4/D11, replicated, bounded + flushed
// TODO(phase-1): pub mod flight_recorder;  // D8, tenant/session/slot/turn

/// Default UDP port the relay listens on for client + mesh QUIC connections.
// TODO(phase-5): reconcile with the Fargate task def + per-game IP rotation (WS-G).
pub const DEFAULT_PORT: u16 = 14_900;
