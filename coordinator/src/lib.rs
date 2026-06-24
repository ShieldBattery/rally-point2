//! `rally-point-coordinator` — the multi-tenant netcode v2 control plane
//! (library half).
//!
//! The coordinator is control-plane only: it finds / spins up relays and sets
//! policy, but stays **off the turn hot path** (**D9**) so running games survive
//! a coordinator outage. Responsibilities:
//!
//! - **registry** — authenticated relay phone-home + fleet inventory (**D6**).
//! - **sessions** — accept app-server session requests (N players / regions),
//!   issue connection-bound, per-tenant tokens, and push session descriptors
//!   including the pre-provisioned backup relay (**D11**).
//! - **tenants** — per-tenant signing keys, quotas, rate limits, provisioning
//!   budget; **prod is an isolated deployment** (**D2**).
//! - **policy** — set latency/leave consensus *bounds* at setup; the relay
//!   executes per-turn (**D9**).
//!
//! The modules for these land in Phase 3; this half currently exposes only
//! shared constants. The binary half ([`main`](../main.rs)) wires up the process.

// TODO(phase-3): pub mod registry;  // authenticated phone-home (D6)
// TODO(phase-3): pub mod session;   // session setup + descriptor push (D11 backup relay)
// TODO(phase-3): pub mod tenant;    // per-tenant keys / quotas (D2/D6)
// TODO(phase-3): pub mod policy;    // consensus policy bounds (D9)

/// Default port the coordinator serves its app-server + relay control API on.
// TODO(phase-3): confirm the control transport (HTTP vs QUIC control streams).
pub const DEFAULT_PORT: u16 = 14_910;
