//! `rally-point-coordinator` — the multi-tenant netcode v2 control plane
//! (library half).
//!
//! The coordinator is control-plane only: it finds / spins up relays and sets
//! policy, but stays **off the turn hot path** so running games survive a
//! coordinator outage. Responsibilities:
//!
//! - **registry** — authenticated relay phone-home + fleet inventory.
//! - **sessions** — accept app-server session requests (N players / regions),
//!   issue connection-bound, per-tenant tokens, and push session descriptors
//!   including the pre-provisioned backup relay.
//! - **tenants** — per-tenant signing keys, quotas, rate limits, provisioning
//!   budget; **prod is an isolated deployment**.
//! - **policy** — set latency/leave consensus *bounds* at setup; the relay
//!   executes per-turn.
//!
//! The modules for these are not built yet; this half currently exposes only
//! shared constants. The binary half ([`main`](../main.rs)) wires up the process.

// TODO: pub mod registry;  // authenticated phone-home
// TODO: pub mod session;   // session setup + descriptor push (backup relay)
// TODO: pub mod tenant;    // per-tenant keys / quotas
// TODO: pub mod policy;    // consensus policy bounds

/// Default port the coordinator serves its app-server + relay control API on.
// TODO: confirm the control transport (HTTP vs QUIC control streams).
pub const DEFAULT_PORT: u16 = 14_910;
