//! Control-plane messages.
//!
//! Reliable, lower-frequency messages that never ride the turn-datagram hot
//! path:
//!
//! - **coordinator ⇄ relay** — authenticated phone-home registry, session
//!   descriptors, and consensus *policy* (bounds/rates).
//! - **coordinator ⇄ app server** — session requests, token + home/backup relay
//!   handoff, per-tenant quotas.
//!
//! Consensus *decisions* are deliberately **not** here: per **D9** the relay/mesh
//! executes per-turn latency/leave consensus keyed on
//! [`crate::wire::GameFrameCount`], so a coordinator outage never stalls a
//! running game.
//!
//! TODO(phase-3): define the concrete message set + transport/codec (build plan
//! WS-C/WS-D). These types only freeze the module boundary for now.

use serde::{Deserialize, Serialize};

use crate::version::ProtocolVersion;

/// Identifies a coordinator tenant — prod, staging, or a specific developer.
///
/// Per **D2/D6** every tenant has its own signing key and quotas; this id scopes
/// registry entries, tokens, and observability data. Prod is an isolated
/// deployment with its own coordinator + key + fleet.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);

/// The first message a relay sends when it phones home to its coordinator.
///
/// Authenticated via a coordinator-injected bootstrap secret (**D6**) so a rogue
/// relay cannot register and MITM. Placeholder — the full enrollment payload is
/// defined in Phase 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RelayHello {
    /// Protocol version the relay implements.
    pub protocol: ProtocolVersion,
}
