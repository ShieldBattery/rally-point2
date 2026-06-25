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
//! Consensus *decisions* are deliberately **not** here: the relay/mesh executes
//! per-turn latency/leave consensus keyed on [`crate::ids::GameFrameCount`], so
//! a coordinator outage never stalls a running game.
//!
//! TODO(phase-3): define the concrete message set + transport/codec. These
//! types only freeze the module boundary for now.

use serde::{Deserialize, Serialize};

use crate::version::ProtocolVersion;

/// Identifies a coordinator tenant — prod, staging, or a specific developer.
///
/// Every tenant has its own signing key and quotas; this id scopes
/// registry entries, tokens, and observability data. Prod is an isolated
/// deployment with its own coordinator + key + fleet.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);

impl TenantId {
    /// Construct a tenant id, rejecting strings longer than
    /// [`crate::token::MAX_STRING_LEN`]. The token's wire format uses a `u8`
    /// length prefix, so a tenant id longer than 255 bytes cannot be encoded.
    pub fn new(s: impl Into<String>) -> Result<Self, crate::token::TokenError> {
        let s = s.into();
        if s.len() > crate::token::MAX_STRING_LEN {
            return Err(crate::token::TokenError::StringTooLong);
        }
        Ok(Self(s))
    }
}

impl From<TenantId> for String {
    fn from(tid: TenantId) -> String {
        tid.0
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The first message a relay sends when it phones home to its coordinator.
///
/// Authenticated via a coordinator-injected bootstrap secret so a rogue
/// relay cannot register and MITM. Placeholder — the full enrollment payload is
/// not defined yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RelayHello {
    /// Protocol version the relay implements.
    pub protocol: ProtocolVersion,
}
