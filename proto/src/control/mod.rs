//! Control-plane messages.
//!
//! Reliable, lower-frequency messages that never ride the turn-datagram hot
//! path:
//!
//! - **coordinator ⇄ relay** — authenticated phone-home registry, session
//!   descriptors, and consensus *policy* (bounds/rates).
//! - **coordinator ⇄ app server** — session requests, token + home relay
//!   handoff, per-tenant quotas.
//!
//! Consensus *decisions* are deliberately **not** here: the relay/mesh executes
//! per-turn latency/leave consensus keyed on [`crate::ids::GameFrameCount`], so
//! a coordinator outage never stalls a running game. What lives here is the
//! *policy* the coordinator sets at setup ([`BufferBounds`]) — the bounds the
//! relay's decision-maker clamps to — not the per-turn decision itself.
//!
//! Everything crossing a component boundary is defined here first, before the
//! coordinator logic modules that produce or consume it.
//!
//! Split by concern across sibling files, all re-exported here so every path
//! that was `rally_point_proto::control::X` before the split still resolves:
//! `relay` (the relay registry and its client/mesh-facing shapes), `session`
//! (session setup plus the fleet registry data pushed to relays), `messages`
//! (the control-connection message envelopes), and `notices` (relay-authored
//! per-session event reports).

use serde::{Deserialize, Serialize};

mod messages;
mod notices;
mod relay;
mod session;

pub use messages::*;
pub use notices::*;
pub use relay::*;
pub use session::*;

/// serde helper for opaque byte slices (token wire bytes).
///
/// Shared by `relay`, `session`, and `messages` — every family with a raw byte
/// field (certs, tokens, keys, signatures) — so it stays here rather than next
/// to any one of them; each references it as `super::serde_bytes`.
mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(d)
    }
}

// ---------------------------------------------------------------------------
// Tenancy
// ---------------------------------------------------------------------------

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

/// Identifies a coordinator-configured relay region — an opaque placement label,
/// deliberately *not* an AWS region name so a non-AWS region stays expressible.
///
/// A relay enrolls tagged with the region it serves; the coordinator validates
/// that tag against its configured region list (an unknown one is refused,
/// [`crate::version::CONTROL_CLOSE_UNKNOWN_REGION`]). A session slot names the
/// region the player wants their home relay in, and the coordinator homes the
/// slot on a relay enrolled in that region — falling back to a region-blind pick
/// when the region names no live relay. The string is the wire name everywhere
/// (`"us-east"`, not `us-east-1`); its allowed shape (charset, length) is
/// enforced where the coordinator loads its region config, not by this type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionId(pub String);

impl From<RegionId> for String {
    fn from(rid: RegionId) -> String {
        rid.0
    }
}

impl AsRef<str> for RegionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests;
