//! Connection-bound, per-tenant authorization tokens.
//!
//! A token authorizes one client to submit turns for one slot in one session.
//! It carries a `kid` (which tenant signing key signed it), is bound to the
//! client's QUIC connection (so a stolen bearer token is useless off its
//! connection), and is validated by the relay before any turn is accepted.
//!
//! TODO: define the signed token layout + the connection-binding mechanism —
//! key-confirmed channel vs fingerprint claim is an open question.

use serde::{Deserialize, Serialize};

use crate::{
    control::TenantId,
    ids::{SessionId, SlotId},
};

/// Identifies which tenant signing key signed a token — the `kid` claim.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

/// The authorization claims a relay validates before accepting any turn.
///
/// Placeholder for the signed payload — the wire encoding, signature, and
/// connection-binding proof are still to be defined.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TokenClaims {
    /// Signing key id.
    pub kid: KeyId,
    /// Tenant this token belongs to.
    pub tenant: TenantId,
    /// Session the bearer may submit turns for.
    pub session: SessionId,
    /// Slot the bearer is bound to; the relay binds every submitted turn to it.
    pub slot: SlotId,
}
