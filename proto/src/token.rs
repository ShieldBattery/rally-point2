//! Connection-bound, per-tenant authorization tokens.
//!
//! A token authorizes one client to submit turns for one slot in one session.
//! Per **D6** it carries a `kid` (which tenant signing key signed it), is bound
//! to the client's QUIC connection (so a stolen bearer token is useless off its
//! connection), and is validated by the relay before any turn is accepted
//! (**D10**).
//!
//! TODO(phase-0): define the signed token layout + the connection-binding
//! mechanism — key-confirmed channel vs fingerprint claim is an open question
//! (build plan §6). Full issuance/validation lands in Phase 3 (WS-D).

use serde::{Deserialize, Serialize};

use crate::{
    control::TenantId,
    wire::{SessionId, SlotId},
};

/// Identifies which tenant signing key signed a token — the `kid` claim (**D6**).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

/// The authorization claims a relay validates before accepting any turn.
///
/// Placeholder for the signed payload — the wire encoding, signature, and
/// connection-binding proof are defined in Phase 0 / Phase 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TokenClaims {
    /// Signing key id (**D6**).
    pub kid: KeyId,
    /// Tenant this token belongs to.
    pub tenant: TenantId,
    /// Session the bearer may submit turns for.
    pub session: SessionId,
    /// Slot the bearer is bound to; the relay binds every submitted turn to it
    /// (**D10**).
    pub slot: SlotId,
}
