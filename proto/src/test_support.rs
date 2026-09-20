//! Fixtures shared by more than one module's tests.
//!
//! Compiled only under `cfg(test)`, so nothing here reaches the frozen public
//! surface. A fixture belongs here once a second module needs it; one that only
//! ever serves a single module stays beside that module's tests.

use crate::control::TenantId;
use crate::ids::{SessionId, SlotId};
use crate::token::{
    ClientPublicKey, ExpiresAt, KeyId, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, SignedToken,
    TokenClaims,
};

/// A fully populated token with every string field non-empty and every integer
/// field distinctive, so a field swap or an endianness flip shows up in the
/// encoded bytes. These exact values back the v1 golden wire vector, so
/// changing them changes that vector too.
pub fn sample_token() -> SignedToken {
    SignedToken::from_parts(
        KeyId("staging-key-1".to_owned()),
        sample_claims(),
        Signature([0xCD; SIGNATURE_LEN]),
    )
}

/// The claims inside [`sample_token`], separately for tests that rebuild the
/// token around a different kid or signature.
pub fn sample_claims() -> TokenClaims {
    TokenClaims::new(
        TenantId("sb-staging".to_owned()),
        SessionId(0xDEAD_BEEF_CAFE_BABE),
        SlotId(3),
        ExpiresAt(1_800_000_000),
        ClientPublicKey([0xAB; PUBLIC_KEY_LEN]),
    )
}
