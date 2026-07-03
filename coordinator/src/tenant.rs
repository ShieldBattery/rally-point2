//! Per-tenant signing keys: the coordinator's counterpart to the relay's
//! [`Registry`](rally_point_relay::auth::Registry).
//!
//! The relay verifies tokens; the coordinator signs them. Each tenant has its
//! own Ed25519 signing key, registered here with a `kid` that the relay looks
//! up to find the verifying key. A stolen coordinator key is contained to one
//! tenant (per-tenant signing keys, not one global key), and a token forged
//! for another tenant fails the relay's `kid → tenant` cross-check.
//!
//! The relay holds only the *public* (verifying) half. The *private* signing
//! key lives here, on the coordinator, and never leaves it — the coordinator
//! signs tokens at issuance; the relay verifies with the public key the
//! coordinator registered.
//!
//! # Key management
//!
//! Keys are generated in-memory with `ring` (the same crypto provider the
//! relay uses for verification). Persistence (surviving a coordinator restart)
//! and key rotation are open — a coordinator restart today loses all tenant
//! keys, and the relays that verified tokens signed by the old keys reject new
//! tokens signed by regenerated keys. Production needs durable key storage
//! (AWS KMS or a sealed local store) and a rotation flow.

use std::collections::HashMap;

use parking_lot::Mutex;
use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::token::{
    ClientPublicKey, ExpiresAt, KeyId, PUBLIC_KEY_LEN, Signature, SignedToken, TokenClaims,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use std::sync::Arc;

/// The coordinator's view of one tenant's signing key + policy.
#[derive(Clone)]
struct TenantSigningKey {
    /// The `kid` naming this key in tokens.
    kid: KeyId,
    /// The tenant this key belongs to.
    tenant: TenantId,
    /// The Ed25519 signing keypair. The private half signs tokens; the public
    /// half is what the relay registers for verification. Wrapped in `Arc`
    /// because `Ed25519KeyPair` is not `Clone` — the coordinator shares one
    /// key across cloned `TenantStore` handles without copying the key
    /// material.
    pair: Arc<Ed25519KeyPair>,
    /// The latency-buffer bounds this tenant's sessions use. The coordinator
    /// sets policy (bounds); the relay's decision-maker clamps to them.
    bounds: BufferBounds,
}

impl std::fmt::Debug for TenantSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantSigningKey")
            .field("kid", &self.kid)
            .field("tenant", &self.tenant)
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

/// The coordinator's tenant store: `TenantId` → that tenant's signing key +
/// policy. Each tenant has exactly one active signing key at a time (key
/// rotation replaces, not adds).
///
/// A plain (non-async) mutex mirrors the relay's `Registry` and the
/// coordinator's `RelayRegistry`: every critical section is a short,
/// await-free insert or lookup.
#[derive(Clone, Default)]
pub struct TenantStore {
    tenants: Arc<Mutex<HashMap<TenantId, TenantSigningKey>>>,
}

/// A freshly generated tenant enrollment: the public (verifying) key to seed
/// relays with, plus the PKCS#8 keypair document so the caller can persist it
/// and re-enroll the same key later via [`enroll_from_pkcs8`] (a coordinator
/// restart otherwise regenerates the key, orphaning the relays' copy).
pub struct GeneratedTenantKey {
    /// The public (verifying) key relays verify tokens against.
    pub verifying_key: [u8; PUBLIC_KEY_LEN],
    /// The PKCS#8 document holding the full keypair (private half included).
    pub pkcs8: Vec<u8>,
}

/// Generates a fresh Ed25519 keypair for `tenant` with the given `kid` and
/// `bounds`, registering it in the store. Returns the public (verifying) key
/// so a relay can be seeded with it.
///
/// If the tenant already exists, its key and bounds are replaced (key
/// rotation). The relay fleet must be updated with the new verifying key
/// before old tokens are considered expired.
pub fn enroll(
    store: &TenantStore,
    kid: KeyId,
    tenant: TenantId,
    bounds: BufferBounds,
) -> Result<[u8; PUBLIC_KEY_LEN], KeyError> {
    Ok(enroll_generated(store, kid, tenant, bounds)?.verifying_key)
}

/// Like [`enroll`], but also returns the generated PKCS#8 keypair document so
/// the caller can persist it (dev flow: the binary prints it so the same key
/// can be pinned across restarts).
pub fn enroll_generated(
    store: &TenantStore,
    kid: KeyId,
    tenant: TenantId,
    bounds: BufferBounds,
) -> Result<GeneratedTenantKey, KeyError> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| KeyError::KeyGeneration)?;
    let verifying_key = enroll_from_pkcs8(store, kid, tenant, bounds, pkcs8.as_ref())?;
    Ok(GeneratedTenantKey {
        verifying_key,
        pkcs8: pkcs8.as_ref().to_vec(),
    })
}

/// Registers a tenant from a pre-generated PKCS#8 keypair (e.g. loaded from
/// durable storage). Returns the verifying key.
pub fn enroll_from_pkcs8(
    store: &TenantStore,
    kid: KeyId,
    tenant: TenantId,
    bounds: BufferBounds,
    pkcs8: &[u8],
) -> Result<[u8; PUBLIC_KEY_LEN], KeyError> {
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| KeyError::InvalidPkcs8)?;
    let pubkey: [u8; PUBLIC_KEY_LEN] = pair.public_key().as_ref().try_into().unwrap();
    store.tenants.lock().insert(
        tenant.clone(),
        TenantSigningKey {
            kid,
            tenant,
            pair: Arc::new(pair),
            bounds,
        },
    );
    Ok(pubkey)
}

/// Looks up a tenant's signing key, returning the `kid` and verifying key.
pub fn verifying_key(
    store: &TenantStore,
    tenant: &TenantId,
) -> Option<(KeyId, [u8; PUBLIC_KEY_LEN])> {
    store.tenants.lock().get(tenant).map(|t| {
        let pk: [u8; PUBLIC_KEY_LEN] = t.pair.public_key().as_ref().try_into().unwrap();
        (t.kid.clone(), pk)
    })
}

/// Looks up a tenant's buffer bounds.
pub fn bounds(store: &TenantStore, tenant: &TenantId) -> Option<BufferBounds> {
    store.tenants.lock().get(tenant).map(|t| t.bounds)
}

/// Whether the tenant is enrolled.
pub fn is_enrolled(store: &TenantStore, tenant: &TenantId) -> bool {
    store.tenants.lock().contains_key(tenant)
}

/// The number of enrolled tenants.
pub fn len(store: &TenantStore) -> usize {
    store.tenants.lock().len()
}

/// Whether the store has no tenants.
pub fn is_empty(store: &TenantStore) -> bool {
    store.tenants.lock().is_empty()
}

/// Mints a connection-bound authorization token for `slot` in `session`,
/// signed by `tenant`'s key. The token embeds `client_pubkey` so the relay can
/// verify the connection-binding challenge, and carries `expires_at` so the
/// relay rejects stale tokens.
///
/// This is the coordinator's counterpart to the relay's `verify_token`: the
/// coordinator assembles the claims, signs the canonical message, and returns
/// the wire-encoded token bytes the app server hands to the game DLL at launch.
pub fn mint_token(
    store: &TenantStore,
    tenant: &TenantId,
    session: SessionId,
    slot: SlotId,
    client_pubkey: ClientPublicKey,
    expires_at: ExpiresAt,
) -> Result<SignedToken, KeyError> {
    let guard = store.tenants.lock();
    let key = guard
        .get(tenant)
        .ok_or(KeyError::TenantNotFound(tenant.clone()))?;

    let claims = TokenClaims::new(tenant.clone(), session, slot, expires_at, client_pubkey);

    // Build the token with a placeholder signature to obtain the canonical
    // signed-message bytes, then sign and replace — matching the test
    // harness's mint_token pattern.
    let mut token = SignedToken::from_parts(
        key.kid.clone(),
        claims,
        Signature([0u8; rally_point_proto::token::SIGNATURE_LEN]),
    );

    let mut message = Vec::new();
    token
        .signed_message(&mut message)
        .map_err(KeyError::Token)?;
    let sig = key.pair.sign(&message);
    let sig_bytes: [u8; rally_point_proto::token::SIGNATURE_LEN] = sig.as_ref().try_into().unwrap();
    token.signature = Signature(sig_bytes);

    Ok(token)
}

/// Why a token could not be minted or a tenant enrolled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The tenant is not enrolled (no signing key registered for it).
    #[error("tenant {0:?} is not enrolled")]
    TenantNotFound(TenantId),
    /// The Ed25519 key generation or PKCS#8 loading failed.
    #[error("key generation failed")]
    KeyGeneration,
    /// The provided PKCS#8 bytes are not a valid Ed25519 keypair.
    #[error("invalid PKCS#8 key material")]
    InvalidPkcs8,
    /// The token could not be encoded (oversized kid or tenant string).
    #[error("token encoding error: {0}")]
    Token(rally_point_proto::token::TokenError),
}

/// Creates an empty tenant store for a coordinator with no tenants enrolled.
pub fn new_store() -> TenantStore {
    TenantStore::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rally_point_proto::control::{BufferBounds, TenantId};
    use rally_point_proto::ids::{SessionId, SlotId};
    use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};

    fn store_with_tenant() -> (TenantStore, KeyId, TenantId) {
        let store = new_store();
        let kid = KeyId("test-key-1".to_owned());
        let tenant = TenantId("sb-test".to_owned());
        enroll(
            &store,
            kid.clone(),
            tenant.clone(),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        (store, kid, tenant)
    }

    #[test]
    fn enroll_then_verifying_key_roundtrips() {
        let (store, kid, tenant) = store_with_tenant();
        let (found_kid, _pubkey) = verifying_key(&store, &tenant).unwrap();
        assert_eq!(found_kid, kid);
        assert!(is_enrolled(&store, &tenant));
    }

    #[test]
    fn mint_token_then_relay_verifies() {
        // The round-trip test: coordinator mints, relay verifies.
        let (store, kid, tenant) = store_with_tenant();
        let (_, pubkey) = verifying_key(&store, &tenant).unwrap();

        let mut relay_registry = rally_point_relay::auth::Registry::new();
        relay_registry.insert(kid, tenant.clone(), pubkey);

        let client_pub = ClientPublicKey([0x42; 32]);
        let token = mint_token(
            &store,
            &tenant,
            SessionId(1),
            SlotId(0),
            client_pub,
            ExpiresAt(u64::MAX),
        )
        .unwrap();

        // The relay verifies the token against the registered key.
        let authorized =
            rally_point_relay::auth::verify_token(&relay_registry, &token, u64::MAX - 1).unwrap();
        assert_eq!(authorized.tenant, tenant);
        assert_eq!(authorized.session, SessionId(1));
        assert_eq!(authorized.slot, SlotId(0));
        assert_eq!(authorized.client_pubkey, client_pub);
    }

    #[test]
    fn mint_token_for_unenrolled_tenant_fails() {
        let store = new_store();
        let result = mint_token(
            &store,
            &TenantId("nope".to_owned()),
            SessionId(1),
            SlotId(0),
            ClientPublicKey([0; 32]),
            ExpiresAt(u64::MAX),
        );
        assert!(matches!(result, Err(KeyError::TenantNotFound(_))));
    }

    #[test]
    fn re_enroll_replaces_key() {
        let store = new_store();
        let kid = KeyId("test-key-1".to_owned());
        let tenant = TenantId("sb-test".to_owned());
        let bounds = BufferBounds::new(1, 6).unwrap();

        let pubkey1 = enroll(&store, kid.clone(), tenant.clone(), bounds).unwrap();
        let pubkey2 = enroll(&store, kid, tenant.clone(), bounds).unwrap();

        // A new key replaces the old one.
        assert_ne!(pubkey1, pubkey2);
        assert_eq!(len(&store), 1);
    }

    #[test]
    fn different_tenants_get_different_keys() {
        let store = new_store();
        let bounds = BufferBounds::new(1, 6).unwrap();
        let pk1 = enroll(
            &store,
            KeyId("kid-a".to_owned()),
            TenantId("tenant-a".to_owned()),
            bounds,
        )
        .unwrap();
        let pk2 = enroll(
            &store,
            KeyId("kid-b".to_owned()),
            TenantId("tenant-b".to_owned()),
            bounds,
        )
        .unwrap();
        assert_ne!(pk1, pk2);
        assert_eq!(len(&store), 2);
    }

    #[test]
    fn bounds_lookup_returns_enrolled_bounds() {
        let (store, _, tenant) = store_with_tenant();
        let b = bounds(&store, &tenant).unwrap();
        assert_eq!(b, BufferBounds::new(1, 6).unwrap());
    }

    #[test]
    fn enroll_generated_pkcs8_re_enrolls_the_same_key() {
        // The dev restart flow: enroll fresh, persist the PKCS#8, re-enroll
        // from it on a new (restarted) store — same verifying key.
        let store = new_store();
        let bounds = BufferBounds::new(1, 6).unwrap();
        let generated = enroll_generated(
            &store,
            KeyId("dev-key-1".to_owned()),
            TenantId("sb-dev".to_owned()),
            bounds,
        )
        .unwrap();

        let restarted = new_store();
        let re_enrolled = enroll_from_pkcs8(
            &restarted,
            KeyId("dev-key-1".to_owned()),
            TenantId("sb-dev".to_owned()),
            bounds,
            &generated.pkcs8,
        )
        .unwrap();

        assert_eq!(re_enrolled, generated.verifying_key);
    }

    #[test]
    fn enroll_from_pkcs8_roundtrips() {
        // Generate a keypair, extract PKCS#8, register from it.
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let expected_pub: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();

        let store = new_store();
        let pub_from_store = enroll_from_pkcs8(
            &store,
            KeyId("pkcs8-key".to_owned()),
            TenantId("sb-pkcs8".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
            pkcs8.as_ref(),
        )
        .unwrap();

        assert_eq!(pub_from_store, expected_pub);
    }
}
