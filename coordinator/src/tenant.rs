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

/// Where the coordinator notifies a tenant of mid-game player departures: the
/// webhook URL to POST to. Absent on a tenant means departure notifications
/// are off for it (everything else unchanged).
///
/// The POST is authenticated by an Ed25519 signature from this tenant's own
/// signing key (the same key that mints tokens) — see [`sign_webhook`] — not a
/// shared secret, so there is nothing else to configure here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyConfig {
    /// The URL the coordinator POSTs a departure webhook to.
    pub url: String,
}

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
    /// Where the coordinator pushes departure notifications for this tenant, if
    /// configured. Set out of band via [`set_notify`] (enrollment leaves it
    /// `None`); absent = departure notifications off for the tenant.
    notify: Option<NotifyConfig>,
    /// The tenant's inbound-request verifying key: the public half of the
    /// Ed25519 keypair the app server signs its coordinator-bound requests with
    /// (`x-rp2-signature`). Distinct from `pair` (this coordinator's own
    /// token/webhook signing key) — that signs coordinator→tenant; this
    /// verifies tenant→coordinator, and the coordinator holds only its public
    /// half. Set out of band via [`set_client_pubkey`] (enrollment leaves it
    /// `None`); a tenant without one cannot make an authenticated request, so
    /// inbound verification fails closed.
    client_pubkey: Option<[u8; PUBLIC_KEY_LEN]>,
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
            notify: None,
            client_pubkey: None,
        },
    );
    Ok(pubkey)
}

/// Sets (or clears) a tenant's departure-notify config, if the tenant is
/// enrolled. Kept separate from enrollment so the many `enroll*` call sites are
/// unaffected: the dev flow enrolls first, then sets notify from its CLI flags.
/// Returns whether the tenant existed (a no-op on an unknown tenant).
pub fn set_notify(store: &TenantStore, tenant: &TenantId, notify: Option<NotifyConfig>) -> bool {
    match store.tenants.lock().get_mut(tenant) {
        Some(entry) => {
            entry.notify = notify;
            true
        }
        None => false,
    }
}

/// Looks up a tenant's departure-notify config, or `None` when the tenant is
/// unknown or has no config (notifications off).
pub fn notify_config(store: &TenantStore, tenant: &TenantId) -> Option<NotifyConfig> {
    store
        .tenants
        .lock()
        .get(tenant)
        .and_then(|t| t.notify.clone())
}

/// Sets a tenant's inbound-request verifying key (the public half of the app
/// server's request-signing keypair), if the tenant is enrolled. Kept separate
/// from enrollment — like [`set_notify`] — so the many `enroll*` call sites are
/// unaffected: the dev flow enrolls the signing key first, then sets this from
/// its CLI flag. Returns whether the tenant existed (a no-op on an unknown
/// tenant).
pub fn set_client_pubkey(
    store: &TenantStore,
    tenant: &TenantId,
    client_pubkey: [u8; PUBLIC_KEY_LEN],
) -> bool {
    match store.tenants.lock().get_mut(tenant) {
        Some(entry) => {
            entry.client_pubkey = Some(client_pubkey);
            true
        }
        None => false,
    }
}

/// Looks up a tenant's inbound-request verifying key, or `None` when the tenant
/// is unknown or has no client key set. `None` fails inbound request auth
/// closed — an unenrolled or client-key-less tenant cannot make an
/// authenticated request.
pub fn client_pubkey(store: &TenantStore, tenant: &TenantId) -> Option<[u8; PUBLIC_KEY_LEN]> {
    store
        .tenants
        .lock()
        .get(tenant)
        .and_then(|t| t.client_pubkey)
}

/// Derives the Ed25519 verifying (public) key from a raw 32-byte private seed.
///
/// The interchange format for a tenant client key is the raw 32-byte seed as
/// hex, not a PKCS#8 document: `ring` accepts only PKCS#8 v2 and Node's crypto
/// exports only v1, and whether either imports the other's form is
/// version-dependent — the raw seed is the one representation both sides build
/// a keypair from without ASN.1 version drift. The app server holds the seed
/// (`SB_RP2_CLIENT_KEY`) and signs with it; the coordinator stores only the
/// public half this returns and verifies against it.
pub fn client_pubkey_from_seed(seed: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], KeyError> {
    let pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| KeyError::InvalidSeed)?;
    Ok(pair.public_key().as_ref().try_into().unwrap())
}

/// Generates a fresh 32-byte Ed25519 private seed for a dev tenant's client
/// key, from the same `ring` system RNG the signing-key generation uses. The
/// dev flow logs this seed (hex) for the app server's `SB_RP2_CLIENT_KEY` and
/// stores only its derived public half.
pub fn generate_client_key_seed() -> [u8; 32] {
    let rng = SystemRandom::new();
    let seed: ring::rand::Random<[u8; 32]> =
        ring::rand::generate(&rng).expect("the system RNG can produce 32 bytes");
    seed.expose()
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

/// Signs `message` with `tenant`'s Ed25519 signing key — the same key that
/// mints tokens, reused for the departure-webhook signature headers
/// (`x-rp2-signature`) rather than a second key. Returns `None` if the tenant
/// is not enrolled (or was removed since).
///
/// A narrow signing primitive, not a broader key handle: the private key
/// (`Ed25519KeyPair`) never leaves this module, only the resulting signature
/// bytes do — the same posture `mint_token` already has. It differs from
/// `mint_token` in taking an arbitrary caller-supplied byte string rather than
/// building a `SignedToken`: the webhook signs its own domain-separated
/// message (a timestamp + the exact request body), which has nothing to do
/// with the token wire format.
pub fn sign_webhook(
    store: &TenantStore,
    tenant: &TenantId,
    message: &[u8],
) -> Option<[u8; rally_point_proto::token::SIGNATURE_LEN]> {
    let guard = store.tenants.lock();
    let key = guard.get(tenant)?;
    let sig = key.pair.sign(message);
    Some(
        sig.as_ref()
            .try_into()
            .expect("an Ed25519 signature is always SIGNATURE_LEN bytes"),
    )
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
    /// The provided bytes are not a valid Ed25519 private seed (must be exactly
    /// 32 bytes).
    #[error("invalid Ed25519 seed")]
    InvalidSeed,
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

    #[test]
    fn sign_webhook_verifies_against_the_enrolled_verifying_key() {
        let (store, _, tenant) = store_with_tenant();
        let (_, pubkey) = verifying_key(&store, &tenant).unwrap();

        let message = b"rp2-webhook-v1:1700000000000:{\"tenant\":\"sb-test\"}";
        let sig = sign_webhook(&store, &tenant, message).unwrap();

        let verifying = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pubkey);
        assert!(
            verifying.verify(message, &sig).is_ok(),
            "the webhook signature verifies against the tenant's public key",
        );

        // A mutated message (or a wrong key) must not verify.
        assert!(verifying.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn sign_webhook_for_an_unenrolled_tenant_returns_none() {
        let store = new_store();
        assert!(sign_webhook(&store, &TenantId("nope".to_owned()), b"anything").is_none());
    }

    // RFC 8032 §7.1 test vector 1: the same seed → public key pair pinned in the
    // app-side key tests (app/game/netcode-v2-keys.test.ts) and the game's
    // credentials.rs, reused here so the client-key seed derivation is checked
    // against a known-answer vector rather than only round-tripping itself.
    const RFC8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_PUBLIC_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    #[test]
    fn client_pubkey_from_seed_matches_the_rfc8032_vector() {
        let derived = client_pubkey_from_seed(&RFC8032_SEED).unwrap();
        assert_eq!(hex::encode(derived), RFC8032_PUBLIC_HEX);
    }

    #[test]
    fn client_pubkey_from_seed_rejects_a_wrong_length_seed() {
        assert!(matches!(
            client_pubkey_from_seed(&[0u8; 31]),
            Err(KeyError::InvalidSeed)
        ));
    }

    #[test]
    fn set_and_get_client_pubkey_roundtrips() {
        let (store, _, tenant) = store_with_tenant();

        // Absent until set.
        assert!(client_pubkey(&store, &tenant).is_none());

        let pubkey = client_pubkey_from_seed(&RFC8032_SEED).unwrap();
        assert!(set_client_pubkey(&store, &tenant, pubkey));
        assert_eq!(client_pubkey(&store, &tenant), Some(pubkey));

        // A no-op (and no panic) on an unknown tenant.
        assert!(!set_client_pubkey(
            &store,
            &TenantId("nope".to_owned()),
            pubkey
        ));
        assert!(client_pubkey(&store, &TenantId("nope".to_owned())).is_none());
    }

    #[test]
    fn generate_client_key_seed_derives_a_valid_pubkey() {
        // A generated seed is a usable Ed25519 seed: it derives a 32-byte key,
        // and two calls differ (the RNG isn't stuck).
        let seed = generate_client_key_seed();
        assert!(client_pubkey_from_seed(&seed).is_ok());
        assert_ne!(seed, generate_client_key_seed());
    }
}
