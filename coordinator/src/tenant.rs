//! Per-tenant signing keys: the coordinator's counterpart to the relay's
//! `auth::Registry`.
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
use rally_point_proto::control::{BufferBounds, TenantId, TenantVerifyingKey};
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

/// A tenant's operational state — an operator lever over whether it may start
/// new games, only keep serving the ones already running, or neither.
///
/// Only tenants loaded from the registry file carry a state; a dev tenant has
/// none of its own and is always treated as [`TenantState::Active`]. Nothing in
/// the netcode protocol conveys this state to the tenant: a suspended tenant's
/// create requests simply begin failing through the ordinary error surface, with
/// no distinct signal that the tenant was suspended rather than misconfigured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantState {
    /// Full service: new games and running games alike.
    Active,
    /// New games are refused, but everything a running game relies on keeps
    /// working — failover re-home, the liveness probe, the presence query, the
    /// verifying-key fetch, and webhook delivery. Stops new games without
    /// stranding the ones already in progress.
    Suspended,
    /// No service at all: every tenant-authenticated request is refused, the
    /// verifying-key fetch reports the tenant as absent, and no webhook is
    /// delivered for it.
    Revoked,
}

/// The latency-buffer bounds a tenant's sessions use when its configuration
/// names none: a 1-turn floor up to a 12-turn worst case.
///
/// **Why 12.** Under netcode v2 the client's turn pipe depth *is* `buffer_turns`
/// exactly — the seam's pipe replacement bypasses the game's own built-in 2-turn
/// base and user-latency setting entirely, so total one-way tolerance is
/// `buffer_turns * ~42ms` at the 24 turns/sec rate. The parity target is BW's old
/// TR8 "Extra High" ceiling (~480ms one-way), which needs a depth of 12
/// (~504ms).
///
/// **BW-side ceiling.** The game's own sync bookkeeping (the `0x37` command's
/// ring nibble; see the relay's `consensus::SYNC_RING_MODULUS`) is a 16-entry
/// ring, and under v2 in-flight turns equal `buffer_turns` exactly (no native +2
/// on top of it, per the pipe-replacement note above) — so 12 leaves 4 ring
/// entries of headroom. Bounds beyond ~14 should get a hard look before shipping:
/// past that point they start crowding the game's own wraparound, not just the
/// relay's own tuning.
pub fn default_bounds() -> BufferBounds {
    BufferBounds::new(1, 12).expect("1..=12 is a valid bounds range")
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
    /// The tenant's inbound-request verifying keys: the public halves of the
    /// Ed25519 keypairs the app server may sign its coordinator-bound requests
    /// with (`x-rp2-signature`). Distinct from `pair` (this coordinator's own
    /// token/webhook signing key) — that signs coordinator→tenant; these verify
    /// tenant→coordinator, and the coordinator holds only their public halves.
    /// Verification accepts a signature from ANY key in the list, so an app
    /// server rotates its request-signing key with no downtime: add the next
    /// key, roll the app servers onto it, then drop the old one. Set out of band
    /// via [`set_client_pubkeys`] (enrollment leaves it empty); an empty list
    /// authenticates no request, so inbound verification fails closed.
    client_pubkeys: Vec<[u8; PUBLIC_KEY_LEN]>,
    /// This tenant's operational state — whether it may create new games, only
    /// keep serving running ones, or neither. Enrollment defaults it to
    /// [`TenantState::Active`]; the registry loader overrides it per the config
    /// file, and a dev tenant stays `Active`.
    state: TenantState,
}

impl std::fmt::Debug for TenantSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantSigningKey")
            .field("kid", &self.kid)
            .field("tenant", &self.tenant)
            .field("bounds", &self.bounds)
            .field("state", &self.state)
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
/// durable storage). Accepts both the v1 form (private key only — what
/// `openssl genpkey -algorithm ed25519` and Node's `generateKeyPair` emit) and
/// the v2 form (public key included — what ring's own `generate_pkcs8` emits).
/// Returns the verifying key.
pub fn enroll_from_pkcs8(
    store: &TenantStore,
    kid: KeyId,
    tenant: TenantId,
    bounds: BufferBounds,
    pkcs8: &[u8],
) -> Result<[u8; PUBLIC_KEY_LEN], KeyError> {
    // `maybe_unchecked`: ring verifies the embedded public key when the
    // document carries one (v2) and simply has none to check in the v1 form —
    // the verifying key returned below is derived from the private half either
    // way, so a v1 document yields exactly the key its private half implies.
    let pair =
        Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8).map_err(|_| KeyError::InvalidPkcs8)?;
    let pubkey: [u8; PUBLIC_KEY_LEN] = pair.public_key().as_ref().try_into().unwrap();
    store.tenants.lock().insert(
        tenant.clone(),
        TenantSigningKey {
            kid,
            tenant,
            pair: Arc::new(pair),
            bounds,
            notify: None,
            client_pubkeys: Vec::new(),
            state: TenantState::Active,
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
/// unknown, has no config (notifications off), or is [`TenantState::Revoked`].
/// A revoked tenant reports no notify config so no webhook is delivered for it —
/// every webhook path resolves this config before enqueuing anything, so gating
/// it here turns delivery off for a revoked tenant at a single point.
pub fn notify_config(store: &TenantStore, tenant: &TenantId) -> Option<NotifyConfig> {
    store
        .tenants
        .lock()
        .get(tenant)
        .filter(|t| t.state != TenantState::Revoked)
        .and_then(|t| t.notify.clone())
}

/// Sets a tenant's inbound-request verifying keys (the public halves of the app
/// server's request-signing keypairs), if the tenant is enrolled. Kept separate
/// from enrollment — like [`set_notify`] — so the many `enroll*` call sites are
/// unaffected: the dev flow enrolls the signing key first, then sets this from
/// its CLI flag. One or two keys let an app server rotate its request key with
/// no downtime; an empty list leaves the tenant unable to authenticate. Returns
/// whether the tenant existed (a no-op on an unknown tenant).
pub fn set_client_pubkeys(
    store: &TenantStore,
    tenant: &TenantId,
    client_pubkeys: Vec<[u8; PUBLIC_KEY_LEN]>,
) -> bool {
    match store.tenants.lock().get_mut(tenant) {
        Some(entry) => {
            entry.client_pubkeys = client_pubkeys;
            true
        }
        None => false,
    }
}

/// Looks up a tenant's inbound-request verifying keys, or an empty list when the
/// tenant is unknown or has none set. An empty list fails inbound request auth
/// closed — an unenrolled or client-key-less tenant cannot make an authenticated
/// request. When more than one key is present, verification accepts a signature
/// from any of them, which is what makes app-server request-key rotation
/// zero-downtime.
pub fn client_pubkeys(store: &TenantStore, tenant: &TenantId) -> Vec<[u8; PUBLIC_KEY_LEN]> {
    store
        .tenants
        .lock()
        .get(tenant)
        .map(|t| t.client_pubkeys.clone())
        .unwrap_or_default()
}

/// Sets a tenant's operational state, if the tenant is enrolled. Kept separate
/// from enrollment — like [`set_notify`] and [`set_client_pubkeys`] — so the
/// registry loader can enroll a tenant's signing key first and then stamp its
/// configured state. Returns whether the tenant existed (a no-op on an unknown
/// tenant).
pub fn set_state(store: &TenantStore, tenant: &TenantId, state: TenantState) -> bool {
    match store.tenants.lock().get_mut(tenant) {
        Some(entry) => {
            entry.state = state;
            true
        }
        None => false,
    }
}

/// Looks up a tenant's operational state, or `None` when the tenant is not
/// enrolled.
pub fn tenant_state(store: &TenantStore, tenant: &TenantId) -> Option<TenantState> {
    store.tenants.lock().get(tenant).map(|t| t.state)
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

/// Every enrolled tenant's verifying key, as the entries a
/// [`CoordinatorToRelay::TenantKeys`](rally_point_proto::control::CoordinatorToRelay::TenantKeys)
/// push carries: the `kid`, the owning tenant, and the Ed25519 public key the
/// relay verifies that tenant's client tokens against.
///
/// The coordinator distributes this whole set to a relay right after it enrolls,
/// so the relay can verify any tenant's clients before a session descriptor for
/// that tenant reaches it. The private signing halves never leave the store.
pub fn all_verifying_keys(store: &TenantStore) -> Vec<TenantVerifyingKey> {
    store
        .tenants
        .lock()
        .values()
        .map(|t| TenantVerifyingKey {
            kid: t.kid.clone(),
            tenant: t.tenant.clone(),
            verifying_key: t.pair.public_key().as_ref().to_vec(),
        })
        .collect()
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

/// The number of enrolled tenants in each operational state, taken in one lock
/// acquisition. The three counts sum to [`len`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TenantStateCounts {
    /// Tenants in [`TenantState::Active`].
    pub active: u64,
    /// Tenants in [`TenantState::Suspended`].
    pub suspended: u64,
    /// Tenants in [`TenantState::Revoked`].
    pub revoked: u64,
}

/// Counts the enrolled tenants by operational state.
pub fn state_counts(store: &TenantStore) -> TenantStateCounts {
    let mut counts = TenantStateCounts::default();
    for entry in store.tenants.lock().values() {
        match entry.state {
            TenantState::Active => counts.active += 1,
            TenantState::Suspended => counts.suspended += 1,
            TenantState::Revoked => counts.revoked += 1,
        }
    }
    counts
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
///
/// A [`TenantState::Revoked`] tenant signs nothing (`None`), so a revoked
/// tenant's key can never mint a webhook signature even if a caller reaches this
/// primitive without first consulting [`notify_config`].
pub fn sign_webhook(
    store: &TenantStore,
    tenant: &TenantId,
    message: &[u8],
) -> Option<[u8; rally_point_proto::token::SIGNATURE_LEN]> {
    let guard = store.tenants.lock();
    let key = guard.get(tenant)?;
    if key.state == TenantState::Revoked {
        return None;
    }
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

    #[test]
    fn a_pkcs8_v1_document_enrolls_and_derives_the_matching_verifying_key() {
        // The RFC 5208 v1 prefix for an Ed25519 private key, followed by the
        // raw 32-byte seed — the exact document `openssl genpkey -algorithm
        // ed25519` emits (no embedded public key).
        const V1_PREFIX: [u8; 16] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        let seed = [0x42u8; 32];
        let mut doc = V1_PREFIX.to_vec();
        doc.extend_from_slice(&seed);

        let store = new_store();
        let enrolled = enroll_from_pkcs8(
            &store,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
            &doc,
        )
        .unwrap();

        let expected = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        assert_eq!(enrolled.as_slice(), expected.public_key().as_ref());
    }

    #[test]
    fn non_pkcs8_bytes_still_fail_enrollment() {
        let store = new_store();
        let err = enroll_from_pkcs8(
            &store,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
            b"not a key document",
        )
        .unwrap_err();
        assert!(matches!(err, KeyError::InvalidPkcs8));
    }

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
    fn all_verifying_keys_returns_every_enrolled_tenant() {
        let store = new_store();
        let bounds = BufferBounds::new(1, 6).unwrap();
        let pk_a = enroll(
            &store,
            KeyId("kid-a".to_owned()),
            TenantId("tenant-a".to_owned()),
            bounds,
        )
        .unwrap();
        let pk_b = enroll(
            &store,
            KeyId("kid-b".to_owned()),
            TenantId("tenant-b".to_owned()),
            bounds,
        )
        .unwrap();

        let mut keys = all_verifying_keys(&store);
        keys.sort_by(|l, r| l.kid.as_ref().cmp(r.kid.as_ref()));
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].kid, KeyId("kid-a".to_owned()));
        assert_eq!(keys[0].tenant, TenantId("tenant-a".to_owned()));
        assert_eq!(keys[0].verifying_key, pk_a.to_vec());
        assert_eq!(keys[1].kid, KeyId("kid-b".to_owned()));
        assert_eq!(keys[1].verifying_key, pk_b.to_vec());
    }

    #[test]
    fn all_verifying_keys_is_empty_for_a_store_with_no_tenants() {
        assert!(all_verifying_keys(&new_store()).is_empty());
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
    fn set_and_get_client_pubkeys_roundtrips() {
        let (store, _, tenant) = store_with_tenant();

        // Empty until set.
        assert!(client_pubkeys(&store, &tenant).is_empty());

        let pubkey = client_pubkey_from_seed(&RFC8032_SEED).unwrap();
        assert!(set_client_pubkeys(&store, &tenant, vec![pubkey]));
        assert_eq!(client_pubkeys(&store, &tenant), vec![pubkey]);

        // A no-op (and no panic) on an unknown tenant.
        assert!(!set_client_pubkeys(
            &store,
            &TenantId("nope".to_owned()),
            vec![pubkey]
        ));
        assert!(client_pubkeys(&store, &TenantId("nope".to_owned())).is_empty());
    }

    #[test]
    fn set_client_pubkeys_holds_two_keys_in_order() {
        // Rotation posture: a tenant can carry two request-verifying keys at once
        // (old + new), both retrievable in the order they were set.
        let (store, _, tenant) = store_with_tenant();
        let first = client_pubkey_from_seed(&[0x11; 32]).unwrap();
        let second = client_pubkey_from_seed(&[0x22; 32]).unwrap();
        assert!(set_client_pubkeys(&store, &tenant, vec![first, second]));
        assert_eq!(client_pubkeys(&store, &tenant), vec![first, second]);
    }

    #[test]
    fn a_freshly_enrolled_tenant_is_active() {
        let (store, _, tenant) = store_with_tenant();
        assert_eq!(tenant_state(&store, &tenant), Some(TenantState::Active));
        // An unknown tenant has no state.
        assert_eq!(tenant_state(&store, &TenantId("nope".to_owned())), None);
    }

    #[test]
    fn set_and_get_state_roundtrips() {
        let (store, _, tenant) = store_with_tenant();
        assert!(set_state(&store, &tenant, TenantState::Suspended));
        assert_eq!(tenant_state(&store, &tenant), Some(TenantState::Suspended));
        assert!(set_state(&store, &tenant, TenantState::Revoked));
        assert_eq!(tenant_state(&store, &tenant), Some(TenantState::Revoked));

        // A no-op on an unknown tenant.
        assert!(!set_state(
            &store,
            &TenantId("nope".to_owned()),
            TenantState::Active
        ));
    }

    #[test]
    fn notify_config_is_withheld_from_a_revoked_tenant() {
        let (store, _, tenant) = store_with_tenant();
        set_notify(
            &store,
            &tenant,
            Some(NotifyConfig {
                url: "http://localhost/hook".to_owned(),
            }),
        );

        // Active and suspended both report the config (a suspended tenant's live
        // games keep delivering webhooks); revoked withholds it entirely.
        assert!(notify_config(&store, &tenant).is_some());
        set_state(&store, &tenant, TenantState::Suspended);
        assert!(notify_config(&store, &tenant).is_some());
        set_state(&store, &tenant, TenantState::Revoked);
        assert!(notify_config(&store, &tenant).is_none());
    }

    #[test]
    fn sign_webhook_refuses_a_revoked_tenant() {
        let (store, _, tenant) = store_with_tenant();
        assert!(sign_webhook(&store, &tenant, b"anything").is_some());
        set_state(&store, &tenant, TenantState::Suspended);
        assert!(
            sign_webhook(&store, &tenant, b"anything").is_some(),
            "a suspended tenant's key still signs its live games' webhooks",
        );
        set_state(&store, &tenant, TenantState::Revoked);
        assert!(sign_webhook(&store, &tenant, b"anything").is_none());
    }

    #[test]
    fn default_bounds_is_one_to_twelve() {
        assert_eq!(default_bounds(), BufferBounds::new(1, 12).unwrap());
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
