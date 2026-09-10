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
    // Every enrollment path funnels through here (`enroll`, `enroll_generated`,
    // and the durable-key startup path), so this is where the game-side buffer
    // ceiling is enforced for programmatic tenant sources — the JSON registry
    // loader checks it separately for its friendlier startup error, but a
    // caller handing in deserialized bounds bypasses that loader entirely
    // (`BufferBounds`'s fields are public and the type derives `Deserialize`,
    // both bypassing `BufferBounds::new`). Inversion is rejected first: with
    // `min > max`, `max` alone understates what `clamp`'s swap-tolerant
    // reading actually allows (`{ min: 15, max: 1 }` clamps as `1..=15`), so
    // an inverted range could smuggle an over-ceiling depth past a max-only
    // check. A `max` past the ceiling would have every session's relay clamp
    // it back anyway, so refusing here surfaces the misconfiguration instead
    // of silently serving narrower bounds than the tenant asked for.
    if bounds.min > bounds.max {
        return Err(KeyError::InvertedBounds {
            min: bounds.min,
            max: bounds.max,
        });
    }
    if bounds.max > rally_point_proto::control::GAME_SYNC_SAFE_BUFFER_MAX {
        return Err(KeyError::BoundsPastGameSafeMax { max: bounds.max });
    }
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
    /// The tenant's buffer-bounds `max` exceeds the game-sync-safe ceiling
    /// ([`rally_point_proto::control::GAME_SYNC_SAFE_BUFFER_MAX`]) — a depth
    /// past it deterministically mass-drops the game's players, so enrollment
    /// refuses it rather than serving a tenant whose policy the relays would
    /// have to clamp back.
    #[error(
        "buffer bounds max {max} exceeds the game-sync-safe ceiling \
         ({})",
        rally_point_proto::control::GAME_SYNC_SAFE_BUFFER_MAX
    )]
    BoundsPastGameSafeMax { max: u32 },
    /// The tenant's buffer bounds are inverted (`min > max`) — only reachable
    /// through deserialized bounds that bypassed `BufferBounds::new`, and
    /// refused rather than swap-read because an inverted range's real extent
    /// is `max..=min`, which a max-only ceiling check would misjudge.
    #[error("buffer bounds inverted: min {min} > max {max}")]
    InvertedBounds { min: u32, max: u32 },
}

/// Creates an empty tenant store for a coordinator with no tenants enrolled.
pub fn new_store() -> TenantStore {
    TenantStore::default()
}

#[cfg(test)]
mod tests;
