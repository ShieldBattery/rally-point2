//! Client authorization: who is allowed to submit turns, and proof they are who
//! their token claims.
//!
//! A client presents a signed authorization token once, right after the QUIC
//! handshake, and the relay turns it into an [`AuthorizedClient`] — a tenant,
//! session, and slot it trusts for the lifetime of the connection. Two
//! independent things have to hold before that trust is granted:
//!
//! - **The token is authentic and current.** It carries a `kid` naming the
//!   tenant signing key that signed it. The relay looks that `kid` up in its
//!   [`Registry`], verifies the Ed25519 signature over the token's canonical
//!   bytes with the registered key, confirms the token hasn't expired, and
//!   confirms the tenant the token *claims* matches the tenant the registry says
//!   that key belongs to. That last check matters: a valid signature only proves
//!   "the key `kid` signed these claims", not that the claimed tenant owns the
//!   key — so the registry's `kid → tenant` mapping is authoritative and the
//!   claim field is cross-checked against it, never trusted on its own.
//! - **The presenter holds the client private key.** The token embeds the
//!   client's Ed25519 *public* key. A stolen bearer token would otherwise be
//!   replayable, so the relay sends a fresh random challenge and requires a
//!   signature over it — bound to this connection's TLS channel — with the
//!   matching private key before accepting anything. The private key never leaves
//!   the trusted local process pair, so a token lifted off the wire is useless
//!   without it, and the channel binding means a relay that forwards the token
//!   can't relay the resulting signature onto a different session it holds.
//!
//! The handshake rides one client-opened bidirectional QUIC stream — reliable,
//! off the turn-datagram path — with this shape, all on that one stream:
//!
//! ```text
//!   client → relay   u16-LE length, then that many token bytes
//!   relay  → client  32 random challenge bytes
//!   client → relay   64-byte Ed25519 signature over the challenge
//!   relay  → client  one HANDSHAKE_OK byte (only after the slot is registered)
//! ```
//!
//! The relay holds the `OK` byte back until the authorized slot is registered for
//! routing, so any peer that observes this client as connected can already have
//! its turns delivered here. `OK` means *authorized and routable*, not *game
//! started*: deciding when every expected player is present and the session may
//! begin exchanging turns is a higher-layer concern (lobby / ready, over a
//! reliable channel), out of scope for this transport edge — the relay doesn't
//! even know a session's expected roster yet.
//!
//! [`verify_token`] and [`verify_challenge`] are pure and synchronous so the
//! authorization rules are tested without a socket; [`authenticate`] drives the
//! stream around them. This is attacker-facing input: every length is bounded and
//! nothing here can panic on a hostile token.

use std::collections::HashMap;

use rally_point_proto::control::TenantId;
use rally_point_proto::handshake::{self, HandshakeError};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::token::{
    CHALLENGE_LEN, CHANNEL_BINDING_EXPORTER_LABEL, CHANNEL_BINDING_LEN, ChallengeResponse,
    ClientPublicKey, ConnectionChallenge, KeyId, PUBLIC_KEY_LEN, SIGNATURE_LEN, SignedToken,
    TokenError,
};
use rally_point_transport::quinn;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, UnparsedPublicKey};

/// The byte the relay writes to acknowledge an authorized, routable connection.
/// Re-exported from the shared handshake codec so callers reading the relay's
/// edge see it here, while the wire framing stays defined in one place.
pub use rally_point_proto::handshake::HANDSHAKE_OK;

/// What a tenant signing key (`kid`) resolves to: the tenant that owns it and the
/// Ed25519 public key that verifies tokens it signed.
#[derive(Debug, Clone)]
struct TenantKey {
    tenant: TenantId,
    verifying_key: [u8; PUBLIC_KEY_LEN],
}

/// The relay's view of which tenant signing keys exist and who owns them.
///
/// Maps each `kid` to its tenant and verifying key. The relay verifies token
/// signatures against this — never against anything the token itself asserts —
/// so the `kid → tenant` binding here is the authority a forged tenant claim is
/// checked against. A coordinator populates it (authenticated phone-home) once
/// that exists; until then it's seeded directly.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    by_kid: HashMap<KeyId, TenantKey>,
}

impl Registry {
    /// An empty registry that trusts no signing keys.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a tenant signing key: tokens carrying this `kid` are verified
    /// against `verifying_key` and bound to `tenant`. Re-inserting the same `kid`
    /// replaces the prior entry (key rotation).
    pub fn insert(&mut self, kid: KeyId, tenant: TenantId, verifying_key: [u8; PUBLIC_KEY_LEN]) {
        self.by_kid.insert(
            kid,
            TenantKey {
                tenant,
                verifying_key,
            },
        );
    }

    /// Whether any signing keys are registered. A relay with an empty registry
    /// rejects every client, which is worth surfacing at startup.
    pub fn is_empty(&self) -> bool {
        self.by_kid.is_empty()
    }
}

/// A client the relay has authorized: the identity it trusts for the connection.
///
/// `tenant` is the registry's tenant for the signing key, not the token's claim;
/// `session` and `slot` come from the verified token. Every turn this connection
/// submits is bound to `slot`, regardless of what the client puts on the wire.
#[derive(Debug, Clone)]
pub struct AuthorizedClient {
    /// Tenant that owns the signing key — authoritative, from the registry.
    pub tenant: TenantId,
    /// Session the client may submit turns for.
    pub session: SessionId,
    /// Slot the relay binds every submitted turn to.
    pub slot: SlotId,
    /// The client's Ed25519 public key, used to verify the connection-binding
    /// challenge.
    pub client_pubkey: ClientPublicKey,
}

/// Why a client failed authorization.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The token's `kid` is not in the registry, so no key can verify it.
    #[error("token signing key is not registered")]
    UnknownKey,
    /// The signature verified, but the token claims a tenant other than the one
    /// the registry binds to its signing key — a tenant minting a token for
    /// someone else's identity.
    #[error("token claims a tenant that does not own its signing key")]
    TenantMismatch,
    /// The token's expiry is at or before the current time.
    #[error("token has expired")]
    Expired,
    /// The Ed25519 signature over the token's claims did not verify against the
    /// registered tenant key.
    #[error("token signature is invalid")]
    BadSignature,
    /// The client did not prove possession of the private key matching the
    /// token's embedded public key.
    #[error("connection-binding challenge response is invalid")]
    ChallengeFailed,
    /// The connection's TLS channel binding could not be derived, so the
    /// connection-binding proof cannot be checked.
    #[error("deriving the connection's channel binding failed")]
    ChannelBinding,
    /// The presented token was structurally malformed.
    #[error("malformed token: {0}")]
    Token(#[from] TokenError),
    /// The handshake framing was rejected — most often a token length prefix
    /// beyond the allowed maximum, refused without allocating the claimed size.
    #[error("handshake framing error: {0}")]
    Handshake(#[from] HandshakeError),
    /// The secure RNG failed to produce a challenge nonce.
    #[error("generating a challenge nonce failed")]
    Rng,
    /// The QUIC connection failed while opening the handshake stream.
    #[error("handshake connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// Reading the token or challenge response from the handshake stream failed.
    #[error("handshake read error: {0}")]
    Read(#[from] quinn::ReadExactError),
    /// Writing the challenge or acknowledgement to the handshake stream failed.
    #[error("handshake write error: {0}")]
    Write(#[from] quinn::WriteError),
}

/// Verifies a presented token against the registry and the clock, yielding the
/// identity to trust.
///
/// In order: resolve the `kid` to a registered key; verify the Ed25519 signature
/// over the token's canonical bytes (so nothing downstream acts on unauthenticated
/// claims); confirm the claimed tenant matches the key's registered tenant; and
/// confirm the token is still within its validity window. `now_unix_secs` is the
/// current Unix time in seconds; a token expiring exactly now is rejected.
///
/// Proving possession of the client key is a separate step — see
/// [`verify_challenge`] — because it needs a live round trip with the client.
pub fn verify_token(
    registry: &Registry,
    token: &SignedToken,
    now_unix_secs: u64,
) -> Result<AuthorizedClient, AuthError> {
    let entry = registry
        .by_kid
        .get(&token.kid)
        .ok_or(AuthError::UnknownKey)?;

    let mut signed = Vec::new();
    token.signed_message(&mut signed)?;
    verify_ed25519(&entry.verifying_key, &signed, token.signature.as_bytes())
        .map_err(|()| AuthError::BadSignature)?;

    if token.claims.tenant != entry.tenant {
        return Err(AuthError::TenantMismatch);
    }
    if token.claims.expires_at.0 <= now_unix_secs {
        return Err(AuthError::Expired);
    }

    Ok(AuthorizedClient {
        tenant: entry.tenant.clone(),
        session: token.claims.session,
        slot: token.claims.slot,
        client_pubkey: token.claims.client_pubkey,
    })
}

/// Verifies the client's proof that it holds the private key for `client_pubkey`:
/// an Ed25519 signature over the challenge's domain-tagged bytes, bound to
/// `channel_binding` — the keying material exported from this connection. The
/// relay derives `channel_binding` from its own end of the connection, so a
/// signature made against a different session's binding fails here.
pub fn verify_challenge(
    client_pubkey: &ClientPublicKey,
    challenge: &ConnectionChallenge,
    channel_binding: &[u8; CHANNEL_BINDING_LEN],
    response: &ChallengeResponse,
) -> Result<(), AuthError> {
    verify_ed25519(
        client_pubkey.as_bytes(),
        &challenge.signed_message(channel_binding),
        response.as_bytes(),
    )
    .map_err(|()| AuthError::ChallengeFailed)
}

/// Runs the full authorization handshake on `connection` and returns the
/// authorized client, the per-slot resume cursors it presented, and the still-open
/// send stream.
///
/// The caller writes [`HANDSHAKE_OK`] on the returned stream once it has wired the
/// client into routing, so a client only learns it's accepted after its slot can
/// receive turns. On any failure the connection is left for the caller to close.
///
/// The resume cursors are the reconnecting client's per-peer-slot delivery
/// position: the seq it next needs from each slot, so a re-register can replay only
/// the turns the client missed while it was gone. A fresh dial presents an empty
/// map. They are read after — and only after — the challenge-response proof
/// succeeds, so only an authenticated client's cursors are ever parsed; the count
/// is bounded, so a hostile client cannot make the relay read an unbounded frame.
pub async fn authenticate(
    connection: &quinn::Connection,
    registry: &Registry,
    now_unix_secs: u64,
) -> Result<(AuthorizedClient, HashMap<SlotId, u64>, quinn::SendStream), AuthError> {
    let (mut send, mut recv) = connection.accept_bi().await?;

    let mut len_buf = [0u8; handshake::TOKEN_LEN_PREFIX_LEN];
    recv.read_exact(&mut len_buf).await?;
    let token_len = handshake::decode_token_len(len_buf)?;
    let mut token_bytes = vec![0u8; token_len];
    recv.read_exact(&mut token_bytes).await?;
    let token = SignedToken::decode(&token_bytes)?;

    let authorized = verify_token(registry, &token, now_unix_secs)?;

    let mut nonce = [0u8; CHALLENGE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| AuthError::Rng)?;
    let challenge = ConnectionChallenge(nonce);
    send.write_all(challenge.as_bytes()).await?;

    let mut response = [0u8; SIGNATURE_LEN];
    recv.read_exact(&mut response).await?;

    // The proof is bound to this connection's TLS channel, so derive the same
    // keying material the client signed over from our end of the connection.
    let mut channel_binding = [0u8; CHANNEL_BINDING_LEN];
    connection
        .export_keying_material(&mut channel_binding, CHANNEL_BINDING_EXPORTER_LABEL, &[])
        .map_err(|_| AuthError::ChannelBinding)?;

    verify_challenge(
        &authorized.client_pubkey,
        &challenge,
        &channel_binding,
        &ChallengeResponse(response),
    )?;

    let resume_cursors = read_resume_cursors(&mut recv).await?;

    Ok((authorized, resume_cursors, send))
}

/// Reads the client's resume-cursor frame off the authenticated handshake stream:
/// a bounded entry count, then that many `(slot, cursor)` entries. Every length is
/// checked before it is read, so a hostile count cannot force an unbounded read.
async fn read_resume_cursors(
    recv: &mut quinn::RecvStream,
) -> Result<HashMap<SlotId, u64>, AuthError> {
    let mut count_buf = [0u8; handshake::RESUME_CURSOR_COUNT_PREFIX_LEN];
    recv.read_exact(&mut count_buf).await?;
    let count = handshake::decode_resume_cursor_count(count_buf)?;

    let mut cursors = HashMap::with_capacity(count);
    for _ in 0..count {
        let mut entry = [0u8; handshake::RESUME_CURSOR_ENTRY_LEN];
        recv.read_exact(&mut entry).await?;
        let (slot, cursor) = handshake::decode_resume_cursor_entry(entry);
        cursors.insert(slot, cursor);
    }
    Ok(cursors)
}

/// Verifies an Ed25519 signature, collapsing ring's opaque error to `()` so the
/// caller attaches the context-specific meaning (bad token vs. bad challenge).
fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ()> {
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rally_point_proto::token::{ExpiresAt, Signature, TokenClaims};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const NOW: u64 = 1_700_000_000;
    const KID: &str = "staging-key-1";
    const TENANT: &str = "sb-staging";

    /// An Ed25519 keypair we can both sign with and read the public key of.
    struct TestKey {
        pair: Ed25519KeyPair,
        public: [u8; PUBLIC_KEY_LEN],
    }

    fn test_key() -> TestKey {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public = pair.public_key().as_ref().try_into().unwrap();
        TestKey { pair, public }
    }

    impl TestKey {
        fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
            self.pair.sign(message).as_ref().try_into().unwrap()
        }
    }

    /// Mints a token for `slot` signed by `tenant_key`, with the given claimed
    /// tenant and expiry, embedding `client_pub` as the connection-binding key.
    fn mint(
        tenant_key: &TestKey,
        kid: &str,
        claimed_tenant: &str,
        slot: SlotId,
        expires_at: u64,
        client_pub: [u8; PUBLIC_KEY_LEN],
    ) -> SignedToken {
        let claims = TokenClaims::new(
            TenantId(claimed_tenant.to_owned()),
            SessionId(7),
            slot,
            ExpiresAt(expires_at),
            ClientPublicKey(client_pub),
        );
        let mut token =
            SignedToken::from_parts(KeyId(kid.to_owned()), claims, Signature([0; SIGNATURE_LEN]));
        let mut message = Vec::new();
        token.signed_message(&mut message).unwrap();
        token.signature = Signature(tenant_key.sign(&message));
        token
    }

    fn registry_with(kid: &str, tenant: &str, key: &TestKey) -> Registry {
        let mut registry = Registry::new();
        registry.insert(
            KeyId(kid.to_owned()),
            TenantId(tenant.to_owned()),
            key.public,
        );
        registry
    }

    #[test]
    fn accepts_a_well_formed_token() {
        let tenant_key = test_key();
        let client = test_key();
        let registry = registry_with(KID, TENANT, &tenant_key);
        let token = mint(&tenant_key, KID, TENANT, SlotId(3), NOW + 60, client.public);

        let authorized = verify_token(&registry, &token, NOW).unwrap();
        assert_eq!(authorized.tenant.as_ref(), TENANT);
        assert_eq!(authorized.session, SessionId(7));
        assert_eq!(authorized.slot, SlotId(3));
        assert_eq!(authorized.client_pubkey.0, client.public);
    }

    #[test]
    fn rejects_an_unregistered_kid() {
        let tenant_key = test_key();
        let client = test_key();
        let registry = registry_with(KID, TENANT, &tenant_key);
        let token = mint(
            &tenant_key,
            "other-key",
            TENANT,
            SlotId(0),
            NOW + 60,
            client.public,
        );

        assert!(matches!(
            verify_token(&registry, &token, NOW),
            Err(AuthError::UnknownKey)
        ));
    }

    #[test]
    fn rejects_a_signature_from_the_wrong_key() {
        let registered = test_key();
        let impostor = test_key();
        let client = test_key();
        let registry = registry_with(KID, TENANT, &registered);
        // Same kid the registry knows, but signed by a different key.
        let token = mint(&impostor, KID, TENANT, SlotId(0), NOW + 60, client.public);

        assert!(matches!(
            verify_token(&registry, &token, NOW),
            Err(AuthError::BadSignature)
        ));
    }

    #[test]
    fn rejects_a_tampered_claim() {
        let tenant_key = test_key();
        let client = test_key();
        let registry = registry_with(KID, TENANT, &tenant_key);
        let mut token = mint(&tenant_key, KID, TENANT, SlotId(0), NOW + 60, client.public);
        // Flip the slot after signing; the signature no longer covers it.
        token.claims.slot = SlotId(1);

        assert!(matches!(
            verify_token(&registry, &token, NOW),
            Err(AuthError::BadSignature)
        ));
    }

    #[test]
    fn rejects_a_tenant_claim_that_does_not_match_the_key() {
        let tenant_key = test_key();
        let client = test_key();
        // The registry binds this key to TENANT; the token, validly signed by the
        // same key, claims to be a different tenant.
        let registry = registry_with(KID, TENANT, &tenant_key);
        let token = mint(
            &tenant_key,
            KID,
            "some-other-tenant",
            SlotId(0),
            NOW + 60,
            client.public,
        );

        assert!(matches!(
            verify_token(&registry, &token, NOW),
            Err(AuthError::TenantMismatch)
        ));
    }

    #[test]
    fn rejects_an_expired_token() {
        let tenant_key = test_key();
        let client = test_key();
        let registry = registry_with(KID, TENANT, &tenant_key);
        // Expires exactly at NOW — the boundary is treated as expired.
        let token = mint(&tenant_key, KID, TENANT, SlotId(0), NOW, client.public);

        assert!(matches!(
            verify_token(&registry, &token, NOW),
            Err(AuthError::Expired)
        ));
    }

    const CHANNEL_BINDING: [u8; CHANNEL_BINDING_LEN] = [0x6B; CHANNEL_BINDING_LEN];

    #[test]
    fn verifies_a_genuine_challenge_response() {
        let client = test_key();
        let challenge = ConnectionChallenge([0x5A; CHALLENGE_LEN]);
        let signature = client.sign(&challenge.signed_message(&CHANNEL_BINDING));

        verify_challenge(
            &ClientPublicKey(client.public),
            &challenge,
            &CHANNEL_BINDING,
            &ChallengeResponse(signature),
        )
        .unwrap();
    }

    #[test]
    fn rejects_a_challenge_signed_by_the_wrong_key() {
        let client = test_key();
        let impostor = test_key();
        let challenge = ConnectionChallenge([0x5A; CHALLENGE_LEN]);
        let signature = impostor.sign(&challenge.signed_message(&CHANNEL_BINDING));

        assert!(matches!(
            verify_challenge(
                &ClientPublicKey(client.public),
                &challenge,
                &CHANNEL_BINDING,
                &ChallengeResponse(signature),
            ),
            Err(AuthError::ChallengeFailed)
        ));
    }

    #[test]
    fn rejects_a_response_to_a_different_challenge() {
        let client = test_key();
        let issued = ConnectionChallenge([0x11; CHALLENGE_LEN]);
        let other = ConnectionChallenge([0x22; CHALLENGE_LEN]);
        // The client signs a challenge the relay never issued.
        let signature = client.sign(&other.signed_message(&CHANNEL_BINDING));

        assert!(matches!(
            verify_challenge(
                &ClientPublicKey(client.public),
                &issued,
                &CHANNEL_BINDING,
                &ChallengeResponse(signature),
            ),
            Err(AuthError::ChallengeFailed)
        ));
    }

    #[test]
    fn rejects_a_response_bound_to_a_different_channel() {
        // The client signs the right challenge with the right key, but bound to a
        // different connection's channel — the relay-in-the-middle replay. Verified
        // against this connection's binding, it must fail.
        let client = test_key();
        let challenge = ConnectionChallenge([0x5A; CHALLENGE_LEN]);
        let other_channel = [0xC4; CHANNEL_BINDING_LEN];
        let signature = client.sign(&challenge.signed_message(&other_channel));

        assert!(matches!(
            verify_challenge(
                &ClientPublicKey(client.public),
                &challenge,
                &CHANNEL_BINDING,
                &ChallengeResponse(signature),
            ),
            Err(AuthError::ChallengeFailed)
        ));
    }
}
