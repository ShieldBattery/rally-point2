//! Connection-bound, per-tenant authorization tokens.
//!
//! A token authorizes one client to submit turns for one slot in one session.
//! It carries a `kid` (which tenant signing key signed it), is bound to the
//! client's QUIC connection (so a stolen bearer token is useless off its
//! connection), and is validated by the relay before any turn is accepted.
//!
//! ## Token format (v1)
//!
//! The wire encoding is a compact, length-prefixed binary format — not protobuf
//! — because the signature must cover a *canonical* byte sequence and protobuf
//! field ordering is not guaranteed canonical across encoders:
//!
//! ```text
//!  offset  field           type/size        signed?
//!  ------  -----           ---------        -------
//!  0       version         u8 (= 1)         ✓
//!  1       kid_len         u8
//!  2       kid             [u8; kid_len]    ✓
//!  2+kl    tenant_len      u8               ✓
//!  3+kl    tenant          [u8; tenant_len] ✓
//!  ..      session         u64 LE           ✓
//!  ..      slot            u8               ✓
//!  ..      expires_at      u64 LE           ✓
//!  ..      client_pubkey   [u8; 32]         ✓
//!  ..      signature       [u8; 64]         —
//! ```
//!
//! The *signed message* is the byte range `[version .. client_pubkey]` inclusive
//! (everything except the trailing 64-byte signature). The signature is Ed25519
//! over that range, made with the tenant's signing private key (looked up via
//! `kid`). This crate defines the format and encodes/decodes it; the actual
//! sign/verify operations use a crypto library in the consuming crate
//! (coordinator signs, relay verifies — see [`SignedToken::signed_message`]).
//!
//! ## kid → tenant binding (verifier obligation)
//!
//! A valid signature proves only that "the key identified by `kid` signed these
//! claims" — it does **not** prove that `claims.tenant` is the tenant that key
//! belongs to. The relay must treat its registry's `kid → tenant` mapping as
//! authoritative: either verify `claims.tenant` equals the registered tenant
//! for that `kid`, or derive the tenant from `kid` and ignore the claim field.
//! Trusting `claims.tenant` on its own lets a tenant mint a token asserting
//! another tenant's id.
//!
//! ## Connection binding
//!
//! The token embeds the client's Ed25519 public key ([`ClientPublicKey`]). After
//! the QUIC connection is established, the relay sends a random 32-byte
//! [`ConnectionChallenge`]; the client signs it — together with a channel binding
//! derived from the connection — with the matching private key and returns a
//! [`ChallengeResponse`]. The relay verifies the proof against the public key from
//! the token claims. A stolen bearer token is therefore useless without the
//! client's private key, which never leaves the trusted local process pair (app +
//! game DLL).
//!
//! The signed message folds in a TLS channel binding (an RFC 5705 keying-material
//! exporter, [`CHANNEL_BINDING_EXPORTER_LABEL`]) so the proof is tied to the one
//! QUIC/TLS session it was made on. Were it over the nonce alone, a relay the
//! client trusts but that is malicious or mis-selected could forward the real
//! relay's challenge to the client and replay the resulting signature onto its own
//! session to impersonate the client; because the two sessions export different
//! bindings, that replay no longer verifies. This rides the server-authenticated
//! TLS session the client already has, so it still needs no *client* certificate.
//!
//! ## Operational flow (who generates what, when)
//!
//! The **app (Electron)** generates the client's per-session Ed25519 keypair,
//! not the game DLL. This keeps token issuance off the game-startup critical
//! path — the token is signed and ready *before* the game launches, so there is
//! no game→coordinator round-trip during load:
//!
//! ```text
//!  1. app generates Ed25519 keypair (per-session, ephemeral)
//!  2. app → coordinator: session request (includes client_pubkey)
//!  3. coordinator signs token {kid, tenant, session, slot, expires_at, client_pubkey}
//!  4. app → game DLL (launch handoff): {token, private_key, relay_addr}
//!  5. game DLL → relay: QUIC connect + present token
//!  6. relay → game DLL: ConnectionChallenge (32 random bytes)
//!  7. game DLL → relay: ChallengeResponse (Ed25519 signature over challenge)
//!  8. relay verifies signature against client_pubkey from token claims
//! ```
//!
//! The private key is ephemeral (per-session, never persisted) and lives only
//! in trusted local processes: the app briefly, then the game DLL. The
//! app→game handoff crosses the Electron↔native-DLL boundary alongside the
//! token and relay address (the launch-handoff channel that already exists).
//!
//! This crate is format-only — it defines the token layout, claims, and
//! encode/decode. The sign/verify operations use a crypto library in the
//! consuming crates (coordinator signs; relay verifies).

use serde::{Deserialize, Serialize};

use crate::{
    control::TenantId,
    ids::{SessionId, SlotId},
};

/// Current token wire-format version.
pub const TOKEN_VERSION: u8 = 1;

/// Ed25519 public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 signature length in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Length of the relay's connection-binding challenge nonce, in bytes.
pub const CHALLENGE_LEN: usize = 32;

/// Length of the channel-binding value folded into the signed challenge, in bytes.
pub const CHANNEL_BINDING_LEN: usize = 32;

/// RFC 5705 TLS exporter label the client and relay both use to derive the
/// channel binding from their shared QUIC connection. Exporting with the same
/// label, context, and length on each end of one TLS session yields identical
/// bytes, while a different session — such as one a relay-in-the-middle holds —
/// yields different bytes; that difference is what ties the connection proof to
/// its own channel.
pub const CHANNEL_BINDING_EXPORTER_LABEL: &[u8] = b"rally-point2/connection-binding/v1";

/// Maximum length of a `kid` or tenant string in the wire format. The length
/// prefix is a single `u8`, so 255 is the hard protocol limit — strings longer
/// than this cannot be encoded and are rejected at construction time.
pub const MAX_STRING_LEN: usize = u8::MAX as usize;

/// A 1-byte domain tag prepended to every challenge the client signs, so the
/// ephemeral client key can never be confused with the tenant signing key (which
/// signs tokens, not challenges). Cheap insurance against cross-context
/// signature reuse if the client key is ever repurposed.
pub const CHALLENGE_DOMAIN_TAG: u8 = 0x01;

/// Identifies which tenant signing key signed a token — the `kid` header.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

impl KeyId {
    /// Construct a `kid`, rejecting strings longer than [`MAX_STRING_LEN`].
    ///
    /// The wire format uses a `u8` length prefix, so a `kid` longer than 255
    /// bytes cannot be encoded. Validating at construction prevents a silent
    /// truncation in [`SignedToken::encode`].
    pub fn new(s: impl Into<String>) -> Result<Self, TokenError> {
        let s = s.into();
        if s.len() > MAX_STRING_LEN {
            return Err(TokenError::StringTooLong);
        }
        Ok(Self(s))
    }
}

impl From<KeyId> for String {
    fn from(kid: KeyId) -> String {
        kid.0
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The client's Ed25519 public key, embedded in the token to bind it to the
/// client's QUIC connection.
///
/// The client proves possession of the matching private key via a
/// challenge-response after connecting (see module docs). Stored as a raw byte
/// array — this crate does not depend on a crypto library; sign/verify live in
/// the consuming crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientPublicKey(pub [u8; PUBLIC_KEY_LEN]);

impl ClientPublicKey {
    /// Construct from a byte slice, copying into a fixed array. Returns `None`
    /// if the slice is not exactly [`PUBLIC_KEY_LEN`] bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        let arr: &[u8; PUBLIC_KEY_LEN] = slice.try_into().ok()?;
        Some(Self(*arr))
    }

    /// The raw key bytes.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }
}

/// An Ed25519 signature over a token's signed-message range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature(pub [u8; SIGNATURE_LEN]);

impl Signature {
    /// Construct from a byte slice. Returns `None` if the slice is not exactly
    /// [`SIGNATURE_LEN`] bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        let arr: &[u8; SIGNATURE_LEN] = slice.try_into().ok()?;
        Some(Self(*arr))
    }

    /// The raw signature bytes.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

/// Unix timestamp (seconds) after which the token is no longer valid.
///
/// Set by the coordinator at issuance (typically connection lifetime + margin)
/// and checked by the relay on every connection. Carried in the token's binary
/// encoding as a little-endian u64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExpiresAt(pub u64);

/// The authorization claims a relay validates before accepting any turn.
///
/// These are the fields covered by the coordinator's signature — once signed,
/// they are tamper-evident. The relay checks every submitted turn against
/// `slot` and `session` to prevent slot-spoofing and cross-session replay.
///
/// **kid → tenant:** a valid signature proves only that key `kid` signed these
/// claims; it does **not** prove that `tenant` is the tenant that key belongs
/// to. The relay must cross-check `tenant` against its registry's `kid → tenant`
/// mapping (or derive the tenant from `kid` and ignore this field). See the
/// module-level "kid → tenant binding" docs.
///
/// Serialized via the custom binary format in [`SignedToken`], not serde: the
/// signature must cover a canonical byte sequence, and serde's encoding is not
/// guaranteed canonical across encoders.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TokenClaims {
    /// Tenant this token belongs to.
    pub tenant: TenantId,
    /// Session the bearer may submit turns for.
    pub session: SessionId,
    /// Slot the bearer is bound to; the relay binds every submitted turn to it.
    pub slot: SlotId,
    /// When the token expires (Unix seconds).
    pub expires_at: ExpiresAt,
    /// The client's Ed25519 public key — binds the token to the connection.
    pub client_pubkey: ClientPublicKey,
}

impl TokenClaims {
    /// Construct a new claims set with the given fields.
    pub fn new(
        tenant: TenantId,
        session: SessionId,
        slot: SlotId,
        expires_at: ExpiresAt,
        client_pubkey: ClientPublicKey,
    ) -> Self {
        Self {
            tenant,
            session,
            slot,
            expires_at,
            client_pubkey,
        }
    }
}

/// A signed authorization token: the claims plus the coordinator's Ed25519
/// signature over the canonical signed-message range.
///
/// The token is presented by the client to the relay once, at QUIC connection
/// setup — never per-turn. The relay verifies the signature (using the tenant's
/// public key, looked up by `kid`) and then runs the connection-binding
/// challenge-response (see module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedToken {
    /// Which tenant signing key produced `signature`.
    pub kid: KeyId,
    /// The signed authorization claims.
    pub claims: TokenClaims,
    /// The Ed25519 signature over the signed-message range.
    pub signature: Signature,
}

/// Errors that arise when encoding, decoding, or inspecting a token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The byte sequence does not conform to any known token format.
    #[error("malformed token: {0}")]
    Malformed(&'static str),
    /// The token's version byte is not recognized by this build.
    #[error("unsupported token version: {0}")]
    UnsupportedVersion(u8),
    /// The `kid` or tenant string exceeds [`MAX_STRING_LEN`] bytes.
    #[error("string field exceeds {MAX_STRING_LEN} bytes")]
    StringTooLong,
    /// The trailing bytes after the signature are not empty — the token has
    /// unexpected trailing data.
    #[error("unexpected trailing bytes after signature")]
    TrailingBytes,
}

impl SignedToken {
    /// Assemble a token from pre-computed parts.
    ///
    /// The coordinator calls this after signing
    /// [`SignedToken::signed_message`] with the tenant's private key. This
    /// crate does not perform the signing — the consuming crate supplies the
    /// signature.
    pub fn from_parts(kid: KeyId, claims: TokenClaims, signature: Signature) -> Self {
        Self {
            kid,
            claims,
            signature,
        }
    }

    /// The canonical byte range that the Ed25519 signature covers.
    ///
    /// This is everything in the wire encoding *except* the trailing 64-byte
    /// signature: `[version][kid][tenant][session][slot][expires_at]
    /// [client_pubkey]`. The coordinator signs these exact bytes; the relay
    /// verifies the signature against them.
    ///
    /// Returns an error if the `kid` or tenant string exceeds [`MAX_STRING_LEN`]
    /// (which can only happen if the token was built via [`KeyId`] or
    /// [`TenantId`](crate::control::TenantId) without the checked constructors).
    /// Appends the bytes to `out`; the caller owns the buffer.
    pub fn signed_message(&self, out: &mut Vec<u8>) -> Result<(), TokenError> {
        encode_signed_range(out, TOKEN_VERSION, &self.kid, &self.claims)
    }

    /// Encode the full token (signed range + signature) to a byte vector.
    ///
    /// Returns an error if the `kid` or tenant string exceeds [`MAX_STRING_LEN`]
    /// — the `u8` length prefix cannot represent a longer string, and silent
    /// truncation would corrupt the signed range.
    pub fn encode(&self) -> Result<Vec<u8>, TokenError> {
        let cap = self.encoded_len().unwrap_or(0);
        let mut buf = Vec::with_capacity(cap);
        self.encode_to(&mut buf)?;
        Ok(buf)
    }

    /// Append the full token encoding to `out`.
    ///
    /// Returns an error if the `kid` or tenant string exceeds [`MAX_STRING_LEN`].
    pub fn encode_to(&self, out: &mut Vec<u8>) -> Result<(), TokenError> {
        encode_signed_range(out, TOKEN_VERSION, &self.kid, &self.claims)?;
        out.extend_from_slice(&self.signature.0);
        Ok(())
    }

    /// The exact byte length of this token's wire encoding, or `None` if a
    /// string field exceeds [`MAX_STRING_LEN`] (in which case the token cannot
    /// be encoded).
    pub fn encoded_len(&self) -> Option<usize> {
        checked_signed_range_len(&self.kid, &self.claims).map(|n| n + SIGNATURE_LEN)
    }

    /// Decode a token from its wire encoding.
    ///
    /// Peeks the version byte first, so a future-format token reports
    /// [`TokenError::UnsupportedVersion`] rather than a misleading
    /// [`TokenError::Malformed`]. Verifies structural validity but does **not**
    /// verify the Ed25519 signature — that requires a crypto library and is the
    /// relay's job. Use [`SignedToken::signed_message`] to obtain the bytes the
    /// signature covers, then verify against the tenant's public key.
    pub fn decode(bytes: &[u8]) -> Result<Self, TokenError> {
        let version = *bytes.first().ok_or(TokenError::Malformed("empty token"))?;
        if version != TOKEN_VERSION {
            return Err(TokenError::UnsupportedVersion(version));
        }

        let (kid, claims, rest) = decode_signed_range_v1(bytes)?;

        let signature_bytes: &[u8; SIGNATURE_LEN] = rest
            .get(..SIGNATURE_LEN)
            .ok_or(TokenError::Malformed("signature too short"))?
            .try_into()
            .unwrap();
        let trailing = &rest[SIGNATURE_LEN..];
        if !trailing.is_empty() {
            return Err(TokenError::TrailingBytes);
        }
        let signature = Signature(*signature_bytes);

        Ok(Self {
            kid,
            claims,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// Connection-binding challenge / response
// ---------------------------------------------------------------------------

/// The relay's challenge nonce, sent to the client after it presents a token.
///
/// The client signs [`signed_message`] with the private key matching the token's
/// [`ClientPublicKey`] and returns a [`ChallengeResponse`]. This proves the
/// client possesses the private key, completing the key-confirmed channel — a
/// stolen bearer token is useless without it.
///
/// [`signed_message`]: ConnectionChallenge::signed_message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionChallenge(pub [u8; CHALLENGE_LEN]);

impl ConnectionChallenge {
    /// Construct from a byte slice. Returns `None` if the slice is not exactly
    /// [`CHALLENGE_LEN`] bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        let arr: &[u8; CHALLENGE_LEN] = slice.try_into().ok()?;
        Some(Self(*arr))
    }

    /// The raw challenge bytes.
    pub fn as_bytes(&self) -> &[u8; CHALLENGE_LEN] {
        &self.0
    }

    /// The canonical bytes the client signs with its Ed25519 private key.
    ///
    /// The message is a 1-byte [`CHALLENGE_DOMAIN_TAG`], then the connection's
    /// `channel_binding`, then this nonce. The domain tag keeps the signature from
    /// ever being confused with the tenant key's token signature (a different byte
    /// range, no tag). The channel binding ties the proof to the one QUIC/TLS
    /// session it was produced on, so a relay that forwards a client's token cannot
    /// relay the client's signature onto a *different* session it holds — the two
    /// sessions derive different bindings. The client and relay both derive the
    /// bytes through this method, so they cannot disagree on the shape, and both
    /// must pass the same `channel_binding`, exported from their shared connection
    /// with [`CHANNEL_BINDING_EXPORTER_LABEL`].
    pub fn signed_message(
        &self,
        channel_binding: &[u8; CHANNEL_BINDING_LEN],
    ) -> [u8; 1 + CHANNEL_BINDING_LEN + CHALLENGE_LEN] {
        let mut out = [0u8; 1 + CHANNEL_BINDING_LEN + CHALLENGE_LEN];
        out[0] = CHALLENGE_DOMAIN_TAG;
        out[1..1 + CHANNEL_BINDING_LEN].copy_from_slice(channel_binding);
        out[1 + CHANNEL_BINDING_LEN..].copy_from_slice(&self.0);
        out
    }
}

/// The client's proof-of-possession: an Ed25519 signature over the relay's
/// [`ConnectionChallenge`].
///
/// The relay verifies this against the [`ClientPublicKey`] from the token's
/// claims. Like [`Signature`], this is a plain byte array — this crate does not
/// perform the verification; the consuming crate (relay) supplies the crypto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChallengeResponse(pub [u8; SIGNATURE_LEN]);

impl ChallengeResponse {
    /// Construct from a byte slice. Returns `None` if the slice is not exactly
    /// [`SIGNATURE_LEN`] bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        let arr: &[u8; SIGNATURE_LEN] = slice.try_into().ok()?;
        Some(Self(*arr))
    }

    /// The raw signature bytes.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Internal encode/decode helpers
// ---------------------------------------------------------------------------

/// Append the signed byte range (version through client_pubkey) to `out`.
///
/// Returns an error if the `kid` or tenant string exceeds [`MAX_STRING_LEN`].
fn encode_signed_range(
    out: &mut Vec<u8>,
    version: u8,
    kid: &KeyId,
    claims: &TokenClaims,
) -> Result<(), TokenError> {
    out.push(version);

    push_string(out, &kid.0)?;
    push_string(out, &claims.tenant.0)?;

    out.extend_from_slice(&claims.session.0.to_le_bytes());
    out.push(claims.slot.0);
    out.extend_from_slice(&claims.expires_at.0.to_le_bytes());
    out.extend_from_slice(&claims.client_pubkey.0);
    Ok(())
}

/// Byte length of the signed range for the given kid + claims, or `None` if a
/// string exceeds [`MAX_STRING_LEN`].
fn checked_signed_range_len(kid: &KeyId, claims: &TokenClaims) -> Option<usize> {
    if kid.0.len() > MAX_STRING_LEN || claims.tenant.0.len() > MAX_STRING_LEN {
        return None;
    }
    Some(signed_range_len(kid, claims))
}

/// Byte length of the signed range. Caller must ensure both strings are
/// `<= MAX_STRING_LEN` (checked by [`checked_signed_range_len`]).
fn signed_range_len(kid: &KeyId, claims: &TokenClaims) -> usize {
    1 // version
    + 1 + kid.0.len() // kid_len + kid
    + 1 + claims.tenant.0.len() // tenant_len + tenant
    + 8 // session
    + 1 // slot
    + 8 // expires_at
    + PUBLIC_KEY_LEN // client_pubkey
}

/// Append a length-prefixed UTF-8 string. Returns an error if the string
/// exceeds [`MAX_STRING_LEN`] — the `u8` length prefix cannot represent a
/// longer value, and silent truncation would corrupt the signed range.
fn push_string(out: &mut Vec<u8>, s: &str) -> Result<(), TokenError> {
    let len = s.len();
    if len > MAX_STRING_LEN {
        return Err(TokenError::StringTooLong);
    }
    out.push(len as u8);
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Decode the v1 signed range (version through client_pubkey), returning the
/// remaining bytes (the signature).
///
/// The version byte is assumed to have already been validated by the caller.
fn decode_signed_range_v1(bytes: &[u8]) -> Result<(KeyId, TokenClaims, &[u8]), TokenError> {
    let mut pos = 1; // skip version (validated by caller)

    let (kid, kid_bytes) = read_string(&bytes[pos..])?;
    pos += kid_bytes;

    let (tenant, tenant_bytes) = read_string(&bytes[pos..])?;
    pos += tenant_bytes;

    let session = read_u64_le(&bytes[pos..])?;
    pos += 8;

    let slot = *bytes
        .get(pos)
        .ok_or(TokenError::Malformed("truncated at slot"))?;
    pos += 1;

    let expires_at = ExpiresAt(read_u64_le(&bytes[pos..])?);
    pos += 8;

    let pubkey_bytes = bytes
        .get(pos..pos + PUBLIC_KEY_LEN)
        .ok_or(TokenError::Malformed("truncated at client_pubkey"))?;
    let client_pubkey = ClientPublicKey::from_slice(pubkey_bytes)
        .ok_or(TokenError::Malformed("invalid client_pubkey length"))?;
    pos += PUBLIC_KEY_LEN;

    let rest = bytes.get(pos..).unwrap_or(&[]);

    let claims = TokenClaims {
        tenant: TenantId(tenant),
        session: SessionId(session),
        slot: SlotId(slot),
        expires_at,
        client_pubkey,
    };

    Ok((KeyId(kid), claims, rest))
}

/// Read a length-prefixed UTF-8 string, returning (string, bytes_consumed).
fn read_string(bytes: &[u8]) -> Result<(String, usize), TokenError> {
    let len = *bytes
        .first()
        .ok_or(TokenError::Malformed("truncated at string length"))? as usize;
    let s_bytes = bytes
        .get(1..1 + len)
        .ok_or(TokenError::Malformed("truncated at string body"))?;
    let s = std::str::from_utf8(s_bytes)
        .map_err(|_| TokenError::Malformed("string field is not valid UTF-8"))?;
    Ok((s.to_owned(), 1 + len))
}

/// Read a little-endian u64, or fail.
fn read_u64_le(bytes: &[u8]) -> Result<u64, TokenError> {
    let arr: &[u8; 8] = bytes
        .get(..8)
        .ok_or(TokenError::Malformed("truncated at u64"))?
        .try_into()
        .unwrap();
    Ok(u64::from_le_bytes(*arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims() -> TokenClaims {
        TokenClaims::new(
            TenantId("sb-staging".to_owned()),
            SessionId(0xDEAD_BEEF_CAFE_BABE),
            SlotId(3),
            ExpiresAt(1_800_000_000),
            ClientPublicKey([0xAB; PUBLIC_KEY_LEN]),
        )
    }

    fn sample_token() -> SignedToken {
        SignedToken::from_parts(
            KeyId("staging-key-1".to_owned()),
            sample_claims(),
            Signature([0xCD; SIGNATURE_LEN]),
        )
    }

    #[test]
    fn round_trip_encode_decode() {
        let token = sample_token();
        let encoded = token.encode().unwrap();
        let decoded = SignedToken::decode(&encoded).unwrap();

        assert_eq!(decoded, token);
    }

    #[test]
    fn encoded_len_is_exact() {
        let token = sample_token();
        let encoded = token.encode().unwrap();
        assert_eq!(encoded.len(), token.encoded_len().unwrap());
    }

    #[test]
    fn signed_message_excludes_signature() {
        let token = sample_token();
        let encoded = token.encode().unwrap();

        let mut signed_msg = Vec::new();
        token.signed_message(&mut signed_msg).unwrap();

        // The signed message is the encoding minus the trailing signature.
        assert_eq!(signed_msg.len(), encoded.len() - SIGNATURE_LEN);
        assert_eq!(&signed_msg[..], &encoded[..encoded.len() - SIGNATURE_LEN]);
    }

    #[test]
    fn signed_message_is_stable() {
        // The same token must always produce the same signed bytes.
        let token = sample_token();

        let mut a = Vec::new();
        let mut b = Vec::new();
        token.signed_message(&mut a).unwrap();
        token.signed_message(&mut b).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn decode_rejects_empty() {
        assert_eq!(
            SignedToken::decode(&[]).unwrap_err(),
            TokenError::Malformed("empty token")
        );
    }

    #[test]
    fn decode_rejects_truncated_signature() {
        let token = sample_token();
        let mut encoded = token.encode().unwrap();
        encoded.truncate(encoded.len() - 1); // drop one signature byte

        assert_eq!(
            SignedToken::decode(&encoded).unwrap_err(),
            TokenError::Malformed("signature too short")
        );
    }

    #[test]
    fn decode_rejects_truncated_claims() {
        let token = sample_token();
        let encoded = token.encode().unwrap();
        // Cut off everything after the version + kid.
        let truncated = &encoded[..1 + 1 + token.kid.0.len()];

        assert!(matches!(
            SignedToken::decode(truncated),
            Err(TokenError::Malformed(_))
        ));
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let token = sample_token();
        let mut encoded = token.encode().unwrap();
        encoded[0] = 99; // bogus version

        assert_eq!(
            SignedToken::decode(&encoded).unwrap_err(),
            TokenError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn decode_unknown_version_before_structural_parse() {
        // A token whose version byte is unknown must report UnsupportedVersion,
        // not Malformed — even if the body is too short to parse as v1.
        let bytes = &[99u8]; // version only, no body
        assert_eq!(
            SignedToken::decode(bytes).unwrap_err(),
            TokenError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn decode_rejects_non_utf8_string() {
        // Build a token with invalid UTF-8 in the kid field.
        let mut buf = Vec::new();
        buf.push(TOKEN_VERSION);
        buf.push(2); // kid_len = 2
        buf.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        // Pad with enough bytes to look like a complete token.
        buf.push(0); // tenant_len = 0
        buf.extend_from_slice(&[0u8; 8]); // session
        buf.push(0); // slot
        buf.extend_from_slice(&[0u8; 8]); // expires_at
        buf.extend_from_slice(&[0u8; PUBLIC_KEY_LEN]); // pubkey
        buf.extend_from_slice(&[0u8; SIGNATURE_LEN]); // signature

        assert!(matches!(
            SignedToken::decode(&buf),
            Err(TokenError::Malformed("string field is not valid UTF-8"))
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let token = sample_token();
        let mut encoded = token.encode().unwrap();
        encoded.push(0x00); // extra byte after signature

        assert_eq!(
            SignedToken::decode(&encoded).unwrap_err(),
            TokenError::TrailingBytes
        );
    }

    #[test]
    fn minimal_token_round_trips() {
        // Smallest valid token: empty kid and tenant strings.
        let token = SignedToken::from_parts(
            KeyId(String::new()),
            TokenClaims::new(
                TenantId(String::new()),
                SessionId(0),
                SlotId(0),
                ExpiresAt(0),
                ClientPublicKey([0; PUBLIC_KEY_LEN]),
            ),
            Signature([0; SIGNATURE_LEN]),
        );

        let encoded = token.encode().unwrap();
        // version(1) + kid_len(1) + tenant_len(1) + session(8) + slot(1)
        // + expires(8) + pubkey(32) + sig(64) = 116
        assert_eq!(encoded.len(), 116);

        let decoded = SignedToken::decode(&encoded).unwrap();
        assert_eq!(decoded, token);
    }

    #[test]
    fn encode_to_appends_without_clearing() {
        let token = sample_token();
        let mut buf = vec![0xFF, 0xEE];
        token.encode_to(&mut buf).unwrap();

        // The prefix is preserved.
        assert_eq!(&buf[..2], &[0xFF, 0xEE]);
        // The rest is the token.
        assert_eq!(buf.len(), 2 + token.encoded_len().unwrap());
    }

    #[test]
    fn public_key_from_slice_rejects_wrong_length() {
        assert!(ClientPublicKey::from_slice(&[]).is_none());
        assert!(ClientPublicKey::from_slice(&[0; 31]).is_none());
        assert!(ClientPublicKey::from_slice(&[0; 33]).is_none());
        assert!(ClientPublicKey::from_slice(&[0; PUBLIC_KEY_LEN]).is_some());
    }

    #[test]
    fn signature_from_slice_rejects_wrong_length() {
        assert!(Signature::from_slice(&[0; 63]).is_none());
        assert!(Signature::from_slice(&[0; 65]).is_none());
        assert!(Signature::from_slice(&[0; SIGNATURE_LEN]).is_some());
    }

    #[test]
    fn key_id_new_rejects_oversized() {
        assert!(KeyId::new(String::new()).is_ok());
        assert!(KeyId::new("a".repeat(MAX_STRING_LEN)).is_ok());
        assert_eq!(
            KeyId::new("a".repeat(MAX_STRING_LEN + 1)).unwrap_err(),
            TokenError::StringTooLong
        );
    }

    #[test]
    fn encode_rejects_oversized_kid() {
        let token = SignedToken::from_parts(
            KeyId("a".repeat(MAX_STRING_LEN + 1)),
            sample_claims(),
            Signature([0; SIGNATURE_LEN]),
        );

        assert_eq!(token.encode().unwrap_err(), TokenError::StringTooLong);
        assert!(token.encoded_len().is_none());
    }

    #[test]
    fn encode_rejects_oversized_tenant() {
        let token = SignedToken::from_parts(
            KeyId("ok".to_owned()),
            TokenClaims::new(
                TenantId("b".repeat(MAX_STRING_LEN + 1)),
                SessionId(0),
                SlotId(0),
                ExpiresAt(0),
                ClientPublicKey([0; PUBLIC_KEY_LEN]),
            ),
            Signature([0; SIGNATURE_LEN]),
        );

        assert_eq!(token.encode().unwrap_err(), TokenError::StringTooLong);
    }

    // --- Challenge / response tests ---

    #[test]
    fn challenge_signed_message_has_tag_binding_and_nonce() {
        let challenge = ConnectionChallenge([0x42; CHALLENGE_LEN]);
        let binding = [0x7C; CHANNEL_BINDING_LEN];
        let signed = challenge.signed_message(&binding);

        assert_eq!(signed[0], CHALLENGE_DOMAIN_TAG);
        assert_eq!(&signed[1..1 + CHANNEL_BINDING_LEN], &binding);
        assert_eq!(&signed[1 + CHANNEL_BINDING_LEN..], challenge.as_bytes());
    }

    #[test]
    fn challenge_signed_message_is_deterministic() {
        let challenge = ConnectionChallenge([0x99; CHALLENGE_LEN]);
        let binding = [0x33; CHANNEL_BINDING_LEN];
        assert_eq!(
            challenge.signed_message(&binding),
            challenge.signed_message(&binding)
        );
    }

    #[test]
    fn challenge_signed_messages_differ_for_different_challenges() {
        let binding = [0x33; CHANNEL_BINDING_LEN];
        let a = ConnectionChallenge([0x11; CHALLENGE_LEN]);
        let b = ConnectionChallenge([0x22; CHALLENGE_LEN]);
        assert_ne!(a.signed_message(&binding), b.signed_message(&binding));
    }

    #[test]
    fn challenge_signed_messages_differ_for_different_channel_bindings() {
        // The same challenge bound to two channels signs differently — the property
        // that stops a proof from being replayed across connections.
        let challenge = ConnectionChallenge([0x55; CHALLENGE_LEN]);
        let cb_a = [0xA1; CHANNEL_BINDING_LEN];
        let cb_b = [0xB2; CHANNEL_BINDING_LEN];
        assert_ne!(
            challenge.signed_message(&cb_a),
            challenge.signed_message(&cb_b)
        );
    }

    #[test]
    fn challenge_from_slice_rejects_wrong_length() {
        assert!(ConnectionChallenge::from_slice(&[]).is_none());
        assert!(ConnectionChallenge::from_slice(&[0; 31]).is_none());
        assert!(ConnectionChallenge::from_slice(&[0; 33]).is_none());
        assert!(ConnectionChallenge::from_slice(&[0; CHALLENGE_LEN]).is_some());
    }

    #[test]
    fn v1_wire_bytes_match_the_golden_vector() {
        // Fixed bytes captured from the v1 encoder, not derived from it at test
        // time. A round-trip test alone would not catch a change that shifts
        // both `encode` and `decode` the same way (e.g. reordering two fields) --
        // that kind of change breaks every token issued by a coordinator before
        // the change, since relays running older code decode the old layout.
        // If this test needs to change, the wire format changed, which means
        // TOKEN_VERSION must be bumped and decode() extended to still accept the
        // old layout -- do not just update the golden bytes below.
        #[rustfmt::skip]
        const GOLDEN: [u8; 139] = [
            // version
            0x01,
            // kid_len(13) + "staging-key-1"
            0x0D, 0x73, 0x74, 0x61, 0x67, 0x69, 0x6E, 0x67, 0x2D, 0x6B, 0x65, 0x79, 0x2D, 0x31,
            // tenant_len(10) + "sb-staging"
            0x0A, 0x73, 0x62, 0x2D, 0x73, 0x74, 0x61, 0x67, 0x69, 0x6E, 0x67,
            // session = 0xDEAD_BEEF_CAFE_BABE, little-endian
            0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE,
            // slot = 3
            0x03,
            // expires_at = 1_800_000_000, little-endian
            0x00, 0xD2, 0x49, 0x6B, 0x00, 0x00, 0x00, 0x00,
            // client_pubkey = [0xAB; 32]
            0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
            0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
            0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
            0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
            // signature = [0xCD; 64]
            0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
            0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
            0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
            0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
            0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
            0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
            0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
            0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
        ];

        let token = sample_token();
        let encoded = token.encode().unwrap();
        assert_eq!(encoded, GOLDEN);

        // The decoder must accept its own golden vector, and produce the same
        // claims that encoded it.
        let decoded = SignedToken::decode(&GOLDEN).unwrap();
        assert_eq!(decoded, token);
    }

    #[test]
    fn challenge_response_from_slice_rejects_wrong_length() {
        assert!(ChallengeResponse::from_slice(&[0; 63]).is_none());
        assert!(ChallengeResponse::from_slice(&[0; 65]).is_none());
        assert!(ChallengeResponse::from_slice(&[0; SIGNATURE_LEN]).is_some());
    }
}
