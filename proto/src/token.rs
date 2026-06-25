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
//! ## Connection binding
//!
//! The token embeds the client's Ed25519 public key ([`ClientPublicKey`]). After
//! the QUIC connection is established, the relay sends a random 32-byte
//! challenge; the client signs it with the matching private key and returns the
//! signature. The relay verifies the proof against the public key from the token
//! claims. A stolen bearer token is therefore useless without the client's
//! private key, which never leaves the game process.
//!
//! This is a *key-confirmed channel*: the binding is independent of QUIC's own
//! TLS identity layer, so it works with any QUIC configuration and doesn't
//! require client TLS certificates.
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
//!  6. relay → game DLL: 32-byte challenge
//!  7. game DLL → relay: Ed25519 signature over challenge (proves private key)
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

/// Maximum length of a `kid` or tenant string in the wire format (one length
/// byte, so the hard limit is 255; this is a sanity bound, not a protocol limit).
pub const MAX_STRING_LEN: usize = 255;

/// Identifies which tenant signing key signed a token — the `kid` header.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

/// The client's Ed25519 public key, embedded in the token to bind it to the
/// client's QUIC connection.
///
/// The client proves possession of the matching private key via a
/// challenge-response after connecting (see module docs). Stored as a raw byte
/// array — this crate does not depend on a crypto library; sign/verify live in
/// the consuming crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
/// public key, looked up by [`kid`]) and then runs the connection-binding
/// challenge-response (see module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedToken {
    /// Which tenant signing key produced [`signature`].
    pub kid: KeyId,
    /// The signed authorization claims.
    pub claims: TokenClaims,
    /// The Ed25519 signature over [`signed_message`].
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
    /// The `kid` or tenant string exceeds [`MAX_STRING_LEN`].
    #[error("string field exceeds {MAX_STRING_LEN} bytes")]
    StringTooLong,
}

impl SignedToken {
    /// Assemble a token from pre-computed parts.
    ///
    /// The coordinator calls this after signing [`TokenClaims::signed_message`]
    /// with the tenant's private key. This crate does not perform the signing —
    /// the consuming crate supplies the signature.
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
    /// Returns the bytes appended to `out`; the caller owns the buffer.
    pub fn signed_message(&self, out: &mut Vec<u8>) {
        encode_signed_range(out, TOKEN_VERSION, &self.kid, &self.claims);
    }

    /// Encode the full token (signed range + signature) to a byte vector.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode_to(&mut buf);
        buf
    }

    /// Append the full token encoding to `out`.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        encode_signed_range(out, TOKEN_VERSION, &self.kid, &self.claims);
        out.extend_from_slice(&self.signature.0);
    }

    /// The exact byte length of this token's wire encoding.
    pub fn encoded_len(&self) -> usize {
        signed_range_len(&self.kid, &self.claims) + SIGNATURE_LEN
    }

    /// Decode a token from its wire encoding.
    ///
    /// Verifies the version byte and structural validity but does **not**
    /// verify the Ed25519 signature — that requires a crypto library and is the
    /// relay's job. Use [`signed_message`] to obtain the bytes the signature
    /// covers, then verify against the tenant's public key.
    pub fn decode(bytes: &[u8]) -> Result<Self, TokenError> {
        let (version, kid, claims, rest) = decode_signed_range(bytes)?;

        if version != TOKEN_VERSION {
            return Err(TokenError::UnsupportedVersion(version));
        }

        let signature =
            Signature::from_slice(rest).ok_or(TokenError::Malformed("signature too short"))?;

        Ok(Self {
            kid,
            claims,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// Internal encode/decode helpers
// ---------------------------------------------------------------------------

/// Append the signed byte range (version through client_pubkey) to `out`.
fn encode_signed_range(out: &mut Vec<u8>, version: u8, kid: &KeyId, claims: &TokenClaims) {
    out.push(version);

    push_string(out, &kid.0);
    push_string(out, &claims.tenant.0);

    out.extend_from_slice(&claims.session.0.to_le_bytes());
    out.push(claims.slot.0);
    out.extend_from_slice(&claims.expires_at.0.to_le_bytes());
    out.extend_from_slice(&claims.client_pubkey.0);
}

/// Byte length of the signed range for the given kid + claims.
fn signed_range_len(kid: &KeyId, claims: &TokenClaims) -> usize {
    1 // version
    + 1 + kid.0.len() // kid_len + kid
    + 1 + claims.tenant.0.len() // tenant_len + tenant
    + 8 // session
    + 1 // slot
    + 8 // expires_at
    + PUBLIC_KEY_LEN // client_pubkey
}

/// Append a length-prefixed UTF-8 string. Caller must ensure `len <= MAX_STRING_LEN`.
fn push_string(out: &mut Vec<u8>, s: &str) {
    let len = s.len();
    debug_assert!(len <= MAX_STRING_LEN);
    out.push(len as u8);
    out.extend_from_slice(s.as_bytes());
}

/// Decode the signed range (version through client_pubkey), returning the
/// remaining bytes (the signature).
fn decode_signed_range(bytes: &[u8]) -> Result<(u8, KeyId, TokenClaims, &[u8]), TokenError> {
    let mut pos = 0;

    let version = *bytes.first().ok_or(TokenError::Malformed("empty token"))?;
    pos += 1;

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

    Ok((version, KeyId(kid), claims, rest))
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
        let encoded = token.encode();
        let decoded = SignedToken::decode(&encoded).unwrap();

        assert_eq!(decoded, token);
    }

    #[test]
    fn encoded_len_is_exact() {
        let token = sample_token();
        let encoded = token.encode();
        assert_eq!(encoded.len(), token.encoded_len());
    }

    #[test]
    fn signed_message_excludes_signature() {
        let token = sample_token();
        let encoded = token.encode();

        let mut signed_msg = Vec::new();
        token.signed_message(&mut signed_msg);

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
        token.signed_message(&mut a);
        token.signed_message(&mut b);

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
        let mut encoded = token.encode();
        encoded.truncate(encoded.len() - 1); // drop one signature byte

        assert_eq!(
            SignedToken::decode(&encoded).unwrap_err(),
            TokenError::Malformed("signature too short")
        );
    }

    #[test]
    fn decode_rejects_truncated_claims() {
        let token = sample_token();
        let encoded = token.encode();
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
        let mut encoded = token.encode();
        encoded[0] = 99; // bogus version

        assert_eq!(
            SignedToken::decode(&encoded).unwrap_err(),
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

        let encoded = token.encode();
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
        token.encode_to(&mut buf);

        // The prefix is preserved.
        assert_eq!(&buf[..2], &[0xFF, 0xEE]);
        // The rest is the token.
        assert_eq!(buf.len(), 2 + token.encoded_len());
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
}
