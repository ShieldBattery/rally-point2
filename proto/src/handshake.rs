//! Sans-I/O codec for the post-QUIC authorization handshake.
//!
//! Right after the QUIC handshake, a client proves it may submit turns over a
//! single client-opened bidirectional stream, in a fixed four-step exchange:
//!
//! ```text
//!   client → relay   u16-LE length, then that many token bytes
//!   relay  → client  32 random challenge bytes
//!   client → relay   64-byte Ed25519 signature over the challenge
//!   relay  → client  one HANDSHAKE_OK byte (only once the slot is routable)
//! ```
//!
//! The two endpoints live in different crates and must agree on this shape to the
//! byte, so the framing is defined here once and consumed by both. This module is
//! pure: it frames and unframes the one variable-length message — the
//! length-prefixed token — and owns the fixed sizes and the acknowledgement
//! sentinel. The actual stream reads and writes, and the Ed25519 sign/verify,
//! stay with the caller, so neither async I/O nor a crypto backend leaks in here.
//!
//! The two fixed-size frames need no codec of their own: the challenge and the
//! response are carried by [`ConnectionChallenge`](crate::token::ConnectionChallenge)
//! and [`ChallengeResponse`](crate::token::ChallengeResponse), whose
//! `as_bytes`/`from_slice` are their wire form, and the acknowledgement is the
//! single [`HANDSHAKE_OK`] byte.

use crate::token::{SignedToken, TokenError};

/// Width of the little-endian length prefix that precedes the presented token, in
/// bytes. The prefix is a `u16`, so the relay reads exactly this many bytes before
/// it knows how large the token body is.
pub const TOKEN_LEN_PREFIX_LEN: usize = 2;

/// Upper bound on the length-prefixed token a client may present, in bytes.
///
/// A well-formed token tops out near 626 bytes (a 255-byte `kid`, a 255-byte
/// tenant, the fixed claim fields, and the 64-byte signature); this leaves
/// headroom while capping the buffer a relay allocates for an attacker-supplied
/// length prefix. It sits well below `u16::MAX`, so a length that passes this
/// bound always fits the prefix.
pub const MAX_TOKEN_LEN: usize = 1024;

/// Byte the relay writes once a connection is authorized and its slot is routable:
/// the relay will now carry this client's turns to its peers and peers' turns to
/// it. This is a transport-readiness signal, not a game-start one — when the
/// session actually begins exchanging turns is decided a layer up (lobby / ready,
/// over a reliable channel), so a compliant client has no turns to send until then.
pub const HANDSHAKE_OK: u8 = 0x01;

/// Why framing or unframing a handshake message failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    /// The token's framed length exceeds [`MAX_TOKEN_LEN`]. On decode this is
    /// refused before allocating the claimed size; on encode the token is simply
    /// too large to present.
    #[error("token frame length {len} exceeds the maximum of {MAX_TOKEN_LEN}")]
    TokenTooLong { len: usize },
    /// The token could not be encoded — a `kid` or tenant string exceeds the wire
    /// format's per-string limit.
    #[error("malformed token: {0}")]
    Token(#[from] TokenError),
}

/// Frames a token for presentation: a little-endian [`TOKEN_LEN_PREFIX_LEN`]-byte
/// length followed by the encoded token. The client writes the returned bytes to
/// the handshake stream as its first message.
pub fn encode_token_frame(token: &SignedToken) -> Result<Vec<u8>, HandshakeError> {
    let encoded = token.encode()?;
    if encoded.len() > MAX_TOKEN_LEN {
        return Err(HandshakeError::TokenTooLong { len: encoded.len() });
    }
    // Bounded above by MAX_TOKEN_LEN, which is below u16::MAX, so the cast is lossless.
    let len = encoded.len() as u16;
    let mut frame = Vec::with_capacity(TOKEN_LEN_PREFIX_LEN + encoded.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&encoded);
    Ok(frame)
}

/// Reads the token length from its little-endian prefix, bounding the body the
/// relay reads next. Refusing an over-long length here means a hostile prefix
/// cannot make the relay allocate an unbounded buffer for a token that will never
/// arrive.
pub fn decode_token_len(prefix: [u8; TOKEN_LEN_PREFIX_LEN]) -> Result<usize, HandshakeError> {
    let len = usize::from(u16::from_le_bytes(prefix));
    if len > MAX_TOKEN_LEN {
        return Err(HandshakeError::TokenTooLong { len });
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::TenantId;
    use crate::ids::{SessionId, SlotId};
    use crate::token::{
        ClientPublicKey, ExpiresAt, KeyId, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, TokenClaims,
    };

    fn sample_token() -> SignedToken {
        SignedToken::from_parts(
            KeyId("staging-key-1".to_owned()),
            TokenClaims::new(
                TenantId("sb-staging".to_owned()),
                SessionId(7),
                SlotId(3),
                ExpiresAt(1_800_000_000),
                ClientPublicKey([0xAB; PUBLIC_KEY_LEN]),
            ),
            Signature([0xCD; SIGNATURE_LEN]),
        )
    }

    #[test]
    fn token_frame_round_trips_through_the_length_prefix() {
        let token = sample_token();
        let frame = encode_token_frame(&token).unwrap();

        // Split the frame the way the relay does: read the prefix, then the body.
        let prefix: [u8; TOKEN_LEN_PREFIX_LEN] = frame[..TOKEN_LEN_PREFIX_LEN].try_into().unwrap();
        let len = decode_token_len(prefix).unwrap();
        let body = &frame[TOKEN_LEN_PREFIX_LEN..];

        assert_eq!(len, body.len());
        assert_eq!(SignedToken::decode(body).unwrap(), token);
    }

    #[test]
    fn decode_token_len_refuses_an_over_long_prefix() {
        let too_long = u16::try_from(MAX_TOKEN_LEN + 1).unwrap();
        assert_eq!(
            decode_token_len(too_long.to_le_bytes()),
            Err(HandshakeError::TokenTooLong {
                len: MAX_TOKEN_LEN + 1
            })
        );
    }

    #[test]
    fn decode_token_len_accepts_the_maximum() {
        let max = u16::try_from(MAX_TOKEN_LEN).unwrap();
        assert_eq!(decode_token_len(max.to_le_bytes()), Ok(MAX_TOKEN_LEN));
    }

    #[test]
    fn encode_token_frame_rejects_an_unencodable_token() {
        // A token with an oversized kid can't be encoded at all, so framing fails
        // with the underlying token error rather than producing a bad frame.
        let token = SignedToken::from_parts(
            KeyId("a".repeat(crate::token::MAX_STRING_LEN + 1)),
            sample_token().claims,
            Signature([0; SIGNATURE_LEN]),
        );
        assert!(matches!(
            encode_token_frame(&token),
            Err(HandshakeError::Token(_))
        ));
    }
}
