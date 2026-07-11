//! Sans-I/O codec for the post-QUIC authorization handshake.
//!
//! Right after the QUIC handshake, a client proves it may submit turns over a
//! single client-opened bidirectional stream, in a fixed five-step exchange:
//!
//! ```text
//!   client → relay   u16-LE length, then that many token bytes
//!   relay  → client  32 random challenge bytes
//!   client → relay   64-byte Ed25519 signature over the challenge
//!   client → relay   u16-LE entry count, then that many (u8 slot, u64-LE cursor)
//!                    resume-cursor entries — an empty (zero-count) frame on a
//!                    fresh connect, and never skipped: the relay reads it
//!                    unconditionally, so omitting it deadlocks the handshake
//!   relay  → client  one HANDSHAKE_OK byte (only once the slot is routable)
//! ```
//!
//! The two endpoints live in different crates and must agree on this shape to the
//! byte, so the framing is defined here once and consumed by both. This module is
//! pure: it frames and unframes the two variable-length messages — the
//! length-prefixed token and the count-prefixed resume cursors — and owns the
//! fixed sizes and the acknowledgement sentinel. The actual stream reads and
//! writes, and the Ed25519 sign/verify, stay with the caller, so neither async
//! I/O nor a crypto backend leaks in here.
//!
//! The two fixed-size frames need no codec of their own: the challenge and the
//! response are carried by [`ConnectionChallenge`](crate::token::ConnectionChallenge)
//! and [`ChallengeResponse`](crate::token::ChallengeResponse), whose
//! `as_bytes`/`from_slice` are their wire form, and the acknowledgement is the
//! single [`HANDSHAKE_OK`] byte.

use crate::ids::SlotId;
use crate::token::{SignedToken, TokenError};

/// Width of the little-endian length prefix that precedes the presented token, in
/// bytes. The prefix is a `u16`, so the relay reads exactly this many bytes before
/// it knows how large the token body is.
pub const TOKEN_LEN_PREFIX_LEN: usize = 2;

/// Width of the little-endian count prefix on the resume-cursor frame, in bytes.
/// The prefix is a `u16`, so the relay reads exactly this many bytes before it
/// knows how many `(slot, cursor)` entries follow.
pub const RESUME_CURSOR_COUNT_PREFIX_LEN: usize = 2;

/// Wire width of one resume-cursor entry: a `u8` slot id then a little-endian
/// `u64` cursor.
pub const RESUME_CURSOR_ENTRY_LEN: usize = 1 + 8;

/// Upper bound on the resume-cursor entries a client may present. A game has at
/// most [`MAX_GAME_SLOTS`](crate::ids)-many slots and a client resumes only its
/// peers, so this leaves headroom while capping the buffer the relay reads for an
/// attacker-supplied count. Sixteen entries is 144 bytes — never a real allocation
/// concern, but bounded on principle since the count is attacker-facing.
pub const MAX_RESUME_CURSORS: usize = 16;

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
    /// The resume-cursor frame's entry count exceeds [`MAX_RESUME_CURSORS`]. On
    /// decode this is refused before reading the claimed entries; on encode the
    /// client is trying to resume more slots than a game can hold.
    #[error("resume-cursor count {count} exceeds the maximum of {MAX_RESUME_CURSORS}")]
    TooManyResumeCursors { count: usize },
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

/// Frames the client's per-slot resume cursors for the handshake: a little-endian
/// [`RESUME_CURSOR_COUNT_PREFIX_LEN`]-byte entry count, then each entry as a `u8`
/// slot id and a little-endian `u64` cursor. A reconnecting client sends the seq
/// it next needs from each peer slot; a fresh dial sends an empty map (count 0),
/// which asks the relay to replay nothing. The client writes the returned bytes to
/// the handshake stream right after its challenge response.
pub fn encode_resume_cursors(cursors: &[(SlotId, u64)]) -> Result<Vec<u8>, HandshakeError> {
    if cursors.len() > MAX_RESUME_CURSORS {
        return Err(HandshakeError::TooManyResumeCursors {
            count: cursors.len(),
        });
    }
    // Bounded above by MAX_RESUME_CURSORS, which is below u16::MAX, so the cast is
    // lossless.
    let count = cursors.len() as u16;
    let mut frame = Vec::with_capacity(
        RESUME_CURSOR_COUNT_PREFIX_LEN + cursors.len() * RESUME_CURSOR_ENTRY_LEN,
    );
    frame.extend_from_slice(&count.to_le_bytes());
    for (slot, cursor) in cursors {
        frame.push(slot.0);
        frame.extend_from_slice(&cursor.to_le_bytes());
    }
    Ok(frame)
}

/// Reads the resume-cursor entry count from its little-endian prefix, bounding the
/// entries the relay reads next. Refusing an over-count prefix here means a hostile
/// count cannot make the relay read entries for cursors that will never arrive.
pub fn decode_resume_cursor_count(
    prefix: [u8; RESUME_CURSOR_COUNT_PREFIX_LEN],
) -> Result<usize, HandshakeError> {
    let count = usize::from(u16::from_le_bytes(prefix));
    if count > MAX_RESUME_CURSORS {
        return Err(HandshakeError::TooManyResumeCursors { count });
    }
    Ok(count)
}

/// Decodes one resume-cursor entry from its fixed [`RESUME_CURSOR_ENTRY_LEN`]-byte
/// wire form: a `u8` slot id then a little-endian `u64` cursor.
pub fn decode_resume_cursor_entry(bytes: [u8; RESUME_CURSOR_ENTRY_LEN]) -> (SlotId, u64) {
    let slot = SlotId(bytes[0]);
    let cursor = u64::from_le_bytes(bytes[1..].try_into().expect("entry has 8 trailing bytes"));
    (slot, cursor)
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
    fn resume_cursor_frame_round_trips() {
        let cursors = [(SlotId(0), 5u64), (SlotId(3), 40), (SlotId(7), 0)];
        let frame = encode_resume_cursors(&cursors).unwrap();

        // Split the frame the way the relay does: the count prefix, then that many
        // fixed-width entries.
        let prefix: [u8; RESUME_CURSOR_COUNT_PREFIX_LEN] =
            frame[..RESUME_CURSOR_COUNT_PREFIX_LEN].try_into().unwrap();
        let count = decode_resume_cursor_count(prefix).unwrap();
        assert_eq!(count, cursors.len());

        let mut decoded = Vec::new();
        let mut rest = &frame[RESUME_CURSOR_COUNT_PREFIX_LEN..];
        for _ in 0..count {
            let entry: [u8; RESUME_CURSOR_ENTRY_LEN] =
                rest[..RESUME_CURSOR_ENTRY_LEN].try_into().unwrap();
            decoded.push(decode_resume_cursor_entry(entry));
            rest = &rest[RESUME_CURSOR_ENTRY_LEN..];
        }
        assert_eq!(decoded, cursors);
        assert!(rest.is_empty());
    }

    #[test]
    fn an_empty_resume_cursor_frame_is_just_a_zero_count() {
        let frame = encode_resume_cursors(&[]).unwrap();
        assert_eq!(frame, 0u16.to_le_bytes());
        let count = decode_resume_cursor_count(frame.as_slice().try_into().unwrap()).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn resume_cursor_count_refuses_an_over_long_prefix() {
        let too_many = u16::try_from(MAX_RESUME_CURSORS + 1).unwrap();
        assert_eq!(
            decode_resume_cursor_count(too_many.to_le_bytes()),
            Err(HandshakeError::TooManyResumeCursors {
                count: MAX_RESUME_CURSORS + 1,
            }),
        );
    }

    #[test]
    fn encode_resume_cursors_refuses_too_many() {
        let cursors: Vec<(SlotId, u64)> = (0..=MAX_RESUME_CURSORS)
            .map(|i| (SlotId(i as u8), 0))
            .collect();
        assert!(matches!(
            encode_resume_cursors(&cursors),
            Err(HandshakeError::TooManyResumeCursors { .. })
        ));
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
