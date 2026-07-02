//! Sans-I/O framing for the client ↔ relay reliable control stream.
//!
//! The datagram path deliberately carries only what redundancy can recover: a
//! turn too large to ever fit a datagram has no bundle that could re-carry it,
//! so it travels here instead — the reliable side-channel each side opens as
//! one bidirectional QUIC stream right after the auth handshake. QUIC's stream
//! reliability replaces the redundancy/ack machinery for these payloads;
//! nothing rides the stream that ordinary turns need, so the head-of-line
//! blocking a reliable stream brings is confined to the rare oversize turn
//! that chose it. (The same "reliable is fine off the turn path" reasoning as
//! the ack-beacon: see [`beacon`](crate::beacon).)
//!
//! The framing is a 4-byte little-endian length prefix followed by an encoded
//! [`ControlFrame`]. Unlike the hello and beacon frames, a control frame is
//! variable-size — it carries a whole payload — so the length prefix is
//! load-bearing and **attacker-facing**: the relay reads these off client
//! connections, so the length is capped ([`MAX_CONTROL_FRAME_LEN`]) before any
//! allocation, and a frame over the cap is a protocol error that closes the
//! stream, never a `Vec::with_capacity` the peer sized.
//!
//! Like the sibling codecs, the stream reads and writes stay with the caller;
//! this module only frames and unframes.

use prost::Message;

use crate::messages::ControlFrame;

/// The largest encoded [`ControlFrame`] a reader will accept, and the largest
/// a writer will produce. Bounds the allocation an attacker-supplied length
/// prefix can demand. Generous against its resident: an oversize turn is one
/// game step's command bytes — a few hundred bytes past the ~1200-byte
/// datagram budget in practice — so 64 KiB leaves room for pathological turns
/// and future frame kinds without letting a length prefix demand megabytes.
pub const MAX_CONTROL_FRAME_LEN: usize = 64 * 1024;

/// Size of the length prefix that precedes each encoded frame.
pub const CONTROL_LEN_PREFIX: usize = 4;

/// A control frame that could not be encoded or decoded.
#[derive(Debug, thiserror::Error)]
pub enum ControlStreamError {
    /// The frame (encoded, or as declared by a received length prefix) exceeds
    /// [`MAX_CONTROL_FRAME_LEN`]. On the read side this is the guard that a
    /// peer-supplied length never sizes an allocation; on the write side it
    /// means the payload is too large even for the control stream and must be
    /// refused outright.
    #[error("control frame of {len} bytes exceeds the {MAX_CONTROL_FRAME_LEN}-byte cap")]
    FrameTooLarge { len: usize },
    /// The frame bytes did not decode as a [`ControlFrame`].
    #[error("control frame did not decode: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Encodes `frame` with its length prefix, ready to write to the stream.
pub fn encode_frame(frame: &ControlFrame) -> Result<Vec<u8>, ControlStreamError> {
    let len = frame.encoded_len();
    if len > MAX_CONTROL_FRAME_LEN {
        return Err(ControlStreamError::FrameTooLarge { len });
    }
    let mut bytes = Vec::with_capacity(CONTROL_LEN_PREFIX + len);
    bytes.extend_from_slice(&(len as u32).to_le_bytes());
    frame.encode(&mut bytes).expect("Vec write is infallible");
    Ok(bytes)
}

/// Validates a received length prefix, returning the frame body length to
/// read. Rejecting an over-cap length *here* — before the caller allocates or
/// reads — is the attacker-facing guard.
pub fn frame_len(prefix: [u8; CONTROL_LEN_PREFIX]) -> Result<usize, ControlStreamError> {
    let len = u32::from_le_bytes(prefix) as usize;
    if len > MAX_CONTROL_FRAME_LEN {
        return Err(ControlStreamError::FrameTooLarge { len });
    }
    Ok(len)
}

/// Decodes a frame body of exactly the length [`frame_len`] returned.
pub fn decode_frame(body: &[u8]) -> Result<ControlFrame, ControlStreamError> {
    Ok(ControlFrame::decode(body)?)
}

#[cfg(test)]
mod tests {
    use crate::messages::{Payload, control_frame};

    use super::*;

    fn oversize_turn(bytes: usize) -> ControlFrame {
        ControlFrame {
            kind: Some(control_frame::Kind::OversizeTurn(Payload {
                seq: 9,
                slot: 2,
                commands: vec![0x0C; bytes].into(),
                game_frame_count: Some(41),
                buffer_directive: None,
            })),
        }
    }

    #[test]
    fn frames_round_trip() {
        let frame = oversize_turn(2000);
        let encoded = encode_frame(&frame).unwrap();

        let mut prefix = [0u8; CONTROL_LEN_PREFIX];
        prefix.copy_from_slice(&encoded[..CONTROL_LEN_PREFIX]);
        let len = frame_len(prefix).unwrap();
        assert_eq!(len, encoded.len() - CONTROL_LEN_PREFIX);
        assert_eq!(decode_frame(&encoded[CONTROL_LEN_PREFIX..]).unwrap(), frame);
    }

    #[test]
    fn an_over_cap_length_prefix_is_rejected_before_any_read() {
        // An attacker-supplied length prefix demanding 4GB must fail at the
        // prefix check, never reach an allocation.
        let prefix = u32::MAX.to_le_bytes();
        assert!(matches!(
            frame_len(prefix),
            Err(ControlStreamError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn an_over_cap_frame_is_refused_at_encode() {
        let frame = oversize_turn(MAX_CONTROL_FRAME_LEN + 1);
        assert!(matches!(
            encode_frame(&frame),
            Err(ControlStreamError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn an_unknown_frame_kind_decodes_with_the_oneof_unset() {
        // A frame kind a newer peer added: field 15, some bytes. It must
        // decode (kind = None) so the reader can skip it, not a stream-fatal
        // decode error.
        let unknown = [0x7A, 0x03, 1, 2, 3]; // field 15, wire type 2, len 3
        let frame = decode_frame(&unknown).unwrap();
        assert_eq!(frame.kind, None);
    }
}
