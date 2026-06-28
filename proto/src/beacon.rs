//! Sans-I/O codec for the ack-beacon side-channel.
//!
//! Under sustained datagram loss the per-link unacked window can grow without
//! bound: the relay receives a client's turns slower than the client produces
//! them, so the client keeps re-carrying turns the relay has not yet seen, and
//! its `payloads_in_flight` climbs until the relay's receive window rejects the
//! seqs outright. The beacon is the reliable side-channel that keeps the window
//! bounded in the *recoverable* case — when the relay *has* received the turns
//! but the acks riding the datagrams were lost.
//!
//! It is a **push** side-channel, not request/response. Each side opens one
//! outbound unidirectional QUIC stream and writes its monotonic
//! `delivered_through` (the top of the contiguous run of payloads it has handed
//! to its consumer) whenever it advances; the peer reads it and force-retires
//! everything up to that cursor. A cursor that never advances means the peer has
//! a genuine forward gap redundancy cannot cover — that is the sustained-loss
//! case the hard cap on the unacked window trips on, not something a beacon
//! could rescue (it can only retire what the peer actually received).
//!
//! This rides a **reliable ordered QUIC stream** deliberately. The "no
//! reliable-ordered stream for turns" rule in the architecture targets the *data
//! plane*: in-order delivery would head-of-line-block later turns behind a lost
//! one, and retransmit-on-timeout would cost a round-trip per loss — both fatal
//! to lockstep. A single monotonic cursor has no such hazard: there is no
//! "later turn" to block, and ordered delivery of one `u64` is exactly right.
//! Turns stay on datagrams; only the cursor rides the stream.
//!
//! The frame is a fixed-width little-endian `u64`. There is no length prefix
//! (the body is fixed-size, like the handshake's challenge/response frames), so
//! a reader always reads exactly [`BEACON_FRAME_LEN`] bytes per cursor.

/// Wire width of one beacon frame: a single little-endian `u64`.
pub const BEACON_FRAME_LEN: usize = 8;

/// One beacon frame as bytes: `delivered_through` little-endian.
///
/// The caller writes the returned bytes to its outbound beacon stream. Writes
/// are idempotent in effect — the cursor is monotonic, so re-sending the same
/// value is a no-op for the peer (its retire guard rejects anything not strictly
/// greater), but callers should still push only on advance to keep the stream
/// quiet when nothing is moving.
pub fn encode_frame(delivered_through: u64) -> [u8; BEACON_FRAME_LEN] {
    delivered_through.to_le_bytes()
}

/// Decodes one beacon frame's delivered-through cursor.
///
/// `bytes` must be exactly [`BEACON_FRAME_LEN`] long; the reader is responsible
/// for assembling a complete frame before calling this (a dedicated read-loop
/// task that forwards complete frames over a channel — see the transport
/// `Link`), so partial reads never reach here.
pub fn decode_frame(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; BEACON_FRAME_LEN];
    buf.copy_from_slice(bytes);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_cursor() {
        for &seq in &[0, 1, 42, 0x100, u64::MAX] {
            assert_eq!(decode_frame(&encode_frame(seq)), seq);
        }
    }

    #[test]
    fn a_later_cursor_decodes_larger_than_an_earlier_one() {
        // Monotonicity is the property the retire guard relies on; confirm the
        // encoding preserves byte ordering for ascending values.
        let a = encode_frame(100);
        let b = encode_frame(101);
        assert!(u64::from_le_bytes(a) < u64::from_le_bytes(b));
    }
}
