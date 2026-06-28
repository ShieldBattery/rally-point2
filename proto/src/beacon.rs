//! Sans-I/O codec for the ack-beacon side-channel.
//!
//! Under sustained datagram loss the per-link unacked window can grow without
//! a bound: the relay receives a client's turns slower than the client produces
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
//! # Per-slot cursors
//!
//! A payload's transport `seq` is its **origin** identity: assigned once by the
//! sending client (the sole authority for its own slot's turn stream; it alone
//! knows production order) and preserved end-to-end across every hop, never
//! restamped. Because each slot carries its own monotonic seq space starting at
//! 0, a single global cursor would retire one slot's seqs against another's. So
//! the beacon carries a `(slot, cursor)` pair: the peer force-retires through
//! `cursor` *for that slot only*. Cursors are monotonic per slot, so a re-sent
//! value is a no-op for the peer (its retire guard rejects anything not strictly
//! greater), but callers should still push only on advance to keep the stream
//! quiet when nothing is moving.
//!
//! This rides a **reliable ordered QUIC stream** deliberately. The "no
//! reliable-ordered stream for turns" rule in the architecture targets the *data
//! plane*: in-order delivery would head-of-line-block later turns behind a lost
//! one, and retransmit-on-timeout would cost a round-trip per loss — both fatal
//! to lockstep. A single monotonic cursor has no such hazard: there is no
//! "later turn" to block, and ordered delivery of one `(slot, cursor)` is exactly
//! right. Turns stay on datagrams; only the cursors ride the stream.
//!
//! The frame is fixed-width: a little-endian `u32` slot followed by a
//! little-endian `u64` cursor. There is no length prefix (the body is
//! fixed-size, like the handshake's challenge/response frames), so a reader
//! always reads exactly [`BEACON_FRAME_LEN`] bytes per cursor.

use crate::ids::SlotId;

/// Wire width of one beacon frame: a `u32` slot plus a `u64` cursor.
pub const BEACON_FRAME_LEN: usize = 4 + 8;

/// One beacon frame as bytes: `slot` (LE u32) then `delivered_through` (LE u64).
///
/// The caller writes the returned bytes to its outbound beacon stream. Writes
/// are idempotent in effect — the cursor is monotonic per slot, so re-sending
/// the same value is a no-op for the peer (its retire guard rejects anything not
/// strictly greater), but callers should still push only on advance to keep the
/// stream quiet when nothing is moving.
pub fn encode_frame(slot: SlotId, delivered_through: u64) -> [u8; BEACON_FRAME_LEN] {
    let mut buf = [0u8; BEACON_FRAME_LEN];
    buf[0..4].copy_from_slice(&u32::from(slot.0).to_le_bytes());
    buf[4..12].copy_from_slice(&delivered_through.to_le_bytes());
    buf
}

/// Decodes one beacon frame's `(slot, delivered-through)` cursor.
///
/// `bytes` must be exactly [`BEACON_FRAME_LEN`] long; the reader is responsible
/// for assembling a complete frame before calling this (a dedicated read-loop
/// task that forwards complete frames over a channel — see the transport
/// `Link`), so partial reads never reach here. The slot is narrowed to a `u8`;
/// a frame whose slot does not fit is malformed and rejected by the reader.
pub fn decode_frame(bytes: &[u8]) -> Result<(SlotId, u64), BadSlot> {
    let mut slot_buf = [0u8; 4];
    slot_buf.copy_from_slice(&bytes[0..4]);
    let mut cursor_buf = [0u8; 8];
    cursor_buf.copy_from_slice(&bytes[4..12]);
    let slot_raw = u32::from_le_bytes(slot_buf);
    let cursor = u64::from_le_bytes(cursor_buf);
    u8::try_from(slot_raw)
        .map(SlotId)
        .map(|slot| (slot, cursor))
        .map_err(|_| BadSlot(slot_raw))
}

/// A beacon frame carried a slot that does not fit in a [`SlotId`].
///
/// The wire field is `u32` (matching `Payload.slot`), but a live game never has
/// more than 256 slots, so a value above 255 is a malformed or hostile stream.
/// The reader drops the frame rather than let a garbage slot reach
/// `retire_through`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("beacon slot {0} is out of range for a SlotId (0..=255)")]
pub struct BadSlot(pub u32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_cursor() {
        for &slot in &[0u8, 1, 7, 255] {
            for &seq in &[0, 1, 42, 0x100, u64::MAX] {
                let (got_slot, got_seq) = decode_frame(&encode_frame(SlotId(slot), seq)).unwrap();
                assert_eq!(got_slot, SlotId(slot));
                assert_eq!(got_seq, seq);
            }
        }
    }

    #[test]
    fn rejects_a_slot_that_does_not_fit() {
        // A slot above 255 can't be a SlotId; the reader drops the frame.
        let mut buf = encode_frame(SlotId(0), 0);
        buf[0..4].copy_from_slice(&300u32.to_le_bytes());
        assert_eq!(decode_frame(&buf), Err(BadSlot(300)));
    }
}
