//! Turn-datagram wire framing and the shared turn coordinate.
//!
//! This is the hot path: SC:R turns travel as QUIC datagrams from the game DLL
//! to its home relay, are fanned out across the mesh, and are delivered back
//! into `player_turns[]`. The exact byte layout — session/slot prefix, the
//! `game_frame_count` turn coordinate, and the forward-recovery ack bitfield —
//! is a core Phase 0 contract and is frozen here once reviewed.
//!
//! Recovery is **ours, not QUIC's** (build plan §4): turns ride unreliable QUIC
//! datagrams and the application layer adds redundancy + an ack bitfield over
//! the top. QUIC supplies only encryption, congestion control, migration, and a
//! loss signal.
//!
//! TODO(phase-0): finalize + document the on-wire byte layout and the
//! `encode`/`decode` routines that size bundles to the live `max_datagram_size()`
//! (truncate, never drop the current turn). See build plan §4 and Phase 1 WS-B.

use serde::{Deserialize, Serialize};

/// The shared turn coordinate carried on every turn: SC:R's `game_frame_count`.
///
/// Per **D9**, runtime latency/leave consensus is keyed on this value — not on a
/// transport-local sequence number — so the relay, every mesh peer, and the
/// client all agree on *which* turn a decision applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GameFrameCount(pub u32);

/// A player's 0-based slot within a game.
///
/// The relay binds each submitted turn to the slot carried by the sender's token
/// (**D10**) to prevent slot-spoofing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SlotId(pub u8);

/// Identifies one game session, assigned by the coordinator at session setup.
///
/// One axis of the `tenant/session/slot/turn` observability correlation key
/// (**D8**).
// TODO(phase-0): pin the width/representation alongside the datagram layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

/// A sliding-window acknowledgement bitfield for app-level forward recovery.
///
/// Each leg acknowledges turn receipt with a `(base, received)` pair: `base` is
/// the lowest turn the receiver has *not yet contiguously received*, and
/// `received` marks which of the turns in `base+1 ..= base+WINDOW` have already
/// arrived out of order. The sender uses this to drop already-delivered turns
/// from its retransmit bundle.
///
/// The [`Self::WINDOW`]-turn window is a documented starting point, subject to
/// the Phase 0 interface review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckBitfield {
    base: GameFrameCount,
    /// Bit `i` set ⇒ turn `base + 1 + i` has been received out of order.
    received: u64,
}

impl AckBitfield {
    /// Number of turns past `base` the window can track.
    pub const WINDOW: u32 = u64::BITS;

    /// A fresh bitfield expecting `base` next, with nothing received past it.
    pub fn new(base: GameFrameCount) -> Self {
        Self { base, received: 0 }
    }

    /// The lowest turn the receiver has not yet contiguously received.
    pub fn base(&self) -> GameFrameCount {
        self.base
    }

    /// Record that `turn` was received, advancing `base` over any newly
    /// contiguous run. Turns older than `base`, or more than [`Self::WINDOW`]
    /// ahead of it, are ignored — the sender will retransmit them.
    pub fn ack(&mut self, turn: GameFrameCount) {
        if turn < self.base {
            return;
        }
        let offset = turn.0 - self.base.0;
        if offset == 0 {
            self.slide_over_base();
        } else if offset <= Self::WINDOW {
            self.received |= 1u64 << (offset - 1);
        }
        // offset > WINDOW: beyond the window, ignored.
    }

    /// Whether `turn` has been received (contiguously below `base`, or marked
    /// out of order within the window).
    pub fn is_received(&self, turn: GameFrameCount) -> bool {
        if turn < self.base {
            return true;
        }
        let offset = turn.0 - self.base.0;
        if offset == 0 || offset > Self::WINDOW {
            return false;
        }
        self.received & (1u64 << (offset - 1)) != 0
    }

    /// `base` itself just arrived; walk it forward over every already-received
    /// turn immediately following it.
    fn slide_over_base(&mut self) {
        loop {
            self.base = GameFrameCount(self.base.0 + 1);
            let next_already_received = self.received & 1 != 0;
            self.received >>= 1;
            if !next_already_received {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: u32) -> GameFrameCount {
        GameFrameCount(n)
    }

    #[test]
    fn contiguous_acks_advance_base() {
        let mut acks = AckBitfield::new(t(0));
        acks.ack(t(0));
        acks.ack(t(1));
        acks.ack(t(2));
        assert_eq!(acks.base(), t(3));
    }

    #[test]
    fn out_of_order_then_fill_jumps_base() {
        let mut acks = AckBitfield::new(t(10));
        acks.ack(t(12));
        acks.ack(t(11));
        // base can't move until the turn it's waiting on actually arrives.
        assert_eq!(acks.base(), t(10));
        assert!(!acks.is_received(t(10)));
        assert!(acks.is_received(t(11)));
        assert!(acks.is_received(t(12)));

        acks.ack(t(10));
        // ...then it jumps over the run that arrived early.
        assert_eq!(acks.base(), t(13));
    }

    #[test]
    fn ignores_stale_and_beyond_window() {
        let mut acks = AckBitfield::new(t(100));
        acks.ack(t(50)); // stale
        acks.ack(t(100 + AckBitfield::WINDOW + 5)); // beyond the window
        assert_eq!(acks.base(), t(100));
    }

    #[test]
    fn tracks_the_window_edge() {
        let mut acks = AckBitfield::new(t(0));
        let edge = t(AckBitfield::WINDOW); // furthest trackable turn
        acks.ack(edge);
        assert!(acks.is_received(edge));
        assert!(!acks.is_received(t(AckBitfield::WINDOW + 1)));
    }
}
