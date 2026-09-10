//! The peer's recent-packet record, kept in the exact shape the wire's
//! `ack` / `ack_bits` pair needs.
//!
//! It is the receive-side half of the ack machinery and the only place loss in
//! the peer-to-us direction is ever measured, so it is grouped on its own,
//! away from the send-side bookkeeping it feeds.

/// The peer packet history represented directly in the wire format's shape.
///
/// `most_recent` is the packet named by `Packet::ack`; bit `N` of `ack_bits`
/// records `most_recent - (N + 1)`. Receiving a newer packet shifts the window
/// forward, while a late packet sets its one bit if it is still insertable by
/// the prior 33-entry [`SequenceBuffer`] semantics. Keeping this rolling form
/// makes reading the outgoing ack state constant-time instead of probing a ring
/// 32 times for every packet built.
///
/// [`SequenceBuffer`]: crate::sequence_buffer::SequenceBuffer
#[derive(Default)]
pub(super) struct ReceivedPacketHistory {
    pub(super) most_recent: Option<u32>,
    pub(super) ack_bits: u32,
    /// Peer packet seqs that left the window without ever being received — the
    /// receive-side mirror of the QUIC path's send-side `lost_packets`, and the
    /// only measure of loss in the peer-to-us direction (an endpoint cannot ask
    /// its stack what it never got). Counted at the moment a seq becomes
    /// unrecoverable rather than when a gap first appears, so a packet
    /// reordered behind up to 31 of its successors still lands as received.
    ///
    /// Peer-assigned seqs, so a peer that skips them inflates its own number.
    /// That makes this an observability signal only: nothing that sizes a
    /// buffer or decides a session may read it without the same
    /// client-influenceable treatment the delivery cursors get.
    pub(super) lost: u64,
    /// The first seq ever recorded, so the empty window a connection opens with
    /// is not read as 32 packets that went missing before it began.
    first: Option<u32>,
}

impl ReceivedPacketHistory {
    pub(super) fn record(&mut self, seq: u32) {
        let Some(most_recent) = self.most_recent else {
            self.most_recent = Some(seq);
            self.first = Some(seq);
            return;
        };

        match seq.cmp(&most_recent) {
            std::cmp::Ordering::Greater => {
                let advanced = seq - most_recent;
                self.note_departed(most_recent, advanced);
                self.ack_bits = if advanced <= 32 {
                    self.ack_bits.checked_shl(advanced).unwrap_or(0) | (1u32 << (advanced - 1))
                } else {
                    0
                };
                self.most_recent = Some(seq);
            }
            std::cmp::Ordering::Less => {
                let behind = most_recent - seq;
                // The old 33-entry SequenceBuffer's next-free cursor is one
                // beyond `most_recent`, so a packet exactly 32 behind is already
                // one full capacity behind that cursor and is not inserted.
                if behind < 32 {
                    self.ack_bits |= 1u32 << (behind - 1);
                }
            }
            std::cmp::Ordering::Equal => {}
        }
    }

    /// Accrues the seqs that this advance pushes out of reach, given the window
    /// is about to shift by `advanced`.
    ///
    /// Two disjoint groups leave. The tracked ones are the top `advanced` bits
    /// of the current window (bit `N` holds `most_recent - (N + 1)`, so the
    /// oldest seqs sit in the highest bits); every one of those still unset was
    /// never received. Beyond that, an advance of more than 33 skips seqs that
    /// the shifted window will not even cover — those are gone without ever
    /// having had a bit to set. Positions addressing seqs from before the
    /// connection's first are neither: they are the window still filling.
    fn note_departed(&mut self, most_recent: u32, advanced: u32) {
        let Some(first) = self.first else {
            return;
        };
        let tracked = advanced.min(32);
        let mut unset = 0u32;
        for age in (32 - tracked)..32 {
            // Bit `age` holds `most_recent - (age + 1)`. A position addressing a
            // seq the connection never reached is empty window, not a gap.
            let Some(departing) = most_recent.checked_sub(age + 1) else {
                continue;
            };
            if departing >= first && self.ack_bits & (1u32 << age) == 0 {
                unset += 1;
            }
        }
        let never_tracked = advanced.saturating_sub(33);
        self.lost = self
            .lost
            .saturating_add(u64::from(unset))
            .saturating_add(u64::from(never_tracked));
    }
}
