//! How much redundancy an outgoing packet spends and how often one payload is
//! re-carried.
//!
//! Both knobs are pure policy — no state, no I/O — so they live apart from the
//! manager that applies them: the byte budget bounds a single packet's
//! redundancy, and the carry-spacing schedule bounds how often one payload
//! comes back around.

/// Policy governing how much redundancy a packet carries and how often one
/// payload is re-carried.
///
/// The unacked window is proportional to the path's round-trip time (a payload
/// stays in it until an ack returns), so an unbounded refill makes bundle bytes
/// grow with delay — largest exactly when the path is squeezed and every byte
/// deepens the queue. The two knobs bound that coupling independently: the
/// byte budget caps what any single packet spends on redundancy, and carry
/// spacing stops re-carrying a payload every packet once it has had its dense
/// initial coverage, letting bundles fall back toward baseline even while the
/// window itself is stretched by an inflated RTT.
///
/// The fresh payload is exempt from both: the current turn always rides.
///
/// The two bounds hold in different failure regimes, which is why both exist
/// (established in `recarry_sim`, whose squeeze scenarios reproduce the
/// production fade shape). When a fade squeezes the path near the turn
/// stream's own byte rate, the *spacing* is what keeps the system stable: it
/// converts unacked-window growth into flat redundancy load, where an
/// every-packet refill — even a budget-capped one — feeds the queue→RTT→window
/// feedback loop until delivery runs seconds behind. When the path is squeezed
/// *below* the fresh byte rate (an outright outage-grade fade, where lockstep
/// must stall no matter what), spacing's aggregate no longer converges — the
/// due set grows with the window — and the *budget* is what still bounds every
/// bundle. Neither bound substitutes for the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecarryPolicy {
    /// Max encoded bytes of redundant payload elements per packet (each counted
    /// as its full repeated-field element, tag and length included, matching
    /// how the datagram budget is consumed). `None` fills to the datagram
    /// budget. The datagram budget still applies on top: the effective cap is
    /// the smaller of the two. A packet's *first* redundancy element is capped
    /// by the datagram budget alone — a payload wider than this budget must
    /// still be re-carryable (lockstep cannot drop it), so the real bound per
    /// packet is this budget plus at most one payload.
    pub redundancy_byte_budget: Option<usize>,
    /// Minimum packets between carries of one payload, as a function of how
    /// often it has been carried. `None` re-carries every packet.
    pub spacing: Option<CarrySpacing>,
}

impl RecarryPolicy {
    /// No bounds: every packet re-carries the whole unacked window up to the
    /// datagram budget. For tests that isolate the refill mechanics.
    pub fn unbounded() -> Self {
        Self {
            redundancy_byte_budget: None,
            spacing: None,
        }
    }
}

impl Default for RecarryPolicy {
    /// The shipped policy, chosen from the `recarry_sim` sweeps: a 384-byte
    /// redundancy budget (several typical turns, comfortably above the
    /// healthy-window all-fit size, far under the datagram budget) with dense
    /// carries 2 / max spacing 8. Two dense carries preserve next-packet
    /// recovery of an isolated loss while keeping the sustained re-carry rate
    /// low enough that a capacity-edge fade damps instead of amplifying — the
    /// sweeps tip into runaway at three. The spacing cap of 8 keeps the
    /// worst-case re-carry cadence a third of a second at the turn rate, and
    /// measured best-in-sweep on burst tails and blackout drain.
    fn default() -> Self {
        Self {
            redundancy_byte_budget: Some(384),
            spacing: Some(CarrySpacing {
                dense_carries: 2,
                max_spacing: 8,
            }),
        }
    }
}

/// Carry-spacing schedule: dense at first, then geometrically sparser.
///
/// A payload's first `dense_carries` carries ride consecutive packets — the
/// window in which recovering an isolated loss at the very next packet is the
/// whole point of redundancy. After that, each further carry must wait twice as
/// many packets as the one before, capped at `max_spacing`, so a payload that
/// stays unacked only because acks are late stops taxing every bundle, while
/// one whose carries genuinely died keeps being rescheduled every
/// `max_spacing` packets until the ack-beacon cursor or a packet ack retires
/// it. The schedule is a *floor* on the gap, not a ceiling on the wait: when
/// the due backlog outgrows what the byte budget can serve per packet, due
/// payloads queue — the constrained refill serves the longest-waiting first,
/// so service stays recurrent (the wait scales with the backlog, which the
/// unacked-window cap bounds) but no fixed cadence can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarrySpacing {
    /// Carries that ride consecutive packets before backoff begins.
    pub dense_carries: u32,
    /// Ceiling on the inter-carry gap, in packets.
    pub max_spacing: u32,
}

impl CarrySpacing {
    /// Packets that must elapse since the payload's last carry before it may be
    /// carried again, given it has been carried `send_count` times.
    pub(super) fn required_gap(&self, send_count: u32) -> u32 {
        if send_count <= self.dense_carries {
            1
        } else {
            let doublings = (send_count - self.dense_carries).min(30);
            (1u32 << doublings).min(self.max_spacing.max(1))
        }
    }
}
