//! End-to-end turn-delivery tracking: which origin's turns have reached which
//! destination *client*, folded at the session's authority relay.
//!
//! Per-link delivery already exists everywhere (packet acks, the ack-beacon),
//! but a packet seq is only an ack handle — a turn can clear one hop and die on
//! the next with no single link looking bad, and chained per-link stalls blow
//! the latency budget invisibly. The final-delivery truth this module folds
//! already exists, though: each client pushes per-origin-slot
//! `delivered_through` cursors up its ack-beacon stream, and its home relay
//! reads them for `retire_through`. That cursor *is* "origin S's turns reached
//! destination D through seq N" — so this is plumbing, not new measurement. The
//! home relay taps the cursor where it already reads it, ships it to the
//! session's other relays over the mesh control stream
//! (`DeliveryCursors`, throttled by [`DELIVERY_SYNC_MIN_INTERVAL`]), and every
//! relay's decision-maker folds its local and mesh-received cursors here.
//!
//! # Lag and hops
//!
//! Per `(origin, dest)` pair, the end-to-end lag in turns is the newest origin
//! seq this relay has observed minus the destination's delivered cursor — one
//! origin seq is exactly one turn. Hop count needs no wire: turns are never
//! re-forwarded relay-to-relay (one mesh hop max), so the source a slot's
//! turns/cursors arrive by *is* its home — the local client edge, or the mesh
//! link to one peer. A pair sharing a home crosses one relay; a cross-homed
//! pair crosses two.
//!
//! # Feeding the buffer (and the adversarial bound)
//!
//! The worst pair lag and the session's max hop count feed the latency-buffer
//! decision as a **clamped additive cushion** ([`cushion_turns`]
//! (DeliveryTracking::cushion_turns)) on the control law's target — the law
//! itself is untouched, and the cushion rides into the existing `BufferBounds`
//! clamp. Beacon cursors are **client-claimed**: a malicious client can only
//! *understate its own* delivery — the same bounded push-the-buffer-up lever it
//! already has by inflating its own link loss — and the cushion cap plus the
//! bounds clamp contain it. It can never stall anyone (an understated cursor
//! never blocks a turn) and never frame another player (a destination's cursor
//! speaks only for that destination).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rally_point_proto::ids::{RelayId, SlotId};

/// The minimum interval between a destination's `DeliveryCursors` shares to the
/// session's mesh peers. Cursors advance roughly once per delivered turn
/// (24/sec), so an unthrottled push-on-advance would spam the control stream
/// with per-turn frames; at this interval a destination costs its home relay at
/// most four tiny frames a second. Coarse is fine: the consumer is a buffer
/// cushion and observability, not the turn path — but the interval also bounds
/// how stale a remote cursor can read, which is why
/// [`E2E_LAG_SLACK_TURNS`] sits comfortably above the ~6 turns of staleness
/// this can add.
pub const DELIVERY_SYNC_MIN_INTERVAL: Duration = Duration::from_millis(250);

/// Cushion turns added per relay hop beyond the first: a cross-relay pair's
/// turn crosses one more send-buffer/redundancy stage than a same-relay pair's,
/// so the buffer carries one extra turn of slack for it. Hop count is 1 or 2 by
/// construction (turns are never re-forwarded relay-to-relay), so this term is
/// bounded at one extra turn without needing its own cap.
pub const EXTRA_HOP_CUSHION_TURNS: u32 = 1;

/// End-to-end lag tolerated before the lag cushion engages, in turns. Observed
/// lag is never zero in healthy play: it includes the turns legitimately in
/// flight (~the path in turns), the beacon's own trip back, and — for a remote
/// destination — up to [`DELIVERY_SYNC_MIN_INTERVAL`] of share staleness
/// (~6 turns at the 24/sec rate). Twelve turns (~500ms) sits clear of all of
/// that; lag beyond it is genuine cross-hop trouble.
pub const E2E_LAG_SLACK_TURNS: u64 = 12;

/// Turns of excess lag (past [`E2E_LAG_SLACK_TURNS`]) per added cushion turn —
/// the lag-responsive term's slope. Deliberately shallow: the cushion nudges
/// the buffer toward absorbing a chained-hop stall, it does not chase the lag.
pub const E2E_LAG_TURNS_PER_CUSHION_TURN: u64 = 4;

/// The lag-responsive cushion term's hard cap, in turns. This is the
/// adversarial bound: a destination that wildly understates its cursor (the
/// worst a malicious client can do with claim-based input) saturates here, so
/// the most it can extract is a few turns of extra buffer for its own session —
/// then the `BufferBounds` clamp contains even that.
pub const E2E_LAG_CUSHION_CAP_TURNS: u32 = 3;

/// Where a slot's traffic reaches this relay from — the basis for hop
/// inference. Turns are never re-forwarded relay-to-relay, so the source *is*
/// the slot's home relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryHome {
    /// The slot is homed on this relay (its turns arrive on the client edge;
    /// its cursors on the local beacon tap).
    Local,
    /// The slot is homed on the named peer relay (its turns arrive on that
    /// peer's mesh link; its cursors in that peer's `DeliveryCursors` frames).
    Peer(RelayId),
}

/// One `(origin, dest)` pair's delivery view, as folded from what the relay
/// observes.
#[derive(Debug, Default, Clone, Copy)]
struct PairDelivery {
    /// The destination's claimed delivered-through cursor for this origin.
    delivered_seq: u64,
}

/// The per-session end-to-end delivery fold, held inside the session's
/// decision-maker alongside its per-slot condition tracking.
#[derive(Debug, Default)]
pub struct DeliveryTracking {
    /// The newest origin seq this relay has observed per slot, with the home
    /// the observation arrived by.
    origins: HashMap<SlotId, (u64, DeliveryHome)>,
    /// Each destination's home plus its per-origin delivered cursors.
    dests: HashMap<SlotId, (DeliveryHome, HashMap<SlotId, PairDelivery>)>,
}

impl DeliveryTracking {
    /// Records one observed origin turn: `origin` produced (and this relay saw)
    /// `seq`, arriving by `home`. Monotonic on the seq, and only a *strictly
    /// fresher* seq re-stamps the home: the mesh legitimately delivers an
    /// already-seen turn again (the flood's echo, which the topological dedup
    /// drops downstream of this observation), and letting an echo rename a
    /// locally-homed origin as mesh-homed would misread every same-relay pair
    /// as cross-relay. The first path to carry each fresh seq is the slot's
    /// home — the source, by the never-re-forwarded rule — so home inference
    /// follows fresh turns exactly like the dedup follows first copies. A
    /// re-homed slot's fresh turns arrive by its new home, so the stamp still
    /// tracks a re-home.
    pub fn observe_origin(&mut self, origin: SlotId, seq: u64, home: DeliveryHome) {
        match self.origins.get_mut(&origin) {
            Some(entry) => {
                if seq > entry.0 {
                    *entry = (seq, home);
                }
            }
            None => {
                self.origins.insert(origin, (seq, home));
            }
        }
    }

    /// Folds one destination cursor: `dest` claims origin `origin`'s turns
    /// reached it through `delivered_seq`, reported by `home`. Monotonic per
    /// pair — a regressing cursor (a reordered share, or a hostile rewind) is
    /// ignored, mirroring the transport's own `retire_through` guard.
    pub fn observe_delivery(
        &mut self,
        dest: SlotId,
        origin: SlotId,
        delivered_seq: u64,
        home: DeliveryHome,
    ) {
        // A slot never receives its own turns; a self-pair is meaningless.
        if dest == origin {
            return;
        }
        let (dest_home, cursors) = self
            .dests
            .entry(dest)
            .or_insert_with(|| (home, HashMap::new()));
        *dest_home = home;
        let pair = cursors.entry(origin).or_default();
        if delivered_seq > pair.delivered_seq {
            pair.delivered_seq = delivered_seq;
        }
    }

    /// Forgets a departed slot, as origin and destination alike, so a gone
    /// client's frozen cursor cannot hold the worst-lag view (and the cushion)
    /// up forever.
    pub fn forget_slot(&mut self, slot: SlotId) {
        self.origins.remove(&slot);
        self.dests.remove(&slot);
        for (_, cursors) in self.dests.values_mut() {
            cursors.remove(&slot);
        }
    }

    /// The worst observed end-to-end lag across pairs, in turns: newest origin
    /// seq seen here minus the destination's delivered cursor, maximized over
    /// every `(origin, dest)` pair with evidence on both sides. `None` when no
    /// pair has reported yet — absence of evidence adds no cushion.
    pub fn worst_lag_turns(&self) -> Option<u64> {
        let mut worst = None;
        for (dest, (_, cursors)) in &self.dests {
            for (origin, pair) in cursors {
                if origin == dest {
                    continue;
                }
                let Some((newest, _)) = self.origins.get(origin) else {
                    continue;
                };
                let lag = newest.saturating_sub(pair.delivered_seq);
                worst = Some(worst.map_or(lag, |w: u64| w.max(lag)));
            }
        }
        worst
    }

    /// The session's maximum relay hop count across observed pairs: 1 when
    /// every pair shares a home, 2 when any pair crosses relays. `None` until
    /// at least one pair has both ends' homes observed.
    pub fn max_relay_hops(&self) -> Option<u32> {
        let mut max = None;
        for (dest, (dest_home, cursors)) in &self.dests {
            for origin in cursors.keys() {
                if origin == dest {
                    continue;
                }
                let Some((_, origin_home)) = self.origins.get(origin) else {
                    continue;
                };
                let hops = if origin_home == dest_home { 1 } else { 2 };
                max = Some(max.map_or(hops, |m: u32| m.max(hops)));
            }
        }
        max
    }

    /// The clamped additive cushion the latency-buffer target gains from
    /// end-to-end delivery: one turn per relay hop beyond the first
    /// ([`EXTRA_HOP_CUSHION_TURNS`]) plus a shallow lag-responsive term capped
    /// at [`E2E_LAG_CUSHION_CAP_TURNS`]. Zero with no evidence (a fresh or
    /// single-pair-less session), so sessions without delivery data are sized
    /// exactly as before this input existed. See the module docs for the
    /// adversarial bound on the claim-based inputs.
    pub fn cushion_turns(&self) -> u32 {
        let hop_term = self
            .max_relay_hops()
            .unwrap_or(1)
            .saturating_sub(1)
            .saturating_mul(EXTRA_HOP_CUSHION_TURNS);
        let lag_term = self
            .worst_lag_turns()
            .map(|lag| {
                let excess = lag.saturating_sub(E2E_LAG_SLACK_TURNS);
                ((excess / E2E_LAG_TURNS_PER_CUSHION_TURN) as u32).min(E2E_LAG_CUSHION_CAP_TURNS)
            })
            .unwrap_or(0);
        hop_term + lag_term
    }
}

/// The per-destination share throttle a home relay runs at its beacon tap:
/// accumulates the destination's per-origin cursors and decides when a
/// `DeliveryCursors` frame should go to the session's mesh peers —
/// push-on-advance, at most one frame per [`DELIVERY_SYNC_MIN_INTERVAL`].
///
/// Every emitted snapshot is the destination's *complete* current cursor map
/// (declarative, like the frame it fills), which is also what makes a
/// reconnected mesh link converge without an explicit on-establish re-send:
/// cursors advance continuously during play, so the first post-reconnect share
/// — at most one interval away — fully re-syncs the peer.
pub struct CursorShare {
    cursors: HashMap<SlotId, u64>,
    last_sent: Option<Instant>,
    min_interval: Duration,
}

impl CursorShare {
    /// A throttle with the given minimum share interval (production passes
    /// [`DELIVERY_SYNC_MIN_INTERVAL`]; tests inject something tiny or huge).
    pub fn new(min_interval: Duration) -> Self {
        Self {
            cursors: HashMap::new(),
            last_sent: None,
            min_interval,
        }
    }

    /// Records one cursor advance at `now`. Returns the complete snapshot to
    /// share when a frame is due (the cursor advanced and the interval has
    /// elapsed — or nothing was ever shared), else `None`. A non-advancing
    /// cursor never emits: the beacon re-pushing an unchanged value carries no
    /// new information. A first-ever cursor for an origin is an advance even at
    /// seq 0 (delivered-through 0 is the first turn confirmed, not nothing).
    pub fn advance(&mut self, origin: SlotId, seq: u64, now: Instant) -> Option<Vec<(SlotId, u64)>> {
        if let Some(&current) = self.cursors.get(&origin)
            && seq <= current
        {
            return None;
        }
        self.cursors.insert(origin, seq);
        let due = self
            .last_sent
            .is_none_or(|last| now.duration_since(last) >= self.min_interval);
        if !due {
            return None;
        }
        self.last_sent = Some(now);
        let mut snapshot: Vec<(SlotId, u64)> = self.cursors.iter().map(|(s, c)| (*s, *c)).collect();
        snapshot.sort_by_key(|(s, _)| s.0);
        Some(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(n: u8) -> SlotId {
        SlotId(n)
    }

    #[test]
    fn a_regressing_cursor_is_ignored() {
        let mut tracking = DeliveryTracking::default();
        tracking.observe_origin(slot(0), 100, DeliveryHome::Local);
        tracking.observe_delivery(slot(1), slot(0), 90, DeliveryHome::Local);
        assert_eq!(tracking.worst_lag_turns(), Some(10));

        // A stale or hostile rewind must not regress the pair.
        tracking.observe_delivery(slot(1), slot(0), 40, DeliveryHome::Local);
        assert_eq!(tracking.worst_lag_turns(), Some(10));
    }

    #[test]
    fn lag_is_newest_origin_seq_minus_the_delivered_cursor_worst_pair_wins() {
        let mut tracking = DeliveryTracking::default();
        tracking.observe_origin(slot(0), 100, DeliveryHome::Local);
        tracking.observe_origin(slot(1), 200, DeliveryHome::Local);
        // Dest 2 is nearly caught up on origin 0, far behind on origin 1.
        tracking.observe_delivery(slot(2), slot(0), 98, DeliveryHome::Local);
        tracking.observe_delivery(slot(2), slot(1), 150, DeliveryHome::Local);
        assert_eq!(tracking.worst_lag_turns(), Some(50), "the worst pair wins");

        // A pair with no origin evidence contributes nothing.
        tracking.observe_delivery(slot(2), slot(7), 3, DeliveryHome::Local);
        assert_eq!(tracking.worst_lag_turns(), Some(50));
    }

    #[test]
    fn hop_inference_reads_shared_home_as_one_and_cross_home_as_two() {
        let mut tracking = DeliveryTracking::default();
        assert_eq!(tracking.max_relay_hops(), None, "no evidence, no verdict");

        // Origin 0 and dest 1 both local: one relay hop.
        tracking.observe_origin(slot(0), 10, DeliveryHome::Local);
        tracking.observe_delivery(slot(1), slot(0), 10, DeliveryHome::Local);
        assert_eq!(tracking.max_relay_hops(), Some(1));

        // Origin 2 homed on a peer, dest 1 local: the pair crosses two relays.
        tracking.observe_origin(slot(2), 10, DeliveryHome::Peer(RelayId(9)));
        tracking.observe_delivery(slot(1), slot(2), 10, DeliveryHome::Local);
        assert_eq!(tracking.max_relay_hops(), Some(2));

        // Two slots sharing the same *peer* home are still one hop apart: their
        // turns never route through this relay.
        let mut same_peer = DeliveryTracking::default();
        same_peer.observe_origin(slot(0), 5, DeliveryHome::Peer(RelayId(9)));
        same_peer.observe_delivery(slot(1), slot(0), 5, DeliveryHome::Peer(RelayId(9)));
        assert_eq!(same_peer.max_relay_hops(), Some(1));
    }

    #[test]
    fn a_mesh_echo_of_a_seen_turn_does_not_re_stamp_the_origins_home() {
        // The mesh flood re-delivers a locally-validated turn (the echo the
        // topological dedup drops); observed pre-dedup with the same seq, it
        // must not rename the local origin as mesh-homed — that would misread
        // every same-relay pair as cross-relay.
        let mut tracking = DeliveryTracking::default();
        tracking.observe_origin(slot(0), 10, DeliveryHome::Local);
        tracking.observe_origin(slot(0), 10, DeliveryHome::Peer(RelayId(2)));
        tracking.observe_delivery(slot(1), slot(0), 10, DeliveryHome::Local);
        assert_eq!(
            tracking.max_relay_hops(),
            Some(1),
            "the echo did not re-stamp the origin's home",
        );

        // A strictly fresher seq by a new source DOES move the home — a
        // re-homed slot's fresh turns arrive by its new home relay.
        tracking.observe_origin(slot(0), 11, DeliveryHome::Peer(RelayId(2)));
        assert_eq!(tracking.max_relay_hops(), Some(2));
    }

    #[test]
    fn a_forgotten_slot_releases_the_worst_lag_view() {
        let mut tracking = DeliveryTracking::default();
        tracking.observe_origin(slot(0), 100, DeliveryHome::Local);
        tracking.observe_delivery(slot(1), slot(0), 10, DeliveryHome::Local);
        assert_eq!(tracking.worst_lag_turns(), Some(90));

        // The lagging destination departs: its frozen cursor must not hold the
        // cushion up forever.
        tracking.forget_slot(slot(1));
        assert_eq!(tracking.worst_lag_turns(), None);
    }

    #[test]
    fn the_cushion_is_zero_without_evidence_and_saturates_at_its_caps() {
        let mut tracking = DeliveryTracking::default();
        assert_eq!(tracking.cushion_turns(), 0, "no evidence adds nothing");

        // A healthy same-relay pair inside the slack: still zero.
        tracking.observe_origin(slot(0), 100, DeliveryHome::Local);
        tracking.observe_delivery(slot(1), slot(0), 95, DeliveryHome::Local);
        assert_eq!(tracking.cushion_turns(), 0);

        // A cross-relay pair adds the hop term.
        tracking.observe_origin(slot(2), 100, DeliveryHome::Peer(RelayId(9)));
        tracking.observe_delivery(slot(1), slot(2), 95, DeliveryHome::Local);
        assert_eq!(tracking.cushion_turns(), EXTRA_HOP_CUSHION_TURNS);

        // The malicious case: a destination understating its cursor by miles
        // saturates the lag term at its cap — never more.
        tracking.observe_delivery(slot(1), slot(0), 0, DeliveryHome::Local);
        tracking.observe_origin(slot(0), 1_000_000, DeliveryHome::Local);
        assert_eq!(
            tracking.cushion_turns(),
            EXTRA_HOP_CUSHION_TURNS + E2E_LAG_CUSHION_CAP_TURNS,
            "an absurd understated cursor saturates at the cap",
        );
    }

    #[test]
    fn the_share_throttle_emits_once_per_interval() {
        let mut share = CursorShare::new(Duration::from_millis(250));
        let t0 = Instant::now();

        // The first advance shares immediately (nothing was ever sent).
        let first = share.advance(slot(0), 1, t0);
        assert_eq!(first, Some(vec![(slot(0), 1)]));

        // Two rapid advances inside the interval emit nothing further.
        assert_eq!(share.advance(slot(0), 2, t0 + Duration::from_millis(50)), None);
        assert_eq!(share.advance(slot(0), 3, t0 + Duration::from_millis(100)), None);

        // The next advance past the interval carries the complete current map.
        let later = share.advance(slot(0), 4, t0 + Duration::from_millis(300));
        assert_eq!(later, Some(vec![(slot(0), 4)]));

        // A non-advancing re-push emits nothing even past the interval.
        assert_eq!(share.advance(slot(0), 4, t0 + Duration::from_secs(10)), None);
    }

    #[test]
    fn the_share_snapshot_carries_every_origins_cursor() {
        let mut share = CursorShare::new(Duration::from_millis(0));
        let t0 = Instant::now();
        share.advance(slot(2), 7, t0);
        let snapshot = share.advance(slot(0), 3, t0 + Duration::from_millis(1));
        assert_eq!(
            snapshot,
            Some(vec![(slot(0), 3), (slot(2), 7)]),
            "each share is the destination's complete, sorted cursor map",
        );
    }
}
