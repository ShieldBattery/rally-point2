//! What every loop folds a received turn into: the exact-delivery ledger and
//! the latency/stall accounting around it.
//!
//! Grouped here because all three loops share one instance and none of them
//! interprets it — they hand turns in, and `run_player` reads the totals back
//! out once every loop has finished.

use std::collections::HashMap;
use std::time::Instant;

use rally_point_client::proto::messages::Payload;
use rally_point_proto::ids::SlotId;
use tokio::sync::mpsc;

use crate::metrics::PlayerReport;

use super::SendTimes;

/// Compact exact-delivery ledger for one destination player. Each bit names one
/// measured `(origin slot, frame)`; the own-slot range remains unused so indexing
/// stays a cheap multiply/add on the receive path.
pub(super) struct DeliveryTracker {
    own_slot: usize,
    players: usize,
    measured_turns: usize,
    seen: Vec<bool>,
    pub(super) distinct: u64,
    pub(super) duplicate: u64,
}

impl DeliveryTracker {
    pub(super) fn new(own_slot: SlotId, players: usize, measured_turns: u64) -> Self {
        let measured_turns =
            usize::try_from(measured_turns).expect("validated measured turn count must fit usize");
        let entries = players
            .checked_mul(measured_turns)
            .expect("validated delivery ledger size must fit usize");
        Self {
            own_slot: usize::from(own_slot.0),
            players,
            measured_turns,
            seen: vec![false; entries],
            distinct: 0,
            duplicate: 0,
        }
    }

    pub(super) fn observe(&mut self, payload: &Payload) {
        let Ok(origin) = usize::try_from(payload.slot) else {
            return;
        };
        let Some(frame) = payload
            .game_frame_count
            .and_then(|frame| usize::try_from(frame).ok())
        else {
            return;
        };
        if origin >= self.players || origin == self.own_slot || frame >= self.measured_turns {
            return;
        }
        let index = origin * self.measured_turns + frame;
        if self.seen[index] {
            self.duplicate += 1;
        } else {
            self.seen[index] = true;
            self.distinct += 1;
        }
    }

    pub(super) fn expected(&self) -> u64 {
        (self.players.saturating_sub(1) as u64).saturating_mul(self.measured_turns as u64)
    }

    pub(super) fn is_complete(&self) -> bool {
        self.distinct == self.expected()
    }
}

/// One player's measurement state, threaded through every loop as a unit: the
/// shared send-instant map to measure fan-out against, the stall threshold, the
/// per-origin arrival clock, the report being filled in, and the delivery
/// ledger.
pub(super) struct Measurement<'a> {
    pub(super) send_times: &'a SendTimes,
    stall_threshold_us: u64,
    last_recv: HashMap<u32, Instant>,
    pub(super) stats: PlayerReport,
    pub(super) deliveries: DeliveryTracker,
}

impl<'a> Measurement<'a> {
    pub(super) fn new(
        send_times: &'a SendTimes,
        stall_threshold_us: u64,
        stats: PlayerReport,
        deliveries: DeliveryTracker,
    ) -> Self {
        Self {
            send_times,
            stall_threshold_us,
            last_recv: HashMap::new(),
            stats,
            deliveries,
        }
    }

    /// Folds one received peer turn in: fan-out latency (against the shared send
    /// instant for its `(slot, frame)`) and inter-arrival gap/stall accounting
    /// per source slot.
    pub(super) fn observe(&mut self, payload: &Payload) {
        self.stats.turns_received += 1;
        self.deliveries.observe(payload);
        let now = Instant::now();

        if let Some(frame) = payload.game_frame_count {
            let sent = self
                .send_times
                .lock()
                .ok()
                .and_then(|map| map.get(&(payload.slot, frame)).copied());
            if let Some(sent) = sent {
                self.stats
                    .fan_out_latency_us
                    .push(now.saturating_duration_since(sent).as_micros() as u64);
            }
        }

        if let Some(prev) = self.last_recv.get(&payload.slot).copied() {
            let gap = now.saturating_duration_since(prev).as_micros() as u64;
            self.stats.inter_arrival_gap_us.push(gap);
            if gap > self.stall_threshold_us {
                self.stats.stalls += 1;
            }
        }
        self.last_recv.insert(payload.slot, now);
    }

    /// Counts payloads the driver already handed to the game channel before its
    /// task completed. A Tokio receiver retains buffered values after the sender
    /// drops; returning on the joined driver first would otherwise manufacture
    /// terminal delivery loss in the harness's own accounting.
    pub(super) fn absorb_buffered(&mut self, inbound: &mut mpsc::Receiver<Payload>) {
        while let Ok(payload) = inbound.try_recv() {
            self.observe(&payload);
        }
    }
}
