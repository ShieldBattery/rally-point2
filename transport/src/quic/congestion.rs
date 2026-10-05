//! The congestion controller every link runs: noq's Cubic, with a floor under its window that the
//! turn stream always fits through.
//!
//! Turn traffic is a small fixed-rate stream the game needs delivered whatever the path is doing:
//! the sender can't slow down, only queue. A loss-based controller reads random loss (a weak Wi-Fi
//! link dropping packets without being congested) as congestion and cuts the window on every round
//! trip that loses a packet, until it sits at Cubic's own floor of two full-size packets. On a slow
//! path that is less than the turn stream itself: a client receiving six peers' turns at 24 a
//! second, each bundled with a few hundred bytes of re-carried redundancy, needs about 40 KB/s,
//! while two packets per 100 ms round trip allow 24 KB/s. Turns then wait behind the window and
//! arrive late on exactly the links that were already struggling, while sending less does nothing
//! for the path: the turns are tiny next to whatever else is filling it.
//!
//! So the window never drops below [`MIN_CONGESTION_WINDOW`], which carries the largest session's
//! turn stream over a slow, lossy round trip. Above it Cubic governs exactly as it would alone,
//! which is where a mesh link's aggregated traffic and every connection's slow start live.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use noq::congestion::{Controller, ControllerFactory, ControllerMetrics, CubicConfig};
use noq_proto::RttEstimator;

/// The smallest congestion window a link's controller holds, in bytes.
///
/// The heaviest stream it must carry is a twelve-slot session's eleven peers' turns, 24 a second
/// each, as packets of up to about 500 bytes (a turn with its re-carried redundancy, plus QUIC's
/// header, frame and AEAD tag): 132 KB a second. The window has to cover more than that stream's
/// bytes per round trip, which is all that a lossless path holds in flight. A lost packet counts as
/// in flight until loss detection declares it lost, about another round trip later, and acks arrive
/// up to the ack delay late; at 10% loss over a 400 ms round trip, the stream holds about 62 KB in
/// flight. The controller also refuses a send that would bring the bytes in flight up to the
/// window, reserving a full-size packet. A window at the bare estimate still starves at its peaks
/// and queues turns for seconds, so the floor is twice it.
pub const MIN_CONGESTION_WINDOW: u64 = 128 * 1024;

/// Builds the controller every link runs (see the module docs).
#[derive(Debug, Default)]
pub(super) struct FlooredCubicConfig {
    cubic: Arc<CubicConfig>,
}

impl ControllerFactory for FlooredCubicConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(FlooredCubic {
            inner: Arc::clone(&self.cubic).build(now, current_mtu),
        })
    }
}

/// Cubic, with its window held at [`MIN_CONGESTION_WINDOW`] or above.
#[derive(Debug)]
struct FlooredCubic {
    inner: Box<dyn Controller>,
}

impl Controller for FlooredCubic {
    fn on_sent(&mut self, now: Instant, bytes: u64, largest_pn: u64) {
        self.inner.on_sent(now, bytes, largest_pn);
    }

    fn on_packet_sent(&mut self, now: Instant, bytes: u16, pn: u64) {
        self.inner.on_packet_sent(now, bytes, pn);
    }

    fn on_cwnd_limited(&mut self) {
        self.inner.on_cwnd_limited();
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        pn: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.inner.on_ack(now, sent, bytes, pn, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.inner
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        lost_bytes: u64,
        largest_lost_pn: u64,
    ) {
        self.inner.on_congestion_event(
            now,
            sent,
            is_persistent_congestion,
            is_ecn,
            lost_bytes,
            largest_lost_pn,
        );
    }

    fn on_packet_lost(&mut self, lost_bytes: u16, pn: u64, now: Instant) {
        self.inner.on_packet_lost(lost_bytes, pn, now);
    }

    fn on_spurious_congestion_event(&mut self) {
        self.inner.on_spurious_congestion_event();
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.inner.on_mtu_update(new_mtu);
    }

    fn on_ack_frequency_update(
        &mut self,
        ack_eliciting_threshold: u64,
        requested_max_ack_delay: Duration,
    ) {
        self.inner
            .on_ack_frequency_update(ack_eliciting_threshold, requested_max_ack_delay);
    }

    fn window(&self) -> u64 {
        self.inner.window().max(MIN_CONGESTION_WINDOW)
    }

    /// Cubic's metrics with the floored window, which is also what the pacer spreads sends over a
    /// round trip by: pacing against the unfloored window would hold turns back just the same.
    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = self.inner.metrics();
        metrics.congestion_window = self.window();
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(FlooredCubic {
            inner: self.inner.clone_box(),
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.initial_window().max(MIN_CONGESTION_WINDOW)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests;
