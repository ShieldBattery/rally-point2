//! Unit coverage for the pieces a live session cannot exercise deterministically:
//! the exact-delivery ledger's counting rules, and the post-driver drain that
//! must not manufacture delivery loss.

use std::sync::{Arc, Mutex};

use rally_point_client::proto::messages::Payload;
use rally_point_proto::ids::SlotId;

use crate::metrics::PlayerReport;

use super::SendTimes;
use super::measure::{DeliveryTracker, Measurement};

fn payload(origin: u32, frame: u32) -> Payload {
    Payload {
        seq: u64::from(frame),
        slot: origin,
        commands: Default::default(),
        game_frame_count: Some(frame),
        sync_generation: None,
        buffer_directive: None,
    }
}

#[test]
fn delivery_tracker_counts_exact_frames_and_duplicates() {
    let mut tracker = DeliveryTracker::new(SlotId(0), 2, 3);
    tracker.observe(&payload(1, 2));
    tracker.observe(&payload(1, 0));
    tracker.observe(&payload(1, 2));
    // Own-slot, unknown-slot, and post-measurement frames are not expected
    // fan-out deliveries and cannot make the ledger look complete.
    tracker.observe(&payload(0, 1));
    tracker.observe(&payload(2, 1));
    tracker.observe(&payload(1, 3));

    assert_eq!(tracker.expected(), 3);
    assert_eq!(tracker.distinct, 2);
    assert_eq!(tracker.duplicate, 1);
    assert!(!tracker.is_complete());

    tracker.observe(&payload(1, 1));
    assert!(tracker.is_complete());
}

#[tokio::test]
async fn buffered_inbound_is_counted_after_the_driver_ends() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    tx.send(payload(1, 0)).await.unwrap();
    drop(tx);

    let send_times: SendTimes = Arc::new(Mutex::new(Default::default()));
    let mut measure = Measurement::new(
        &send_times,
        1_000,
        PlayerReport::default(),
        DeliveryTracker::new(SlotId(0), 2, 1),
    );
    measure.absorb_buffered(&mut rx);

    assert_eq!(measure.stats.turns_received, 1);
    assert_eq!(measure.deliveries.distinct, 1);
    assert!(measure.deliveries.is_complete());
}
