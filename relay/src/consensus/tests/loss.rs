//! Loss-window folding from cumulative counters: stale, duplicate and late-refined samples.

use super::*;

/// A stale sidecar (non-monotonic counters) produces no negative loss.
#[test]
fn stale_sidecar_no_spurious_loss() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 0, 50), 2);
    assert_eq!(maker.target(), Some(4));
    assert_eq!(d, None);
}

/// A late cumulative sample is ignored as a counter endpoint. The windowed
/// rate keeps differencing from the accepted history, not the stale packet
/// that happened to arrive in between.
#[test]
fn stale_counter_sample_does_not_poison_the_loss_windows() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());

    // Counter pairs are written as sent/lost: 100/0 -> 120/10.
    maker.ingest_remote(&conditions(0, 150_000, 0, 100), 10_000);
    maker.ingest_remote(&conditions(0, 160_000, 10, 120), 20_000);
    assert_eq!(
        slot_loss_rate(&maker, 0),
        Some(0.5),
        "10 lost out of the 20 sent since the baseline",
    );

    // 110/0 is older than the accepted 120/10 sample. Its sender RTT is
    // stale too, but the mesh hop was sampled locally on receipt and stays
    // current even when the sender counters regress.
    maker.ingest_remote(&conditions(0, 900_000, 0, 110), 30_000);
    let state = &maker.slots[&SlotId(0)];
    assert_eq!((state.curr_sent, state.curr_lost), (120, 10));
    assert_eq!(slot_loss_rate(&maker, 0), Some(0.5), "stale sample ignored");
    assert_eq!(state.rtt(), 160_000, "stale RTT does not age the window");
    assert_eq!(state.mesh_rtt_us, 30_000, "the local mesh sample is fresh");

    maker.ingest_remote(&conditions(0, 140_000, 10, 130), 40_000);
    let state = &maker.slots[&SlotId(0)];
    assert_eq!((state.curr_sent, state.curr_lost), (130, 10));
    // Exactly as if the stale sample never arrived: 10 lost of the 30
    // sent since the baseline. Had the stale 110/0 been accepted as an
    // endpoint, the loss would instead read as 10 of the 20 packets after
    // it -- the same 0.5 as before, poisoned against ever declining.
    assert_eq!(slot_loss_rate(&maker, 0), Some(10.0 / 30.0));
}

/// Exact re-delivery is idempotent for both the loss windows and the
/// sample-count RTT window. Equal counters with a changed RTT remain a
/// fresh latency observation.
#[test]
fn duplicate_counters_neither_erase_nor_reapply_the_loss_windows() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.ingest_remote(&conditions(0, 150_000, 0, 100), 10_000);
    maker.ingest_remote(&conditions(0, 160_000, 10, 120), 10_000);
    let rtt_samples = maker.slots[&SlotId(0)].rtt_window.len;

    maker.ingest_remote(&conditions(0, 160_000, 10, 120), 20_000);
    let state = &maker.slots[&SlotId(0)];
    assert_eq!((state.curr_sent, state.curr_lost), (120, 10));
    assert_eq!(state.advancing_samples, 1, "a duplicate does not advance");
    assert_eq!(slot_loss_rate(&maker, 0), Some(0.5));
    assert_eq!(state.rtt_window.len, rtt_samples);
    assert_eq!(state.mesh_rtt_us, 20_000);

    // Same cumulative point, new instantaneous RTT: update latency only.
    maker.ingest_remote(&conditions(0, 180_000, 10, 120), 30_000);
    let state = &maker.slots[&SlotId(0)];
    assert_eq!(state.rtt(), 180_000);
    assert_eq!(state.rtt_window.len, rtt_samples + 1);
    assert_eq!(slot_loss_rate(&maker, 0), Some(0.5));
    assert_eq!(state.curr_sent, 120);

    maker.ingest_remote(&conditions(0, 170_000, 10, 130), 40_000);
    let state = &maker.slots[&SlotId(0)];
    assert_eq!((state.curr_sent, state.curr_lost), (130, 10));
    // The 10 lost packets count once against the 30 sent since the
    // baseline -- the duplicates neither erased them nor doubled them.
    assert_eq!(slot_loss_rate(&maker, 0), Some(10.0 / 30.0));
}

/// Noq can declare a packet lost after the sent-packet endpoint containing
/// it was sampled. A higher lost count at the same sent count refines the
/// current endpoint immediately, and the loss then counts exactly once in
/// the windows -- it declines as clean packets accumulate rather than
/// re-spiking on later samples.
#[test]
fn late_loss_declaration_refines_the_current_endpoint_without_advancing_it() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.ingest_local(&conditions(0, 150_000, 0, 100));
    maker.ingest_local(&conditions(0, 150_000, 0, 120));
    assert_eq!(slot_loss_rate(&maker, 0), Some(0.0));

    maker.ingest_local(&conditions(0, 150_000, 10, 120));
    let state = &maker.slots[&SlotId(0)];
    assert_eq!((state.curr_sent, state.curr_lost), (120, 10));
    assert_eq!(state.advancing_samples, 1, "a refinement does not advance");
    assert_eq!(slot_loss_rate(&maker, 0), Some(0.5));

    maker.ingest_local(&conditions(0, 150_000, 10, 130));
    let state = &maker.slots[&SlotId(0)];
    assert_eq!((state.curr_sent, state.curr_lost), (130, 10));
    assert_eq!(slot_loss_rate(&maker, 0), Some(10.0 / 30.0));
}

/// Loss detection may advance before a second sent endpoint has established
/// any window. It must refine the baseline snapshot too: otherwise the
/// window anchored there would attribute that already-sent loss to the few
/// packets sent after it, reading tens-of-percent loss on a clean link.
#[test]
fn late_loss_declaration_refines_the_baseline_snapshot() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.ingest_local(&conditions(0, 150_000, 0, 100));
    maker.ingest_local(&conditions(0, 150_000, 10, 100));

    let baseline = &maker.slots[&SlotId(0)];
    assert_eq!((baseline.curr_sent, baseline.curr_lost), (100, 10));
    assert_eq!(
        slot_loss_rate(&maker, 0),
        None,
        "no packets span the window"
    );

    // The 10 packets sent after the refined baseline arrived intact, and
    // that is exactly what the window reports.
    maker.ingest_local(&conditions(0, 150_000, 10, 110));
    let state = &maker.slots[&SlotId(0)];
    assert_eq!((state.curr_sent, state.curr_lost), (110, 10));
    assert_eq!(slot_loss_rate(&maker, 0), Some(0.0));
}

/// Counter admission is per slot, not per sidecar: one stale entry cannot
/// prevent another slot in the same batch from advancing normally.
#[test]
fn mixed_stale_and_fresh_batch_updates_each_slot_independently() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.ingest_remote(
        &multi_conditions(&[(0, 100_000, 0, 100), (1, 200_000, 0, 100)]),
        10_000,
    );
    maker.ingest_remote(
        &multi_conditions(&[(0, 110_000, 10, 120), (1, 210_000, 5, 120)]),
        20_000,
    );

    maker.ingest_remote(
        &multi_conditions(&[(0, 900_000, 0, 110), (1, 190_000, 5, 130)]),
        30_000,
    );

    let stale = &maker.slots[&SlotId(0)];
    assert_eq!((stale.curr_sent, stale.curr_lost), (120, 10));
    assert_eq!(slot_loss_rate(&maker, 0), Some(0.5));
    let stale = &maker.slots[&SlotId(0)];
    assert_eq!(stale.rtt(), 110_000);
    assert_eq!(stale.mesh_rtt_us, 30_000);

    let fresh = &maker.slots[&SlotId(1)];
    assert_eq!((fresh.curr_sent, fresh.curr_lost), (130, 5));
    assert_eq!(slot_loss_rate(&maker, 1), Some(5.0 / 30.0));
    let fresh = &maker.slots[&SlotId(1)];
    assert_eq!(fresh.mesh_rtt_us, 30_000);
}

/// A reconnect's lower QUIC counters are legitimate only after the existing
/// departure/reinstatement lifecycle has retired the old `SlotState`. Its
/// first new sample establishes a baseline; the following sample forms the
/// first interval of the new connection.
#[test]
fn reinstated_slot_accepts_reset_counters_as_a_fresh_baseline() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.ingest_local(&conditions(0, 150_000, 0, 100));
    maker.ingest_local(&conditions(0, 160_000, 10, 120));

    maker.record_departure(SlotId(0), DepartureStamps::default(), DROPPED);
    assert!(!maker.slots.contains_key(&SlotId(0)));
    assert!(maker.reinstate_slot(SlotId(0)));

    maker.ingest_local(&conditions(0, 50_000, 0, 3));
    let baseline = &maker.slots[&SlotId(0)];
    assert_eq!((baseline.curr_sent, baseline.curr_lost), (3, 0));
    assert_eq!(slot_loss_rate(&maker, 0), None);
    let baseline = &maker.slots[&SlotId(0)];
    assert_eq!(baseline.rtt(), 50_000, "the old RTT window was retired");

    maker.ingest_local(&conditions(0, 60_000, 1, 13));
    let state = &maker.slots[&SlotId(0)];
    assert_eq!((state.curr_sent, state.curr_lost), (13, 1));
    assert!(
        (slot_loss_rate(&maker, 0).expect("new window") - 0.1).abs() < f64::EPSILON,
        "1 lost of the 10 sent since the fresh baseline",
    );
}
