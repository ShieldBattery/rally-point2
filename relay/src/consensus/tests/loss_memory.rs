//! The loss memory window and the blackout-run burst term.

use super::*;

/// A lossy stretch followed by clean traffic must not snap the target
/// straight back down: the memory window keeps pricing the loss in until
/// it ages out of the snapshot ring, and only then does the (dwell-gated,
/// sustained) lower fire. An instantaneous estimator would read 0% in the
/// first loss-free stretch, collapse the target, and flap the buffer.
#[test]
fn loss_memory_holds_the_target_through_clean_stretches_then_releases() {
    // A short memory (32 samples, snapshot every 2) and shrink lookback so
    // the test can age the loss out with a handful of samples.
    let law = ControlLaw {
        loss_attack_samples: 4,
        loss_memory_samples: 32,
        shrink_lookback_turns: 120,
        ..ControlLaw::default()
    };
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law,
        Authority::SelfRelay,
        HashSet::new(),
    );
    // Clean baseline: 150ms -> target 4, raise.
    ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    // 50 of the next 100 packets lost: loss_risk = 0.5 * 150000 = 75000us
    // -> +2 turns. Raise fires immediately.
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 50, 200), 2);
    assert_eq!(d.unwrap().buffer, BufferSize(6));

    // Clean traffic from here on. The loss stays inside the memory window,
    // so the target declines gradually instead of snapping to 4 -- and no
    // decision fires.
    let mut sent = 200;
    for frame in 3..=20 {
        sent += 10;
        let d = ingest_at(&mut maker, &conditions(0, 150_000, 50, sent), frame);
        assert_eq!(d, None, "held while the loss is in memory (frame {frame})");
    }
    assert!(
        maker.target().unwrap() > 4,
        "the memory window still prices the loss in",
    );

    // Enough further clean samples to push every lossy snapshot out of the
    // ring: the loss term goes to zero and the target returns to 4.
    for frame in 21..=60 {
        sent += 10;
        ingest_at(&mut maker, &conditions(0, 150_000, 50, sent), frame);
    }
    assert_eq!(maker.target(), Some(4), "the memory aged out");

    // With the improvement sustained well past the dwell, the shrink fires.
    sent += 10;
    let d = ingest_at(&mut maker, &conditions(0, 150_000, 50, sent), 200);
    assert_eq!(
        d.unwrap().buffer,
        BufferSize(6 - law.lower_step),
        "one earned step down after sustained improvement",
    );
}

/// A stretch of sample intervals that lost *every* packet is a link
/// blackout, and its length is available to the target as whole turns
/// (capped): delivery inside it is dark for exactly that many re-carries,
/// which the mean loss rate understates for bursty loss. The two loss
/// terms describe one blackout from two angles, so the target takes the
/// worse rather than their sum.
#[test]
fn a_full_blackout_prices_its_duration_into_the_target() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    // Clean baseline at 150ms: path 4 turns.
    ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);

    // Three consecutive intervals lose all 10 of their packets: a ~3-turn
    // blackout. Both loss terms see it -- the windowed rate saturates
    // (30 lost of the 30 sent since baseline -> 1.0 * 150ms -> 4 turns)
    // *because* every packet in the blackout was dropped, and the burst
    // term measures the same darkness directly as its 3-turn run. They are
    // one hazard counted two ways, so the target carries the worse of them
    // once, not 7 turns of loss allowance for 3 turns of dark link.
    ingest_at(&mut maker, &conditions(0, 150_000, 10, 110), 2);
    ingest_at(&mut maker, &conditions(0, 150_000, 20, 120), 3);
    ingest_at(&mut maker, &conditions(0, 150_000, 30, 130), 4);
    assert_eq!(maker.target(), Some(4 + 4));

    // Partial loss is not a blackout: re-carries still get through, so
    // the run resets and the burst term stops growing.
    ingest_at(&mut maker, &conditions(0, 150_000, 31, 150), 5);
    let partial_burst = maker.target_inputs().unwrap().burst_turns;
    assert_eq!(partial_burst, 3, "the remembered burst, not a longer one");
}

/// However long a blackout runs, the burst term is capped: covering a
/// rare many-turn outage would cost every turn of input latency
/// permanently, while riding it out costs one brief stall.
#[test]
fn the_burst_term_is_capped() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 30),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    for step in 1..=10u32 {
        let moved = u64::from(step) * 10;
        ingest_at(
            &mut maker,
            &conditions(0, 150_000, moved, 100 + moved),
            step + 1,
        );
    }
    assert_eq!(maker.target_inputs().unwrap().burst_turns, BURST_TURNS_CAP);
}

/// A counter interval spanning a stall-length receive gap is an outage,
/// not weather: the loss windows restart past it instead of differencing
/// the dead-path interval in -- the rate term, which would otherwise
/// read tens of percent for the whole loss memory and hold the shrink
/// floor up long after recovery, reads clean, and the excluded gap
/// leaves no burst trace either. An outage past the QUIC idle timeout
/// reconnects and resets these windows via the connection epoch; a
/// shorter fade must not be punished harder.
#[test]
fn a_stall_spanning_gap_is_excluded_from_the_loss_windows() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    let start = Instant::now();
    let step = Duration::from_millis(42);
    // Clean flowing history at 150ms: path 4 turns, no loss.
    ingest_at(&mut maker, &conditions(0, 150_000, 0, 100), 1);
    for i in 1..=10u32 {
        let update = sample_at(&mut maker, 0, 0, 100 + u64::from(i) * 5, start + step * i);
        assert_eq!(update, CounterUpdate::Advanced);
    }
    assert_eq!(slot_loss_rate(&maker, 0), Some(0.0));

    // A 5s fade: 40 flush-paced sends into the dead path, all declared
    // lost by the time the first post-resume sample lands.
    let resume = start + step * 10 + Duration::from_secs(5);
    let update = sample_at(&mut maker, 0, 40, 190, resume);
    assert_eq!(update, CounterUpdate::OutageRebaselined);

    // The poisoned interval is invisible: no rate until the restarted
    // window spans enough packets, then the actual (clean) post-resume
    // weather.
    assert_eq!(slot_loss_rate(&maker, 0), None);
    for i in 1..=10u32 {
        sample_at(&mut maker, 0, 40, 190 + u64::from(i) * 5, resume + step * i);
    }
    assert_eq!(slot_loss_rate(&maker, 0), Some(0.0));

    // No trace at all: the target is back to its path term alone.
    assert_eq!(maker.target_inputs().unwrap().burst_turns, 0);
    assert_eq!(maker.target(), Some(4));
}
