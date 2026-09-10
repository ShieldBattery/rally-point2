//! Property tests over the simulator in the parent module: stability (no
//! flapping under sustained or bursty loss), coverage (bounded underruns),
//! and recovery (monotonic, prompt descent once weather clears), plus two
//! `--ignored` tuning aids that print traces instead of asserting.

use super::*;

/// A clean, stable network: after the initial adaptation the buffer must
/// simply sit still.
#[test]
fn clean_network_holds_one_buffer() {
    for seed in [3, 17, 4242] {
        let result = run(
            ControlLaw::default(),
            &[Weather::clean(seconds(180), 150_000)],
            seed,
        );
        assert!(
            result.changes.len() <= 2,
            "seed {seed}: a clean network churned past its adaptation: {:?}",
            result.changes,
        );
        assert_eq!(result.dips_within(seconds(20)), 0, "seed {seed}");
    }
}

/// The clumsy case that motivated the sustained-shrink rule: sustained
/// uniform packet loss. The buffer must adapt up and then *park* -- no
/// shrink-and-re-raise churn on the dwell cadence -- while still covering
/// delivery (bounded underruns).
#[test]
fn sustained_random_loss_parks_the_buffer() {
    for seed in [7, 99, 1234] {
        let phases = [
            Weather::clean(seconds(20), 150_000),
            Weather::random_loss(seconds(120), 150_000, 0.10),
        ];
        let result = run(ControlLaw::default(), &phases, seed);

        // One probe dip is the price of discovering an edge whose peaks
        // recur past the lookback; the burn it earns must keep it from
        // ever becoming a cadence.
        assert!(
            result.dips_within(seconds(20)) <= 1,
            "seed {seed}: the buffer flapped: {:?}",
            result.changes,
        );
        // Once the loss phase has been running a few seconds, the buffer
        // is adapted; from there it must be effectively parked. Allow a
        // couple of late escalations (loss keeps randomly clustering) and
        // the single probe pair, but nothing like the one-change-per-dwell
        // flap this replaces (~22 for this window).
        let settled = result.changes_between(seconds(30), seconds(140));
        assert!(
            settled.len() <= 4,
            "seed {seed}: churn while parked: {settled:?}",
        );
        // The parked buffer actually covers the weather. The proxy counts
        // a turn whenever *either* link's delivery need exceeded the
        // cushion; 2% of a 2-minute lossy stretch is a handful of brief
        // hiccups, not the recurring micro-stutter of an undersized buffer.
        let lossy_turns = seconds(120);
        assert!(
            result.underrun_turns <= lossy_turns / 50,
            "seed {seed}: {} underrun turns of {lossy_turns}",
            result.underrun_turns,
        );
    }
}

/// After the loss clears, the buffer must come back down -- monotonically,
/// within a bounded time -- rather than sticking at the high-water mark or
/// oscillating on the way down.
#[test]
fn recovery_descends_monotonically_and_promptly() {
    for seed in [11, 555, 90210] {
        let phases = [
            Weather::clean(seconds(20), 150_000),
            Weather::random_loss(seconds(60), 150_000, 0.10),
            Weather::clean(seconds(120), 150_000),
        ];
        let result = run(ControlLaw::default(), &phases, seed);

        let recovery_start = seconds(20 + 60);
        let recovery = result.changes_between(recovery_start, seconds(200));
        assert!(
            recovery
                .windows(2)
                .all(|pair| pair[1].buffer < pair[0].buffer),
            "seed {seed}: non-monotonic recovery: {recovery:?}",
        );

        // The descent is bounded: the shrink lookback (~25s) has to age the
        // loss-era peaks out, then one dwell (~5s) per step down. 65s
        // covers the ~6 steps this weather needs with margin. The endpoint
        // is the clean steady state the first phase found.
        let clean_buffer = result.buffer_at(seconds(19));
        let recovered = result.buffer_at(recovery_start + seconds(65));
        assert!(
            recovered <= clean_buffer + 1,
            "seed {seed}: stuck high after recovery: {recovered} vs clean {clean_buffer}",
        );
        assert!(result.dips_within(seconds(20)) <= 1, "seed {seed}");
    }
}

/// Loss arriving in short bursts every couple of seconds -- the bad-wifi
/// shape. The gaps between bursts are exactly what an instantaneous
/// estimator mistakes for recovery; the law must ride through them.
#[test]
fn bursty_loss_does_not_flap() {
    for seed in [23, 808, 31337] {
        let phases = [
            Weather::clean(seconds(20), 150_000),
            Weather::bursty(seconds(150), 150_000, 0.35),
        ];
        let result = run(ControlLaw::default(), &phases, seed);

        // Probe dips are capped by the burn budget; past that the edge is
        // parked for good.
        assert!(
            result.dips_within(seconds(20)) <= 2,
            "seed {seed}: flapped between bursts: {:?}",
            result.changes,
        );
        // Bursty weather is genuinely non-stationary at the target level
        // -- burst clusters of different depths keep re-pricing it -- so
        // raises tracking it are correct, not churn. Bound the total well
        // below the dwell cadence's worst case (a change every ~5s would
        // be ~22 for this window).
        let settled = result.changes_between(seconds(60), seconds(170));
        assert!(
            settled.len() <= 8,
            "seed {seed}: churn while settled: {settled:?}",
        );
    }
}

/// The clumsy shape that motivated the burst term: short full blackouts
/// recurring several times a second. The mean loss rate alone
/// under-provisions this weather; with the burst term the parked buffer
/// must actually cover it (rare underruns), and stay parked.
#[test]
fn throttle_blackouts_are_covered_and_parked() {
    for seed in [5, 42, 777] {
        let phases = [
            Weather::clean(seconds(20), 150_000),
            Weather::throttled(seconds(120), 150_000),
        ];
        let result = run(ControlLaw::default(), &phases, seed);

        assert!(
            result.dips_within(seconds(20)) <= 2,
            "seed {seed}: flapped: {:?}",
            result.changes,
        );
        let settled = result.changes_between(seconds(45), seconds(140));
        assert!(settled.len() <= 6, "seed {seed}: churn: {settled:?}");
        // Blackouts here run ~1-2 turns; a buffer sized by the burst term
        // rides out nearly all of them. 1% of the lossy stretch is a
        // couple of brief hiccups, not recurring micro-stutter.
        let lossy_turns = seconds(120);
        assert!(
            result.underrun_turns <= lossy_turns / 100,
            "seed {seed}: {} underrun turns of {lossy_turns}",
            result.underrun_turns,
        );
    }
}

/// Peaks recurring just *past* the base lookback -- the exact bait for an
/// edge dip (shrink at lookback expiry, disproven by the next peak).
/// Probation limits the law to at most one dip per episode.
#[test]
fn peaks_just_past_the_lookback_dip_at_most_once() {
    for seed in [9, 314, 2718] {
        // A 1s 260ms RTT spike every 30s riding on a 200ms base: the
        // target peaks 1 turn above its resting level, with the peaks
        // spaced wider than the base shrink lookback.
        let mut phases = vec![Weather::clean(seconds(5), 200_000)];
        for _ in 0..7 {
            phases.push(Weather::clean(seconds(1), 260_000));
            phases.push(Weather::clean(seconds(29), 200_000));
        }
        let result = run(ControlLaw::default(), &phases, seed);

        // The one allowed probe: shrink at lookback expiry, disproven by
        // the next spike, burned -- and then parked for the remaining
        // cycles.
        assert!(result.dips_within(seconds(20)) <= 1, "seed {seed}");
        let settled = result.changes_between(seconds(40), seconds(215));
        assert!(settled.len() <= 2, "seed {seed}: edge churn: {settled:?}");
    }
}

/// RTT riding a few milliseconds under a whole-turn boundary, with brief
/// few-ms excursions across it -- the boundary-hover shape that used to
/// flip the buffer between adjacent sizes on sub-ms RTT noise. The shrink
/// headroom refuses those shrinks outright, so the buffer parks at the
/// covering size with zero dips (not even probation's one-per-episode).
#[test]
fn a_boundary_hovering_rtt_parks_the_buffer_with_no_dips() {
    for seed in [13, 606, 5150] {
        // Base path a hair under the 4-turn boundary (166,664us): raw
        // target 4, margined path pinned at 5. Excursions to ~170ms every
        // 30s price the 5 the headroom then refuses to give back.
        let hover = Weather {
            turns: seconds(29),
            rtt_us: 163_000,
            jitter: 0.01,
            loss: 0.0,
            burst_start: 0.0,
            burst_end: 1.0,
        };
        let spike = Weather {
            turns: seconds(1),
            rtt_us: 170_000,
            ..hover
        };
        let mut phases = vec![Weather {
            turns: seconds(5),
            ..hover
        }];
        for _ in 0..7 {
            phases.push(spike);
            phases.push(hover);
        }
        let result = run(ControlLaw::default(), &phases, seed);

        assert_eq!(
            result.dips_within(seconds(20)),
            0,
            "seed {seed}: dipped on the boundary: {:?}",
            result.changes,
        );
        // After the first excursion prices the covering size, the buffer
        // must simply sit still for the rest of the session.
        let settled = result.changes_between(seconds(10), seconds(215));
        assert!(
            settled.is_empty(),
            "seed {seed}: boundary churn: {settled:?}"
        );
    }
}

/// Tuning aid: what a *brief* bad episode costs after it is over. The
/// scenario tests all run sustained weather, where a buffer that stays up
/// is doing its job; this measures the opposite case, where it is not.
///
/// The number to watch is how far the elevated-after column tracks the
/// episode length. It cannot track it closely -- the loss memory holds the
/// target up past the weather by design, and the shrink floor then holds
/// the peak for its lookback -- but a law where a two-second blip costs
/// what a minute-long outage costs is charging every player for weather
/// that has been over for half a minute. Run with
/// `cargo test -p rally-point-relay buffer_law_sim -- --ignored --nocapture`.
#[test]
#[ignore = "manual tuning aid, prints measurements"]
fn dump_transient_cost() {
    println!("== cost of a brief episode, after it ends ==");
    for episode in [2u32, 5, 15, 60] {
        let mut elevated = Vec::new();
        let mut peaks = Vec::new();
        for seed in [7u64, 99, 1234, 11, 555] {
            let phases = [
                Weather::clean(seconds(60), 40_000),
                Weather::throttled(seconds(episode), 40_000),
                Weather::clean(seconds(240), 40_000),
            ];
            let result = run(ControlLaw::default(), &phases, seed);
            let baseline = result.buffer_at(seconds(59));
            let end = seconds(60) + seconds(episode);
            let last = result.buffer_by_turn.len() as u32;
            peaks.push((end..last).map(|t| result.buffer_at(t)).max().unwrap_or(0));
            let recovered = (end..last)
                .find(|&t| result.buffer_at(t) <= baseline)
                .unwrap_or(last);
            elevated.push((recovered - end) / 24);
        }
        let mean = f64::from(elevated.iter().sum::<u32>()) / elevated.len() as f64;
        println!(
            "   episode {episode:>3}s: peak buffer {peaks:?}, elevated after {elevated:?}                  (mean {mean:.1}s)",
        );
    }
}

/// Trace dump for tuning sessions: per-2s rows of weather, target, and
/// buffer for each scenario. Run with
/// `cargo test -p rally-point-relay buffer_law_sim -- --ignored --nocapture`.
#[test]
#[ignore = "manual tuning aid, prints traces"]
fn dump_traces() {
    let scenarios: [(&str, Vec<Weather>); 4] = [
        (
            "uniform 10% loss @150ms",
            vec![
                Weather::clean(seconds(20), 150_000),
                Weather::random_loss(seconds(120), 150_000, 0.10),
                Weather::clean(seconds(60), 150_000),
            ],
        ),
        (
            "bursty 35% loss @150ms",
            vec![
                Weather::clean(seconds(20), 150_000),
                Weather::bursty(seconds(120), 150_000, 0.35),
                Weather::clean(seconds(60), 150_000),
            ],
        ),
        ("clean 300ms", vec![Weather::clean(seconds(120), 300_000)]),
        (
            "clumsy throttle @150ms",
            vec![
                Weather::clean(seconds(20), 150_000),
                Weather::throttled(seconds(120), 150_000),
                Weather::clean(seconds(60), 150_000),
            ],
        ),
    ];

    for (name, phases) in &scenarios {
        let result = run(ControlLaw::default(), phases, 7);
        println!("== {name} ==");
        let mut boundary = 0;
        for weather in phases {
            boundary += weather.turns;
            println!(
                "   phase to {:>4}s: rtt {}ms loss {:.0}% (burst {:.2}/{:.2})",
                boundary / 24,
                weather.rtt_us / 1000,
                weather.loss * 100.0,
                weather.burst_start,
                weather.burst_end,
            );
        }
        for (turn, buffer) in result.buffer_by_turn.iter().enumerate().step_by(48) {
            println!("   t={:>4}s buffer={}", turn / 24, buffer);
        }
        println!(
            "   changes after adaptation: {:?}\n   underrun turns: {}\n",
            result.changes, result.underrun_turns,
        );
    }
}
