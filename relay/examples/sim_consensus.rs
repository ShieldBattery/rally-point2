//! Simulation harness for the latency-buffer decision-maker.
//!
//! `DecisionMaker` is pure and synchronous: no I/O, no async, no locks of its
//! own. This harness feeds it synthetic per-turn RTT/loss samples and records the
//! buffer size, target, and decision events over time, then prints a text
//! timeline per scenario. The point is to *see* the control law's timing
//! interactions — the 120-turn lower dwell, the 32-sample RTT window, and the
//! raise-fast / lower-slow asymmetry — which are hard to reason about
//! analytically but jump out on a timeline.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p rally-point-relay --example sim_consensus
//! ```
//!
//! Each scenario prints a header with the expected behavior, then one row per
//! turn showing the raw RTT, the jitter-window max, the computed target, the
//! current buffer, and any decision that fired (annotated with the applied
//! frame). A compact sparkline of the buffer sits below each scenario so the
//! overall shape is visible at a glance.

use std::fmt::Write;

use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{GameFrameCount, SessionId, SlotId};
use rally_point_proto::messages::{LinkConditions, SlotConditions};
use rally_point_relay::consensus::{Authority, ControlLaw, DecisionMaker};
use rally_point_relay::routing::SessionKey;

/// One turn's worth of synthetic link conditions for a single slot. RTT is in
/// microseconds; `lost`/`sent` are per-turn deltas the harness accumulates into
/// the cumulative counters the decision-maker differences.
#[derive(Clone, Copy)]
struct Sample {
    rtt_us: u32,
    lost: u64,
    sent: u64,
}

/// A named, self-contained scenario: a sequence of per-turn samples, the
/// bounds the coordinator set, and a one-line description of what the timeline
/// should show. The harness feeds each sample at a monotonically increasing
/// frame and records what the decision-maker did.
struct Scenario {
    name: &'static str,
    description: &'static str,
    bounds: BufferBounds,
    /// Per-turn samples for slot 0 (the harness uses a single local slot,
    /// which is enough to exercise the path, jitter, and loss terms).
    samples: Vec<Sample>,
}

/// One recorded row in the timeline — everything the decision-maker exposed
/// about its state at a given frame, plus the decision (if any) it emitted.
struct Row {
    frame: u32,
    rtt_us: u32,
    /// The recent-max RTT the jitter window held at this frame — the value the
    /// decision-maker actually used. Lags the raw RTT: a spike stays in the
    /// window for `RTT_WINDOW_SIZE` turns, so `jitter_max_us` stays high long
    /// after `rtt_us` has dropped.
    jitter_max_us: u32,
    target: Option<u32>,
    buffer: u32,
    decision: Option<Decision>,
}

#[derive(Clone, Copy)]
struct Decision {
    buffer: u32,
    applied_frame: u32,
}

fn session_key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("sb-sim").unwrap(),
        session: SessionId(1),
    }
}

/// A ring buffer of recent RTT samples, mirroring the decision-maker's internal
/// `RTT_WINDOW_SIZE` (32) so the harness can display the exact recent-max the
/// decision-maker used. The decision-maker doesn't expose its window, but the
/// harness controls every RTT input, so keeping a parallel window reproduces the
/// same max without relying on inverting the (loss-folding) target.
struct JitterWindow {
    samples: std::collections::VecDeque<u32>,
    cap: usize,
}

impl JitterWindow {
    const SIZE: usize = 32;

    fn new() -> Self {
        Self {
            samples: std::collections::VecDeque::with_capacity(Self::SIZE),
            cap: Self::SIZE,
        }
    }

    fn push(&mut self, rtt_us: u32) {
        // Match the decision-maker: a 0 (no measurement) is skipped.
        if rtt_us == 0 {
            return;
        }
        if self.samples.len() >= self.cap {
            self.samples.pop_front();
        }
        self.samples.push_back(rtt_us);
    }

    fn max(&self) -> u32 {
        self.samples.iter().copied().max().unwrap_or(0)
    }
}

/// Runs one scenario: feeds each sample through `ingest_local` at consecutive
/// frames, collecting a row per turn. The harness keeps a parallel RTT ring
/// buffer so the jitter-window max is reported exactly (the decision-maker
/// doesn't expose it, and inverting the target would fold in the loss term and
/// only yield a quantization floor).
///
/// Per-turn `lost`/`sent` are deltas the harness accumulates into the cumulative
/// counters the decision-maker differences. A flat baseline of `sent` advances
/// each turn so a nonzero loss rate is expressible without the caller tracking
/// arithmetic.
fn run(scenario: &Scenario) -> Vec<Row> {
    let mut maker = DecisionMaker::new(
        session_key(),
        scenario.bounds,
        ControlLaw::default(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
    );

    let mut rows = Vec::with_capacity(scenario.samples.len());
    let mut jitter = JitterWindow::new();
    let mut cumulative_lost: u64 = 0;
    let mut cumulative_sent: u64 = 0;

    for (i, sample) in scenario.samples.iter().enumerate() {
        let frame = GameFrameCount((i + 1) as u32);
        cumulative_sent += sample.sent;
        cumulative_lost += sample.lost;
        let conditions = LinkConditions {
            slots: vec![SlotConditions {
                slot: 0,
                rtt_us: sample.rtt_us,
                lost_packets: cumulative_lost,
                sent_packets: cumulative_sent,
                connection_epoch: None,
            }],
        };

        // Push into the parallel window *before* ingest so the max reflects the
        // same sample the decision-maker pushed this turn. ingest_local runs
        // decide() after pushing internally, so maker.target() after ingest is
        // the target the decision actually used (not a pre-ingest lag). The
        // frame is observed first, the way the turn path does it (frames come
        // off validated turns, conditions off the carrying packet).
        jitter.push(sample.rtt_us);
        maker.observe_frame(SlotId(0), frame);
        let decision = maker.ingest_local(&conditions).map(|d| Decision {
            buffer: d.buffer.0,
            applied_frame: d.applied_frame.0,
        });

        rows.push(Row {
            frame: frame.0,
            rtt_us: sample.rtt_us,
            jitter_max_us: jitter.max(),
            target: maker.target(),
            buffer: maker.buffer().0,
            decision,
        });
    }

    rows
}

/// Prints the per-turn timeline and a buffer sparkline for one scenario.
fn print_timeline(scenario: &Scenario, rows: &[Row]) {
    println!();
    println!("=== {} ===", scenario.name);
    println!("{}", scenario.description);
    println!();

    // Column header. Widths chosen so the rows align at typical magnitudes.
    println!(
        "{:>5}  {:>8}  {:>8}  {:>6}  {:>6}  decision",
        "frame", "rtt_ms", "jmax_ms", "target", "buffer"
    );

    for row in rows {
        let decision_str = match row.decision {
            Some(d) => format!("-> {} @f{}", d.buffer, d.applied_frame),
            None => String::new(),
        };
        println!(
            "{:>5}  {:>8.1}  {:>8.1}  {:>6}  {:>6}  {}",
            row.frame,
            row.rtt_us as f64 / 1000.0,
            row.jitter_max_us as f64 / 1000.0,
            row.target.unwrap_or(0),
            row.buffer,
            decision_str,
        );
    }

    println!();
    println!(
        "buffer: {}",
        sparkline(&rows.iter().map(|r| r.buffer).collect::<Vec<_>>())
    );
    println!();
}

/// Renders a compact ASCII sparkline for a series of small non-negative
/// integers (buffer sizes). Each cell maps to one bar height 0-8.
fn sparkline(values: &[u32]) -> String {
    const BARS: [char; 9] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█', '█'];
    let max = values.iter().copied().max().unwrap_or(1).max(1);
    let mut out = String::with_capacity(values.len());
    for &v in values {
        // Map 0 -> the lowest bar, max -> the highest. Scale into 0..=7.
        let idx = if max == 0 {
            0
        } else {
            ((v as f64 / max as f64) * 7.0).round() as usize
        };
        out.push(BARS[idx.min(7)]);
    }
    out
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Builds a vector of `n` clean samples at a constant RTT, with a flat sent
/// baseline so the cumulative counter advances and loss stays zero.
fn stable(rtt_us: u32, n: usize) -> Vec<Sample> {
    (0..n)
        .map(|_| Sample {
            rtt_us,
            lost: 0,
            sent: 100,
        })
        .collect()
}

/// Stable 50ms 1v1. Target is `ceil(50000/41667) = 2`; the buffer should raise
/// to 2 on the first sample and hold there for the full run.
fn scenario_stable_low_latency() -> Scenario {
    Scenario {
        name: "stable 50ms (1v1)",
        description: "target=2; raise to 2 on frame 1, hold for 60 turns",
        bounds: BufferBounds { min: 0, max: 20 },
        samples: stable(50_000, 60),
    }
}

/// Cross-region 150ms. Target is `ceil(150000/41667) = 4`; raise to 4 and hold.
fn scenario_cross_region() -> Scenario {
    Scenario {
        name: "cross-region 150ms",
        description: "target=4; raise to 4 on frame 1, hold for 60 turns",
        bounds: BufferBounds { min: 0, max: 20 },
        samples: stable(150_000, 60),
    }
}

/// Sudden latency spike: 50ms for 30 turns, then 300ms for 10 turns, back to
/// 50ms. The raise to 8 should fire on the first 300ms sample (frame 31); the
/// lower should be suppressed by the dwell, and the jitter window should keep
/// the target at 8 until the spike ages out (~frame 62).
fn scenario_latency_spike() -> Scenario {
    let mut samples = stable(50_000, 30);
    samples.extend(stable(300_000, 10));
    samples.extend(stable(50_000, 60));
    Scenario {
        name: "sudden latency spike",
        description: "50ms -> 300ms for 10 turns -> 50ms; raise to 8 @31, lower suppressed by dwell",
        bounds: BufferBounds { min: 0, max: 20 },
        samples,
    }
}

/// Burst of packet loss on a 150ms link. A clean baseline, then a 30% loss
/// burst for 5 turns, then clean again. The loss term should raise the target
/// to `4 + ceil(0.3*150000/41667) = 4 + 2 = 6` during the burst, then the
/// buffer should lower back after the dwell once loss clears.
fn scenario_loss_burst() -> Scenario {
    let mut samples = stable(150_000, 30);
    // 30% loss burst: 30 of 100 sent packets lost each turn.
    for _ in 0..5 {
        samples.push(Sample {
            rtt_us: 150_000,
            lost: 30,
            sent: 100,
        });
    }
    samples.extend(stable(150_000, 120));
    Scenario {
        name: "loss burst on 150ms",
        description: "30% loss for 5 turns; loss term raises target to 6, lower after dwell",
        bounds: BufferBounds { min: 0, max: 20 },
        samples,
    }
}

/// Oscillating link: 50ms and 150ms alternating. The first 150ms raises to 4;
/// subsequent oscillations should raise on worsening and hold on improvement
/// (lowers suppressed by the dwell). The buffer should never lower during the
/// run — the dwell is longer than the oscillation period.
fn scenario_oscillating() -> Scenario {
    let mut samples = Vec::new();
    for i in 0..60 {
        let rtt = if i % 2 == 0 { 50_000 } else { 150_000 };
        samples.push(Sample {
            rtt_us: rtt,
            lost: 0,
            sent: 100,
        });
    }
    Scenario {
        name: "oscillating 50ms/150ms",
        description: "raise on first 150ms (frame 2), hold through dwell; never lowers",
        bounds: BufferBounds { min: 0, max: 20 },
        samples,
    }
}

/// Raises within the dwell: 50ms baseline, spike to 300ms, back to 50ms, then
/// a *second* spike to 400ms. Confirms a raise resets the dwell clock — the
/// second raise fires even though the first raise's dwell hasn't elapsed.
fn scenario_raise_resets_dwell() -> Scenario {
    let mut samples = stable(50_000, 30);
    samples.extend(stable(300_000, 5));
    samples.extend(stable(50_000, 20));
    samples.extend(stable(400_000, 5));
    samples.extend(stable(50_000, 100));
    Scenario {
        name: "raise resets dwell",
        description: "two spikes; second raise fires despite unelapsed dwell from the first",
        bounds: BufferBounds { min: 0, max: 20 },
        samples,
    }
}

fn main() {
    let scenarios: Vec<Scenario> = vec![
        scenario_stable_low_latency(),
        scenario_cross_region(),
        scenario_latency_spike(),
        scenario_loss_burst(),
        scenario_oscillating(),
        scenario_raise_resets_dwell(),
    ];

    let mut summary = String::new();
    for scenario in &scenarios {
        let rows = run(scenario);
        print_timeline(scenario, &rows);

        // Summary: first and last buffer, max buffer reached, decision count.
        let first = rows.first().map(|r| r.buffer).unwrap_or(0);
        let last = rows.last().map(|r| r.buffer).unwrap_or(0);
        let max = rows.iter().map(|r| r.buffer).max().unwrap_or(0);
        let decisions = rows.iter().filter(|r| r.decision.is_some()).count();
        let _ = writeln!(
            summary,
            "{:>28}  start={} end={} max={} decisions={}",
            scenario.name, first, last, max, decisions
        );
    }

    println!();
    println!("=== summary ===");
    println!(
        "{:>28}  {:>5} {:>3} {:>3}  decisions",
        "", "start", "end", "max"
    );
    print!("{summary}");
}

// A trivial assertion so `cargo test --example sim_consensus` confirms the
// harness itself produces sane output — the stable-50ms scenario must settle
// at buffer 2 with exactly one decision (the initial raise). This guards the
// harness against future API drift in DecisionMaker.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_low_latency_settles_at_2() {
        let rows = run(&scenario_stable_low_latency());
        let last = rows.last().unwrap();
        assert_eq!(last.buffer, 2, "stable 50ms should settle at buffer 2");
        let decisions = rows.iter().filter(|r| r.decision.is_some()).count();
        assert_eq!(
            decisions, 1,
            "exactly one decision (the initial raise to 2)"
        );
    }

    #[test]
    fn cross_region_settles_at_4() {
        let rows = run(&scenario_cross_region());
        let last = rows.last().unwrap();
        assert_eq!(
            last.buffer, 4,
            "cross-region 150ms should settle at buffer 4"
        );
    }

    #[test]
    fn latency_spike_raises_immediately() {
        let rows = run(&scenario_latency_spike());
        // Frame 31 is the first 300ms sample.
        let spike = &rows[30]; // 0-indexed: frame 31
        assert_eq!(
            spike.frame, 31,
            "sanity: frame 31 is the first spike sample"
        );
        assert!(
            spike.decision.is_some(),
            "raise should fire on the first 300ms sample"
        );
        assert_eq!(spike.buffer, 8, "300ms should raise the buffer to 8");
    }
}
