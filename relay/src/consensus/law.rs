//! The buffer control law's tunables and the raw signal windows it reads.
//!
//! Grouped here because these are the pure, state-free pieces of the target
//! formula: the tuning knobs, the derived-input record the trace reports, and
//! the small per-slot accumulators (recent-RTT ring, loss-window snapshots,
//! outage absorption pool) that turn raw counters into the formula's terms.

use super::*;

/// The fixed margin of the apply horizon, in turns, added on top of the buffer
/// span (see [`DecisionMaker::decide`]). The buffer span covers observation lag
/// and client spread, which both scale with the cushion; this margin covers the
/// delivery of the stamped turn itself. At the 24/sec turn rate a few turns is
/// well under a quarter-second of scheduling slack -- comfortable for any
/// reasonable path, tight enough that a player feeling lag sees relief
/// promptly.
pub(in crate::consensus) const APPLY_HORIZON: u32 = 3;

/// How much session-frame progress must elapse between rate-limited traces of the
/// control law's inputs (see [`DecisionMaker::trace_control_inputs`]). 600 turns
/// is ~25s at the 24/sec turn rate -- rare enough that a full game logs only a
/// handful of lines at the debug level, frequent enough to watch the buffer
/// track conditions over the course of a match.
pub(in crate::consensus) const BUFFER_TRACE_INTERVAL_TURNS: u32 = 600;

/// The control law's target buffer size together with the intermediates it was
/// derived from, so the diagnostic trace can report *why* a target came out where
/// it did without recomputing the formula. `path_us` is the worst pairwise path,
/// `worst_loss_risk` the highest per-slot `loss_rate * eff_rtt`, `burst_turns`
/// the worst per-slot capped blackout-run length.
pub(in crate::consensus) struct TargetInputs {
    pub(in crate::consensus) target: u32,
    /// The target as the shrink gate sees it: identical, except the path term
    /// is `ceil`'d with [`ControlLaw::shrink_headroom_us`] of margin added, so
    /// a path within the margin of a whole-turn boundary rounds up to the size
    /// it is hugging instead of baiting a shrink. Always `>= target`; raises
    /// never use it.
    pub(in crate::consensus) shrink_target: u32,
    pub(in crate::consensus) path_us: u32,
    pub(in crate::consensus) worst_loss_risk: f64,
    pub(in crate::consensus) burst_turns: u32,
}

/// How many recent RTT samples to keep per slot for jitter-aware sizing.
/// At 24 turns/sec this is ~1.3s of history -- enough to catch the latency
/// spikes that cause lockstep stalls while retaining bounded, inline storage.
pub(in crate::consensus) const RTT_WINDOW_SIZE: usize = 32;

/// How many decimated loss-counter snapshots each slot retains. The ring spans
/// [`ControlLaw::loss_memory_samples`] of history, so each snapshot covers
/// `loss_memory_samples / LOSS_SNAPSHOT_COUNT` conditions samples; 16 keeps the
/// per-slot footprint small (a few hundred bytes) while making the memory
/// window's decay reasonably smooth (~0.5s steps at the default horizon).
pub(in crate::consensus) const LOSS_SNAPSHOT_COUNT: usize = 16;

/// Minimum sent-packet delta a loss window needs before it reports a rate. A
/// window over fewer packets quantizes brutally -- one loss in two packets
/// reads as 50% -- and a single such reading, multiplied by a high-latency
/// link's RTT, would swing the target by several turns on what is statistically
/// noise. Below this floor the window reports "no estimate" instead.
pub(in crate::consensus) const MIN_LOSS_WINDOW_SENT: u64 = 8;

/// A receive gap at or past this marks the enclosing counter interval as an
/// outage, not flowing weather. Conditions samples are receive-triggered (one
/// lands only when the slot's link delivers fresh turns), so the time between
/// accepted samples is the link's receive gap: a gap this long means the
/// session was stalled or the link was dark, and no depth inside any session's
/// buffer bounds -- a few hundred milliseconds -- can absorb that lateness.
/// The loss counted across such a gap is evidence about a dead path, not about
/// the weather the buffer prices, so the interval is excluded from the loss
/// windows (see [`SlotState::rebaseline_after_outage`]). Folding it in would
/// also punish a short outage *harder* than a long one: past the QUIC idle
/// timeout the connection tears and the reconnect epoch resets the windows
/// clean, while a shorter fade would keep the poisoned interval for the whole
/// loss memory plus the shrink floor.
pub(in crate::consensus) const OUTAGE_GAP_MIN: Duration = Duration::from_secs(1);

/// How many advancing samples after its gap an outage pool's banked credit
/// may still absorb late loss declarations. Loss detection needs post-resume
/// acks to declare the gap's packets lost, so those declarations land
/// *after* the gap sample -- as refinements or inside the first post-resume
/// intervals -- and would poison the restarted windows if differenced in as
/// fresh weather. Each gap's banked credit expires this many advancing
/// samples after *its own* gap -- a later gap never renews an earlier
/// pool's sample deadline -- so a leftover can never mask genuine
/// post-resume loss beyond a brief resolution window. ~1s of flowing
/// samples at the nominal cadence: comfortably past loss detection's
/// resolution (about one RTT after acks resume) at a fraction of the loss
/// memory. Advancing samples can run far slower than wall time on a
/// low-traffic link, which is what the wall-clock companion bound below
/// caps.
pub(in crate::consensus) const OUTAGE_LOSS_RESOLUTION_SAMPLES: u32 = 24;

/// The wall-clock companion to [`OUTAGE_LOSS_RESOLUTION_SAMPLES`]: banked
/// credit expires when *either* bound passes. The sample bound alone
/// stretches on a link whose sent counter advances rarely (advancing
/// samples can be far sparser than turns), which would let leftover credit
/// mask genuine loss for tens of seconds; this caps that stretch. It sits
/// above the sample bound's nominal ~1s so the sample bound stays the
/// binding one on a healthy-cadence link. The one place the wall bound is
/// not enforced is a gap-closing sample's own consumption (see
/// [`SlotState::rebaseline_after_outage`]): a frozen, ack-less gap defers a
/// recurrent fade's declarations to exactly that instant, so credit whose
/// wall window the gap swallowed may still meet them there -- but its
/// unmet remainder is dropped right after, never carried, because a
/// *healthy* stall's ack-only traffic resolves pending declarations
/// mid-gap (a receive gap does not imply an ack gap) and unmet expired
/// credit is therefore stale.
pub(in crate::consensus) const OUTAGE_LOSS_RESOLUTION_MAX_AGE: Duration = Duration::from_secs(2);

/// Ceiling on any single ingested RTT sample, in microseconds (10 seconds).
/// RTTs arrive as claims — a remote relay's conditions sidecar carries values
/// its own clients influenced — and no playable link approaches this. The
/// clamp keeps a hostile near-`u32::MAX` claim from saturating every
/// effective-RTT sum built on the sample; the target it would inflate is
/// clamped to the session's buffer bounds regardless, so this only tidies the
/// arithmetic, never the outcome.
pub(in crate::consensus) const MAX_INGEST_RTT_US: u32 = 10_000_000;

/// Tuning for the control law. The defaults encode the target formula with
/// asymmetric "raise fast, lower slow" movement; they are `pub` so a test or
/// a future tuning pass can override them without touching the law itself.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ControlLaw {
    /// The duration of one game turn in microseconds. At the SC:R turn rate
    /// of 24/sec this is `1_000_000 / 24` (~41,667us). The buffer is sized in
    /// turns, so this converts RTT (us) to turns.
    pub turn_duration_us: u32,
    /// How many turns to decrement per lower decision. Raising jumps to the
    /// target immediately; lowering steps down.
    ///
    /// The step is not what keeps a shrink safe -- the floor is. A lower may
    /// never land below the target's trailing high-water mark whatever the
    /// step size, so a larger step cannot descend anywhere a sequence of
    /// single steps would not have reached anyway; it only spends fewer
    /// decisions getting there, and every one of those decisions is a resize
    /// every player feels. What the step does control is how long the buffer
    /// stays above a floor that has genuinely dropped, which is the whole cost
    /// of a brief episode once the weather behind it is over.
    pub lower_step: u32,
    /// Minimum number of turns between *lower* decisions -- and the span for
    /// which the target must have stayed *strictly below* the buffer before a
    /// lower fires (see `DecisionMaker::decide`). Raises fire immediately
    /// (no dwell) -- you can't dwell through a stall. The dwell gates only
    /// shrinks: every buffer-size change alters the game feel for every
    /// player, so shrinks should be infrequent and well-validated. 120 turns
    /// ~ 5s -- enough samples (120) to be confident the improvement is stable
    /// before the buffer shrinks.
    pub min_dwell_turns: u32,
    /// Margin (us) added to the pairwise path before the shrink gate's `ceil`:
    /// a lower fires only if the target re-computed with this margin on its
    /// path term still sits below the buffer. The dwell, floor, and probation
    /// all act in quantized turn space, which cannot tell a path 60% of the
    /// way into its whole-turn bucket (comfortable slack, shrink is safe) from
    /// one at 99.5% (sub-millisecond slack, a shrink is a stutter waiting for
    /// the next RTT wobble) -- both yield the identical target. This is the
    /// continuous-space deadband that refuses the boundary-hugging shrinks
    /// outright instead of letting probation punish them after players felt
    /// the dip. Sized to clear the estimator noise the recent-max jitter
    /// window hasn't already captured (a few ms on a stable link) while
    /// staying well under a turn, so a genuine regime drop still shrinks
    /// promptly. Raises never see the margin.
    pub shrink_headroom_us: u32,
    /// The short loss window: how many recent conditions samples (samples
    /// arrive roughly once per turn) the fast-reacting loss estimate covers.
    /// Long enough that its packet denominator makes the rate statistically
    /// meaningful, short enough that a fresh loss burst moves the target
    /// within about a second. 24 samples ~ 1s at 24/sec.
    pub loss_attack_samples: u32,
    /// The long loss window: how many recent conditions samples the
    /// slow-decaying loss estimate covers. This is the buffer's loss
    /// *memory* -- how long after packet loss subsides the target keeps
    /// pricing it in. Random loss produces loss-free stretches many times
    /// longer than its mean gap, so this must dwarf the attack window or the
    /// target collapses (and the buffer flaps) between drops. 192 samples
    /// ~ 8s at 24/sec.
    pub loss_memory_samples: u32,
    /// How many turns of session-frame progress the shrink floor looks back
    /// over: a lower never takes the buffer below the target's maximum in this
    /// trailing window. This is the knob for how long the buffer stays
    /// cautious after conditions improve. Too short and noise whose peaks
    /// recur less often than the window flaps the buffer (shrink into the
    /// recurrence, re-raise on the next peak); too long and the buffer is the
    /// SC:R stuck-high complaint. 600 turns ~ 25s at 24/sec rides out
    /// realistic burst spacing while a genuine improvement still shows up
    /// well under a minute (the lookback, then one dwell per step down).
    pub shrink_lookback_turns: u32,
}

impl Default for ControlLaw {
    fn default() -> Self {
        Self {
            turn_duration_us: 1_000_000 / 24, // ~41,667us at 24 turns/sec
            lower_step: 2,
            min_dwell_turns: 120,       // ~5s at 24/sec
            shrink_headroom_us: 5_208,  // an eighth of a turn at 24/sec (~5.2ms)
            loss_attack_samples: 24,    // ~1s at 24/sec
            loss_memory_samples: 192,   // ~8s at 24/sec
            shrink_lookback_turns: 600, // ~25s at 24/sec
        }
    }
}

impl ControlLaw {
    /// How many conditions samples elapse between loss-counter snapshots: the
    /// memory window spread across the fixed snapshot ring.
    pub(in crate::consensus) fn loss_snapshot_interval(&self) -> u32 {
        (self.loss_memory_samples / LOSS_SNAPSHOT_COUNT as u32).max(1)
    }

    /// The width of one target-peak bucket in frames: the base shrink
    /// lookback spread across its bucket slice (the whole tracker spans 4x
    /// the lookback for the probation windows).
    pub(in crate::consensus) fn target_floor_bucket_span(&self) -> u32 {
        (self.shrink_lookback_turns / TARGET_FLOOR_BASE_BUCKETS as u32).max(1)
    }

    /// The width of one blackout-run bucket in conditions samples: the
    /// loss-memory horizon spread across the run tracker.
    pub(in crate::consensus) fn blackout_run_bucket_span(&self) -> u32 {
        (self.loss_memory_samples / BLACKOUT_RUN_BUCKETS as u32).max(1)
    }
}

/// How many buckets the target-peak tracker holds. Its bucket span is the
/// base shrink lookback divided by [`TARGET_FLOOR_BASE_BUCKETS`], so the whole
/// structure spans 4x the lookback -- room for the edge-probation windows
/// (base, 2x, 4x) to be read as progressively longer slices of one tracker.
pub(in crate::consensus) const TARGET_FLOOR_BUCKETS: usize = 32;

/// How many trailing buckets make up the *base* shrink floor -- the slice
/// spanning one `shrink_lookback_turns`.
pub(in crate::consensus) const TARGET_FLOOR_BASE_BUCKETS: usize = 8;

/// How many buckets the per-slot blackout-run tracker holds; it spans the
/// loss-memory window, so an observed blackout keeps its length in the burst
/// term for the same horizon the loss rate itself is remembered.
pub(in crate::consensus) const BLACKOUT_RUN_BUCKETS: usize = 8;

/// Ceiling on the burst term: however long an observed blackout ran, it never
/// adds more than this many turns to the target. Blackouts longer than this
/// are rare-tail weather that a buffer shouldn't chase -- covering them costs
/// every turn of input latency permanently, while riding them out costs one
/// brief stall.
pub(in crate::consensus) const BURST_TURNS_CAP: u32 = 4;

/// The evidence window a *burned* edge shrink must clear, as trailing
/// target-peak buckets: the tracker's whole span, 4x the base lookback
/// (~100s). One strike is all an edge gets -- a second dip into a level the
/// last dip already proved stuttery is exactly the feel this law exists to
/// avoid -- but the window is still finite, so recovery is bounded, never
/// stuck.
pub(in crate::consensus) const EDGE_PROBATION_BUCKETS: usize = TARGET_FLOOR_BUCKETS;

/// A trailing maximum over a sliding coordinate window (session frames or
/// sample counts), kept as per-bucket maxima so old peaks age out in
/// bucket-sized steps instead of requiring a full sample history. Reads are
/// slices of trailing buckets, so one tracker serves nested windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::consensus) struct BucketedMax<const N: usize> {
    pub(in crate::consensus) buckets: [u32; N],
    /// Index of the bucket currently accumulating.
    pub(in crate::consensus) head: usize,
    /// The coordinate at which the head bucket began, `None` until the first
    /// observation.
    pub(in crate::consensus) head_start: Option<u32>,
}

impl<const N: usize> Default for BucketedMax<N> {
    fn default() -> Self {
        Self {
            buckets: [0; N],
            head: 0,
            head_start: None,
        }
    }
}

impl<const N: usize> BucketedMax<N> {
    /// Folds one observation at coordinate `at` into the window.
    /// `bucket_span` is the width of one bucket in coordinate units.
    pub(in crate::consensus) fn observe(&mut self, at: u32, value: u32, bucket_span: u32) {
        let bucket_span = bucket_span.max(1);
        match self.head_start {
            None => self.head_start = Some(at),
            Some(start) => {
                let elapsed = at.saturating_sub(start);
                let advance = elapsed / bucket_span;
                if advance as usize >= N {
                    // The whole window slid past every bucket (a long stall or
                    // coordinate jump): nothing observed in it survives.
                    self.buckets = [0; N];
                    self.head_start = Some(at);
                } else {
                    for _ in 0..advance {
                        self.head = (self.head + 1) % N;
                        self.buckets[self.head] = 0;
                    }
                    self.head_start = Some(start + advance * bucket_span);
                }
            }
        }
        self.buckets[self.head] = self.buckets[self.head].max(value);
    }

    /// The maximum over the trailing `n_buckets` buckets (clamped to the
    /// tracker's size), including the currently accumulating one.
    pub(in crate::consensus) fn max_over_last(&self, n_buckets: usize) -> u32 {
        (0..n_buckets.min(N))
            .map(|age| self.buckets[(self.head + N - age) % N])
            .max()
            .unwrap_or(0)
    }
}

/// A fixed-size ring buffer of recent RTT samples for one slot. The
/// decision-maker uses the **max** of the recent samples as a crude
/// high-percentile estimator: in lockstep a single late turn stalls every
/// player, so the buffer must cover latency spikes, not the smoothed mean.
///
/// A `0` RTT (QUIC's "no measurement yet" sentinel) is never pushed -- it
/// means "no data," not "zero latency."
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::consensus) struct RttWindow {
    pub(in crate::consensus) samples: [u32; RTT_WINDOW_SIZE],
    pub(in crate::consensus) head: usize,
    pub(in crate::consensus) len: usize,
    /// Sample indices in arrival order with strictly decreasing RTTs. The
    /// front is always the current maximum; dominated samples are removed from
    /// the back as a new sample arrives. Each index enters and leaves once, so
    /// updates are amortized O(1) without a heap allocation.
    pub(in crate::consensus) max_indices: [u8; RTT_WINDOW_SIZE],
    pub(in crate::consensus) max_head: usize,
    pub(in crate::consensus) max_len: usize,
}

impl Default for RttWindow {
    fn default() -> Self {
        Self {
            samples: [0; RTT_WINDOW_SIZE],
            head: 0,
            len: 0,
            max_indices: [0; RTT_WINDOW_SIZE],
            max_head: 0,
            max_len: 0,
        }
    }
}

impl RttWindow {
    /// Pushes `rtt` into the ring buffer. A `0` (no measurement) is skipped.
    pub(in crate::consensus) fn push(&mut self, rtt: u32) {
        if rtt == 0 {
            return;
        }

        let sample_index = self.head;

        // When full, `head` names the sample aging out. Monotonic-queue
        // indices remain in arrival order, so the expired index, when it has
        // not already been dominated, can only be at the front.
        if self.len == RTT_WINDOW_SIZE
            && self.max_len > 0
            && usize::from(self.max_indices[self.max_head]) == sample_index
        {
            self.max_head = (self.max_head + 1) % RTT_WINDOW_SIZE;
            self.max_len -= 1;
        }

        // Samples no larger than the new one can never become the maximum
        // before it expires, so retire them from the back. Removing ties keeps
        // the newest equal maximum, which outlives every older copy.
        while self.max_len > 0 {
            let back = (self.max_head + self.max_len - 1) % RTT_WINDOW_SIZE;
            let back_index = usize::from(self.max_indices[back]);
            if self.samples[back_index] > rtt {
                break;
            }
            self.max_len -= 1;
        }

        self.samples[sample_index] = rtt;
        let max_tail = (self.max_head + self.max_len) % RTT_WINDOW_SIZE;
        self.max_indices[max_tail] = sample_index as u8;
        self.max_len += 1;

        self.head = (self.head + 1) % RTT_WINDOW_SIZE;
        if self.len < RTT_WINDOW_SIZE {
            self.len += 1;
        }
    }

    /// The recent max RTT -- the jitter-aware estimate. Returns `0` when no
    /// sample has been pushed yet (no measurement available).
    pub(in crate::consensus) fn max(&self) -> u32 {
        if self.max_len == 0 {
            return 0;
        }
        self.samples[usize::from(self.max_indices[self.max_head])]
    }
}

/// One accepted cumulative-counter endpoint, retained so a later sample can be
/// differenced against it for a loss rate over the intervening packets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::consensus) struct LossSnapshot {
    /// Cumulative `lost_packets` at the time of the snapshot.
    pub(in crate::consensus) lost: u64,
    /// Cumulative `sent_packets` at the time of the snapshot.
    pub(in crate::consensus) sent: u64,
    /// The slot's `advancing_samples` count when the snapshot was taken --
    /// its age coordinate.
    pub(in crate::consensus) at_sample: u32,
}

/// One slot's condition history. RTT samples go into a ring buffer for
/// jitter-aware sizing (the recent max, not the smoothed mean). The cumulative
/// `lost_packets`/`sent_packets` counters are differenced against a ring of
/// decimated snapshots to get loss rates over two windows: a short one that
/// reacts to a fresh burst within about a second, and a long one that keeps
/// remembering the loss for several seconds after it subsides (see
/// [`windowed_loss_rate`](Self::windowed_loss_rate)).
///
/// `mesh_rtt_us` is the one-way mesh hop from the authority relay to this
/// slot's home relay -- `0` for local slots (home clients on this relay), or the
/// relay-pair RTT for remote slots (home clients on a peer relay). The
/// effective RTT (`rtt + mesh_rtt`) is what the path and loss formulas use,
/// so cross-relay paths include the mesh hop automatically.
///
/// The first sample establishes a baseline snapshot: no loss rate is reported
/// until a later sample reaches a strictly newer sent-packet endpoint (and the
/// window's packet count clears [`MIN_LOSS_WINDOW_SENT`]), so the
/// decision-maker doesn't act on a rate computed from one cumulative snapshot
/// or its later loss refinements. A high RTT on the first sample can still
/// raise the target -- RTT is instantaneous and doesn't need a baseline.
/// One outage gap's banked absorption credit: how many of that gap's sends
/// were not yet declared lost when the gap closed, plus the two deadlines
/// past which the credit no longer absorbs anything -- an advancing-sample
/// deadline ([`OUTAGE_LOSS_RESOLUTION_SAMPLES`]) and a wall-clock one
/// ([`OUTAGE_LOSS_RESOLUTION_MAX_AGE`]), whichever passes first. A zero
/// credit is an empty slot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::consensus) struct OutagePool {
    pub(in crate::consensus) credit: u64,
    pub(in crate::consensus) deadline: u32,
    /// `None` only in an empty slot; banking always stamps a deadline.
    pub(in crate::consensus) expires_at: Option<Instant>,
}
