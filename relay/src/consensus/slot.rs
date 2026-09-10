//! Per-slot decision-maker state: the conditions, counters and link-lifecycle
//! bookkeeping one participant contributes to the control law.
//!
//! Holds [`SlotState`] and its counter/loss-window folding, plus the small
//! connection-epoch lifecycle types the reconnect path returns.

use super::*;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::consensus) struct SlotState {
    /// Ring buffer of recent RTT samples for jitter-aware sizing.
    pub(in crate::consensus) rtt_window: RttWindow,
    /// The one-way mesh hop RTT (us) from the authority to this slot's home
    /// relay. `0` for local slots; the relay-pair RTT for remote slots.
    pub(in crate::consensus) mesh_rtt_us: u32,
    /// The newest `game_frame_count` observed on this slot's validated turns.
    /// Monotonic per slot; `None` until the slot's first framed turn (lobby
    /// turns carry no frame). The session's consensus coordinate is the
    /// *minimum* across slots, so one slot's inflated claim can't poison it.
    pub(in crate::consensus) frame: Option<GameFrameCount>,
    /// A bounded, recent history of `(seq, game_frame_count)` for this slot's
    /// framed turns — the turn's transport seq paired with the frame it stamped.
    /// Used to prove which frames a *survivor* has executed when a leave is
    /// decided: a turn stamped at seq `s` is provably executed once the session
    /// advanced `buffer_max` turns past `s`, so the leave's apply frame can be
    /// clamped to a frame every survivor can reach (see
    /// [`DecisionMaker::reachable_frame`]). Capped relative to the buffer depth,
    /// since only the window back to `frontier − buffer_max` is ever consulted.
    /// Only populated by [`observe_turn_frame`](DecisionMaker::observe_turn_frame)
    /// (the seq-aware production path); the seq-less
    /// [`observe_frame`](DecisionMaker::observe_frame) leaves it empty (tests).
    pub(in crate::consensus) frame_history: VecDeque<(u64, u32)>,
    /// The highest transport seq a framed turn from this slot has been observed
    /// at, so a stamp that arrives out of order (a lower seq after a higher one)
    /// is told apart from a stamp that genuinely went backwards.
    pub(in crate::consensus) newest_framed_seq: Option<u64>,
    /// The silence watch's per-slot clock: when this slot's gap-free prefix of
    /// forwarded turns last genuinely advanced (see
    /// [`note_forward_advance`](DecisionMaker::note_forward_advance)), or when
    /// the slot was last given a fresh link and so a fresh window to advance it
    /// in. `None` until either happens;
    /// [`silent_slot`](DecisionMaker::silent_slot) then measures from the
    /// session's own start instead.
    ///
    /// Deliberately not stamped by anything a client asserts. A turn's arrival,
    /// its frame stamp, and how far ahead its seq runs are all the client's
    /// choice; the forwarded prefix moves only when the turns below it really
    /// arrived, which is what makes this the one progress measure the watch can
    /// assign blame from.
    pub(in crate::consensus) last_forward_advance_at: Option<Instant>,
    /// When this slot's current connection generation was accepted here, or when
    /// a reinstated departure restored the slot onto a fresh link. `None` for a
    /// generation activated before this relay held any state for the slot, which
    /// is the original connection: it has been up for as long as the relay has
    /// known the slot at all.
    ///
    /// The silence watch owes a link this young a full window before it may
    /// close it — a connection that just came up has had no chance to forward
    /// anything yet. Deliberately separate from `last_forward_advance_at`: a new
    /// link buys the slot *time*, never a newer stop time.
    pub(in crate::consensus) connection_up_at: Option<Instant>,
    /// Whether the backwards-stamp tripwire (see
    /// [`DecisionMaker::observe_turn_frame`]) has already fired for this slot.
    /// It reports once: a client whose counter restarted stamps below the
    /// high-water mark on every turn until the counter catches up.
    pub(in crate::consensus) frame_regression_reported: bool,
    /// The current (latest) sample's cumulative `lost_packets`.
    pub(in crate::consensus) curr_lost: u64,
    /// The current (latest) sample's cumulative `sent_packets`.
    pub(in crate::consensus) curr_sent: u64,
    /// Decimated history of accepted `(lost, sent)` counter endpoints, oldest
    /// overwritten first. Differencing the current counters against an entry
    /// gives the loss rate over everything sent since it; entries are stamped
    /// with `advancing_samples` so a window of any sample depth can pick its
    /// anchor. Seeded with the baseline sample, then extended every
    /// [`ControlLaw::loss_snapshot_interval`] advancing samples.
    pub(in crate::consensus) loss_snapshots: [LossSnapshot; LOSS_SNAPSHOT_COUNT],
    /// Next write position in `loss_snapshots` (== oldest entry once full).
    pub(in crate::consensus) loss_snapshot_head: usize,
    /// How many `loss_snapshots` entries are populated.
    pub(in crate::consensus) loss_snapshot_len: usize,
    /// Count of accepted samples that advanced the sent-packet endpoint. The
    /// snapshot decimation clock and the age coordinate snapshots are stamped
    /// with; samples arrive roughly once per turn, so ages measured in it are
    /// approximately turns.
    pub(in crate::consensus) advancing_samples: u32,
    /// How many consecutive advancing samples (so far) lost *every* packet
    /// they covered -- an ongoing link blackout, measured in roughly turns.
    pub(in crate::consensus) blackout_run: u32,
    /// Windowed maximum of blackout-run lengths over the loss-memory horizon.
    /// A blackout of N turns delays a turn's delivery by up to N whole
    /// re-carry turns, which the mean loss rate structurally understates for
    /// bursty loss -- so the target gets this as its own term (capped at
    /// [`BURST_TURNS_CAP`]; see [`burst_turns`](Self::burst_turns)).
    pub(in crate::consensus) blackout_runs: BucketedMax<BLACKOUT_RUN_BUCKETS>,
    /// Whether we've ingested at least one sample for this slot.
    pub(in crate::consensus) seen: bool,
    /// Last sender RTT admitted into `rtt_window`. Equal cumulative counters
    /// can still carry a fresh RTT observation, but an exact duplicate must
    /// not consume another position in the sample-count window.
    pub(in crate::consensus) last_sender_rtt_us: Option<u32>,
    /// When the last *counter-moving* sample landed; the time since it is the
    /// receive gap the outage detection reads ([`OUTAGE_GAP_MIN`]). Samples
    /// with unchanged counters deliberately leave it alone -- across the mesh
    /// they are usually a cached snapshot re-carried on a sibling slot's
    /// traffic, not evidence this slot's link is alive. `None` until the
    /// baseline.
    pub(in crate::consensus) last_sample_at: Option<Instant>,
    /// Banked credit from the last two outage gaps, oldest first: sends from
    /// a gap not yet declared lost, against which later declarations are
    /// absorbed (hidden from the loss windows) instead of being priced as
    /// post-resume weather -- bounded bookkeeping, not packet provenance.
    /// Two generations so a recurrent fade's unresolved pool survives the
    /// next gap while each still expires on its *own* deadlines: a later
    /// gap never renews an earlier pool's deadlines -- at its close an
    /// expired pool may only meet that sample's declarations before its
    /// remainder is dropped.
    pub(in crate::consensus) outage_pools: [OutagePool; 2],
}

/// How one cumulative counter sample relates to the accepted loss baseline.
/// RTT and the receiver-local mesh hop are handled separately because neither
/// is a cumulative sender counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::consensus) enum CounterUpdate {
    /// The slot had no accepted cumulative baseline yet.
    Baseline,
    /// Sent packets advanced and lost packets did not move backward, so this
    /// sample forms a new loss interval.
    Advanced,
    /// Sent packets advanced, but across a receive gap long enough to be a
    /// stall or outage rather than flowing weather. The interval was excluded
    /// from the loss windows -- they re-anchored past it -- instead of being
    /// differenced in.
    OutageRebaselined,
    /// Loss detection advanced for the current sent-packet endpoint. Noq may
    /// declare an already-sent packet lost after the endpoint was sampled, so
    /// this refines that endpoint without rotating it.
    LossAdvanced,
    /// The counters did not move backward, but sent packets did not advance.
    /// There is no new denominator with which to form a loss interval.
    NonAdvancing,
    /// At least one counter moved backward relative to the accepted baseline.
    /// This is an out-of-order or otherwise stale sample.
    Stale,
}

impl SlotState {
    /// Clears observations that belong to one physical client connection while
    /// retaining the slot's game-progress history. A reconnect starts Noq's
    /// RTT and packet counters over, but it is still the same game participant:
    /// its last validated frame remains part of the session coordinate.
    pub(in crate::consensus) fn reset_link_conditions(&mut self) {
        self.rtt_window = RttWindow::default();
        self.mesh_rtt_us = 0;
        self.curr_lost = 0;
        self.curr_sent = 0;
        self.loss_snapshots = [LossSnapshot::default(); LOSS_SNAPSHOT_COUNT];
        self.loss_snapshot_head = 0;
        self.loss_snapshot_len = 0;
        self.advancing_samples = 0;
        self.blackout_run = 0;
        self.blackout_runs = BucketedMax::default();
        self.seen = false;
        self.last_sender_rtt_us = None;
        self.last_sample_at = None;
        self.outage_pools = [OutagePool::default(); 2];
    }

    /// The jitter-aware RTT: the recent max from the ring buffer. Returns `0`
    /// when no sample has been pushed (no measurement yet).
    pub(in crate::consensus) fn rtt(&self) -> u32 {
        self.rtt_window.max()
    }

    /// The effective RTT: `rtt + mesh_rtt`. This is the full one-way path from
    /// the client to the authority relay (client -> home-relay + mesh-hop for
    /// remote slots). The path and loss formulas use this so cross-relay paths
    /// are sized correctly.
    pub(in crate::consensus) fn eff_rtt(&self) -> u32 {
        self.rtt().saturating_add(self.mesh_rtt_us)
    }

    /// Advances the accepted cumulative counters only when a sample has a
    /// strictly newer sent-packet count and a nondecreasing lost-packet count,
    /// maintaining the snapshot ring as endpoints are accepted. A later loss
    /// declaration may refine the current endpoint in place; exact duplicates
    /// and stale samples change nothing, so a duplicate cannot erase history
    /// and an out-of-order sample cannot poison a window.
    ///
    /// `snapshot_interval` is the decimation clock: a snapshot is retained
    /// every that-many advancing samples (plus the baseline), spreading the
    /// ring across the law's loss-memory horizon. `run_bucket_span` is the
    /// blackout-run tracker's bucket width in advancing samples.
    ///
    /// `now` is when the sample was accepted. Samples are receive-driven, so
    /// the time since the previous accepted sample is the link's receive gap;
    /// an advancing sample across a gap of [`OUTAGE_GAP_MIN`] or more is an
    /// outage interval and is excluded from the loss windows rather than
    /// differenced in (see [`rebaseline_after_outage`](Self::rebaseline_after_outage)).
    pub(in crate::consensus) fn update_counters(
        &mut self,
        lost_packets: u64,
        sent_packets: u64,
        snapshot_interval: u32,
        run_bucket_span: u32,
        now: Instant,
    ) -> CounterUpdate {
        if !self.seen {
            self.curr_lost = lost_packets;
            self.curr_sent = sent_packets;
            self.seen = true;
            self.last_sample_at = Some(now);
            self.push_loss_snapshot();
            return CounterUpdate::Baseline;
        }

        if sent_packets < self.curr_sent || lost_packets < self.curr_lost {
            return CounterUpdate::Stale;
        }
        if sent_packets == self.curr_sent {
            if lost_packets > self.curr_lost {
                // Lost moved at the same endpoint: a genuinely fresh home
                // sample (a cached re-send is bit-identical), so it closes
                // the receive gap.
                self.last_sample_at = Some(now);
                // Declarations matched against banked outage credit are
                // hidden from every window; see `absorb_outage_losses`.
                let absorbed = self.absorb_outage_losses(lost_packets - self.curr_lost, now);
                self.curr_lost = lost_packets;
                // A loss declared late still belongs to packets sent at (or
                // before) this endpoint. Any snapshot recorded at this same
                // endpoint under-reported that loss; left alone, a window
                // anchored there would attribute the whole refinement to the
                // few packets sent *after* it, spiking the rate. Refine such
                // snapshots in place (there is at most one in practice: the
                // baseline, or a decimation snapshot that happened to land on
                // this endpoint). Older snapshots legitimately count the
                // refinement -- except the share absorbed by an outage pool,
                // which is hidden from them as well.
                for snapshot in &mut self.loss_snapshots[..self.loss_snapshot_len] {
                    if snapshot.sent == self.curr_sent {
                        snapshot.lost = lost_packets;
                    } else {
                        snapshot.lost = snapshot.lost.saturating_add(absorbed);
                    }
                }
                return CounterUpdate::LossAdvanced;
            }
            return CounterUpdate::NonAdvancing;
        }

        let delta_sent = sent_packets - self.curr_sent;
        let delta_lost = lost_packets.saturating_sub(self.curr_lost);

        // The receive gap is measured between *counter-moving* samples, and
        // only those update the clock. A sample with unchanged counters
        // (NonAdvancing above) must not close the gap: locally it is a no-op
        // interval, and across the mesh it is usually a *cached* snapshot of
        // this slot's conditions re-attached to a co-homed sibling's traffic
        // (see `snapshot_conditions`) -- during this slot's fade the sibling
        // keeps forwarding the stale entry, and letting those duplicates
        // advance the clock would erase the very gap the outage detection
        // reads. A genuinely flowing link moves its counters on essentially
        // every home sample (the relay is always sending it at least acks),
        // so keying the clock to movement costs nothing in the healthy case.
        let gap = self
            .last_sample_at
            .map(|at| now.saturating_duration_since(at));
        self.last_sample_at = Some(now);

        // An advancing sample across a stall-length receive gap measures a
        // dead or idle link, not weather -- exclude it from the windows.
        if gap.is_some_and(|gap| gap >= OUTAGE_GAP_MIN) {
            return self.rebaseline_after_outage(lost_packets, sent_packets, run_bucket_span, now);
        }

        // A declaration matched against banked outage credit is *assumed* to
        // be a gap's late-resolving loss: it is hidden from every retained
        // window anchor, and the blackout run is judged on the remainder.
        // This is bounded bookkeeping, not provenance -- no cumulative
        // counter can say which packets a declaration belongs to -- but the
        // misattribution cost is capped by the credit's size and expiry,
        // while pricing a dead gap's declarations as weather would recreate
        // the very spike the exclusion exists to prevent.
        let absorbed = self.absorb_outage_losses(delta_lost, now);
        let weather_lost = delta_lost - absorbed;
        if absorbed > 0 {
            for snapshot in &mut self.loss_snapshots[..self.loss_snapshot_len] {
                snapshot.lost = snapshot.lost.saturating_add(absorbed);
            }
        }

        // A sample interval that lost *every* packet it covered is a link
        // blackout: nothing sent in it -- including every re-carry -- got
        // through, so consecutive such intervals stack whole turns of delivery
        // delay. Track the run length (>= rather than == because the counters
        // are peer-reported and a claimed lost > sent must still read as a
        // blackout, not wrap around it). Late loss declarations refine totals
        // but arrive without a sent-delta to compare against, so runs are
        // built from advancing samples only -- a slight undercount when loss
        // detection lags, which the rate terms still cover.
        if weather_lost >= delta_sent {
            self.blackout_run = self.blackout_run.saturating_add(1);
        } else {
            self.blackout_run = 0;
        }

        self.curr_lost = lost_packets;
        self.curr_sent = sent_packets;
        self.advancing_samples = self.advancing_samples.saturating_add(1);
        // Observing the (possibly zero) run every advancing sample is what
        // slides the run tracker's window; a stale burst must age out even
        // when no new blackout occurs.
        self.blackout_runs
            .observe(self.advancing_samples, self.blackout_run, run_bucket_span);
        if self.advancing_samples.is_multiple_of(snapshot_interval) {
            self.push_loss_snapshot();
        }
        CounterUpdate::Advanced
    }

    /// Accepts an advancing sample whose interval spanned a stall-length
    /// receive gap ([`OUTAGE_GAP_MIN`]), excluding that interval from the loss
    /// windows instead of differencing it in as weather.
    ///
    /// The windows restart at the post-gap endpoint (mirroring what the
    /// reconnect epoch reset does when an outage runs long enough to tear the
    /// connection), and the gap's sends not yet declared lost are banked to
    /// absorb the late declarations that follow once acks resume.
    ///
    /// Banking is deliberately unconditional, because it is *self-limiting*:
    /// credit only ever cancels losses that actually get declared. A dead
    /// gap's credit is typically consumed by its own late declarations; an
    /// idle gap's keepalive-sized credit either expires unused or -- since
    /// absorption is bookkeeping without packet provenance -- soaks up that
    /// much genuine weather instead. The worst case of over-banking is
    /// therefore bounded and brief: at most the gap's own handful of sends,
    /// until the credit's deadlines pass. The worst case of under-banking is
    /// the original spike this mechanism exists to prevent. (Gating on send
    /// pacing was tried and is unsound: Noq's congestion collapse plus PTO
    /// backoff drives a dead path's *actual* wire rate below any fixed
    /// threshold as a fade lengthens, misclassifying exactly the gaps that
    /// matter.)
    ///
    /// The gap deliberately leaves **no burst-term residue**. Cumulative
    /// counters cannot tie a loss declaration to the packets that died, so
    /// absorption is fungible bookkeeping, not provenance: banked idle
    /// credit could "materialize" genuine weather losses as outage evidence,
    /// charging a healthy link the capped credit -- and send pacing fails in
    /// the opposite direction (above). With no sound dead-path arbiter at
    /// this layer, the residue is omitted: a recurring fade is priced when
    /// it manifests on flowing traffic, which the raise side of the law
    /// already does within about a second.
    pub(in crate::consensus) fn rebaseline_after_outage(
        &mut self,
        lost_packets: u64,
        sent_packets: u64,
        run_bucket_span: u32,
        now: Instant,
    ) -> CounterUpdate {
        let delta_sent = sent_packets - self.curr_sent;
        let delta_lost = lost_packets.saturating_sub(self.curr_lost);

        // Under a recurrent fade the previous outage's losses are often
        // declared inside the *next* gap's interval (acks never resumed in
        // between), so this gap's `delta_lost` consumes the prior pools
        // first -- otherwise the old declarations would cancel the new gap's
        // banking, leaving the new gap's own late declarations to be priced
        // as weather. The wall deadline is deliberately not enforced for
        // this one consumption: a frozen (ack-less) gap defers resolution to
        // exactly this sample, so credit whose wall window the gap itself
        // swallowed still gets to meet its declarations here.
        let consumed = self.drain_pools(delta_lost, None);
        let residual_declared = delta_lost - consumed;
        let fresh_undeclared = delta_sent.saturating_sub(residual_declared);

        // What the close's declarations did not consume survives only within
        // its own wall window; a wall-expired remainder is dropped, never
        // carried. A receive gap proves only that no fresh payload produced
        // a sample -- ack-only traffic still flows through a *healthy* stall
        // and resolves pending declarations mid-gap (they land in this very
        // delta), so expired credit with nothing to meet here is stale, and
        // carrying it (or handing it the gap's length back) would let every
        // ordinary stall revive old credit to mask genuine post-stall loss.
        // Accepted residual corner: a second dead fade beginning within a
        // round-trip of the first and outrunning the wall cap prices the
        // first fade's stragglers as weather -- bounded by that credit, once.
        for pool in &mut self.outage_pools {
            if pool.expires_at.is_none_or(|expires| now >= expires) {
                pool.credit = 0;
            }
        }

        self.curr_lost = lost_packets;
        self.curr_sent = sent_packets;
        self.advancing_samples = self.advancing_samples.saturating_add(1);
        // The gap interval is excluded wholesale: no weather-driven run, and
        // no synthetic residue either (see the no-residue note above).
        self.blackout_run = 0;
        self.blackout_runs
            .observe(self.advancing_samples, self.blackout_run, run_bucket_span);

        // The gap interval never enters the loss windows: restart them at the
        // post-gap endpoint, exactly like a reconnect's window reset.
        self.loss_snapshots = [LossSnapshot::default(); LOSS_SNAPSHOT_COUNT];
        self.loss_snapshot_head = 0;
        self.loss_snapshot_len = 0;
        self.push_loss_snapshot();

        // Bank this gap's credit as its own generation with its own
        // deadlines. A surviving prior pool keeps its deadlines -- a new gap
        // must never renew nearly-expired old credit, or stale credit could
        // absorb genuine loss well past its resolution window. With both
        // generation slots live, the older is dropped: a third unresolved
        // episode inside one resolution window is pathological, and dropping
        // the stalest credit only risks pricing its stragglers as weather,
        // never masking anything.
        if fresh_undeclared > 0 {
            if self.outage_pools[1].credit > 0 {
                self.outage_pools[0] = self.outage_pools[1];
            }
            self.outage_pools[1] = OutagePool {
                credit: fresh_undeclared,
                deadline: self
                    .advancing_samples
                    .saturating_add(OUTAGE_LOSS_RESOLUTION_SAMPLES),
                expires_at: Some(now + OUTAGE_LOSS_RESOLUTION_MAX_AGE),
            };
        }

        CounterUpdate::OutageRebaselined
    }

    /// Takes up to `declared` losses out of the banked outage pools (oldest
    /// generation first), returning how many were absorbed -- counted
    /// against outage credit rather than priced as current weather. This is
    /// deliberately bookkeeping, not attribution: no cumulative counter can
    /// say which packets a declaration belongs to, so what bounds the
    /// misattribution is the credit itself -- capped at each gap's
    /// undeclared sends and expired on the earlier of its sample deadline
    /// ([`OUTAGE_LOSS_RESOLUTION_SAMPLES`]) and its wall-clock age
    /// ([`OUTAGE_LOSS_RESOLUTION_MAX_AGE`]), so a leftover can never mask
    /// genuine post-resume loss for long.
    pub(in crate::consensus) fn absorb_outage_losses(
        &mut self,
        declared: u64,
        now: Instant,
    ) -> u64 {
        self.drain_pools(declared, Some(now))
    }

    /// Drains up to `declared` losses from the banked pools, oldest
    /// generation first. `wall` is the wall-clock instant to enforce expiry
    /// against -- `None` only at a gap-closing sample, where a frozen gap's
    /// deferred declarations get to meet credit whose wall window the gap
    /// itself swallowed (see
    /// [`rebaseline_after_outage`](Self::rebaseline_after_outage), which
    /// drops wall-expired remainders immediately afterward). The sample
    /// deadline is always enforced, lazily expiring what it passes.
    pub(in crate::consensus) fn drain_pools(
        &mut self,
        declared: u64,
        wall: Option<Instant>,
    ) -> u64 {
        let at = self.advancing_samples;
        let mut remaining = declared;
        let mut absorbed = 0;
        for pool in &mut self.outage_pools {
            if pool.credit == 0 {
                continue;
            }
            let wall_expired = match wall {
                Some(now) => pool.expires_at.is_none_or(|expires| now >= expires),
                None => false,
            };
            if at >= pool.deadline || wall_expired {
                pool.credit = 0;
                continue;
            }
            let take = remaining.min(pool.credit);
            pool.credit -= take;
            remaining -= take;
            absorbed += take;
        }
        absorbed
    }

    /// Appends the current counter endpoint to the snapshot ring, overwriting
    /// the oldest entry once full.
    pub(in crate::consensus) fn push_loss_snapshot(&mut self) {
        self.loss_snapshots[self.loss_snapshot_head] = LossSnapshot {
            lost: self.curr_lost,
            sent: self.curr_sent,
            at_sample: self.advancing_samples,
        };
        self.loss_snapshot_head = (self.loss_snapshot_head + 1) % LOSS_SNAPSHOT_COUNT;
        if self.loss_snapshot_len < LOSS_SNAPSHOT_COUNT {
            self.loss_snapshot_len += 1;
        }
    }

    /// The loss rate since `snapshot`: `delta_lost / delta_sent` over
    /// everything sent after it. `None` when fewer than
    /// [`MIN_LOSS_WINDOW_SENT`] packets span the window (too few to be
    /// meaningful). Clamped to 1.0: the counters are peer-reported, so nothing
    /// structural stops a claimed `delta_lost > delta_sent`, and a rate past
    /// certainty means nothing -- unclamped it would only inflate the
    /// loss-risk product downstream.
    pub(in crate::consensus) fn loss_rate_since(&self, snapshot: &LossSnapshot) -> Option<f64> {
        let delta_sent = self.curr_sent.saturating_sub(snapshot.sent);
        if delta_sent < MIN_LOSS_WINDOW_SENT {
            return None;
        }
        let delta_lost = self.curr_lost.saturating_sub(snapshot.lost);
        Some((delta_lost as f64 / delta_sent as f64).min(1.0))
    }

    /// The slot's loss estimate for the control law: the worse of two windowed
    /// rates over the snapshot ring.
    ///
    /// - **Attack** (short window): the rate since the newest snapshot at
    ///   least `attack_samples` old, so a fresh burst raises the estimate
    ///   within about a second of onset -- while still spanning enough packets
    ///   that one drop can't read as tens of percent.
    /// - **Memory** (long window): the rate since the oldest retained
    ///   snapshot, so the estimate decays over the ring's whole horizon after
    ///   loss subsides instead of collapsing at the first loss-free stretch.
    ///   Random loss produces gaps far longer than its mean spacing; without
    ///   the memory the target dips in every gap and the buffer flaps.
    ///
    /// Taking the max gives fast attack *and* slow decay. `None` until a
    /// window spans [`MIN_LOSS_WINDOW_SENT`] packets.
    pub(in crate::consensus) fn windowed_loss_rate(&self, attack_samples: u32) -> Option<f64> {
        if self.loss_snapshot_len == 0 {
            return None;
        }

        let oldest_index = if self.loss_snapshot_len == LOSS_SNAPSHOT_COUNT {
            self.loss_snapshot_head
        } else {
            0
        };
        let memory = self.loss_rate_since(&self.loss_snapshots[oldest_index]);

        // The attack anchor: newest snapshot already `attack_samples` old.
        // Snapshots are decimated, so this walk exits within a step or two;
        // when even the oldest snapshot is younger than the horizon (early
        // session), the oldest anchors a shorter-than-nominal window and the
        // packet-count floor in `loss_rate_since` guards its significance.
        let mut attack_anchor = &self.loss_snapshots[oldest_index];
        for age in 0..self.loss_snapshot_len {
            let index =
                (self.loss_snapshot_head + LOSS_SNAPSHOT_COUNT - 1 - age) % LOSS_SNAPSHOT_COUNT;
            let snapshot = &self.loss_snapshots[index];
            if self.advancing_samples.saturating_sub(snapshot.at_sample) >= attack_samples {
                attack_anchor = snapshot;
                break;
            }
        }
        let attack = self.loss_rate_since(attack_anchor);

        match (attack, memory) {
            (Some(a), Some(m)) => Some(a.max(m)),
            (one, other) => one.or(other),
        }
    }

    /// The burst term this slot contributes to the target: the longest link
    /// blackout observed within the loss-memory horizon, in turns, capped at
    /// [`BURST_TURNS_CAP`]. The `loss_rate * eff_RTT` term prices how *much*
    /// is lost; this prices how *long* delivery goes dark -- for bursty loss
    /// (queue overflows, wifi fades: how real loss usually arrives) the mean
    /// rate can read low while a blackout still delays a turn by its whole
    /// duration in re-carries.
    pub(in crate::consensus) fn burst_turns(&self) -> u32 {
        self.blackout_runs
            .max_over_last(BLACKOUT_RUN_BUCKETS)
            .min(BURST_TURNS_CAP)
    }
}

/// Current physical-link lifecycle for an epoch-aware slot. Absence from the
/// map is the one-way legacy compatibility state. A down generation is a
/// tombstone; once a previously unseen replacement opens, the old token moves
/// to `retired_connection_epochs` and remains rejected for the session lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::consensus) enum ConnectionState {
    Up(u64),
    Down(u64),
}

impl ConnectionState {
    pub(in crate::consensus) fn epoch(self) -> u64 {
        match self {
            Self::Up(epoch) | Self::Down(epoch) => epoch,
        }
    }
}

/// How a reliable `connected=true` frame relates to the locally known slot
/// generation. The caller uses this before claiming a reconnect hold so a
/// terminal current or retired replay cannot consume the hold it must not clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionActivation {
    Current,
    Replacement,
    Rejected,
}

/// Result of atomically resolving a reliable connection-up event against the
/// slot's departure and generation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconnectAdmission {
    /// The generation is live. `reinstated` says an undecided departure was
    /// consumed and its suspended game-progress state restored.
    Admitted { reinstated: bool },
    /// The generation is stale, terminal, or arrived after a final leave.
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::consensus) struct ReconnectTransition {
    pub(in crate::consensus) admission: ReconnectAdmission,
    pub(in crate::consensus) consume_hold: bool,
}

/// Whether an epoch-fenced departure was rejected, recorded as an undecided
/// drop that needs a hold, or merged after a final leave was already cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DepartureRecordOutcome {
    Rejected,
    Pending,
    Terminal,
}
