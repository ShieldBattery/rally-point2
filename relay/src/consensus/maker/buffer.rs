//! The buffer control law as the decision-maker runs it: computing the target
//! from current conditions, applying the raise/shrink asymmetry, scheduling
//! the change at a future turn, and queuing the directive the turn path
//! stamps.

use super::*;

impl DecisionMaker {
    /// Computes the target buffer size from current conditions, without
    /// applying it. This is the formula:
    ///
    /// ```text
    /// target = ceil(pairwise_path / turn_duration)
    ///        + max(ceil(loss_risk / turn_duration), burst_turns)
    /// ```
    ///
    /// Path and loss are `ceil`'d separately because loss recovery is quantized
    /// to whole turns: a re-carry rides the next packet exactly one
    /// `turn_duration` later, so it adds a whole number of turns to the delivery
    /// time, not a continuous fraction absorbed into the path's `ceil` slack.
    /// Combining them into one `ceil` would under-provision -- e.g. at 150ms
    /// path with one re-carry, delivery is `41666 + 150000 = 191666us` needing
    /// 5 turns; the separated form gives `4 + 1 = 5` (correct), a combined form
    /// gives `ceil(157500/41666) = 4` (stalls on a single loss).
    ///
    /// Returns `None` when no slot has an RTT measurement yet (hold until we
    /// have data). Also public so a caller or debug UI can inspect what the
    /// target would be without firing a decision.
    pub fn target(&self) -> Option<u32> {
        self.target_inputs().map(|inputs| inputs.target)
    }

    /// The target buffer size and the intermediates the formula derived it from
    /// (see [`target`](Self::target) for the formula). `decide` computes this once
    /// per ingest -- reusing the intermediates for the diagnostic trace instead of
    /// deriving them a second time -- and `target` is the thin projection to just
    /// the size for external callers. `None` when no slot has an RTT measurement
    /// yet.
    pub(in crate::consensus) fn target_inputs(&self) -> Option<TargetInputs> {
        // Find the two highest effective RTTs and the worst loss risk in one
        // pass. The former used to allocate and sort a Vec, while the latter
        // walked every slot again and recomputed its effective RTT.
        let mut measured = 0;
        let mut highest = 0;
        let mut second_highest = 0;
        let mut worst_loss_risk = 0.0;
        let mut burst_turns = 0;

        for state in self.slots.values() {
            // Effective RTT is the full one-way path from the client to the
            // authority relay, including the mesh hop for remote slots.
            let eff_rtt = state.eff_rtt();
            if eff_rtt > 0 {
                measured += 1;
                if eff_rtt >= highest {
                    second_highest = highest;
                    highest = eff_rtt;
                } else if eff_rtt > second_highest {
                    second_highest = eff_rtt;
                }
            }

            // Burst loss on high-latency links is worse because more packets
            // are in flight during the burst window. Reuse the effective RTT
            // already computed for the pairwise-path calculation.
            if let Some(loss_rate) = state.windowed_loss_rate(self.law.loss_attack_samples) {
                let loss_risk = loss_rate * f64::from(eff_rtt);
                if loss_risk > worst_loss_risk {
                    worst_loss_risk = loss_risk;
                }
            }

            burst_turns = burst_turns.max(state.burst_turns());
        }

        if measured == 0 {
            return None; // no RTT data yet, hold
        }

        // Worst pairwise path: (eff_A + eff_B) / 2 for the two highest.
        // A turn from A to B travels eff_A/2 + eff_B/2 = (eff_A + eff_B) / 2.
        // Using the actual pairwise path (not max_eff) avoids overshooting
        // when only one player has high latency -- lower buffer = less delay.
        let path_us = if measured >= 2 {
            // Summed in u64: each effective RTT is client-influenced and can
            // saturate near u32::MAX, so a u32 sum could overflow (a
            // debug-build panic; a silently small path in release). The
            // halved sum always fits back into u32.
            ((u64::from(highest) + u64::from(second_highest)) / 2) as u32
        } else {
            // One slot: assume symmetric (both legs same eff_RTT).
            highest
        };

        let turn_us = self.law.turn_duration_us as f64;
        let path_turns = (path_us as f64 / turn_us).ceil() as u32;
        let loss_turns = (worst_loss_risk / turn_us).ceil() as u32;
        // The shrink gate's path term: the same ceil with the headroom margin
        // added, so a path within the margin of a whole-turn boundary counts
        // as the size it is hugging. Only the path gets the margin -- the loss
        // and burst terms carry their own smoothing in time (attack/memory
        // windows), and boundary quantization is a path phenomenon.
        let margined_path_turns =
            (path_us.saturating_add(self.law.shrink_headroom_us) as f64 / turn_us).ceil() as u32;

        // Both loss terms estimate one quantity -- the delivery delay the worst
        // link's loss adds -- from different angles, so the estimate is the
        // worse of the two, not their sum.
        let loss_delay_turns = loss_turns.max(burst_turns);

        Some(TargetInputs {
            // Saturating: the terms derive from client-influenced inputs, and
            // an absurd target is clamped to the session bounds at `decide`
            // anyway — overflow here would only trade that clamp for a
            // debug-build panic.
            target: path_turns.saturating_add(loss_delay_turns),
            shrink_target: margined_path_turns.saturating_add(loss_delay_turns),
            path_us,
            worst_loss_risk,
            burst_turns,
        })
    }

    /// Queues a directive moving (or, when `new_buffer` equals the current buffer,
    /// re-affirming) the session buffer to `new_buffer`, scheduled a horizon past
    /// `frame`, and returns the [`Decision`]. Shared by the control law and the
    /// unconditional initial broadcast so both stamp through the identical
    /// machinery: one `decision_seq` increment, one pending directive the caller
    /// hands out via [`active_directive`](Self::active_directive), one apply-horizon
    /// computation.
    ///
    /// The apply horizon: the session frame is the *slowest* client's progress as
    /// observed over its own uplink, so the relay's view lags by roughly the
    /// cushion, and the fastest client runs ahead of the slowest by at most the
    /// cushion again -- both scale with the buffer, so the horizon does too (the
    /// wider of the old and new cushion, plus a fixed delivery margin).
    /// `inputs` is the control-law derivation to record alongside the
    /// directive, or `None` for a directive the law did not author (the
    /// one-shot re-affirm of the standing buffer). It is carried as a
    /// parameter rather than read back off the maker so a caller cannot queue
    /// a directive and leave the previous decision's derivation standing
    /// against it.
    pub(in crate::consensus) fn queue_directive(
        &mut self,
        new_buffer: u32,
        frame: GameFrameCount,
        inputs: Option<BufferDecisionInputs>,
    ) -> Decision {
        // The last line of defense for every locally-authored directive: the
        // decision path clamps through `game_safe_clamp`, but the initial
        // unconditional broadcast re-affirms `self.buffer` raw — which is
        // seeded straight from wire `bounds.min` with no validation — and any
        // future caller could slip the same way. Capping at the single point
        // every directive is built means no configuration can make this relay
        // author a game-breaking depth. Deliberately NOT applied to a peer
        // authority's stamp this relay merely forwards (see
        // `observe_directive`'s caller): rewriting or dropping one selectively
        // would hand different clients different depths, which is itself a
        // desync — and an observed over-ceiling buffer left raw as the
        // baseline is what lets a later promotion here author the corrective
        // lower instead of believing no change is needed.
        let new_buffer = new_buffer.min(GAME_SYNC_SAFE_BUFFER_MAX);
        let span = self.buffer.0.max(new_buffer);
        self.buffer = BufferSize(new_buffer);
        let applied_frame =
            GameFrameCount(frame.0.saturating_add(span).saturating_add(APPLY_HORIZON));
        self.last_decision_frame = Some(frame);

        // A newer decision replaces an older still-broadcasting one -- its higher
        // `decision_seq` tells clients the latest buffer wins even when copies of
        // both interleave on the wire.
        self.decision_seq += 1;
        // This seq now reflects this relay's own authorship, so an equal-seq
        // stamp observed later wins only from a strictly higher relay id --
        // the same displacement rule clients apply.
        self.decision_seq_tiebreak = self.own_relay_id.map(|id| id.0);
        self.pending_decision_inputs = inputs;
        self.pending_directive = Some(BufferDirective {
            buffer_turns: new_buffer,
            apply_at_frame: applied_frame.0,
            decision_seq: self.decision_seq,
            // The deterministic tie-break for the staggered-handoff window
            // where two relays can both briefly believe they hold authority:
            // each stamps its own `decision_seq` count from where IT started,
            // so two independent relays can collide on the same seq with
            // different `buffer_turns`. Clients break the tie by relay id
            // (see `directive::DirectiveTracker`) rather than by whichever
            // copy happened to arrive first.
            authority_relay_id: self.own_relay_id.map(|id| id.0),
        });

        Decision {
            buffer: self.buffer,
            applied_frame,
        }
    }

    /// Runs the control law: compute the target, then move toward it
    /// asymmetrically -- raises jump to the target immediately (no dwell, you
    /// can't dwell through a stall); lowers decrement by `lower_step` gated by
    /// `min_dwell_turns` (shrinks are infrequent and well-validated).
    ///
    /// The first framed turn on this authority also forces one *unconditional*
    /// broadcast of the current buffer if the control law itself made no change:
    /// the law only emits a directive when the buffer moves, so a session that
    /// sits at its initial buffer would otherwise never broadcast one, leaving a
    /// client that seeded a different buffer than the relay uncorrected. A real
    /// decision at the first framed turn already broadcasts the buffer, so the
    /// fallback fires only when the law holds -- exactly the "target sits at the
    /// minimum" gap. Either way, a client already at that depth applies the
    /// directive as a no-op resize. Reset on promotion, so a newly promoted
    /// authority re-affirms the buffer once.
    pub(in crate::consensus) fn decide(&mut self) -> Option<Decision> {
        // No framed turn observed yet (lobby): there is no consensus
        // coordinate to schedule against, so hold.
        let frame = self.session_frame()?;

        let inputs = self.target_inputs();
        if let Some(inputs) = &inputs {
            self.trace_control_inputs(frame, inputs);
        }

        // The control law, when it has an RTT-derived target. The end-to-end
        // delivery cushion is a clamped ADDITIVE term on the law's target — the
        // law itself is untouched: per-hop and lag-responsive slack for the
        // path segments per-link RTT/loss cannot see (a turn clearing one hop
        // and stalling on the next), riding into the same `BufferBounds` clamp
        // below. Its inputs are client-claimed beacon cursors, so a malicious
        // client can only understate its own delivery — the cushion's cap and
        // the bounds clamp bound that lever to a few turns of extra buffer in
        // its own game (see `crate::consensus::delivery`).
        if let Some(inputs) = &inputs {
            // Sustained arrival-interval stretch rides the target the same way
            // the delivery cushion does: a clamped ADDITIVE term, the law
            // itself untouched. It is the relay-measured form of "the clients
            // are stalling anyway" — persistent client-side stalls slow their
            // turn production, which per-link RTT/loss cannot see — and it is
            // the automatic replacement for the retired user-facing latency
            // setting (see `PhaseController::stretch_turns` for the term's
            // shape, sustain, and one-turn cap). Folded before the peak
            // observation below, so the shrink floor and edge probation hold
            // a stretch-raised buffer exactly as they hold any other raise —
            // a lowered buffer that re-triggers the stretch burns the edge
            // and stops being retried.
            let stretch_turns = self.phase.stretch_turns(Instant::now());
            let cushion_turns = self.delivery.cushion_turns();
            let additive_turns = cushion_turns.saturating_add(stretch_turns);
            let target = inputs.target.saturating_add(additive_turns);
            // The same target as the shrink gate sees it: the path term
            // carries the headroom margin, everything else is identical.
            // Always >= target, so the raise and lower branches below stay
            // mutually exclusive.
            let shrink_target = inputs.shrink_target.saturating_add(additive_turns);
            self.target_peaks
                .observe(frame.0, target, self.law.target_floor_bucket_span());

            // Edge burns go stale: after a long stretch with no shrink being
            // disproven, the weather that burned the edge is gone.
            if let Some(burned) = self.last_burn_frame
                && frame.0.saturating_sub(burned) > self.law.shrink_lookback_turns.saturating_mul(8)
            {
                self.edge_burned = false;
                self.last_burn_frame = None;
            }

            let new_buffer = if target > self.buffer.0 {
                // Raise fast: jump to the target immediately. No dwell -- a
                // too-small buffer stalls, and you can't wait through a stall.
                //
                // A raise that promptly returns to (or passes) the level the
                // last shrink departed *disproves* that shrink -- the cushion
                // it removed was still needed, and every frame spent below it
                // was stutter risk. Burn the edge so the next floor-level
                // shrink needs a longer peak-free window.
                if let Some(shrink) = self.last_shrink.take()
                    && target >= shrink.from
                    && frame.0.saturating_sub(shrink.frame)
                        <= self.law.shrink_lookback_turns.saturating_mul(2)
                {
                    self.edge_burned = true;
                    self.last_burn_frame = Some(frame.0);
                }
                Some(target)
            } else if shrink_target < self.buffer.0 {
                // Lower slow: every buffer-size change alters the game feel,
                // so a shrink must be both paced and earned -- and judged on
                // `shrink_target`, whose margined path term refuses a shrink
                // when the path merely rounds under the lowered size's
                // whole-turn boundary without real headroom below it (a raw
                // target below the buffer with `shrink_target` at it holds,
                // deliberately). Paced: at least
                // `min_dwell_turns` since the last decision, so a multi-turn
                // descent steps down gradually. Earned: the shrink may not
                // take the buffer below the target's trailing high-water mark.
                // Noisy conditions make the target *recur* at its peak rather
                // than sit on it -- an instantaneous dip at the moment the
                // dwell expires is not evidence the cushion is oversized, and
                // a buffer lowered into the recurrence is re-raised at its
                // next peak, flapping on the dwell cadence. Parking at the
                // high-water (and following it down only as peaks age out of
                // the lookback) keeps the buffer still through sustained
                // noise, while a genuine improvement still walks it down one
                // dwell per step.
                //
                // A shrink landing exactly ON the floor is an *edge* shrink --
                // riding the boundary the noise oscillates across -- and once
                // one has been disproven, the next must clear the full 4x
                // peak window. Shrinks landing safely above the floor (the
                // target regime falling outright) are never probation-gated,
                // so a burn costs genuine recovery nothing; it expires only
                // by the long-quiet decay above, because a mid-episode lull
                // that merely *looks* like a regime drop must not re-arm the
                // edge for another dip.
                let dwell_elapsed = self
                    .last_decision_frame
                    .is_none_or(|last| frame.0.saturating_sub(last.0) >= self.law.min_dwell_turns);
                // A multi-turn `lower_step` still may not land below what the
                // margined target says is the lowest safe size -- the headroom
                // bounds where a shrink lands, not just whether one fires. A
                // no-op at the default step of 1 (`shrink_target < buffer`
                // already puts it at or under `buffer - 1`).
                let lowered = self
                    .buffer
                    .0
                    .saturating_sub(self.law.lower_step)
                    .max(shrink_target);
                let base_floor = self.target_peaks.max_over_last(TARGET_FLOOR_BASE_BUCKETS);
                let allowed = if lowered == base_floor {
                    let probation_buckets = if self.edge_burned {
                        EDGE_PROBATION_BUCKETS
                    } else {
                        TARGET_FLOOR_BASE_BUCKETS
                    };
                    lowered >= self.target_peaks.max_over_last(probation_buckets)
                } else {
                    lowered >= base_floor
                };
                if dwell_elapsed && allowed {
                    self.last_shrink = Some(ShrinkRecord {
                        from: self.buffer.0,
                        frame: frame.0,
                    });
                    Some(lowered)
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(new_buffer) = new_buffer {
                let new_buffer = self.game_safe_clamp(new_buffer);
                if new_buffer != self.buffer.0 {
                    // Snapshot the derivation before the clamp is applied to
                    // the buffer, so a recording shows what the law asked for
                    // next to what the session was allowed to have.
                    let recorded = self.decision_inputs(
                        inputs,
                        target,
                        shrink_target,
                        cushion_turns,
                        stretch_turns,
                    );
                    // A real change is itself the session's first broadcast, so
                    // the initial-directive fallback below is satisfied.
                    self.initial_directive_sent = true;
                    return Some(self.queue_directive(new_buffer, frame, Some(recorded)));
                }
            }
        }

        // The law made no change (held, or no RTT yet). Broadcast the current
        // buffer once so a differently-seeded client is corrected even while the
        // target sits at the minimum.
        if !self.initial_directive_sent {
            self.initial_directive_sent = true;
            return Some(self.queue_directive(self.buffer.0, frame, None));
        }

        None
    }

    /// Assembles the derivation behind one decision for the flight recording:
    /// the law's own terms, the additive terms folded on top, and the shrink
    /// gate state that bounded how far the buffer could move. Built only on the
    /// path that actually queues a directive -- decisions are rare next to the
    /// per-sample ingests that evaluate the law, and the per-slot gather below
    /// should not ride every one of those.
    pub(in crate::consensus) fn decision_inputs(
        &self,
        inputs: &TargetInputs,
        target: u32,
        shrink_target: u32,
        cushion_turns: u32,
        stretch_turns: u32,
    ) -> BufferDecisionInputs {
        BufferDecisionInputs {
            law_target: inputs.target,
            target,
            shrink_target,
            path_us: inputs.path_us,
            // The risk is a rate times a duration, so it lands in the same
            // microseconds the path is measured in; the fraction it is rounded
            // off carries no meaning the law acts on (the term is `ceil`'d to
            // whole turns before it reaches the target).
            loss_risk_us: inputs.worst_loss_risk.round() as u32,
            burst_turns: inputs.burst_turns,
            cushion_turns,
            stretch_turns,
            shrink_floor: self.target_peaks.max_over_last(TARGET_FLOOR_BASE_BUCKETS),
            edge_burned: self.edge_burned,
            eff_rtts: {
                // Sorted so consecutive recordings of the same session are
                // diffable; the map they come from has no order of its own.
                let mut rtts: Vec<_> = self
                    .slots
                    .iter()
                    .map(
                        |(slot, state)| crate::observability::flight_recorder::SlotEffRtt {
                            slot: slot.0,
                            eff_rtt_us: state.eff_rtt(),
                        },
                    )
                    .collect();
                rtts.sort_unstable_by_key(|row| row.slot);
                rtts
            },
        }
    }

    /// Emits a rate-limited debug trace of the control law's inputs, so a wrong
    /// buffer is diagnosable from logs without turning the decision stream into a
    /// firehose. At most once per [`BUFFER_TRACE_INTERVAL_TURNS`] of session-frame
    /// progress; the frame-counter gate is the only cost when the debug level is
    /// off (the field expressions -- including the per-slot RTT gather -- are
    /// evaluated only if the callsite is enabled).
    pub(in crate::consensus) fn trace_control_inputs(
        &mut self,
        frame: GameFrameCount,
        inputs: &TargetInputs,
    ) {
        let due = self
            .last_trace_frame
            .is_none_or(|last| frame.0.saturating_sub(last) >= BUFFER_TRACE_INTERVAL_TURNS);
        if !due {
            return;
        }
        self.last_trace_frame = Some(frame.0);
        tracing::debug!(
            tenant = self.key.tenant.as_ref(),
            session = self.key.session.0,
            game_frame = frame.0,
            buffer = self.buffer.0,
            target = inputs.target,
            shrink_target = inputs.shrink_target,
            shrink_floor = self.target_peaks.max_over_last(TARGET_FLOOR_BASE_BUCKETS),
            edge_burned = self.edge_burned,
            path_us = inputs.path_us,
            worst_loss_risk = inputs.worst_loss_risk,
            burst_turns = inputs.burst_turns,
            eff_rtts = ?self
                .slots
                .iter()
                .map(|(slot, s)| (slot.0, s.eff_rtt()))
                .collect::<Vec<_>>(),
            "latency-buffer control inputs",
        );
    }

    /// The buffer directive to stamp onto a turn this relay is about to
    /// forward, if a decision is still being broadcast. Returns `None` -- the
    /// overwhelmingly common case, since buffer changes are rare -- once the
    /// session frame reaches the directive's apply frame: by then every slot
    /// has been observed past it, so the change is applied (or moot)
    /// everywhere and the directive retires.
    ///
    /// Stamping every forwarded turn until then (rather than a fixed number)
    /// is what guarantees coverage: a client never receives its own turns
    /// back, so it needs the stamp on a peer's turn -- and if a client's peers
    /// aren't producing turns yet, the session frame isn't advancing either,
    /// so the directive simply waits for them. Copies are cheap (a few bytes
    /// on turns already being sent) and idempotent at the client (same
    /// `decision_seq`).
    ///
    /// The caller sets the returned directive on the outgoing payload's
    /// `buffer_directive` field before fanning it out to local slots and peer
    /// relays. Only the authority ever returns a directive here: a
    /// non-authority relay makes no decisions, so its `pending_directive` is
    /// always `None` -- and its caller must preserve, not overwrite, a stamp
    /// already on the turn.
    pub fn active_directive(&mut self) -> Option<BufferDirective> {
        let directive = self.pending_directive?;
        if self
            .session_frame()
            .is_some_and(|frame| frame.0 >= directive.apply_at_frame)
        {
            self.pending_directive = None;
            return None;
        }
        Some(directive)
    }
}
