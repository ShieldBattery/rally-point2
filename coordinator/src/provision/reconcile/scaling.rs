//! The scale up/down half of a tick: idle-timer bookkeeping, the
//! coverage-bootstrap demand a region contributes while some backbone pair
//! involving it is unmeasured, and launching/draining relays to close the
//! gap between live count and desired count.

use super::*;

impl<P: Provisioner> ProvisionLoop<P> {
    /// Updates each relay's idle timer: a session-free relay's timer starts at its
    /// first session-free observation and holds; a relay serving a session, or one
    /// that left the fleet, loses its timer. Only relays with a live timer are ever
    /// scale-down candidates, so a candidate has been session-free at least since
    /// that first observation.
    pub(super) fn refresh_idle(&mut self, enrolled: &[EnrolledRelay], now: u64) {
        let present: HashSet<RelayId> = enrolled.iter().map(|r| r.relay_id).collect();
        self.idle_since.retain(|id, _| present.contains(id));
        for relay in enrolled {
            if self.setup.session_count_for_relay(relay.relay_id) == 0 {
                self.idle_since.entry(relay.relay_id).or_insert(now);
            } else {
                self.idle_since.remove(&relay.relay_id);
            }
        }
    }

    /// How many of `region`'s configured pairs currently hold a value, and how many
    /// pairs it has. A pair is `(region, other)` for every *other* configured
    /// region, so a single-region config yields `(0, 0)` — no pairs, and thus never
    /// any coverage demand.
    fn region_pair_coverage(
        &self,
        region: &RegionId,
        covered: &HashSet<(RegionId, RegionId)>,
    ) -> (usize, usize) {
        let mut have = 0usize;
        let mut total = 0usize;
        for other in &self.config.regions {
            if other == region {
                continue;
            }
            total += 1;
            let (a, b) = crate::pair_rtts::canonical_pair(region, other);
            if covered.contains(&(a.clone(), b.clone())) {
                have += 1;
            }
        }
        (have, total)
    }

    /// The transient desired relay count region coverage contributes for `region`
    /// this tick, advancing its bootstrap state machine.
    ///
    /// A region "needs bootstrap" while some configured pair involving it has no
    /// stored value — the coordinator has no measurement for that backbone link, so
    /// a relay is asked for to run one. The demand is level-triggered and
    /// self-limiting:
    ///
    /// - Fully covered (including a single-region config, which has no pairs):
    ///   demand 0, and any tracking state is dropped.
    /// - A pair value arriving (coverage rising) resets the cycle: the path works,
    ///   so the failure count clears and a fresh hold window starts.
    /// - Uncovered and within the hold window: demand 1.
    /// - Uncovered and the hold window elapsed: the attempt has failed — count it,
    ///   log it, and back off for an exponentially growing interval during which the
    ///   region demands nothing, so a dead beacon cannot relaunch-churn tasks.
    /// - Backoff elapsed: demand 1 again for a fresh window.
    pub(super) fn coverage_demand(
        &mut self,
        region: &RegionId,
        covered: &HashSet<(RegionId, RegionId)>,
        now: u64,
    ) -> u32 {
        let (have, total) = self.region_pair_coverage(region, covered);
        if have >= total {
            // Every pair covered (or no pairs at all): nothing to bootstrap.
            self.coverage.remove(region);
            crate::metrics::set_beacon_backoff(region, false);
            return 0;
        }
        let state = self
            .coverage
            .entry(region.clone())
            .or_insert_with(|| CoverageState {
                covered_pairs: have,
                attempts: 0,
                phase: CoveragePhase::Trying { since: now },
            });
        if have > state.covered_pairs {
            // Progress since the last observation: the measurement path is live, so
            // clear the failure count and give the region a fresh hold window.
            state.covered_pairs = have;
            state.attempts = 0;
            state.phase = CoveragePhase::Trying { since: now };
        }
        let demand = match state.phase {
            CoveragePhase::Trying { since } => {
                if now.saturating_sub(since) < COVERAGE_HOLD_SECS {
                    // Still within the window: keep asking for a relay.
                    1
                } else {
                    // The window elapsed with the region still uncovered: a failed
                    // attempt. Count it, back off, and demand nothing until the
                    // backoff expires.
                    state.attempts += 1;
                    let backoff = coverage_backoff_secs(state.attempts);
                    state.phase = CoveragePhase::BackingOff {
                        until: now.saturating_add(backoff),
                    };
                    tracing::warn!(
                        region = region.as_ref(),
                        attempt = state.attempts,
                        backoff_secs = backoff,
                        "region bootstrap produced no backbone-RTT measurement within the \
                         hold window; backing off before retrying",
                    );
                    0
                }
            }
            CoveragePhase::BackingOff { until } => {
                if now < until {
                    // Still serving out the backoff: no demand.
                    0
                } else {
                    // Backoff over: demand a relay again for a fresh window.
                    state.phase = CoveragePhase::Trying { since: now };
                    1
                }
            }
        };
        // Publish the resulting phase so the beacon-backoff gauge reflects the
        // loop-local coverage state.
        crate::metrics::set_beacon_backoff(
            region,
            matches!(state.phase, CoveragePhase::BackingOff { .. }),
        );
        demand
    }

    /// Launches relays while `region` is under its target, crediting in-flight
    /// launches so a task still coming up is not double-launched. A mint or launch
    /// failure logs and ends this region's scale-up for the tick; the next tick
    /// re-derives the same gap and retries with a fresh mint.
    pub(super) async fn scale_up(&mut self, region: &RegionId, live: u32, target: u32, now: u64) {
        let mut launching = match self.ledger.count_launching(Some(region), now) {
            Ok(count) => count as u32,
            Err(error) => {
                tracing::warn!(
                    region = region.as_ref(),
                    %error,
                    "counting launching relays failed; skipping scale-up for this region",
                );
                return;
            }
        };
        while live + launching < target {
            let minted = match self
                .ledger
                .mint_at(now, Some(region), self.config.launch_deadline)
            {
                Ok(minted) => minted,
                Err(error) => {
                    crate::metrics::relay_launch_failed(region);
                    tracing::warn!(
                        region = region.as_ref(),
                        %error,
                        "minting a relay id failed; retrying next tick",
                    );
                    return;
                }
            };
            let spec = LaunchSpec {
                relay_id: minted.relay_id,
                enroll_token: minted.token,
                region: Some(region.clone()),
            };
            match self.provisioner.launch(&spec).await {
                Ok(task) => {
                    crate::metrics::relay_launched(region);
                    tracing::info!(
                        region = region.as_ref(),
                        relay_id = minted.relay_id.0,
                        task = %task,
                        "launched a relay task",
                    );
                    self.pending.push(PendingLaunch {
                        relay_id: minted.relay_id,
                        expects_public_ipv4: self.provisioner.expects_public_ipv4(Some(region)),
                        task,
                        launched_at: now,
                    });
                    launching += 1;
                }
                Err(error) => {
                    crate::metrics::relay_launch_failed(region);
                    tracing::warn!(
                        region = region.as_ref(),
                        relay_id = minted.relay_id.0,
                        %error,
                        "launching a relay task failed; retiring the minted id",
                    );
                    if let Err(error) = self.retire_relay(minted.relay_id) {
                        tracing::warn!(
                            relay_id = minted.relay_id.0,
                            %error,
                            "retiring a failed launch's id failed",
                        );
                    }
                    return;
                }
            }
        }
    }

    /// Drains relays while `region` is over its target: the longest-idle
    /// session-free relays past the grace, each through the placement-race-safe
    /// drain sequence, until the live count meets the target or candidates run out.
    pub(super) async fn scale_down(
        &mut self,
        region: &RegionId,
        enrolled: &[EnrolledRelay],
        live: u32,
        target: u32,
        now: u64,
    ) {
        if live <= target {
            return;
        }
        let grace = self.config.idle_grace.as_secs();
        let mut candidates: Vec<(RelayId, u64, u64)> = enrolled
            .iter()
            .filter(|r| !r.draining && r.region.as_ref() == Some(region))
            .filter_map(|r| {
                let idle = now.saturating_sub(*self.idle_since.get(&r.relay_id)?);
                (idle >= grace).then_some((r.relay_id, r.generation, idle))
            })
            .collect();
        // Longest-idle first.
        candidates.sort_by_key(|(_, _, idle)| std::cmp::Reverse(*idle));

        let mut live = live;
        for (relay_id, generation, _) in candidates {
            if live <= target {
                break;
            }
            if self.try_drain_one(relay_id, generation).await {
                // Not counted toward the drain metric here: stopping the task makes
                // the relay announce Draining on its control connection, and that
                // announcement is where every drain — scale-down or relay-initiated
                // — is counted exactly once.
                live -= 1;
            }
        }
    }

    /// Drains one relay, closing the placement race. Marks it draining and
    /// re-checks its session count under the assignment lock, so the mark and the
    /// check are mutually exclusive with any session-create commit: a session that
    /// raced the mark is either seen here (the relay is spared and un-marked) or was
    /// blocked until the mark was visible (so it never placed on the relay). Only
    /// then, with the relay already ineligible for new placement and confirmed
    /// session-free, does it stop the task and retire the id — outside the lock,
    /// since stopping awaits the task's death. Returns whether the relay was
    /// drained.
    pub(super) async fn try_drain_one(&mut self, relay_id: RelayId, generation: u64) -> bool {
        let proceed = {
            let _assignment = self.setup.lock_assignment();
            if !registry::mark_draining(&self.registry, relay_id, generation) {
                // The relay reconnected or left between selection and the mark.
                false
            } else if self.setup.session_count_for_relay(relay_id) != 0 {
                // A session landed in the placement race: spare the relay.
                registry::clear_draining(&self.registry, relay_id, generation);
                false
            } else {
                true
            }
        };
        if !proceed {
            return false;
        }
        match self.ledger.task_arn(relay_id) {
            Ok(Some(arn)) => {
                if let Err(error) = self.provisioner.stop(&TaskId(arn)).await {
                    tracing::warn!(
                        relay_id = relay_id.0,
                        %error,
                        "stopping a drained relay's task failed; retiring the id anyway",
                    );
                }
            }
            Ok(None) => {
                tracing::warn!(
                    relay_id = relay_id.0,
                    "draining a relay with no recorded task; retiring the id only",
                );
            }
            Err(error) => {
                tracing::warn!(
                    relay_id = relay_id.0,
                    %error,
                    "reading a drained relay's task failed; retiring the id anyway",
                );
            }
        }
        if let Err(error) = self.retire_relay(relay_id) {
            tracing::warn!(relay_id = relay_id.0, %error, "retiring a drained relay failed");
        }
        self.idle_since.remove(&relay_id);
        true
    }
}
