//! The fleet-wide sweeps a tick runs after scaling: launches still waiting for
//! their addresses, draining relays with no sessions left, launches whose enroll
//! token expired, bound ids whose relay vanished from the registry, and
//! provisioner tasks the ledger no longer references. Each sweep is
//! independent — one relay's cleanup failing does not block the others — and
//! each re-derives its work from the ledger and registry, so a tick cut short
//! leaves nothing the next one won't find.

use super::*;

impl<P: Provisioner> ProvisionLoop<P> {
    /// Polls each launch whose addresses are not recorded yet at `now` (Unix
    /// seconds). The set is read from the ledger every tick rather than held in
    /// loop memory, so a restart or an interrupted tick loses no launch. A task that
    /// reports running has its addresses recorded, which takes it out of the set —
    /// unless its region expects a public IPv4 address that the reported set does
    /// not carry yet, in which case it is polled again until the address appears or
    /// [`PUBLIC_IPV4_WAIT_SECS`] has elapsed since launch, whichever comes first
    /// (past that point the set is recorded as-is, so a deployment with no public
    /// IPv4 at all is never blocked forever). A task still starting is polled again
    /// next tick; one that stopped before enrolling is a failed launch — its id is
    /// retired so it can never enroll, and the next tick re-mints. A record or poll
    /// error leaves the launch for a later tick.
    pub(super) async fn resolve_pending(&mut self, now: u64) {
        let launches = match self.ledger.unrecorded_launches() {
            Ok(launches) => launches,
            Err(error) => {
                tracing::warn!(%error, "listing unrecorded launches failed; skipping the launch poll");
                return;
            }
        };
        for (launch, launched_at) in launches {
            let Some(task) = launch.task_arn.map(TaskId) else {
                continue;
            };
            match self.provisioner.state(&task).await {
                Ok(TaskState::Running {
                    expected_ips,
                    addrs,
                }) => {
                    let missing_ipv4 = self.provisioner.expects_public_ipv4(launch.region.as_ref())
                        && !expected_ips.iter().any(|ip| ip.is_ipv4());
                    if missing_ipv4 && now < launched_at.saturating_add(PUBLIC_IPV4_WAIT_SECS) {
                        tracing::debug!(
                            relay_id = launch.relay_id.0,
                            task = %task,
                            "task's public IPv4 association has not appeared yet; waiting \
                             before recording its addresses",
                        );
                        continue;
                    }
                    if missing_ipv4 {
                        tracing::warn!(
                            relay_id = launch.relay_id.0,
                            task = %task,
                            "recording a relay's addresses without the expected public IPv4; \
                             the association never appeared",
                        );
                    }
                    if let Err(error) =
                        self.ledger
                            .record_task(launch.relay_id, &task.0, &expected_ips, &addrs)
                    {
                        tracing::warn!(
                            relay_id = launch.relay_id.0,
                            %error,
                            "recording a launched task failed; retrying next tick",
                        );
                    }
                }
                Ok(TaskState::Starting) => {}
                Ok(TaskState::Stopped) => {
                    tracing::warn!(
                        relay_id = launch.relay_id.0,
                        task = %task,
                        "a launched task stopped before enrolling; retiring the id",
                    );
                    if let Err(error) = self.retire_relay(launch.relay_id) {
                        tracing::warn!(
                            relay_id = launch.relay_id.0,
                            %error,
                            "retiring a stopped launch failed",
                        );
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        relay_id = launch.relay_id.0,
                        %error,
                        "polling a launched task failed; retrying next tick",
                    );
                }
            }
        }
    }

    /// Stops and retires every launch whose token expired before it enrolled — the
    /// relay never bound its id, and its token can no longer authorize a first
    /// enroll, so the id is dead.
    pub(super) async fn launch_deadline_sweep(&mut self, now: u64) {
        let expired = match self.ledger.expired_launching(now) {
            Ok(expired) => expired,
            Err(error) => {
                tracing::warn!(%error, "listing expired launches failed; skipping the launch-deadline sweep");
                return;
            }
        };
        for relay in expired {
            if let Some(arn) = relay.task_arn
                && let Err(error) = self.provisioner.stop(&TaskId(arn)).await
            {
                tracing::warn!(
                    relay_id = relay.relay_id.0,
                    %error,
                    "stopping an expired launch's task failed",
                );
            }
            if let Err(error) = self.retire_relay(relay.relay_id) {
                tracing::warn!(
                    relay_id = relay.relay_id.0,
                    %error,
                    "retiring an expired launch failed",
                );
            }
            crate::metrics::relay_reaped(relay.region.as_ref(), "launch_deadline");
            self.idle_since.remove(&relay.relay_id);
        }
    }

    /// Stops and retires every enrolled relay that is draining with no sessions
    /// left while its id is still live in the ledger. The step that marks a relay
    /// draining normally stops it in the same breath, but if that step is cut short
    /// (its stop panicked, or the tick never got past it) the relay would stay
    /// marked: placement and scale-down both skip draining relays, so nothing else
    /// would ever stop it. Re-deriving the work from the registry each tick makes
    /// any interrupted drain finish on the next one. A relay that began its own
    /// drain and has emptied is finished the same way, ahead of its own exit.
    ///
    /// The candidates come from a snapshot, and each stop awaits, so by the time a
    /// later candidate comes up it may have reconnected: the new enrollment starts
    /// undrained and can take sessions. Each one is therefore re-checked under the
    /// assignment lock, as draining under the snapshot's generation with no
    /// sessions, immediately before its stop. A superseded enrollment is skipped;
    /// if it still needs draining, the next tick decides that afresh.
    pub(super) async fn finish_drains(&mut self) {
        let unretired: HashSet<RelayId> = match self.ledger.bound_unretired() {
            Ok(bound) => bound.into_iter().map(|relay| relay.relay_id).collect(),
            Err(error) => {
                tracing::warn!(%error, "listing bound relays failed; skipping the drain sweep");
                return;
            }
        };
        for relay in registry::enrolled_relays(self.setup.registry()) {
            if !relay.draining || !unretired.contains(&relay.relay_id) {
                continue;
            }
            let idle = {
                // Placement and enrollment both hold this lock, so neither can land
                // between the check and the release. A relay confirmed draining here
                // can gain no session before the stop below, which follows with no
                // await in between.
                let _assignment = self.setup.lock_assignment();
                registry::is_draining_at(self.setup.registry(), relay.relay_id, relay.generation)
                    && self.setup.session_count_for_relay(relay.relay_id) == 0
            };
            if !idle {
                continue;
            }
            tracing::info!(
                relay_id = relay.relay_id.0,
                "stopping a draining relay with no sessions left",
            );
            self.stop_and_retire(relay.relay_id).await;
        }
    }

    /// Retires every bound id whose relay is no longer enrolled and whose task has
    /// stopped — the relay died. Retiring tombstones the id so the dead relay's
    /// certificate can never reclaim it. A bound id whose relay is still enrolled,
    /// or whose task is still up, is left alone (a reconnect may yet resume it).
    pub(super) async fn vanished_task_sweep(&mut self) {
        let bound = match self.ledger.bound_unretired() {
            Ok(bound) => bound,
            Err(error) => {
                tracing::warn!(%error, "listing bound relays failed; skipping the vanished-task sweep");
                return;
            }
        };
        for relay in bound {
            if registry::is_enrolled(self.setup.registry(), relay.relay_id) {
                continue;
            }
            let Some(arn) = relay.task_arn else {
                continue;
            };
            match self.provisioner.state(&TaskId(arn)).await {
                Ok(TaskState::Stopped) => {
                    tracing::info!(
                        relay_id = relay.relay_id.0,
                        "retiring a bound relay whose task has stopped and is not enrolled",
                    );
                    if let Err(error) = self.retire_relay(relay.relay_id) {
                        tracing::warn!(
                            relay_id = relay.relay_id.0,
                            %error,
                            "retiring a vanished relay failed",
                        );
                    }
                    crate::metrics::relay_reaped(relay.region.as_ref(), "vanished");
                    self.idle_since.remove(&relay.relay_id);
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(
                        relay_id = relay.relay_id.0,
                        %error,
                        "probing a bound relay's task failed; leaving it for next tick",
                    );
                }
            }
        }
    }

    /// Stops every task the provisioner still runs that no unretired ledger row
    /// references — a task whose id was retired, or one launched without its task
    /// ever reaching the ledger, must not keep running unaccounted. A launch is
    /// referenced from the moment it returns (see `RelayLedger::record_launch`), so
    /// one still coming up is never mistaken for an orphan.
    pub(super) async fn orphan_sweep(&mut self) {
        let tasks = match self.provisioner.list().await {
            Ok(tasks) => tasks,
            Err(error) => {
                tracing::warn!(%error, "listing provisioner tasks failed; skipping the orphan sweep");
                return;
            }
        };
        let accounted: HashSet<String> = match self.ledger.referenced_task_arns() {
            Ok(arns) => arns.into_iter().collect(),
            Err(error) => {
                tracing::warn!(%error, "listing referenced tasks failed; skipping the orphan sweep");
                return;
            }
        };
        for task in tasks {
            if !accounted.contains(&task.0) {
                // An orphaned task has no ledger row, so no region is known for it.
                crate::metrics::relay_reaped(None, "orphan");
                tracing::info!(task = %task, "stopping an orphaned task no live ledger row references");
                if let Err(error) = self.provisioner.stop(&task).await {
                    tracing::warn!(task = %task, %error, "stopping an orphaned task failed");
                }
            }
        }
    }

    /// Retires `relay_id` in the ledger — the tombstone that refuses the id from
    /// ever enrolling again — and, only once that succeeds, forgets every per-relay
    /// shell the setup still holds for it.
    ///
    /// The ledger tombstone is what makes the forget safe: every one of this
    /// method's callers reaches it only for an id that will never enroll again (a
    /// drained, expired, or vanished relay), never for a live relay that merely
    /// lost its connection and might reconnect under the same id. Skipped when the
    /// ledger write itself fails: an untombstoned id might still legitimately
    /// enroll, so its state must stay live for that possibility.
    pub(super) fn retire_relay(&self, relay_id: RelayId) -> Result<(), crate::ledger::LedgerError> {
        self.ledger.retire(relay_id)?;
        self.setup.forget_relay(relay_id);
        Ok(())
    }
}
