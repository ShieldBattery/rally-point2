//! The fleet-wide sweeps a tick runs after scaling: launches whose enroll
//! token expired, bound ids whose relay vanished from the registry, and
//! provisioner tasks the ledger no longer references. Each sweep is
//! independent — one relay's cleanup failing does not block the others.

use super::*;

impl<P: Provisioner> ProvisionLoop<P> {
    /// Polls each pending launch at `now` (Unix seconds). A task that reports
    /// running has its addresses recorded and leaves the pending set — unless the
    /// launch expects a public IPv4 address that the reported set does not carry
    /// yet, in which case the launch stays pending until the address appears or
    /// [`PUBLIC_IPV4_WAIT_SECS`] has elapsed since launch, whichever comes first
    /// (past that point the set is recorded as-is, so a deployment with no public
    /// IPv4 at all is never blocked forever). A task still starting stays
    /// pending; one that stopped before enrolling is a failed launch — its id is
    /// retired so it can never enroll, and the next tick re-mints. A record or
    /// poll error keeps the task pending for a later tick.
    pub(super) async fn resolve_pending(&mut self, now: u64) {
        let pending = std::mem::take(&mut self.pending);
        let mut still = Vec::with_capacity(pending.len());
        for launch in pending {
            match self.provisioner.state(&launch.task).await {
                Ok(TaskState::Running {
                    expected_ips,
                    addrs,
                }) => {
                    let missing_ipv4 =
                        launch.expects_public_ipv4 && !expected_ips.iter().any(|ip| ip.is_ipv4());
                    if missing_ipv4
                        && now < launch.launched_at.saturating_add(PUBLIC_IPV4_WAIT_SECS)
                    {
                        tracing::debug!(
                            relay_id = launch.relay_id.0,
                            task = %launch.task,
                            "task's public IPv4 association has not appeared yet; waiting \
                             before recording its addresses",
                        );
                        still.push(launch);
                        continue;
                    }
                    if missing_ipv4 {
                        tracing::warn!(
                            relay_id = launch.relay_id.0,
                            task = %launch.task,
                            "recording a relay's addresses without the expected public IPv4; \
                             the association never appeared",
                        );
                    }
                    if let Err(error) = self.ledger.record_task(
                        launch.relay_id,
                        &launch.task.0,
                        &expected_ips,
                        &addrs,
                    ) {
                        tracing::warn!(
                            relay_id = launch.relay_id.0,
                            %error,
                            "recording a launched task failed; retrying next tick",
                        );
                        still.push(launch);
                    }
                }
                Ok(TaskState::Starting) => still.push(launch),
                Ok(TaskState::Stopped) => {
                    tracing::warn!(
                        relay_id = launch.relay_id.0,
                        task = %launch.task,
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
                    still.push(launch);
                }
            }
        }
        self.pending = still;
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
            self.pending.retain(|p| p.relay_id != relay.relay_id);
            self.idle_since.remove(&relay.relay_id);
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
            if registry::is_enrolled(&self.registry, relay.relay_id) {
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
    /// references and that this loop is not itself tracking as a pending launch — a
    /// task the ledger lost track of (e.g. one that outlived a coordinator restart
    /// that cleared the pending set) must not keep running unaccounted. A task the
    /// loop just launched but has not recorded yet is spared: it is accounted for
    /// even though the ledger does not reference it yet.
    pub(super) async fn orphan_sweep(&mut self) {
        let tasks = match self.provisioner.list().await {
            Ok(tasks) => tasks,
            Err(error) => {
                tracing::warn!(%error, "listing provisioner tasks failed; skipping the orphan sweep");
                return;
            }
        };
        let mut accounted: HashSet<String> = match self.ledger.referenced_task_arns() {
            Ok(arns) => arns.into_iter().collect(),
            Err(error) => {
                tracing::warn!(%error, "listing referenced tasks failed; skipping the orphan sweep");
                return;
            }
        };
        for launch in &self.pending {
            accounted.insert(launch.task.0.clone());
        }
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
    /// ever enrolling again — and, only once that succeeds, forgets its descriptor
    /// and reap outbox shells too.
    ///
    /// The ledger tombstone is what makes the forget safe: every one of this
    /// method's callers reaches it only for an id that will never enroll again (a
    /// drained, expired, or vanished relay), never for a live relay that merely
    /// lost its connection and might reconnect under the same id. Without this, the
    /// two outboxes grow one shell per relay id for the coordinator's entire
    /// uptime — every Fargate task launched mints a fresh id, so a long-running
    /// coordinator under steady scale-to-zero churn accumulates a shell per task
    /// ever launched, and session cleanup that scans every relay's state
    /// (`RelayReaps::retire`) pays for all of that history on every session close.
    /// The registry's remembered process identity for the id is bounded the same
    /// way and by the same argument. Skipped when the ledger write itself fails: an
    /// untombstoned id might still legitimately enroll, so its state must stay live
    /// for that possibility.
    pub(super) fn retire_relay(&self, relay_id: RelayId) -> Result<(), crate::ledger::LedgerError> {
        self.ledger.retire(relay_id)?;
        self.setup.descriptors().forget(relay_id);
        self.setup.reaps().forget(relay_id);
        self.setup.attest().forget(relay_id);
        crate::registry::forget_boot_id(self.setup.registry(), relay_id);
        Ok(())
    }
}
