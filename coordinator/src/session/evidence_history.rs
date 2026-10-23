//! Short-lived authorization for observations reported after a home assignment ends.

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::time::unix_secs_fail_closed;

use super::{SessionRefs, SessionSetup};

const RETIREMENT_GRACE_SECS: u64 = 600;
const MAX_RETIRED_PER_SLOT: usize = 4;
const MAX_RETIRED_PER_SESSION: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct RetiredAssignment {
    slot: SlotId,
    relay: RelayId,
    boot_id: u64,
    revision: u64,
    expires_at: u64,
}

impl SessionRefs {
    /// Capture authority before replacing the home and its revision. Unknown process
    /// identity cannot authorize history, even if the registry now knows a new boot.
    pub(super) fn retire_evidence_assignments(&mut self, relay: RelayId, now: u64) {
        self.prune_retired_evidence_assignments(now);
        for (&slot, &home) in &self.homes {
            if home != relay {
                continue;
            }
            let (Some(&boot_id), Some(&revision)) = (
                self.evidence_home_boots.get(&slot),
                self.evidence_assignments.get(&slot),
            ) else {
                continue;
            };
            self.retired_evidence_assignments.push(RetiredAssignment {
                slot,
                relay,
                boot_id,
                revision,
                expires_at: now.saturating_add(RETIREMENT_GRACE_SECS),
            });
        }
        self.prune_retired_evidence_assignments(now);
    }

    /// Preserve insertion order so eviction remains oldest-first even after a clock
    /// correction. Clamp deadlines to a full grace period on restored state.
    pub(super) fn prune_retired_evidence_assignments(&mut self, now: u64) {
        let mut slots = std::collections::HashMap::new();
        let mut total = 0;
        // Walk newest-first, then restore insertion order.
        self.retired_evidence_assignments.reverse();
        self.retired_evidence_assignments.retain_mut(|entry| {
            if entry.expires_at <= now {
                return false;
            }
            entry.expires_at = entry
                .expires_at
                .min(now.saturating_add(RETIREMENT_GRACE_SECS));
            let count = slots.entry(entry.slot).or_insert(0);
            if *count >= MAX_RETIRED_PER_SLOT || total >= MAX_RETIRED_PER_SESSION {
                return false;
            }
            *count += 1;
            total += 1;
            true
        });
        self.retired_evidence_assignments.reverse();
    }
}

impl SessionSetup {
    /// Authorizes history for the process that received the current assignment.
    /// Registry enrollment alone cannot transfer that authority to a restarted process.
    pub(crate) fn current_evidence_history_assignment(
        &self,
        relay: RelayId,
        boot_id: u64,
        tenant: &TenantId,
        session: SessionId,
        slot: SlotId,
        revision: u64,
    ) -> bool {
        self.session_refs
            .lock()
            .get(&(tenant.clone(), session))
            .is_some_and(|refs| {
                refs.homes.get(&slot) == Some(&relay)
                    && refs.evidence_assignments.get(&slot) == Some(&revision)
                    && refs.evidence_home_boots.get(&slot) == Some(&boot_id)
            })
    }

    /// Authorizes history only. Current admission and routing must use the live home.
    pub(crate) fn evidence_history_assignment(
        &self,
        relay: RelayId,
        boot_id: u64,
        tenant: &TenantId,
        session: SessionId,
        slot: SlotId,
        revision: u64,
    ) -> bool {
        let now = unix_secs_fail_closed();
        self.session_refs
            .lock()
            .get(&(tenant.clone(), session))
            .is_some_and(|refs| {
                refs.retired_evidence_assignments.iter().any(|entry| {
                    entry.slot == slot
                        && entry.relay == relay
                        && entry.boot_id == boot_id
                        && entry.revision == revision
                        && entry.expires_at > now
                        && entry.expires_at <= now.saturating_add(RETIREMENT_GRACE_SECS)
                })
            })
    }
}

#[cfg(test)]
#[path = "tests/retired_evidence_limits.rs"]
mod tests;
