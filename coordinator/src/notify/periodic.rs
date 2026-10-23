//! Periodic observations are best-effort hints backed by the retained evidence
//! cache. They never wait in a lifecycle queue or consume its dispatch permits.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use parking_lot::Mutex;
use rally_point_proto::control::TenantId;
use serde::Serialize;

use super::ATTEMPT_TIMEOUT;
use super::dispatch::{build_request, send_attempt};
use crate::tenant::{NotifyConfig, TenantStore};

const MAX_CONCURRENT_PERIODIC: usize = 4;
const MAX_CONCURRENT_PER_TENANT: usize = 2;
static PERIODIC_PERMITS: LazyLock<Arc<DispatchGate>> =
    LazyLock::new(|| Arc::new(DispatchGate::default()));

/// A stalled tenant can occupy at most half the shared delivery budget.
/// Only active reservations occupy the map, so at most four tenant entries can
/// exist regardless of how many tenant identities have submitted samples.
#[derive(Default)]
pub(super) struct DispatchGate {
    active: Mutex<HashMap<TenantId, usize>>,
}

impl DispatchGate {
    fn try_acquire(self: &Arc<Self>, tenant: &TenantId) -> Result<Reservation, &'static str> {
        let mut active = self.active.lock();
        if active.get(tenant).copied().unwrap_or(0) >= MAX_CONCURRENT_PER_TENANT {
            return Err("tenant_busy");
        }
        if active.values().sum::<usize>() >= MAX_CONCURRENT_PERIODIC {
            return Err("global_busy");
        }
        *active.entry(tenant.clone()).or_default() += 1;
        Ok(Reservation {
            gate: self.clone(),
            tenant: tenant.clone(),
        })
    }

    #[cfg(test)]
    pub(super) fn counts(&self) -> (usize, usize) {
        let active = self.active.lock();
        (active.values().sum(), active.len())
    }
}

struct Reservation {
    gate: Arc<DispatchGate>,
    tenant: TenantId,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut active = self.gate.active.lock();
        if let Some(count) = active.get_mut(&self.tenant) {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.tenant);
            }
        }
    }
}

pub(super) fn try_dispatch(
    tenants: TenantStore,
    tenant: TenantId,
    config: NotifyConfig,
    payload: &impl Serialize,
) {
    try_dispatch_with(&PERIODIC_PERMITS, tenants, tenant, config, payload);
}

/// Reserve before serializing or spawning: busy delivery sheds the sample rather
/// than growing a queue of tasks waiting for a permit. Recovery reads the latest
/// retained value independently, so there is no retry loop or terminal ordering.
pub(super) fn try_dispatch_with(
    permits: &Arc<DispatchGate>,
    tenants: TenantStore,
    tenant: TenantId,
    config: NotifyConfig,
    payload: &impl Serialize,
) -> bool {
    let permit = match permits.try_acquire(&tenant) {
        Ok(permit) => permit,
        Err(reason) => {
            crate::metrics::periodic_webhook_outcome(&tenant, reason);
            tracing::debug!(
                tenant = tenant.as_ref(),
                reason,
                "periodic webhook budget busy; dropping sample"
            );
            return false;
        }
    };
    let body = match serde_json::to_vec(payload) {
        Ok(body) => Bytes::from(body),
        Err(error) => {
            crate::metrics::periodic_webhook_outcome(&tenant, "serialize_failed");
            tracing::error!(%error, "serializing a periodic webhook failed; dropping sample");
            return false;
        }
    };
    tokio::spawn(async move {
        let _permit = permit;
        let request = match build_request(&tenants, &tenant, &config, body) {
            Ok(Some(request)) => request,
            _ => {
                crate::metrics::periodic_webhook_outcome(&tenant, "request_failed");
                tracing::debug!(
                    tenant = tenant.as_ref(),
                    "periodic webhook cannot be signed or built; dropping sample"
                );
                return;
            }
        };
        let delivered = matches!(send_attempt(request, ATTEMPT_TIMEOUT).await, Ok(200..300));
        crate::metrics::periodic_webhook_outcome(&tenant, if delivered { "ok" } else { "failed" });
        tracing::debug!(
            tenant = tenant.as_ref(),
            delivered,
            "periodic webhook attempt completed"
        );
    });
    true
}
