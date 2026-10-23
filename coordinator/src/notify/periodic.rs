//! Periodic observations are best-effort hints backed by the retained evidence
//! cache. They never wait in a lifecycle queue or consume its dispatch permits.

use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use rally_point_proto::control::TenantId;
use serde::Serialize;
use tokio::sync::Semaphore;

use super::ATTEMPT_TIMEOUT;
use super::dispatch::{build_request, send_attempt};
use crate::tenant::{NotifyConfig, TenantStore};

const MAX_CONCURRENT_PERIODIC: usize = 4;
static PERIODIC_PERMITS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_PERIODIC)));

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
    permits: &Arc<Semaphore>,
    tenants: TenantStore,
    tenant: TenantId,
    config: NotifyConfig,
    payload: &impl Serialize,
) -> bool {
    let Ok(permit) = permits.clone().try_acquire_owned() else {
        tracing::debug!(
            tenant = tenant.as_ref(),
            "periodic webhook budget busy; dropping sample"
        );
        return false;
    };
    let body = match serde_json::to_vec(payload) {
        Ok(body) => Bytes::from(body),
        Err(error) => {
            tracing::error!(%error, "serializing a periodic webhook failed; dropping sample");
            return false;
        }
    };
    tokio::spawn(async move {
        let _permit = permit;
        let request = match build_request(&tenants, &tenant, &config, body) {
            Ok(Some(request)) => request,
            _ => {
                tracing::debug!(
                    tenant = tenant.as_ref(),
                    "periodic webhook cannot be signed or built; dropping sample"
                );
                return;
            }
        };
        let delivered = matches!(send_attempt(request, ATTEMPT_TIMEOUT).await, Ok(200..300));
        crate::metrics::webhook_delivered(&tenant, if delivered { "ok" } else { "gave_up" });
        tracing::debug!(
            tenant = tenant.as_ref(),
            delivered,
            "periodic webhook attempt completed"
        );
    });
    true
}
