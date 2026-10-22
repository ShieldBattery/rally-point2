use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::handshake::{Evidence, EvidenceRequest, MAX_EVIDENCE_BODY_LEN};
use tokio::sync::Semaphore;

const PROVIDER_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) struct Provider {
    callback: Arc<dyn Fn(EvidenceRequest) -> Option<Evidence> + Send + Sync>,
    available: Arc<Semaphore>,
}

impl Provider {
    pub(super) fn new<F>(callback: F) -> Self
    where
        F: Fn(EvidenceRequest) -> Option<Evidence> + Send + Sync + 'static,
    {
        Self {
            callback: Arc::new(callback),
            available: Arc::new(Semaphore::new(1)),
        }
    }

    pub(super) async fn collect(&self, request: EvidenceRequest) -> Option<Evidence> {
        tokio::time::timeout(PROVIDER_TIMEOUT, async {
            // Waiting and running the callback share one deadline. Keep the permit in the
            // blocking task after timeout or cancellation, so a stuck callback cannot
            // accumulate more blocking work.
            let permit = self.available.clone().acquire_owned().await.ok()?;
            let callback = self.callback.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                callback(request).filter(|evidence| evidence.body.len() <= MAX_EVIDENCE_BODY_LEN)
            })
            .await
            .ok()?
        })
        .await
        .ok()?
    }
}

#[cfg(test)]
mod tests;
