use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::handshake::{Evidence, EvidenceRequest, MAX_EVIDENCE_BODY_LEN};
use tokio::sync::Semaphore;
use tokio::time::Instant;

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
        let deadline = Instant::now() + PROVIDER_TIMEOUT;
        tokio::time::timeout_at(deadline, async {
            // Waiting and running the callback share one deadline. Keep the permit in the
            // blocking task after timeout or cancellation, so a stuck callback cannot
            // accumulate more blocking work.
            let permit = self.available.clone().acquire_owned().await.ok()?;
            let callback = self.callback.clone();
            let mut task = AbortTask(tokio::task::spawn_blocking(move || {
                let _permit = permit;
                if Instant::now() >= deadline {
                    return None;
                }
                callback(request).filter(|evidence| evidence.body.len() <= MAX_EVIDENCE_BODY_LEN)
            }));
            (&mut task.0).await.ok()?
        })
        .await
        .ok()?
    }
}

/// Dropping a JoinHandle detaches it. Abort also cancels work that has not
/// started; a running callback retains its semaphore permit until it returns.
struct AbortTask<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests;
