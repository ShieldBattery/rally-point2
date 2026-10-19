//! The process-wide shutdown signal: one latch the binary trips on `SIGTERM` /
//! `Ctrl-C`, which the HTTP servers stop accepting on and every relay control
//! connection closes on. Closing the control connections before the final
//! persistence flush stops relays handing this process new notices that the
//! flush would miss: a relay whose connection is gone keeps its unsent notices
//! queued and delivers them to the next coordinator instead.

use std::sync::Arc;

use tokio::sync::watch;

/// A cheaply cloned shutdown latch. Starts untripped; once tripped it stays
/// tripped, and every current and future [`wait`](Self::wait) resolves.
#[derive(Clone)]
pub struct Shutdown {
    tx: Arc<watch::Sender<bool>>,
}

impl Shutdown {
    /// An untripped latch.
    pub fn new() -> Self {
        Self {
            tx: Arc::new(watch::Sender::new(false)),
        }
    }

    /// Trips the latch. Idempotent.
    pub fn trigger(&self) {
        self.tx.send_replace(true);
    }

    /// Whether the latch has been tripped.
    pub fn is_triggered(&self) -> bool {
        *self.tx.borrow()
    }

    /// Resolves once the latch is tripped — immediately if it already was.
    pub async fn wait(&self) {
        let mut rx = self.tx.subscribe();
        // The sender lives as long as `self`, so this only returns on the trip.
        let _ = rx.wait_for(|tripped| *tripped).await;
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolves when the process receives a shutdown signal: `Ctrl-C` everywhere, plus
/// `SIGTERM` on Unix — the container runtime stops the coordinator with `SIGTERM`
/// (then `SIGKILL` after its stop timeout), so the drain must key on it.
pub async fn os_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "listening for Ctrl-C failed");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(error) => {
                    tracing::warn!(%error, "listening for SIGTERM failed");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            () = ctrl_c => {}
            () = terminate => {}
        }
    }
    #[cfg(not(unix))]
    ctrl_c.await;
}
