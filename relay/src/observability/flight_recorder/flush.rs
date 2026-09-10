//! [`FlightRecorder`]'s flush path: building a session's [`FlightBlob`] on
//! removal, handing it to the configured sink, and the drain-time wholesale
//! flush across every live recording. Split from the create/record/query
//! half in `mod.rs` because this half is where the close-seal and
//! bounded-concurrency reasoning lives.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::routing::SessionKey;

use super::BLOB_VERSION;
use super::FlightRecorder;
use super::events::FlightBlob;
use super::now_ms;
use super::recording::FlushOutcome;
use super::sinks::DRAIN_FLUSH_CONCURRENCY;

impl FlightRecorder {
    /// Removes `key`'s recording and builds its flushed blob, or `None` if no
    /// recording exists. The removal is what makes a flush terminal — and when
    /// `seal` is set, the close seal left behind is what *keeps* it terminal:
    /// without it, a straggling event while the session is still mesh-joined
    /// would start a fresh recording whose store later displaces this blob's
    /// (see [`CloseSeals`]). Sealed even when there was nothing to remove, so
    /// a close evaluated against a never-recorded session still blocks
    /// stragglers. A caller passes `seal: false` only for a session with no
    /// coordinator lifecycle (no descriptor ever named it), where no
    /// retirement will ever clear the seal and nothing remains for it to
    /// guard.
    pub(super) fn take_blob(&self, key: &SessionKey, seal: bool) -> Option<FlightBlob> {
        let recording = {
            let mut state = self.inner.recordings.lock();
            if seal {
                state.closed.seal(key);
            }
            let recording = state.sessions.remove(key)?;
            // Production flushes happen after the slot links quiesce. A drain
            // deadline can force this snapshot while a final link is winding
            // down; that shutdown-tail race is acceptable for telemetry and is
            // outside the steady-state intervals used for CPU comparisons.
            state.retired_work.accumulate(recording.work_snapshot());
            recording
        };
        // Fold a final counter snapshot in, so a short session that never saw a
        // sampling tick still carries its turn-stream totals. Counters only —
        // the consensus state this flush races may already be gone, so the
        // e2e view is deliberately absent here (the periodic rows carry it).
        let final_row = recording.sample_row(None, (None, None));
        recording.push_sample(final_row);
        Some(FlightBlob {
            version: BLOB_VERSION,
            tenant: key.tenant.as_ref().to_owned(),
            session: key.session.0,
            relay_id: self.inner.relay_id.get().map(|r| r.0).unwrap_or(0),
            started_at_ms: recording.started_at_ms,
            flushed_at_ms: now_ms(),
            events_dropped: recording.events_dropped.load(Ordering::Relaxed),
            samples_dropped: recording.samples_dropped.load(Ordering::Relaxed),
            events: recording.events.lock().iter().cloned().collect(),
            samples: recording.samples.lock().iter().cloned().collect(),
        })
    }

    /// Flushes `key`'s recording to the sink (or logs the discard when no sink
    /// is configured). Terminal for the recording either way.
    pub async fn flush_session(&self, key: &SessionKey) -> FlushOutcome {
        self.flush_session_with_seal(key, true).await
    }

    /// [`flush_session`](Self::flush_session) with the caller choosing whether
    /// the flush plants a close seal — see [`take_blob`](Self::take_blob).
    async fn flush_session_with_seal(&self, key: &SessionKey, seal: bool) -> FlushOutcome {
        let Some(blob) = self.take_blob(key, seal) else {
            return FlushOutcome::Nothing;
        };
        let Some(sink) = self.inner.sink.get() else {
            tracing::info!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                events = blob.events.len(),
                "no flight sink configured; discarding the session's recording",
            );
            return FlushOutcome::NoSink;
        };
        match sink.store(&blob).await {
            Ok(()) => {
                tracing::info!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    events = blob.events.len(),
                    samples = blob.samples.len(),
                    "flight recording flushed",
                );
                // One key per session per relay: this store replaced whatever the
                // earlier one wrote, so the earlier recording is no longer
                // readable and the fact belongs in the log rather than only in
                // the difference between two stored objects nobody compares.
                if self.inner.recent_stores.lock().note(key) {
                    tracing::warn!(
                        tenant = key.tenant.as_ref(),
                        session = key.session.0,
                        relay_id = blob.relay_id,
                        events = blob.events.len(),
                        samples = blob.samples.len(),
                        "flight recording stored again for a session already stored; \
                         it replaced this relay's earlier recording",
                    );
                }
                FlushOutcome::Stored
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    "flight recording store failed; the blob is lost",
                );
                FlushOutcome::Failed
            }
        }
    }

    /// Fire-and-forget [`flush_session`](Self::flush_session), for the
    /// session-close path (a sync teardown site inside the runtime). Outside a
    /// tokio runtime — some unit tests exercise the close path directly — the
    /// recording is discarded with a log, matching the no-sink behavior.
    pub fn flush_session_detached(&self, key: &SessionKey, seal: bool) {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let recorder = self.clone();
                let key = key.clone();
                handle.spawn(async move {
                    recorder.flush_session_with_seal(&key, seal).await;
                });
            }
            Err(_) => {
                let _ = self.take_blob(key, seal);
            }
        }
    }

    /// Flushes every live recording, bounded by `deadline` — the drain path's
    /// wholesale flush. Whatever the deadline cuts off is logged and abandoned:
    /// flight data is observability, and the drain's own budget (and Fargate's
    /// stopTimeout behind it) outranks it.
    ///
    /// The fan-out is capped at [`DRAIN_FLUSH_CONCURRENCY`] rather than fully
    /// concurrent: [`CoordinatorSink`](super::sinks::CoordinatorSink) refuses (never blocks on) a full shipment
    /// queue, so an unbounded burst here would overrun that queue on a relay
    /// holding more live sessions than the queue is deep and lose the overflow
    /// even over a healthy connection. Capped below the queue depth, a full
    /// queue at drain time means a genuinely wedged connection, not this flush
    /// racing its own fan-out.
    pub async fn flush_all(&self, deadline: Duration) {
        use futures_util::StreamExt;

        let keys = self.recorded_sessions();
        if keys.is_empty() {
            return;
        }
        tracing::info!(
            sessions = keys.len(),
            "flushing flight recordings for drain"
        );
        let completed = AtomicU64::new(0);
        let flushes = futures_util::stream::iter(keys.iter()).for_each_concurrent(
            DRAIN_FLUSH_CONCURRENCY,
            |key| {
                let completed = &completed;
                async move {
                    self.flush_session(key).await;
                    completed.fetch_add(1, Ordering::Relaxed);
                }
            },
        );
        if tokio::time::timeout(deadline, flushes).await.is_err() {
            let abandoned = keys.len() as u64 - completed.load(Ordering::Relaxed);
            tracing::warn!(
                abandoned,
                "drain flight flush hit its deadline; abandoning the rest",
            );
        }
    }
}
