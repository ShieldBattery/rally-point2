//! Deadlines and WebSocket probes for a single control connection.
use super::{ControlError, connect::ControlDisconnect};
use futures_util::SinkExt;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::{Error, Message};

/// Deadlines for each stage of a control connection.
#[derive(Clone, Copy)]
pub(super) struct ControlTiming {
    /// Deadline for resolving the coordinator hostname.
    pub(super) dns: Duration,
    /// Combined deadline for TCP, TLS, and WebSocket upgrade across all addresses.
    pub(super) dial: Duration,
    /// Deadline for receiving the enrollment challenge after sending Hello.
    pub(super) challenge: Duration,
    /// Deadline from sending the proof to observing an accepted application frame.
    pub(super) acceptance: Duration,
    /// Deadline for each individual WebSocket send.
    pub(super) write: Duration,
    /// Delay after acceptance or a matching Pong before queuing the next probe.
    pub(super) probe_interval: Duration,
    /// Reply budget starting when a probe is queued, including time waiting for the writer.
    pub(super) pong: Duration,
    /// Delay between successive address attempts within the dial race.
    pub(super) stagger: Duration,
}

impl Default for ControlTiming {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(10),
            dial: Duration::from_secs(10),
            challenge: Duration::from_secs(10),
            acceptance: Duration::from_secs(10),
            write: Duration::from_secs(10),
            probe_interval: Duration::from_secs(10),
            // Leave reply time after a preceding write consumes nearly its budget.
            pong: Duration::from_secs(15),
            stagger: Duration::from_millis(250),
        }
    }
}

/// Send one frame within the connection's write deadline.
pub(super) async fn send(
    sink: &mut (impl SinkExt<Message, Error = Error> + Unpin),
    frame: Message,
    write_timeout: Duration,
) -> Result<(), ControlError> {
    tokio::time::timeout(write_timeout, sink.send(frame))
        .await
        .map_err(|_| ControlError::Timeout("write"))??;
    Ok(())
}

/// Require acceptance and then matching replies to connection-local probes.
pub(super) async fn monitor(
    probe_tx: mpsc::UnboundedSender<Vec<u8>>,
    mut pong_rx: mpsc::Receiver<Vec<u8>>,
    mut accepted: watch::Receiver<bool>,
    timing: ControlTiming,
    acceptance_deadline: tokio::time::Instant,
) -> Result<ControlDisconnect, ControlError> {
    tokio::time::timeout_at(acceptance_deadline, async {
        while !*accepted.borrow_and_update() {
            if accepted.changed().await.is_err() {
                break;
            }
        }
    })
    .await
    .map_err(|_| ControlError::Timeout("enrollment acceptance"))?;
    let mut sequence = 0u64;
    loop {
        let next_probe = tokio::time::sleep(timing.probe_interval);
        tokio::pin!(next_probe);
        loop {
            tokio::select! {
                biased;
                _ = &mut next_probe => break,
                pong = pong_rx.recv() => if pong.is_none() { return Ok(ControlDisconnect::Ordinary); },
            }
        }
        sequence += 1;
        let probe = sequence.to_be_bytes().to_vec();
        if probe_tx.send(probe.clone()).is_err() {
            return Ok(ControlDisconnect::Ordinary);
        }
        let deadline = tokio::time::sleep(timing.pong);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                biased;
                _ = &mut deadline => return Err(ControlError::Timeout("pong")),
                pong = pong_rx.recv() => match pong {
                    Some(pong) if pong == probe => break,
                    Some(_) => {},
                    None => return Ok(ControlDisconnect::Ordinary),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timing() -> ControlTiming {
        ControlTiming {
            acceptance: Duration::from_secs(3),
            probe_interval: Duration::from_secs(2),
            pong: Duration::from_secs(4),
            ..Default::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn missing_acceptance_expires_at_deadline_without_probe() {
        let (probe_tx, mut probe_rx) = mpsc::unbounded_channel();
        let (_pong_tx, pong_rx) = mpsc::channel(16);
        let (_accepted_tx, accepted_rx) = watch::channel(false);
        let task = tokio::spawn(monitor(
            probe_tx,
            pong_rx,
            accepted_rx,
            timing(),
            tokio::time::Instant::now() + timing().acceptance,
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3) - Duration::from_millis(1)).await;
        assert!(!task.is_finished());
        assert!(probe_rx.try_recv().is_err());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(matches!(
            task.await.unwrap(),
            Err(ControlError::Timeout("enrollment acceptance"))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn matching_pongs_keep_the_connection_alive() {
        let (probe_tx, mut probe_rx) = mpsc::unbounded_channel();
        let (pong_tx, pong_rx) = mpsc::channel(16);
        let (_accepted_tx, accepted_rx) = watch::channel(true);
        let task = tokio::spawn(monitor(
            probe_tx,
            pong_rx,
            accepted_rx,
            timing(),
            tokio::time::Instant::now() + timing().acceptance,
        ));
        tokio::task::yield_now().await;
        for sequence in 1u64..=3 {
            tokio::time::advance(Duration::from_secs(2)).await;
            let probe = probe_rx.recv().await.unwrap();
            assert_eq!(probe, sequence.to_be_bytes());
            tokio::time::advance(Duration::from_secs(3)).await;
            pong_tx.send(probe).await.unwrap();
            tokio::task::yield_now().await;
            assert!(!task.is_finished());
        }
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_probe_delayed_by_a_recovering_write_has_time_for_its_reply() {
        let timing = ControlTiming::default();
        let (probe_tx, mut probe_rx) = mpsc::unbounded_channel();
        let (pong_tx, pong_rx) = mpsc::channel(16);
        let (_accepted_tx, accepted_rx) = watch::channel(true);
        let task = tokio::spawn(monitor(
            probe_tx,
            pong_rx,
            accepted_rx,
            timing,
            tokio::time::Instant::now() + timing.acceptance,
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(timing.probe_interval).await;
        let first = probe_rx.recv().await.unwrap();
        // A preceding write recovers just inside its deadline, then the probe's
        // round trip takes another second.
        tokio::time::advance(timing.write - Duration::from_millis(1)).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        pong_tx.send(first.clone()).await.unwrap();
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        tokio::time::advance(timing.probe_interval).await;
        let second = probe_rx.recv().await.unwrap();
        assert_ne!(first, second);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn continuously_ready_stale_and_wrong_pongs_do_not_extend_deadline() {
        let (probe_tx, mut probe_rx) = mpsc::unbounded_channel();
        let (pong_tx, pong_rx) = mpsc::channel(16);
        let (_accepted_tx, accepted_rx) = watch::channel(true);
        let task = tokio::spawn(monitor(
            probe_tx,
            pong_rx,
            accepted_rx,
            timing(),
            tokio::time::Instant::now() + timing().acceptance,
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        let first = probe_rx.recv().await.unwrap();
        pong_tx.send(first.clone()).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        let second = probe_rx.recv().await.unwrap();
        assert_ne!(first, second);
        let flood = tokio::spawn(async move {
            loop {
                if pong_tx.send(first.clone()).await.is_err() {
                    break;
                }
                if pong_tx.send(vec![42]).await.is_err() {
                    break;
                }
            }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(4) - Duration::from_millis(1)).await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(matches!(
            task.await.unwrap(),
            Err(ControlError::Timeout("pong"))
        ));
        flood.abort();
    }
}
