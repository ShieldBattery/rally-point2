//! The relay's idle self-reap driven end to end against the real relay binary.
//!
//! A relay that has lost its coordinator — here modeled by a `--coordinator-url`
//! pointing at a loopback port with no listener — holds zero sessions and never
//! establishes a control connection, so once both have held for
//! `--idle-unenrolled-exit-secs` it exits on its own with a success code. The
//! negative gate proves the guardrail: the same launch with **no** coordinator URL
//! keeps serving well past the threshold, since a standalone relay must never
//! self-reap.
//!
//! Both tests spawn the crate's own relay binary (reached via
//! `CARGO_BIN_EXE_rally-point-relay`) and observe the process, not any internal
//! state — the exit (or the absence of one) is the whole assertion.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// A generous ceiling for the self-reap: the relay polls its idle condition on a
/// production-cadence interval, so the exit lands a poll or two past the (short)
/// threshold rather than exactly on it. Well above that, and far below anything
/// that would let a genuinely stuck process pass as a self-reap.
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);

/// The self-exit threshold the launched relay is configured with — small so the
/// test runs quickly, but non-zero so the exit is a real threshold crossing.
const THRESHOLD_SECS: &str = "2";

fn relay_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rally-point-relay"))
}

/// A loopback address with no listener: bind an ephemeral port, capture it, and
/// drop the listener, so a dial to it is refused rather than accepted. Modeling a
/// vanished coordinator this way keeps the relay's control connection permanently
/// unestablished for the whole test.
fn dead_coordinator_url() -> String {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://{}", SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
}

/// Polls the child for exit until `timeout`, returning its status once it exits or
/// `None` if it is still running at the deadline. Discards stdio-free — the caller
/// launched the child with null stdio — so a chatty relay can never wedge on a full
/// pipe.
async fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .expect("polling the relay child's exit status")
        {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn an_idle_relay_that_lost_its_coordinator_self_reaps() {
    let mut child = Command::new(relay_bin())
        .args([
            "--relay-id",
            "1",
            "--coordinator-url",
            &dead_coordinator_url(),
            "--listen",
            "127.0.0.1:0",
            "--idle-unenrolled-exit-secs",
            THRESHOLD_SECS,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the relay binary launches");

    let status = match wait_for_exit(&mut child, EXIT_TIMEOUT).await {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the idle, unenrolled relay did not self-reap within {EXIT_TIMEOUT:?}");
        }
    };
    assert!(
        status.success(),
        "the self-reaping relay exits cleanly (code 0), got {status:?}",
    );
}

#[tokio::test]
async fn a_relay_with_no_coordinator_does_not_self_reap() {
    // No --coordinator-url, so the idle self-exit gets no control-connection watch
    // and never fires — even with the same short threshold set.
    let mut child = Command::new(relay_bin())
        .args([
            "--listen",
            "127.0.0.1:0",
            "--idle-unenrolled-exit-secs",
            THRESHOLD_SECS,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the relay binary launches");

    // Well past the threshold, the relay is still running.
    let exited = wait_for_exit(&mut child, Duration::from_secs(6)).await;
    let still_running = exited.is_none();
    // Clean up regardless of the outcome (a no-op if it already exited).
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        still_running,
        "a relay with no coordinator configured must not self-reap (exited with {exited:?})",
    );
}
