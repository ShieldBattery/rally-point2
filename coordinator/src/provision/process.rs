//! [`ProcessProvisioner`]: a [`Provisioner`] that launches relay binaries as
//! local child processes.
//!
//! Each launch picks a free loopback port, spawns the relay binary with the
//! minted id and enroll token in its environment and `127.0.0.1:<port>` as its
//! listen and advertise address, and reaps the process on stop. Children are
//! spawned kill-on-drop, so a coordinator that exits does not leak relays. This
//! is the substrate that makes the whole provisioning lifecycle exercisable
//! locally, standing in for a cloud task launcher.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use tokio::process::{Child, Command};

use super::{LaunchSpec, ProvisionError, Provisioner, TaskId, TaskState};

/// Static configuration for a [`ProcessProvisioner`]: where the relay binary is
/// and how a launched relay reaches this coordinator.
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    /// Path to the relay binary to spawn.
    pub relay_bin: PathBuf,
    /// Base URL a launched relay dials to open its control connection — this
    /// coordinator's own address, reachable from the child (e.g.
    /// `http://127.0.0.1:14910`).
    pub coordinator_url: String,
    /// Bootstrap secret a launched relay presents to open its control connection,
    /// matching the coordinator's own. `None` for an open (dev/loopback)
    /// coordinator.
    pub bootstrap_secret: Option<String>,
}

/// A spawned relay child and the loopback port it listens on.
struct RunningChild {
    /// The child process handle. Reaped by [`ProcessProvisioner::stop`], or killed
    /// on drop if the provisioner is dropped first.
    child: Child,
    /// The loopback port the relay listens and advertises on.
    port: u16,
}

/// A [`Provisioner`] backed by local child processes. Cheap to share behind an
/// `Arc`; the child map is guarded by a short-critical-section mutex never held
/// across an await.
pub struct ProcessProvisioner {
    config: ProcessConfig,
    children: Mutex<HashMap<String, RunningChild>>,
    next_id: AtomicU64,
}

impl ProcessProvisioner {
    /// Builds a provisioner that spawns the relay binary named by `config`.
    pub fn new(config: ProcessConfig) -> Self {
        Self {
            config,
            children: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }

    /// The number of children currently tracked — the count a test asserts against
    /// after launches and stops.
    pub fn tracked(&self) -> usize {
        self.children.lock().len()
    }
}

/// Picks a free loopback UDP port by binding an ephemeral socket and reading the
/// port the OS assigned, then dropping the socket. The relay listens on UDP
/// (QUIC), so a UDP probe reflects what it will actually bind. A racing bind
/// between the probe and the relay's own bind is possible but rare on loopback
/// and self-corrects: the relay fails to start, its task reports stopped, and the
/// launch is retired and re-minted like any other failed launch.
fn pick_loopback_port() -> Result<u16, ProvisionError> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| ProvisionError::Backend(format!("probing a free port: {e}")))?;
    let port = socket
        .local_addr()
        .map_err(|e| ProvisionError::Backend(format!("reading the probed port: {e}")))?
        .port();
    Ok(port)
}

impl Provisioner for ProcessProvisioner {
    async fn launch(&self, spec: &LaunchSpec) -> Result<TaskId, ProvisionError> {
        let port = pick_loopback_port()?;
        let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

        let mut command = Command::new(&self.config.relay_bin);
        command
            .env("RELAY_ID", spec.relay_id.0.to_string())
            .env("RELAY_ENROLL_TOKEN", &spec.enroll_token)
            .env("RELAY_COORDINATOR_URL", &self.config.coordinator_url)
            .env("RELAY_LISTEN", listen.to_string())
            .env("RELAY_ADVERTISE_ADDR", listen.to_string())
            .kill_on_drop(true)
            .stdout(Stdio::null());

        // Set or clear the optional vars explicitly, so a value inherited from the
        // coordinator's own environment can never leak into a launch that did not
        // ask for it.
        match &spec.region {
            Some(region) => command.env("RELAY_REGION", region.as_ref()),
            None => command.env_remove("RELAY_REGION"),
        };
        match &self.config.bootstrap_secret {
            Some(secret) => command.env("RELAY_COORDINATOR_SECRET", secret),
            None => command.env_remove("RELAY_COORDINATOR_SECRET"),
        };

        let child = command
            .spawn()
            .map_err(|e| ProvisionError::Backend(format!("spawning the relay binary: {e}")))?;

        let task_id = format!("proc-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        self.children
            .lock()
            .insert(task_id.clone(), RunningChild { child, port });
        Ok(TaskId(task_id))
    }

    async fn state(&self, task: &TaskId) -> Result<TaskState, ProvisionError> {
        let mut children = self.children.lock();
        let Some(running) = children.get_mut(&task.0) else {
            // A task the provisioner no longer tracks has been stopped (or never
            // existed): gone, from the caller's point of view.
            return Ok(TaskState::Stopped);
        };
        match running.child.try_wait() {
            // Still running: report its loopback advertise address.
            Ok(None) => {
                let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, running.port));
                Ok(TaskState::Running {
                    expected_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                    addrs: vec![addr],
                })
            }
            // Exited on its own.
            Ok(Some(_status)) => Ok(TaskState::Stopped),
            Err(e) => Err(ProvisionError::Backend(format!(
                "reading child task status: {e}"
            ))),
        }
    }

    async fn stop(&self, task: &TaskId) -> Result<(), ProvisionError> {
        // Take the child out of the map under the lock, then kill it outside the
        // lock (the kill awaits the reap, and the mutex is never held across an
        // await). Stopping a task already gone is a success.
        let running = self.children.lock().remove(&task.0);
        if let Some(mut running) = running {
            running
                .child
                .kill()
                .await
                .map_err(|e| ProvisionError::Backend(format!("killing the relay process: {e}")))?;
        }
        Ok(())
    }

    async fn list(&self) -> Result<Vec<TaskId>, ProvisionError> {
        Ok(self
            .children
            .lock()
            .keys()
            .map(|k| TaskId(k.clone()))
            .collect())
    }
}
