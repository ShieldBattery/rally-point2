//! The reconcile loop and its substrate abstraction: the coordinator keeps each
//! region's relay count matched to TTL'd warm demand without depending on any
//! particular launch substrate.
//!
//! A [`Provisioner`] is the contract a substrate fulfills — launch a relay task
//! from a [`LaunchSpec`], report a task's [`TaskState`], stop a task, and list
//! the tasks it still knows. The reconcile loop ([`ProvisionLoop`]) drives it
//! level-triggered: every tick it re-derives the desired state from scratch
//! (region config, the registry, session membership, the ledger, and
//! [`WarmTargets`]) and takes the actions that close the gap — minting identities,
//! launching tasks, recording their addresses, draining idle relays, and sweeping
//! launches that never enrolled or tasks the ledger lost track of.
//!
//! [`ProcessProvisioner`] is the local substrate: it spawns real relay binaries
//! as child processes, so the whole lifecycle is exercisable without a cloud
//! substrate. A cloud implementation (an ECS task launcher) is a separate
//! [`Provisioner`]; the loop is generic over the trait and never names one.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};

use rally_point_proto::control::RegionId;
use rally_point_proto::ids::RelayId;

mod ecs;
mod process;
mod reconcile;
mod warm;

pub use ecs::{EcsConfig, EcsConfigError, EcsProvisioner};
pub use process::{ProcessConfig, ProcessProvisioner};
pub use reconcile::{ProvisionConfig, ProvisionLoop};
pub use warm::WarmTargets;

/// An opaque handle to a launched relay task. Locally it is a child-process key;
/// a cloud substrate makes it that substrate's task identifier (an ECS task ARN).
/// Stored verbatim as a ledger row's recorded task, so the orphan sweep can match
/// the tasks a provisioner lists against the tasks the ledger references.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaskId(pub String);

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a relay task needs at launch: the ledger-minted id it runs as, the
/// one-time enroll token that authorizes its first enroll, and the region it
/// serves (if any).
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    /// The coordinator-minted relay id the task runs as.
    pub relay_id: RelayId,
    /// The one-time enroll token, in the clear. It rides the task's launch
    /// environment only and is never stored by the provisioner — the ledger keeps
    /// only its hash.
    pub enroll_token: String,
    /// The region the relay serves, passed to the task so it enrolls tagged. A
    /// region-blind launch carries `None`.
    pub region: Option<RegionId>,
}

/// A launched task's observable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    /// The substrate accepted the launch but the task has no reachable address
    /// yet. The loop keeps polling until it reports [`Running`](Self::Running).
    Starting,
    /// The task is up with a known address set. `expected_ips` are the peer
    /// addresses the coordinator may see it enroll from (a dual-stack task can
    /// connect from either family); `addrs` is the advertise set clients and peers
    /// reach it at, first entry primary. An empty `expected_ips` means the
    /// substrate resolved no peer address to gate on.
    Running {
        /// The peer addresses the coordinator may see the relay enroll from —
        /// any one matches. Empty when the substrate cannot resolve one.
        expected_ips: Vec<IpAddr>,
        /// The advertise-address set, in preference order (first is primary).
        addrs: Vec<SocketAddr>,
    },
    /// The task is gone or has exited.
    Stopped,
}

/// A failure operating a provisioner's substrate. The reconcile loop logs one and
/// continues the tick — every action it takes is re-derived and retried on the
/// next tick — so a transient substrate fault never kills the loop.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// The substrate rejected or failed a launch, state, stop, or list call. The
    /// message carries the substrate's own error for the operator log.
    #[error("provisioner backend error: {0}")]
    Backend(String),
}

/// The substrate a [`ProvisionLoop`] launches relays through. Implementations are
/// shared across the loop's ticks (`Send + Sync`), and each method's future is
/// `Send` so the loop can run on the multi-threaded runtime.
pub trait Provisioner: Send + Sync {
    /// Launches a relay task for `spec`, returning the substrate's handle for it.
    /// The returned handle is what [`state`](Self::state) and [`stop`](Self::stop)
    /// later name.
    fn launch(
        &self,
        spec: &LaunchSpec,
    ) -> impl Future<Output = Result<TaskId, ProvisionError>> + Send;

    /// Reports `task`'s current [`TaskState`]. A task the substrate no longer
    /// knows reads as [`TaskState::Stopped`].
    fn state(
        &self,
        task: &TaskId,
    ) -> impl Future<Output = Result<TaskState, ProvisionError>> + Send;

    /// Stops `task`. Idempotent: stopping a task already gone is a success.
    fn stop(&self, task: &TaskId) -> impl Future<Output = Result<(), ProvisionError>> + Send;

    /// The tasks this provisioner started that the substrate still knows about —
    /// the input to the orphan sweep.
    fn list(&self) -> impl Future<Output = Result<Vec<TaskId>, ProvisionError>> + Send;
}

/// A shared provisioner is itself a provisioner: the loop owns one handle while a
/// caller (or a test) keeps another, both dispatching to the same substrate.
impl<P: Provisioner> Provisioner for std::sync::Arc<P> {
    fn launch(
        &self,
        spec: &LaunchSpec,
    ) -> impl Future<Output = Result<TaskId, ProvisionError>> + Send {
        (**self).launch(spec)
    }

    fn state(
        &self,
        task: &TaskId,
    ) -> impl Future<Output = Result<TaskState, ProvisionError>> + Send {
        (**self).state(task)
    }

    fn stop(&self, task: &TaskId) -> impl Future<Output = Result<(), ProvisionError>> + Send {
        (**self).stop(task)
    }

    fn list(&self) -> impl Future<Output = Result<Vec<TaskId>, ProvisionError>> + Send {
        (**self).list()
    }
}
