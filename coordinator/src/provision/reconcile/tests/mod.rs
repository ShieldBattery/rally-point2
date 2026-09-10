//! Shared fixtures for the reconcile-loop tests: `FakeProvisioner` (a
//! scripted, inspectable [`Provisioner`]) and `Harness` (a wired-up
//! `ProvisionLoop` over an in-memory registry/ledger/session-setup), used by
//! every topic file below via `use super::*;`. Split by topic: `scaling`
//! (launch/drain), `sweeps` (the fleet-wide cleanups plus provisioner-error
//! resilience), `coverage` (the backbone-RTT bootstrap demand).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use parking_lot::Mutex;
use rally_point_proto::control::{
    BufferBounds, PlayerHandoff, RelayHello, SessionRequest, TenantId,
};
use rally_point_proto::ids::SlotId;
use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};
use rally_point_proto::version::ProtocolVersion;

use super::*;
use crate::provision::ProvisionError;
use crate::session::create_session;
use crate::tenant;

const TENANT: &str = "sb-test";

/// A scripted, inspectable [`Provisioner`]: it records launches and stops,
/// hands each launch a scripted initial [`TaskState`], and can be told to fail
/// any of its calls, so the loop's resilience is exercisable.
struct FakeProvisioner {
    state: Mutex<FakeState>,
}

struct FakeState {
    next: u64,
    /// The state a freshly launched task takes.
    launch_state: TaskState,
    /// Every launch's spec, in call order.
    launches: Vec<LaunchSpec>,
    /// Each known task's current state.
    tasks: HashMap<String, TaskState>,
    /// Every stopped task id, in call order.
    stops: Vec<String>,
    fail_launch: bool,
    fail_state: bool,
    fail_stop: bool,
    fail_list: bool,
    /// What [`Provisioner::expects_public_ipv4`] reports for every region.
    expects_public_ipv4: bool,
}

/// A running-task state at a fixed loopback address — the usual scripted
/// "the launch came up" outcome.
fn running() -> TaskState {
    TaskState::Running {
        expected_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 15_000))],
    }
}

impl FakeProvisioner {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FakeState {
                next: 0,
                launch_state: running(),
                launches: Vec::new(),
                tasks: HashMap::new(),
                stops: Vec::new(),
                fail_launch: false,
                fail_state: false,
                fail_stop: false,
                fail_list: false,
                expects_public_ipv4: false,
            }),
        })
    }

    fn set_launch_state(&self, state: TaskState) {
        self.state.lock().launch_state = state;
    }

    /// Scripts (or injects) a task's state — used both to advance a launched
    /// task and to plant a task the ledger never minted (an orphan).
    fn set_task_state(&self, task: &str, state: TaskState) {
        self.state.lock().tasks.insert(task.to_owned(), state);
    }

    fn set_fail_launch(&self, fail: bool) {
        self.state.lock().fail_launch = fail;
    }

    fn set_fail_state(&self, fail: bool) {
        self.state.lock().fail_state = fail;
    }

    fn set_fail_stop(&self, fail: bool) {
        self.state.lock().fail_stop = fail;
    }

    fn set_fail_list(&self, fail: bool) {
        self.state.lock().fail_list = fail;
    }

    fn set_expects_public_ipv4(&self, expects: bool) {
        self.state.lock().expects_public_ipv4 = expects;
    }

    fn launches(&self) -> Vec<LaunchSpec> {
        self.state.lock().launches.clone()
    }

    fn stops(&self) -> Vec<String> {
        self.state.lock().stops.clone()
    }
}

impl Provisioner for FakeProvisioner {
    async fn launch(&self, spec: &LaunchSpec) -> Result<TaskId, ProvisionError> {
        let mut state = self.state.lock();
        if state.fail_launch {
            return Err(ProvisionError::Backend("launch failed".into()));
        }
        let id = format!("task-{}", state.next);
        state.next += 1;
        state.launches.push(spec.clone());
        let launch_state = state.launch_state.clone();
        state.tasks.insert(id.clone(), launch_state);
        Ok(TaskId(id))
    }

    async fn state(&self, task: &TaskId) -> Result<TaskState, ProvisionError> {
        let state = self.state.lock();
        if state.fail_state {
            return Err(ProvisionError::Backend("state failed".into()));
        }
        Ok(state
            .tasks
            .get(&task.0)
            .cloned()
            .unwrap_or(TaskState::Stopped))
    }

    async fn stop(&self, task: &TaskId) -> Result<(), ProvisionError> {
        let mut state = self.state.lock();
        if state.fail_stop {
            return Err(ProvisionError::Backend("stop failed".into()));
        }
        state.stops.push(task.0.clone());
        state.tasks.insert(task.0.clone(), TaskState::Stopped);
        Ok(())
    }

    async fn list(&self) -> Result<Vec<TaskId>, ProvisionError> {
        let state = self.state.lock();
        if state.fail_list {
            return Err(ProvisionError::Backend("list failed".into()));
        }
        Ok(state
            .tasks
            .iter()
            .filter(|(_, s)| **s != TaskState::Stopped)
            .map(|(id, _)| TaskId(id.clone()))
            .collect())
    }

    fn expects_public_ipv4(&self, _region: Option<&RegionId>) -> bool {
        self.state.lock().expects_public_ipv4
    }
}

fn region(name: &str) -> RegionId {
    RegionId(name.to_owned())
}

/// How many launches the fake provisioner has recorded for `region` so far —
/// the coverage tests' demand signal (paired with a launch state that stops
/// before enrolling, one demanding tick equals one launch for the region).
fn launches_for(h: &Harness, region: &RegionId) -> usize {
    h.fake
        .launches()
        .into_iter()
        .filter(|spec| spec.region.as_ref() == Some(region))
        .count()
}

/// A hello for `id`, tagged with `region`, on a per-id loopback port.
fn hello_in_region(id: u64, region: &RegionId) -> RelayHello {
    RelayHello::new(
        RelayId(id),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14_900 + id as u16)),
        ProtocolVersion::CURRENT,
        vec![id as u8; 4],
    )
    .with_region(region.clone())
}

/// A two-player, region-blind session request — its slots home on whatever
/// relay is available.
fn two_player_request() -> SessionRequest {
    SessionRequest {
        tenant: TenantId(TENANT.to_owned()),
        players: vec![
            PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xAA; 32]),
                external_ref: None,
                observer: false,
                region: None,
            },
            PlayerHandoff {
                slot: SlotId(1),
                client_pubkey: ClientPublicKey([0xBB; 32]),
                external_ref: None,
                observer: false,
                region: None,
            },
        ],
        external_id: None,
        latency_estimate_ms: None,
    }
}

/// A test rig: shared registry, ledger, session setup (with one enrolled
/// tenant), warm demand, a fake provisioner, and the loop built over them.
struct Harness {
    reg: RelayRegistry,
    ledger: Arc<RelayLedger>,
    setup: SessionSetup,
    warm: WarmTargets,
    pair_rtts: PairRttStore,
    fake: Arc<FakeProvisioner>,
    provision: ProvisionLoop<Arc<FakeProvisioner>>,
}

impl Harness {
    fn new(regions: Vec<RegionId>, idle_grace: Duration, launch_deadline: Duration) -> Self {
        let reg = registry::new_registry();
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId(TENANT.to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = SessionSetup::new(reg.clone(), tenants);
        let ledger =
            Arc::new(RelayLedger::open(Path::new(":memory:")).expect("in-memory ledger opens"));
        let warm = WarmTargets::new();
        let pair_rtts = crate::pair_rtts::new_store();
        let fake = FakeProvisioner::new();
        let config = ProvisionConfig {
            regions,
            tick_interval: Duration::from_secs(5),
            launch_deadline,
            idle_grace,
        };
        let provision = ProvisionLoop::new(
            config,
            setup.registry().clone(),
            setup.clone(),
            ledger.clone(),
            warm.clone(),
            pair_rtts.clone(),
            fake.clone(),
        );
        Self {
            reg,
            ledger,
            setup,
            warm,
            pair_rtts,
            fake,
            provision,
        }
    }

    /// Mints, binds, records a task for, and enrolls a live relay in `region`
    /// at `now`, as if it had come up and enrolled. Returns its id and enroll
    /// generation.
    fn seed_live_relay(&self, region: &RegionId, now: u64) -> (RelayId, u64) {
        let minted = self
            .ledger
            .mint_at(now, Some(region), Duration::from_secs(3_600))
            .unwrap();
        self.ledger
            .authorize_enroll_at(now, minted.relay_id, [0x11; 32], Some(&minted.token), None)
            .unwrap();
        self.ledger
            .record_task(
                minted.relay_id,
                &format!("task-live-{}", minted.relay_id.0),
                &[],
                &[],
            )
            .unwrap();
        let generation = registry::enroll(&self.reg, hello_in_region(minted.relay_id.0, region));
        (minted.relay_id, generation)
    }
}

mod coverage;
mod scaling;
mod sweeps;
