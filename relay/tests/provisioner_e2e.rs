//! The provisioning loop driven end to end against the real relay binary.
//!
//! A ledger-backed coordinator runs in-process; its reconcile loop is driven by a
//! [`ProcessProvisioner`] pointed at this crate's own relay binary (reached via
//! `CARGO_BIN_EXE_rally-point-relay`). The test proves the whole lifecycle without
//! a cloud substrate: warm demand mints an id and launches a real relay process,
//! that relay enrolls over its control connection (a WebSocket, with
//! proof-of-possession and a one-time token), its registry entry carries the
//! ledger-recorded loopback address, an idle scale-down stops the process and
//! retires the id, and a subsequent launch mints a fresh id (the retired one is
//! never reused).
//!
//! This is a dev-dependency cycle: the coordinator crate dev-depends on this relay
//! crate, and this test dev-depends on the coordinator crate. Cargo permits it —
//! dev-dependencies do not feed the library build graph — which is what lets the
//! e2e both spawn the real relay binary (only its own crate's tests get
//! `CARGO_BIN_EXE_...`) and build a ledger-backed coordinator in-process.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rally_point_coordinator::api::{self, ControlAuth, CoordinatorState};
use rally_point_coordinator::ledger::RelayLedger;
use rally_point_coordinator::lifecycle::Lifecycle;
use rally_point_coordinator::provision::{
    ProcessConfig, ProcessProvisioner, ProvisionConfig, ProvisionLoop, Provisioner, WarmTargets,
};
use rally_point_coordinator::regions::RegionsConfig;
use rally_point_coordinator::registry::{self, EnrolledRelay, RelayRegistry};
use rally_point_coordinator::session::SessionSetup;
use rally_point_coordinator::{notify, tenant};
use rally_point_proto::control::RegionId;

/// The single region the coordinator is configured for; the relay enrolls tagged
/// with it.
const REGION: &str = "local";

/// A generous poll ceiling for anything that waits on a real relay process
/// (spawning, enrolling, its control connection dropping after a kill).
const POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// The current Unix time in seconds — the base instant the loop's injected ticks
/// build on. The coordinator authorizes enrolls against its own wall clock, so the
/// loop must mint from a realistic instant (not an arbitrary small one) or a token
/// would read as already expired.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}

/// A one-region config the relay's enroll validates its region tag against.
fn one_region_config() -> RegionsConfig {
    RegionsConfig::from_json(
        r#"{"regions":[{"id":"local","display_name":"Local","beacon":"h:1","fallback":"h:2"}]}"#,
    )
    .expect("a valid one-region config")
}

/// Serves a ledger-backed coordinator (open auth, one region) on an ephemeral
/// loopback port, **with connect-info** so the ledger's expected-address gate sees
/// the relay's real loopback peer. Returns the base URL, the shared registry,
/// ledger, and session setup the reconcile loop reconciles over.
async fn serve_coordinator() -> (String, RelayRegistry, Arc<RelayLedger>, SessionSetup) {
    let ledger =
        Arc::new(RelayLedger::open(std::path::Path::new(":memory:")).expect("ledger opens"));
    let reg = registry::new_registry();
    let setup = SessionSetup::new(reg.clone(), tenant::new_store());
    let lifecycle = Lifecycle::new(setup.clone());
    let state = CoordinatorState {
        setup: setup.clone(),
        notices: notify::new_dedup(),
        lifecycle,
        control_auth: ControlAuth::Open,
        hello_timeout: api::HELLO_TIMEOUT,
        liveness_timeout: Duration::from_secs(30),
        regions: one_region_config(),
        player_token_lifetime: Duration::from_secs(3_600),
        ledger: Some(ledger.clone()),
    };
    let app = api::router(state);
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (format!("http://{addr}"), reg, ledger, setup)
}

/// Polls `f` until it returns `Some`, or panics with `context` after the deadline.
async fn poll_until<T>(context: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        if let Some(value) = f() {
            return value;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for: {context}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The one enrolled relay, if exactly one is present (draining or not).
fn sole_enrolled(reg: &RelayRegistry) -> Option<EnrolledRelay> {
    let mut enrolled = registry::enrolled_relays(reg);
    (enrolled.len() == 1).then(|| enrolled.remove(0))
}

#[tokio::test]
async fn provisioning_lifecycle_launches_enrolls_drains_and_re_mints_a_fresh_id() {
    let relay_bin = PathBuf::from(env!("CARGO_BIN_EXE_rally-point-relay"));
    let (coordinator_url, reg, ledger, setup) = serve_coordinator().await;
    let region = RegionId(REGION.to_owned());

    let provisioner = Arc::new(ProcessProvisioner::new(ProcessConfig {
        relay_bin,
        coordinator_url,
        bootstrap_secret: None,
    }));
    let warm = WarmTargets::new();
    // A short idle grace and warm TTL keep the drain reachable with a few injected
    // ticks; the launch deadline stays long so a real enroll's token is valid.
    let mut provision = ProvisionLoop::new(
        ProvisionConfig {
            regions: vec![region.clone()],
            tick_interval: Duration::from_secs(5),
            launch_deadline: Duration::from_secs(300),
            idle_grace: Duration::from_secs(2),
        },
        reg.clone(),
        setup,
        ledger.clone(),
        warm.clone(),
        provisioner.clone(),
    );

    let base = now_unix_secs();
    // Warm the region for a couple of seconds: long enough to survive the launch
    // and first steady tick, short enough to lapse before the drain tick.
    warm.warm_at(region.clone(), Duration::from_secs(2), base);

    // Tick 1: mint an id, launch a real relay, and record its loopback address.
    provision.tick(base).await;

    // The real relay process comes up and enrolls over its control connection.
    let first = poll_until("the launched relay to enroll", || sole_enrolled(&reg)).await;
    let first_id = first.relay_id;

    // Its registry entry carries the ledger-recorded loopback advertise address —
    // coordinator-resolved addresses win over the hello's self-report.
    let recorded = ledger
        .advertised_addrs(first_id)
        .unwrap()
        .expect("the loop recorded the launched task's advertise set");
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].ip(), Ipv4Addr::LOCALHOST);
    let entry = registry::entry(&reg, first_id).unwrap();
    assert_eq!(
        entry.relay_addr, recorded[0],
        "the enrolled relay advertises the ledger-recorded loopback address",
    );
    assert_eq!(entry.relay_addrs, recorded);

    // Tick 2 (still warm): the relay is live and matches the target, so nothing
    // changes — and its idle timer starts.
    provision.tick(base + 1).await;
    assert!(
        registry::is_available(&reg, first_id),
        "a steady, warm relay is left alone",
    );

    // Tick 3 (warm lapsed, past the idle grace): the idle relay is drained — its
    // process is stopped, so the provisioner no longer tracks any task.
    provision.tick(base + 10).await;
    assert!(
        provisioner.list().await.unwrap().is_empty(),
        "the drained relay's process was stopped and reaped",
    );

    // The stopped relay's control connection drops, so it leaves the registry.
    poll_until("the drained relay to leave the registry", || {
        registry::enrolled_relays(&reg).is_empty().then_some(())
    })
    .await;

    // Re-warm and tick: a fresh launch mints a NEW id — the retired one is never
    // reused.
    warm.warm_at(region.clone(), Duration::from_secs(60), base + 11);
    provision.tick(base + 11).await;
    let second = poll_until("a re-launched relay to enroll", || {
        sole_enrolled(&reg).filter(|r| r.relay_id != first_id)
    })
    .await;
    assert!(
        second.relay_id.0 > first_id.0,
        "a re-launch mints a fresh, never-reused id ({} then {})",
        first_id.0,
        second.relay_id.0,
    );

    // Stop the re-launched relay so the test leaves nothing running (kill-on-drop
    // would catch it too, but stop it explicitly for a clean exit).
    for task in provisioner.list().await.unwrap() {
        let _ = provisioner.stop(&task).await;
    }
}
