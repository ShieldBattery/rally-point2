//! Entry point for the multi-tenant netcode v2 coordinator.
//!
//! Thin wiring: parses CLI args, builds the coordinator's shared state, and
//! serves the HTTP control-plane API from [`rally_point_coordinator::api`].
//! The binary adds no logic of its own — every failure mode is in the library
//! where it's testable, mirroring the relay binary.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use clap::Parser;
use color_eyre::eyre::{Context, Result};
use rally_point_coordinator::api::{self, ControlAuth, CoordinatorState};
use rally_point_coordinator::{registry, session, tenant};

/// Multi-tenant netcode v2 coordinator.
#[derive(Debug, Parser)]
#[command(name = "rally-point-coordinator", version, about)]
struct Cli {
    /// Address to serve the app-server + relay control API on.
    #[arg(long, env = "COORDINATOR_LISTEN", default_value_t = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), rally_point_coordinator::DEFAULT_PORT))]
    listen: SocketAddr,

    /// Shared bootstrap secret a relay must present (`Authorization: Bearer
    /// <secret>`) to open its control connection. Production injects one so a
    /// rogue relay cannot subscribe to another relay's mesh topology. Without it
    /// the coordinator refuses to start unless `--allow-insecure-control` is set.
    #[arg(long, env = "COORDINATOR_BOOTSTRAP_SECRET")]
    bootstrap_secret: Option<String>,

    /// Run the relay control endpoint with **no authentication**. Required to
    /// start without `--bootstrap-secret`; for trusted dev/loopback only. The
    /// coordinator fails closed (refuses to start) if neither is set, so an
    /// unauthenticated control endpoint is never the silent default.
    #[arg(
        long,
        env = "COORDINATOR_ALLOW_INSECURE_CONTROL",
        default_value_t = false
    )]
    allow_insecure_control: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    init_tracing();

    let cli = Cli::parse();
    tracing::info!(listen = %cli.listen, "rally-point coordinator starting");

    let setup = session::SessionSetup::new(registry::new_registry(), tenant::new_store());

    // Fail closed: a coordinator with no bootstrap secret would serve the relay
    // control endpoint to anyone, leaking mesh topology. Require an explicit
    // insecure opt-in rather than defaulting to open.
    let control_auth = api::resolve_control_auth(cli.bootstrap_secret, cli.allow_insecure_control)
        .map_err(|_| {
            color_eyre::eyre::eyre!(
                "refusing to start: the relay control endpoint would be unauthenticated. \
                 Set --bootstrap-secret <secret> (COORDINATOR_BOOTSTRAP_SECRET), or pass \
                 --allow-insecure-control for trusted dev/loopback."
            )
        })?;
    if matches!(control_auth, ControlAuth::Open) {
        tracing::warn!(
            "relay control endpoint is UNAUTHENTICATED (--allow-insecure-control); \
             for trusted dev/loopback only"
        );
    }

    let state = CoordinatorState {
        setup,
        control_auth,
        hello_timeout: api::HELLO_TIMEOUT,
    };

    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .context("binding coordinator listen address")?;
    tracing::info!("coordinator API listening on {}", cli.listen);

    axum::serve(listener, app)
        .await
        .context("coordinator API server ended with an error")?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}
