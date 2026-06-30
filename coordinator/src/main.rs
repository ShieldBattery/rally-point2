//! Entry point for the multi-tenant netcode v2 coordinator.
//!
//! Thin wiring: parses CLI args, builds the coordinator's shared state, and
//! serves the HTTP control-plane API from [`rally_point_coordinator::api`].
//! The binary adds no logic of its own — every failure mode is in the library
//! where it's testable, mirroring the relay binary.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use clap::Parser;
use color_eyre::eyre::{Context, Result};
use rally_point_coordinator::api::{self, CoordinatorState};
use rally_point_coordinator::{registry, session, tenant};

/// Multi-tenant netcode v2 coordinator.
#[derive(Debug, Parser)]
#[command(name = "rally-point-coordinator", version, about)]
struct Cli {
    /// Address to serve the app-server + relay control API on.
    #[arg(long, env = "COORDINATOR_LISTEN", default_value_t = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), rally_point_coordinator::DEFAULT_PORT))]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    init_tracing();

    let cli = Cli::parse();
    tracing::info!(listen = %cli.listen, "rally-point coordinator starting");

    let setup = session::SessionSetup::new(registry::new_registry(), tenant::new_store());

    let state = CoordinatorState { setup };

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
