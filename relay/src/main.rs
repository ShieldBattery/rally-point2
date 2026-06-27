//! Entry point for the validating netcode v2 relay.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use clap::Parser;
use color_eyre::eyre::Result;
use rally_point_relay::DEFAULT_PORT;

/// Validating netcode v2 relay.
#[derive(Debug, Parser)]
#[command(name = "rally-point-relay", version, about)]
struct Cli {
    /// Address to listen on for client + mesh QUIC connections (dual-stack by
    /// default — IPv6-primary ingress).
    #[arg(long, default_value_t = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DEFAULT_PORT))]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    init_tracing();

    let cli = Cli::parse();
    tracing::info!(listen = %cli.listen, "rally-point relay starting");
    // The client-facing edge (accept loop, token auth, per-session routing) lives
    // in the library; wiring this process to a server certificate and a seeded
    // token registry lands with the coordinator/infra work.
    tracing::warn!("relay process is not wired to a certificate or token registry yet");

    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}
