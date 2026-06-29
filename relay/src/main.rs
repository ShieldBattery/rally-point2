//! Entry point for the validating netcode v2 relay.
//!
//! Thin wiring: parses CLI args, delegates to [`rally_point_relay::config`] for
//! the real logic (cert/registry construction), and drives
//! [`rally_point_relay::server::run`]. The binary adds no logic of its own —
//! every failure mode is in the library where it's testable.
//!
//! The mesh edge is not wired here yet — `mesh_accept` is `None`, so a peer
//! relay that connects is closed. Mesh links land with the coordinator's
//! session-descriptor push (Phase 3), which is also what drives
//! `MeshCommand::Join` in production.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use clap::Parser;
use color_eyre::Result;
use color_eyre::eyre::Context;
use rally_point_relay::config::{
    self, generate_dev_tenant_key, load_cert, self_signed_cert, tenant_key_from_pubkey,
};
use rally_point_relay::mesh;
use rally_point_relay::routing::Sessions;
use rally_point_relay::{DEFAULT_PORT, server};

/// Validating netcode v2 relay.
#[derive(Debug, Parser)]
#[command(name = "rally-point-relay", version, about)]
struct Cli {
    /// Address to listen on for client + mesh QUIC connections (dual-stack by
    /// default — IPv6-primary ingress).
    #[arg(long, env = "RELAY_LISTEN", default_value_t = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DEFAULT_PORT))]
    listen: SocketAddr,

    /// TLS certificate chain for the relay's identity — either a PEM file path
    /// (local dev, Docker volume mount) or inline PEM content (Fargate secret
    /// injection). If absent, a self-signed cert is generated (dev/loopback
    /// only — clients must trust it out-of-band).
    #[arg(long, env = "RELAY_CERT")]
    cert: Option<String>,

    /// PEM private key matching `--cert` — either a file path or inline PEM
    /// content, same as `--cert`. Required when `--cert` is set; ignored (a
    /// fresh key is generated) when `--cert` is absent.
    #[arg(long, env = "RELAY_KEY", requires = "cert")]
    key: Option<String>,

    /// Hex-encoded Ed25519 *public* (verifying) key for the tenant signing key.
    /// The relay verifies client tokens against this; the matching private key
    /// stays with the token issuer, never on the relay. If absent, a keypair is
    /// generated and both halves are logged (the public is registered, the
    /// private is printed so a client can mint matching tokens for loopback).
    #[arg(long, env = "RELAY_TENANT_PUBKEY")]
    tenant_pubkey: Option<String>,

    /// Key id (`kid`) naming the tenant signing key in the registry.
    #[arg(long, env = "RELAY_KID", default_value = "dev-key-1")]
    kid: String,

    /// Tenant id bound to the signing key.
    #[arg(long, env = "RELAY_TENANT", default_value = "sb-dev")]
    tenant: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    init_tracing();

    let cli = Cli::parse();
    tracing::info!(listen = %cli.listen, "rally-point relay starting");

    let (cert_chain, private_key) = match (&cli.cert, &cli.key) {
        (Some(cert_input), Some(key_input)) => load_cert(cert_input, key_input)?,
        (None, None) => {
            let cert = self_signed_cert()?;
            (cert.chain, cert.key)
        }
        // clap's `requires = "cert"` makes the (Some, None) case unreachable.
        _ => unreachable!(),
    };

    let server_config = rally_point_transport::quic::server_config(cert_chain, private_key)
        .context("building QUIC server config")?;

    let tenant_key = match &cli.tenant_pubkey {
        Some(pubkey_hex) => {
            tenant_key_from_pubkey(cli.kid.clone(), cli.tenant.clone(), pubkey_hex)?
        }
        None => {
            let key = generate_dev_tenant_key(cli.kid.clone(), cli.tenant.clone())?;
            if let Some(pkcs8) = &key.generated_pkcs8 {
                tracing::warn!(
                    kid = %cli.kid,
                    tenant = %cli.tenant,
                    pkcs8_hex = %hex::encode(pkcs8),
                    public_key_hex = %hex::encode(key.verifying_key),
                    "generated a dev tenant keypair — use --tenant-pubkey <pub_hex> to pin the public; \
                     use the pkcs8_hex with a client to mint matching tokens",
                );
            }
            key
        }
    };

    let registry = Arc::new(config::registry_from_tenant_key(&tenant_key));
    let sessions: Sessions = Arc::default();
    let mesh_state = mesh::new_mesh_state();

    server::run(
        cli.listen,
        server_config,
        registry,
        sessions,
        mesh_state,
        None, // no mesh edge yet — peer relays are closed
    )
    .await
    .context("relay server ended with an error")?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}
