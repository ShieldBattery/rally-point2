//! Entry point for the validating netcode v2 relay.
//!
//! Thin wiring: parses CLI args, delegates to [`rally_point_relay::config`] for
//! the real logic (cert/registry/mesh-peer parsing), and drives
//! [`rally_point_relay::server::run`]. The binary adds no logic of its own —
//! every failure mode is in the library where it's testable.
//!
//! The mesh edge's connection half is wired here: peer-relay connections that
//! arrive on the mesh ALPN are dispatched to [`mesh_edge::run_mesh_accept`], and
//! each `--mesh-peer` dials via [`mesh_edge::run_mesh_dial`] when the
//! [`should_dial_mesh`] tie-break says this relay is the lower id. Each
//! established link surfaces `(peer id, MeshCommand sender)`, which the binary
//! collects into a [`mesh_control::MeshControl`] — the Join source that turns a
//! coordinator `SessionDescriptor` into targeted `Join`/`Leave` on the link to
//! each session peer. The descriptor *source* is wired too: with `--coordinator-url`
//! set, a [`coordinator_client`] task holds a control connection open to the
//! coordinator and drives the Join source from the descriptor sets it pushes.
//! Without it (pure dev/loopback), the registry fills as links establish and tests
//! drive `Join` directly.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use clap::Parser;
use color_eyre::Result;
use color_eyre::eyre::Context;
use rally_point_proto::control::RelayHello;
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::ProtocolVersion;
use rally_point_relay::config::{
    self, generate_dev_tenant_key, load_cert, self_signed_cert, tenant_key_from_pubkey,
};
use rally_point_relay::coordinator_client;
use rally_point_relay::mesh;
use rally_point_relay::mesh_control;
use rally_point_relay::mesh_dialer;
use rally_point_relay::mesh_edge;
use rally_point_relay::routing::Sessions;
use rally_point_relay::{DEFAULT_PORT, server};
use rally_point_transport::quinn;

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

    /// This relay's id in the mesh (dev/loopback). The mesh link-establishment
    /// tie-break is "lower id dials higher": when two relays could each dial
    /// the other, exactly one must, so each compares its own id to a peer's
    /// configured id and dials only when it is the lower. Leave absent to run
    /// without a mesh edge (single-relay `C–S–C`). In production the
    /// coordinator assigns the relay id (Phase 3).
    #[arg(long, env = "RELAY_ID")]
    relay_id: Option<u64>,

    /// A peer relay to mesh with (dev/loopback): `ADDR#ID`, where ADDR is the
    /// peer's listen endpoint and ID is its `--relay-id`. Repeatable. When this
    /// relay's id is lower than a peer's, it dials that peer; when higher, it
    /// waits for the peer to dial. Both sides of a relay-pair must list each
    /// other. In production the coordinator pushes peer topology at runtime
    /// (relays churn under scale-to-zero, so the peer set is unknowable at
    /// startup), and the dial side needs the peer's id before connecting.
    #[arg(long, env = "RELAY_MESH_PEER", value_name = "ADDR#ID")]
    mesh_peers: Vec<String>,

    /// PEM CA certificate(s) to trust when dialing mesh peers — either a file
    /// path or inline PEM content, same form as `--cert`. For dev/loopback
    /// with two relays sharing one self-signed cert, pass that same cert here;
    /// if absent, the relay's own leaf cert is trusted (the shared-cert dev
    /// case). In production, relay-to-relay trust comes from an internal CA
    /// (both relays trust the same CA root) — Phase 3.
    #[arg(long, env = "RELAY_MESH_ROOTS")]
    mesh_roots: Option<String>,

    /// TLS server name (SNI) to verify on mesh peer certificates. Defaults to
    /// `localhost` for self-signed dev certs. Set to the hostname on the peer's
    /// production cert otherwise.
    #[arg(long, env = "RELAY_MESH_SERVER_NAME", default_value = "localhost")]
    mesh_server_name: String,

    /// Base URL of the coordinator's control-plane API (e.g.
    /// `http://coordinator.internal:14910`). When set together with `--relay-id`,
    /// the relay holds a control connection open to the coordinator and applies
    /// the session descriptors it pushes — the production source of mesh
    /// `Join`/`Leave`. Absent (pure dev/loopback), mesh membership is driven only
    /// by tests or by links establishing; no coordinator is contacted.
    #[arg(long, env = "RELAY_COORDINATOR_URL")]
    coordinator_url: Option<String>,

    /// Bootstrap secret presented to the coordinator (`Authorization: Bearer
    /// <secret>`) when opening the control connection. Must match the
    /// coordinator's `--bootstrap-secret`. Absent for dev/loopback against an
    /// open coordinator.
    #[arg(long, env = "RELAY_COORDINATOR_SECRET")]
    coordinator_secret: Option<String>,

    /// Public address clients and peer relays reach this relay at — sent to the
    /// coordinator in the enroll `Hello`. Defaults to `--listen` when that is a
    /// concrete address, else loopback on the listen port (dev/loopback).
    /// Production sets this explicitly (later, derived from the cloud substrate).
    #[arg(long, env = "RELAY_ADVERTISE_ADDR")]
    advertise_addr: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    init_tracing();

    let cli = Cli::parse();
    tracing::info!(listen = %cli.listen, "rally-point relay starting");

    let (cert_chain, private_key, ca) = match (&cli.cert, &cli.key) {
        (Some(cert_input), Some(key_input)) => {
            let (chain, key) = load_cert(cert_input, key_input)?;
            // The first cert in the chain is the leaf; seed client trust with
            // it when no separate CA is supplied (self-signed dev case).
            let ca = chain[0].clone();
            (chain, key, ca)
        }
        (None, None) => {
            let cert = self_signed_cert()?;
            (cert.chain, cert.key, cert.ca)
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

    // The mesh-edge connection half. When a relay-id is configured, spawn the
    // accept drain (peer relays dialing us arrive on `mesh_accept`) and one
    // dial task per `--mesh-peer` (we dial the peers we're lower-id than).
    // Each established link comes back on `links_rx` as `(peer id, MeshCommand
    // sender)` — the peer id labels which relay the link reaches, so the Join
    // source can target a session join at the right link.
    let mesh_accept = if let Some(our_id) = cli.relay_id {
        let (mesh_accept_tx, mesh_accept_rx) = tokio::sync::mpsc::channel::<quinn::Connection>(8);
        let (links_tx, mut links_rx) = tokio::sync::mpsc::channel::<(
            RelayId,
            tokio::sync::mpsc::UnboundedSender<mesh::MeshCommand>,
        )>(8);

        // Clone `links_tx` for the accept task; the original stays for the dial
        // tasks below (each clones again per peer).
        tokio::spawn(mesh_edge::run_mesh_accept(
            mesh_accept_rx,
            Arc::clone(&sessions),
            mesh_state.clone(),
            links_tx.clone(),
        ));

        // Roots to trust peer certs against — needed by the static `--mesh-peer`
        // dials and the coordinator-driven on-demand dialer alike, so build them
        // once (falls back to our own leaf when `--mesh-roots` is absent).
        let mesh_roots = config::load_mesh_roots(&cli.mesh_roots, &ca)?;

        // Static `--mesh-peer` dials are the no-coordinator dev/loopback path.
        // When a coordinator URL is set, the on-demand dialer drives dialing from
        // the pushed descriptors instead — running both would have two supervisors
        // dial the same peer and fight over its registration, so `--mesh-peer` is
        // ignored in that case.
        let peers = config::parse_mesh_peers(&cli.mesh_peers)?;
        if cli.coordinator_url.is_some() {
            if !peers.is_empty() {
                tracing::warn!(
                    "ignoring --mesh-peer: --coordinator-url is set, so the coordinator's \
                     descriptors drive mesh dialing",
                );
            }
        } else {
            for peer in peers {
                if peer.id.0 == our_id {
                    tracing::warn!(
                        peer_id = peer.id.0,
                        "mesh peer id equals our relay id; skipping (misconfiguration)",
                    );
                    continue;
                }
                let sessions = Arc::clone(&sessions);
                let mesh = mesh_state.clone();
                let links_tx = links_tx.clone();
                let dial = mesh_edge::MeshDial {
                    our_id: RelayId(our_id),
                    peer_id: peer.id,
                    peer_addr: peer.addr,
                    server_name: cli.mesh_server_name.clone(),
                    roots: mesh_roots.clone(),
                };
                tokio::spawn(mesh_edge::run_mesh_dial(dial, sessions, mesh, links_tx));
            }
        }

        // The relay's Join source. Each established link registers here keyed by
        // its peer id; a coordinator `SessionDescriptor` then drives targeted
        // `Join`/`Leave` on the links serving each session. Registering also
        // keeps the drivers' command channels alive — `run_mesh_link` ends when
        // its command sender is dropped, so the registry holding each sender is
        // what keeps a freshly established (not-yet-joined) link parked and ready.
        let mesh_control = mesh_control::MeshControl::new(RelayId(our_id));

        // The descriptor source. When a coordinator URL is configured, hold a
        // control connection open to it and apply the session-descriptor sets it
        // pushes through the Join source — the production path that drives
        // `Join`/`Leave`. Without a URL (pure dev/loopback with `--mesh-peer`),
        // the registry still fills as links establish and tests drive `Join` on
        // the command senders directly.
        if let Some(coordinator_url) = cli.coordinator_url.clone() {
            // The on-demand dialer: establish (and re-establish) mesh links to the
            // peers the coordinator's descriptors name, driven by the Join source's
            // desired-peer set. This is the production dial path — the static
            // `--mesh-peer` dials above are dev/loopback, where no coordinator
            // pushes topology.
            let dialer_config = mesh_dialer::DialerConfig {
                our_id: RelayId(our_id),
                server_name: cli.mesh_server_name.clone(),
                roots: mesh_roots.clone(),
                sessions: Arc::clone(&sessions),
                mesh: mesh_state.clone(),
                links: links_tx.clone(),
                redial_delay: mesh_edge::MESH_REDIAL_DELAY,
            };
            tokio::spawn(mesh_dialer::run_mesh_dialer(
                dialer_config,
                mesh_control.desired_peers(),
            ));

            let advertise_addr = config::resolve_advertise_addr(cli.advertise_addr, cli.listen);
            let relay_hello =
                RelayHello::new(RelayId(our_id), advertise_addr, ProtocolVersion::CURRENT);
            tracing::info!(
                relay_id = our_id,
                advertise = %advertise_addr,
                "enrolling with coordinator over the control connection",
            );
            tokio::spawn(coordinator_client::run_descriptor_subscriber(
                coordinator_url,
                relay_hello,
                cli.coordinator_secret.clone(),
                mesh_control.clone(),
            ));
        }

        tokio::spawn(async move {
            while let Some((peer_id, command_tx)) = links_rx.recv().await {
                mesh_control.register_link(peer_id, command_tx);
            }
        });

        Some(mesh_accept_tx)
    } else {
        None
    };

    server::run(
        cli.listen,
        server_config,
        registry,
        sessions,
        mesh_state,
        mesh_accept,
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
