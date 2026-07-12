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
use std::time::Duration;

use clap::Parser;
use color_eyre::Result;
use color_eyre::eyre::Context;
use rally_point_proto::control::{RegionId, RelayHello};
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
use rally_point_relay::provisional;
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

    /// Fail closed on the mesh accept path: refuse every dialing peer's
    /// connection until the coordinator's fleet-peer set has arrived, rather
    /// than treating an empty set as not-yet-enforced. Off by default, so the
    /// dev/loopback static `--mesh-peer` path (no coordinator, no fleet push
    /// ever arrives) keeps meshing with no peer-identity checks at all.
    /// Production sets this: a coordinator-driven relay should never serve an
    /// unauthenticated mesh accept, not even during the brief startup window
    /// before its first fleet-peer push lands.
    #[arg(long, env = "RELAY_REQUIRE_MESH_PEER_AUTH", default_value_t = false)]
    require_mesh_peer_auth: bool,

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

    /// Public address(es) clients and peer relays reach this relay at — sent to
    /// the coordinator in the enroll `Hello`. Repeatable (or comma-separated in
    /// the env var) for a dual-stack relay: one flag per family, the first is the
    /// primary and the order is the advertised preference. Defaults to `--listen`
    /// when that is a concrete address, else loopback on the listen port
    /// (dev/loopback) — a single-address advertise. Always explicit: the
    /// coordinator never infers these from the control connection's source IP
    /// (the relay reaches it over one family but must advertise both); deriving
    /// them from the cloud substrate (ECS metadata) is a follow-up.
    #[arg(long, env = "RELAY_ADVERTISE_ADDR", value_delimiter = ',')]
    advertise_addr: Vec<SocketAddr>,

    /// How long the coordinated-drain shutdown path waits for in-flight sessions to
    /// finish before exiting and abandoning any that remain to coordinator-mediated
    /// failover. Deliberately under Fargate's 120s `stopTimeout`, so the drain always
    /// completes before the platform SIGKILLs the process.
    #[arg(long, env = "RELAY_DRAIN_TIMEOUT_SECS", default_value_t = 90)]
    drain_timeout_secs: u64,

    /// Directory the flight recorder flushes per-session blobs into
    /// (`<dir>/<tenant>/<session>/<relay_id>.json`) — the dev/loopback sink.
    /// Absent, the recorder still records (cheap, bounded) but a flush discards
    /// the recording with a log line. The durable store (S3) replaces this in
    /// production.
    #[arg(long, env = "RELAY_FLIGHT_DIR")]
    flight_dir: Option<std::path::PathBuf>,

    /// The region this relay serves, sent to the coordinator in the enroll
    /// `Hello`. Must be one of the coordinator's configured region ids, or the
    /// coordinator refuses the control connection (close code 4002) — a typo'd tag
    /// that silently serves nobody is worse than a failed enroll. Absent = an
    /// untagged relay (dev/loopback, or a coordinator with no region config): it
    /// enrolls unconditionally and is only ever the region-blind fallback pick.
    #[arg(long, env = "RELAY_REGION")]
    region: Option<String>,
}

/// How long the drain sequence waits for the coordinator's `DrainAck` before
/// proceeding regardless. A coordinator that is down, or one predating the drain
/// frame, must never wedge shutdown — so this is short and the wait is best-effort.
const DRAIN_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the drain sequence re-checks whether the relay has gone idle. A
/// shutdown path is not latency-critical, so a coarse poll keeps it simple.
const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(250);

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

    // Kept alongside the server identity: a mesh dial presents this same
    // certificate as its TLS client identity (`mesh_client_config`), so a peer
    // relay's acceptor pins exactly what a client would pin from this relay's
    // session responses. Cloned before `server_config` below moves the
    // originals.
    let mesh_cert_chain = cert_chain.clone();
    let mesh_private_key = private_key.clone_key();
    // The same key again, threaded to the coordinator client: it signs the
    // coordinator's enroll proof-of-possession challenge, proving this relay
    // holds the key matching the certificate its Hello presents.
    let identity_key = private_key.clone_key();

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

    // The coordinated-drain seam. On a shutdown signal the drain sequence flips
    // `drain_tx`, the coordinator client sends `Draining` up the control connection,
    // and the coordinator answers `DrainAck` by flipping `drain_acked` — which the
    // drain sequence waits on (bounded). Both are wired into the coordinator client
    // only when a coordinator URL is configured; without one the drain sequence skips
    // the handshake and waits on local idleness alone.
    let has_coordinator = cli.relay_id.is_some() && cli.coordinator_url.is_some();
    let drain_timeout = Duration::from_secs(cli.drain_timeout_secs);
    let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);
    let (drain_acked_tx, mut drain_acked_rx) = tokio::sync::watch::channel(false);
    // The last-applied session set, shared between the coordinator client (which
    // reconciles it on every descriptor push) and the drain sequence (which reads
    // it to tell an assigned-but-not-yet-dialed session from a provably unassigned
    // relay). Trivially empty without a coordinator, so the drain then keys on
    // local slot liveness alone.
    let applied = coordinator_client::AppliedSessions::new();

    // The flight recorder: per-session observability, always recording (cheap,
    // bounded). The sink and identity are optional startup wiring; the sampling
    // tick folds turn counters + link conditions into a row per live session.
    let flight = mesh_state.decision_makers.flight_recorder().clone();
    if let Some(relay_id) = cli.relay_id {
        flight.set_identity(RelayId(relay_id));
    }
    match &cli.flight_dir {
        Some(dir) => {
            tracing::info!(dir = %dir.display(), "flight recordings flush to files");
            flight.set_sink(Arc::new(rally_point_relay::flight_recorder::FileSink::new(
                dir.clone(),
            )));
        }
        None => {
            tracing::info!("no --flight-dir configured; flight recordings are discarded at flush")
        }
    }
    tokio::spawn(rally_point_relay::flight_recorder::run_sampler(
        flight.clone(),
        mesh_state.conditions.clone(),
        Arc::clone(&mesh_state.decision_makers),
        rally_point_relay::flight_recorder::SAMPLE_INTERVAL,
    ));

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

        // The fleet mesh-peer map: the coordinator pushes the currently-enrolled
        // fleet's cert fingerprints down the control connection, the subscriber
        // stores them here, and the mesh acceptor reads them to pin a dialing
        // peer's certificate. Created here so both the accept task (a read handle)
        // and the coordinator subscriber (the writer) share one map; without a
        // coordinator URL it stays empty (dev/static `--mesh-peer`).
        let fleet_peers = coordinator_client::FleetMeshPeers::new();

        // Clone `links_tx` for the accept task; the original stays for the dial
        // tasks below (each clones again per peer).
        tokio::spawn(mesh_edge::run_mesh_accept(
            mesh_accept_rx,
            Arc::clone(&sessions),
            mesh_state.clone(),
            links_tx.clone(),
            fleet_peers.reader(),
            cli.require_mesh_peer_auth,
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
                    // The static dev/loopback path is single-address by nature.
                    peer_addrs: vec![peer.addr],
                    server_name: cli.mesh_server_name.clone(),
                    roots: mesh_roots.clone(),
                    cert_chain: mesh_cert_chain.clone(),
                    key: mesh_private_key.clone_key(),
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
        // Share the decision-maker registry the turn path holds (in `mesh_state`)
        // so a maker created here on a coordinator descriptor is the same one the
        // slot-link and mesh-link tasks feed conditions into and stamp decisions on.
        let mesh_control = mesh_control::MeshControl::new(
            RelayId(our_id),
            mesh_state.decision_makers.clone(),
            mesh_state.presence.clone(),
        )
        // Wire the turn-path handles so a descriptor-driven authority promotion
        // (e.g. the coordinator dropping a crashed former authority) can
        // re-broadcast any synced leave that authority never delivered.
        .with_broadcast(Arc::clone(&sessions), mesh_state.links.clone())
        // Wire the real drop-hold registry so that same promotion skips a slot
        // whose drop is still held undecided, exactly like the presence-driven
        // promotion already does — without this, a descriptor re-push racing a
        // reconnect would decide (and broadcast) a leave for a slot a client is
        // actively returning to.
        .with_drop_holds(mesh_state.drop_holds.clone())
        // Wire the real provisional-admission registry so a descriptor
        // applying here clears the provisional mark client admission may have
        // left on the session (`server.rs`), rather than leaving it to expire
        // on a relay the descriptor already covers.
        .with_provisional(mesh_state.provisional.clone());

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
                cert_chain: mesh_cert_chain,
                key: mesh_private_key,
                sessions: Arc::clone(&sessions),
                mesh: mesh_state.clone(),
                links: links_tx.clone(),
                redial_delay: mesh_edge::MESH_REDIAL_DELAY,
            };
            tokio::spawn(mesh_dialer::run_mesh_dialer(
                dialer_config,
                mesh_control.desired_peers(),
            ));

            let (advertise_addr, advertise_addrs) =
                config::resolve_advertise_addrs(&cli.advertise_addr, cli.listen);
            // The hello carries our client-edge leaf cert so the coordinator
            // can hand it to clients in session responses — they pin exactly
            // this cert to connect — the full `[MIN_SUPPORTED, CURRENT]`
            // protocol window, so a newer relay downgrades to an older
            // coordinator's version instead of being refused, and the complete
            // advertised address set (empty for a single-address relay), so a
            // dual-stack relay's consumers can pick a family.
            let mut relay_hello = RelayHello::new(
                RelayId(our_id),
                advertise_addr,
                ProtocolVersion::CURRENT,
                ca.as_ref().to_vec(),
            )
            .with_min_protocol(ProtocolVersion::MIN_SUPPORTED)
            .with_relay_addrs(advertise_addrs);
            if let Some(region) = &cli.region {
                relay_hello = relay_hello.with_region(RegionId(region.clone()));
            }
            tracing::info!(
                relay_id = our_id,
                advertise = %advertise_addr,
                "enrolling with coordinator over the control connection",
            );

            // The notice notifier: the leave sites and the desync comparator fire
            // a notice onto this channel (a departure or a desync), and the
            // coordinator subscriber drains it up the control connection. Only
            // wired when a coordinator is configured; a standalone relay leaves
            // the notifier unset (firing is then a no-op).
            let (notices_tx, notices_rx) = tokio::sync::mpsc::unbounded_channel();
            mesh_state.decision_makers.set_notice_notifier(notices_tx);

            // The provisional-admission sweep's arming signal: `true` only
            // while the control connection below is actually established (see
            // `coordinator_client::run_descriptor_subscriber`'s doc on
            // `control_connected`). Local to this block, so dev/static mode
            // (no coordinator URL) never constructs it and never spawns the
            // sweep task at all — the simplest possible "never arms".
            let (control_connected_tx, control_connected_rx) = tokio::sync::watch::channel(false);

            tokio::spawn(coordinator_client::run_descriptor_subscriber(
                coordinator_url,
                relay_hello,
                identity_key,
                cli.coordinator_secret.clone(),
                mesh_control.clone(),
                Arc::clone(&sessions),
                applied.clone(),
                fleet_peers,
                notices_rx,
                drain_rx.clone(),
                drain_acked_tx.clone(),
                control_connected_tx,
            ));
            tokio::spawn(provisional::run_sweep(
                mesh_state.provisional.clone(),
                Arc::clone(&sessions),
                control_connected_rx,
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

    // Keep serving during the drain: existing sessions' clients still connect and
    // play while we wind down, so the server runs on its own task rather than being
    // awaited inline. Clone the roster first so the drain path can watch local slot
    // liveness after `sessions` moves into the server.
    let sessions_for_drain = Arc::clone(&sessions);
    let mut server = tokio::spawn(server::run(
        cli.listen,
        server_config,
        registry,
        sessions,
        mesh_state,
        mesh_accept,
    ));

    tokio::select! {
        result = &mut server => {
            // The server ended on its own — a bind failure or a fatal serve error.
            result
                .context("relay server task panicked")?
                .context("relay server ended with an error")?;
        }
        _ = shutdown_signal() => {
            drain_and_exit(
                has_coordinator,
                &drain_tx,
                &mut drain_acked_rx,
                &sessions_for_drain,
                &applied,
                &flight,
                drain_timeout,
            )
            .await;
            // Started sessions still alive here are deliberately abandoned: the
            // coordinator-mediated failover re-homes their clients onto a live relay.
            tracing::info!("drain complete; exiting");
        }
    }
    Ok(())
}

/// Resolves when the process receives a shutdown signal: `Ctrl-C` everywhere, plus
/// `SIGTERM` on Unix — production runs on Linux/Fargate, which stops a task by
/// sending `SIGTERM` (then `SIGKILL` after `stopTimeout`), so the drain must key on
/// `SIGTERM`, not just an interactive interrupt.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing a SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

/// The coordinated-drain sequence, run once a shutdown signal arrives while the
/// server keeps serving: ask the coordinator to stop assigning us new sessions,
/// wait (bounded) for its `DrainAck`, then wait for the relay to go idle before
/// returning so the caller can exit.
///
/// **Idle predicate: no local slot held AND an empty applied descriptor set**
/// ([`coordinator_client::drained_idle`]). The DrainAck contract makes the second
/// half sound: the coordinator pushes our current descriptor set before the ack, so
/// an empty applied set at ack time means we are *provably unassigned* — the
/// truly-idle scale-in case exits immediately (well under a second). A non-empty
/// set names sessions whose clients may not have dialed yet (a session committed
/// just before our drain mark), so we wait: they dial, register slots, and the wait
/// ends when they finish. Slot liveness alone would miss exactly that window and
/// strand those clients dialing a dead relay pre-start, which the client driver
/// cannot recover (it escalates to re-home only after `SessionStart`). The cost of
/// the descriptor half is a *bounded* wait: a session whose clients never dial, or
/// one a peer relay still serves after our players left, holds its descriptor here
/// until the drain timeout — under Fargate's stopTimeout — and is then, like any
/// session still running at the deadline, deliberately abandoned to the
/// coordinator-mediated failover.
async fn drain_and_exit(
    has_coordinator: bool,
    drain_tx: &tokio::sync::watch::Sender<bool>,
    drain_acked_rx: &mut tokio::sync::watch::Receiver<bool>,
    sessions: &Sessions,
    applied: &coordinator_client::AppliedSessions,
    flight: &rally_point_relay::flight_recorder::FlightRecorder,
    drain_timeout: Duration,
) {
    tracing::info!("shutdown signal received; beginning coordinated drain");

    if has_coordinator {
        // Ask the coordinator to stop assigning us new sessions.
        let _ = drain_tx.send(true);
        // Wait for the DrainAck, but never let a down/older coordinator wedge us.
        match tokio::time::timeout(DRAIN_ACK_TIMEOUT, drain_acked_rx.changed()).await {
            Ok(Ok(())) => tracing::info!("coordinator acknowledged drain"),
            Ok(Err(_)) => tracing::warn!("drain-ack channel closed before an ack; proceeding"),
            Err(_) => tracing::warn!("timed out waiting for a drain ack; proceeding"),
        }
    } else {
        tracing::info!("no coordinator configured; skipping the drain handshake");
    }

    // Wait until drained-idle, bounded by the drain timeout.
    let deadline = tokio::time::Instant::now() + drain_timeout;
    loop {
        if coordinator_client::drained_idle(sessions, applied) {
            tracing::info!("relay idle; no local slots held and no session assigned");
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            tracing::warn!(
                "drain timeout reached with sessions still live or assigned; abandoning them to failover",
            );
            break;
        }
        tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
    }

    // Flush whatever flight recordings remain — sessions that never reached
    // their ordinary close-time flush (still running at the deadline, or ended
    // by a descriptor removal with no local slot to close). Bounded by its own
    // deadline inside the drain budget: the rings are size-capped and live
    // sessions bounded, so the volume always fits DRAIN_FLUSH_TIMEOUT, which
    // nests under the 90s drain timeout and Fargate's 120s stopTimeout — the
    // size caps exist precisely so this flush can never wedge the shutdown.
    flight
        .flush_all(rally_point_relay::flight_recorder::DRAIN_FLUSH_TIMEOUT)
        .await;
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}
