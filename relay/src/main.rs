//! Entry point for the validating netcode v2 relay.
//!
//! Thin wiring: parses CLI args, delegates to [`rally_point_relay::config`] for
//! the real logic (cert/registry/mesh-peer parsing), and drives
//! [`rally_point_relay::server::run`]. The binary adds no logic of its own —
//! every failure mode is in the library where it's testable.
//!
//! The mesh edge's connection half is wired here: peer-relay connections that
//! arrive on the mesh ALPN are dispatched to [`mesh::edge::run_mesh_accept`], and
//! each `--mesh-peer` dials via [`mesh::edge::run_mesh_dial`] when the
//! [`should_dial_mesh`] tie-break says this relay is the lower id. Each
//! established link surfaces `(peer id, MeshCommand sender)`, which the binary
//! collects into a [`mesh::control::MeshControl`] — the Join source that turns a
//! coordinator `SessionDescriptor` into targeted `Join`/`Leave` on the link to
//! each session peer. The descriptor *source* is wired too: with `--coordinator-url`
//! set, a [`coordinator::client`] task holds a control connection open to the
//! coordinator and drives the Join source from the descriptor sets it pushes.
//! Without it (pure dev/loopback), the registry fills as links establish and tests
//! drive `Join` directly.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use color_eyre::Result;
use color_eyre::eyre::Context;
use rally_point_proto::control::{RegionId, RelayHello};
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::ProtocolVersion;
use rally_point_relay::auth::{Registry, RegistryReader, SharedRegistry};
use rally_point_relay::config::{
    self, generate_dev_tenant_key, load_cert, self_signed_cert, tenant_key_from_pubkey,
};
use rally_point_relay::coordinator;
use rally_point_relay::coordinator::idle_exit;
use rally_point_relay::coordinator::region_ping;
use rally_point_relay::mesh;
use rally_point_relay::mesh::control;
use rally_point_relay::mesh::dialer;
use rally_point_relay::mesh::edge;
use rally_point_relay::routing::Sessions;
use rally_point_relay::server;
use rally_point_relay::session::provisional;
use rally_point_transport::noq;

mod cli;
mod shutdown;

use cli::Cli;

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

    let has_coordinator = cli.relay_id.is_some() && cli.coordinator_url.is_some();

    // The tenant-key registry the client edge verifies tokens against. A
    // coordinator-driven relay starts EMPTY and lets the coordinator's `TenantKeys`
    // push (which lands before the first session descriptor) fill it, so no tenant
    // key material lives in the relay's environment; `--tenant-pubkey` is ignored
    // there, and no dev keypair is generated. A dev/static relay (no coordinator)
    // keeps a fixed registry seeded from `--tenant-pubkey`, or a generated dev
    // keypair whose halves are logged for loopback token minting.
    if tenant_pubkey_ignored(has_coordinator, cli.tenant_pubkey.is_some()) {
        tracing::warn!(
            "ignoring --tenant-pubkey / RELAY_TENANT_PUBKEY in coordinator mode: the \
             coordinator pushes tenant verifying keys over the control connection",
        );
    }
    let (registry_reader, shared_registry) = if has_coordinator {
        let shared = SharedRegistry::new(Registry::new());
        (shared.reader(), Some(shared))
    } else {
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
        let reader = RegistryReader::fixed(Arc::new(config::registry_from_tenant_key(&tenant_key)));
        (reader, None)
    };

    let sessions: Sessions = Arc::default();
    let mesh_state = mesh::new_mesh_state();

    // Shared observable of the coordinator control connection: the coordinator
    // client's writer refreshes its outbound queue depths and its reader refreshes the
    // descriptor apply lag; the task-stats reporter logs both. Created up front so all
    // share one handle; it stays all-zero without a coordinator connection (nothing
    // writes it).
    let control_conn_stats = coordinator::client::ControlConnStats::new();
    // Obtain the recorder handle before spawning task stats so its
    // relay-lifetime work totals can be sampled alongside Docker CPU. The
    // remaining recorder identity/sink/sampler wiring stays below.
    let flight = mesh_state.decision_makers.flight_recorder().clone();

    // Self-reported Fargate task resources: a no-op outside Fargate (see the
    // module doc), so this is safe to call unconditionally in dev/loopback too.
    rally_point_relay::observability::task_stats::spawn_if_enabled(
        cli.task_stats_interval_secs,
        cli.relay_id,
        Arc::clone(&sessions),
        mesh_state.turn_ring.clone(),
        control_conn_stats.clone(),
        flight.clone(),
    );

    // The coordinated-drain seam. On a shutdown signal the drain sequence flips
    // `drain_tx`, the coordinator client sends `Draining` up the control connection,
    // and the coordinator answers `DrainAck` by flipping `drain_acked` — which the
    // drain sequence waits on (bounded). Both are wired into the coordinator client
    // only when a coordinator URL is configured; without one the drain sequence skips
    // the handshake and waits on local idleness alone.
    let drain_timeout = Duration::from_secs(cli.drain_timeout_secs);
    let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);
    let (drain_acked_tx, mut drain_acked_rx) = tokio::sync::watch::channel(false);
    // The last-applied session set, shared between the coordinator client (which
    // reconciles it on every descriptor push) and the drain sequence (which reads
    // it to tell an assigned-but-not-yet-dialed session from a provably unassigned
    // relay). Trivially empty without a coordinator, so the drain then keys on
    // local slot liveness alone.
    let applied = coordinator::client::AppliedSessions::new();

    // The flight recorder: per-session observability, always recording (cheap,
    // bounded). The sink and identity are optional startup wiring; the sampling
    // tick folds turn counters + link conditions into a row per live session.
    //
    // The flight-shipment channel: a CoordinatorSink installed below hands flushed
    // blobs to the coordinator control connection through it, and the subscriber
    // task drains the receiver. Created here — ahead of both the sink install and
    // the subscriber spawn — so the same channel spans them. Only wired at both
    // ends when a coordinator-connected relay installs the CoordinatorSink;
    // otherwise the receiver is dropped or idles unused.
    let (flight_tx, flight_rx) = tokio::sync::mpsc::channel(
        rally_point_relay::observability::flight_recorder::FLIGHT_SHIP_QUEUE,
    );
    if let Some(relay_id) = cli.relay_id {
        flight.set_identity(RelayId(relay_id));
    }
    match &cli.flight_dir {
        Some(dir) => {
            tracing::info!(dir = %dir.display(), "flight recordings flush to files");
            flight.set_sink(Arc::new(
                rally_point_relay::observability::flight_recorder::FileSink::new(dir.clone()),
            ));
        }
        None if has_coordinator => {
            tracing::info!("flight recordings ship to the coordinator over the control connection");
            flight.set_sink(Arc::new(
                rally_point_relay::observability::flight_recorder::CoordinatorSink::new(flight_tx),
            ));
        }
        None => {
            tracing::info!("no --flight-dir configured; flight recordings are discarded at flush")
        }
    }
    tokio::spawn(
        rally_point_relay::observability::flight_recorder::run_sampler(
            flight.clone(),
            mesh_state.conditions.clone(),
            Arc::clone(&mesh_state.decision_makers),
            rally_point_relay::observability::flight_recorder::SAMPLE_INTERVAL,
        ),
    );

    match cli.silent_slot_window_secs {
        0 => tracing::info!(
            "silent-slot eviction disabled; a client that stops producing turns will stall its session",
        ),
        secs => {
            tracing::info!(window_secs = secs, "silent-slot eviction enabled");
            tokio::spawn(rally_point_relay::consensus::run_silence_watch(
                Arc::clone(&mesh_state.decision_makers),
                Arc::clone(&sessions),
                Duration::from_secs(secs),
                rally_point_relay::consensus::SILENCE_CHECK_INTERVAL,
            ));
        }
    }

    // A read handle onto the coordinator control-connection state, hoisted out of
    // the coordinator-config block so the idle self-exit can watch it. Populated
    // with a clone of the control-connected receiver only when a coordinator is
    // configured; left `None` otherwise, which is exactly what makes a relay with
    // no coordinator never self-exit.
    let mut idle_exit_connected_rx: Option<tokio::sync::watch::Receiver<bool>> = None;

    // The mesh-edge connection half. When a relay-id is configured, spawn the
    // accept drain (peer relays dialing us arrive on `mesh_accept`) and one
    // dial task per `--mesh-peer` (we dial the peers we're lower-id than).
    // Each established link comes back on `links_rx` as `(peer id, local
    // generation, MeshCommand sender)` — the peer id targets joins and the
    // generation rejects late registration from an older physical link.
    let mesh_accept = if let Some(our_id) = cli.relay_id {
        let (mesh_accept_tx, mesh_accept_rx) = tokio::sync::mpsc::channel::<noq::Connection>(8);
        let (links_tx, mut links_rx) = tokio::sync::mpsc::channel::<mesh::MeshLinkHandle>(8);

        // The fleet mesh-peer map: the coordinator pushes the currently-enrolled
        // fleet's cert fingerprints down the control connection, the subscriber
        // stores them here, and the mesh acceptor reads them to pin a dialing
        // peer's certificate. Created here so both the accept task (a read handle)
        // and the coordinator subscriber (the writer) share one map; without a
        // coordinator URL it stays empty (dev/static `--mesh-peer`).
        let fleet_peers = coordinator::client::FleetMeshPeers::new();

        // The region ping-beacon targets + measured-round-trip cache. The
        // coordinator pushes the region beacons down the control connection, the
        // subscriber stores them into `region_targets`, and `run_region_ping`
        // measures a backbone round-trip to each — folding the medians into
        // `region_rtt_cache`, which the heartbeat reports back up. Both stay empty
        // for a relay with no coordinator URL: no targets ever arrive, and the ping
        // loop below is spawned only inside the coordinator-driven block.
        let region_targets = region_ping::RegionPingTargets::new();
        let region_rtt_cache = region_ping::RegionRttCache::new();

        // Clone `links_tx` for the accept task; the original stays for the dial
        // tasks below (each clones again per peer).
        tokio::spawn(edge::run_mesh_accept(
            mesh_accept_rx,
            Arc::clone(&sessions),
            mesh_state.clone(),
            links_tx.clone(),
            fleet_peers.reader(),
            mesh_peer_auth_required(cli.require_mesh_peer_auth, has_coordinator),
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
                let dial = edge::MeshDial {
                    our_id: RelayId(our_id),
                    peer_id: peer.id,
                    // The static dev/loopback path is single-address by nature.
                    peer_addrs: vec![peer.addr],
                    server_name: cli.mesh_server_name.clone(),
                    roots: mesh_roots.clone(),
                    cert_chain: mesh_cert_chain.clone(),
                    key: mesh_private_key.clone_key(),
                };
                tokio::spawn(edge::run_mesh_dial(dial, sessions, mesh, links_tx));
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
        let mesh_control = control::MeshControl::new(
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
        .with_provisional(mesh_state.provisional.clone())
        // Wire the relay-wide session gates, so the descriptor retirement this
        // control plane performs closes the same ingress boundary the turn
        // path, mesh dispatch, and client admission run through.
        .with_gates(mesh_state.gates.clone())
        // Wire the full turn-path state, so a descriptor applying here drains
        // the provisional-turn pen through the ordinary forward path — the
        // freshly created maker's seeded decided leaves then fence a departed
        // slot's held turns instead of letting them reach survivors.
        .with_turn_path(mesh_state.clone());
        // The flight recorder's create-on-first-touch consults the same gates,
        // so a retired session's straggling event cannot begin a recording.
        mesh_state
            .decision_makers
            .flight_recorder()
            .set_gates(mesh_state.gates.clone());

        // The descriptor source. When a coordinator URL is configured, hold a
        // control connection open to it and apply the session-descriptor sets it
        // pushes through the Join source — the production path that drives
        // `Join`/`Leave`. Without a URL (pure dev/loopback with `--mesh-peer`),
        // the registry still fills as links establish and tests drive `Join` on
        // the command senders directly.
        if let Some(coordinator_url) = cli.coordinator_url.clone() {
            // Coordinator-managed: every session's descriptor is expected, so
            // arm the provisional-turn pen — the turn funnel holds a
            // pre-descriptor client's turns until the descriptor proves its
            // slot current (or seeds it departed, fencing them). A standalone
            // dev/loopback relay has no descriptor source and leaves the pen
            // disarmed, keeping its descriptor-less sessions flowing.
            mesh_state.provisional_turns.arm();
            // The on-demand dialer: establish (and re-establish) mesh links to the
            // peers the coordinator's descriptors name, driven by the Join source's
            // desired-peer set. This is the production dial path — the static
            // `--mesh-peer` dials above are dev/loopback, where no coordinator
            // pushes topology.
            let dialer_config = dialer::DialerConfig {
                our_id: RelayId(our_id),
                server_name: cli.mesh_server_name.clone(),
                roots: mesh_roots.clone(),
                cert_chain: mesh_cert_chain,
                key: mesh_private_key,
                sessions: Arc::clone(&sessions),
                mesh: mesh_state.clone(),
                links: links_tx.clone(),
                redial_delay: edge::MESH_REDIAL_DELAY,
            };
            tokio::spawn(dialer::run_mesh_dialer(
                dialer_config,
                mesh_control.desired_peers(),
            ));

            let (advertise_addr, advertise_addrs) =
                config::resolve_advertise_addrs(&cli.advertise_addr, cli.listen);
            // The hello carries our client-edge leaf cert so the coordinator
            // can hand it to clients in session responses — they pin exactly
            // this cert to connect — the `[MIN_SUPPORTED, CURRENT]` protocol
            // window the coordinator negotiates against before enrolling (with
            // CURRENT above MIN_SUPPORTED, this build advertises support for both
            // the current version and the older one it still interoperates with),
            // and the complete advertised address set (empty for a single-address
            // relay), so a dual-stack relay's consumers can pick a family.
            let mut relay_hello = RelayHello::new(
                RelayId(our_id),
                advertise_addr,
                ProtocolVersion::CURRENT,
                ca.as_ref().to_vec(),
            )
            .with_min_protocol(ProtocolVersion::MIN_SUPPORTED)
            .with_relay_addrs(advertise_addrs)
            // This build implements the home-side drop-finalization handshake
            // (and strips unproven dropped counts at every ingress); the
            // coordinator enables the feature per session only when every
            // assigned relay advertises it, and never mixes advertising and
            // non-advertising relays in one session.
            .with_capabilities(vec![
                rally_point_proto::control::CAPABILITY_FINALIZED_DROP_V1.to_owned(),
            ]);
            if let Some(region) = &cli.region {
                relay_hello = relay_hello.with_region(RegionId(region.clone()));
            }
            // Carry the one-time enroll token to a ledger-backed coordinator, which
            // binds this id to the hello's certificate at first enroll. Absent
            // against a coordinator with no ledger, and unnecessary once the
            // certificate is bound (a reconnect authorizes on the certificate).
            if let Some(token) = &cli.enroll_token {
                relay_hello = relay_hello.with_enroll_token(token.clone());
            }
            // This process's own identity, drawn once here and repeated on every
            // hello the reconnect loop sends. It lets the coordinator tell a redial
            // (our retained per-session state is intact) from a restart (it is gone),
            // which is what bounds how far back a load-state snapshot from us can
            // vouch. Left unstamped if the system RNG refuses, which the coordinator
            // reads as no continuity — conservative, and the load-state read is the
            // only thing affected.
            if let Some(boot_id) = coordinator::client::new_boot_id() {
                relay_hello = relay_hello.with_boot_id(boot_id);
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
            // `coordinator::client::run_descriptor_subscriber`'s doc on
            // `control_connected`). Local to this block, so dev/static mode
            // (no coordinator URL) never constructs it and never spawns the
            // sweep task at all — the simplest possible "never arms".
            let (control_connected_tx, control_connected_rx) = tokio::sync::watch::channel(false);
            // Hand the idle self-exit a read handle onto the same signal: a relay
            // that loses this control connection and holds no session self-reaps
            // once both have held for the exit threshold.
            idle_exit_connected_rx = Some(control_connected_rx.clone());

            tokio::spawn(coordinator::client::run_descriptor_subscriber(
                coordinator::client::EnrollConfig {
                    coordinator_url,
                    bootstrap_secret: cli.coordinator_secret.clone(),
                    relay_hello,
                    identity_key,
                },
                coordinator::client::ControlApplyTargets {
                    control: mesh_control.clone(),
                    applied: applied.clone(),
                    fleet: fleet_peers,
                    verifying_keys: shared_registry
                        .clone()
                        .expect("coordinator mode constructs a shared tenant-key registry"),
                    region_targets: region_targets.clone(),
                    drain_acked: drain_acked_tx.clone(),
                },
                coordinator::client::OutboundQueues::new(notices_rx, flight_rx, control_conn_stats),
                coordinator::client::HeartbeatSources {
                    sessions: Arc::clone(&sessions),
                    decision_makers: Arc::clone(&mesh_state.decision_makers),
                    region_rtt_cache: region_rtt_cache.clone(),
                    load_fence: mesh_state.load_fence.clone(),
                },
                drain_rx.clone(),
                control_connected_tx,
            ));
            tokio::spawn(provisional::run_sweep(
                mesh_state.provisional.clone(),
                Arc::clone(&sessions),
                Arc::clone(&mesh_state.decision_makers),
                control_connected_rx,
            ));
            // Measure backbone round-trips to the coordinator's region beacons and
            // report the medians up the heartbeat. Spawned only here, inside the
            // coordinator-driven block, so a static/dev relay (no coordinator, no
            // beacon targets) never pings. The relay's own region is skipped.
            tokio::spawn(region_ping::run_region_ping(
                region_targets,
                region_rtt_cache,
                cli.region.clone().map(RegionId),
            ));
        }

        tokio::spawn(async move {
            while let Some((peer_id, generation, command_tx)) = links_rx.recv().await {
                let _ = mesh_control.register_link(peer_id, generation, command_tx);
            }
        });

        Some(mesh_accept_tx)
    } else {
        None
    };

    // Keep serving during the drain: existing sessions' clients still connect and
    // play while we wind down, so the server runs on its own task rather than being
    // awaited inline. Clone the roster first so the drain path (and the idle
    // self-exit) can watch local slot liveness after `sessions` moves into the
    // server.
    let sessions_for_drain = Arc::clone(&sessions);
    let sessions_for_idle = Arc::clone(&sessions);
    let mut server = tokio::spawn(server::run(
        cli.listen,
        server_config,
        registry_reader,
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
        _ = shutdown::shutdown_signal() => {
            shutdown::drain_and_exit(
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
        report = idle_exit::run(
            sessions_for_idle,
            idle_exit_connected_rx,
            cli.idle_unenrolled_exit_secs,
        ) => {
            // Zero sessions and no coordinator control connection held past the exit
            // threshold: the coordinator vanished, so exit and let the task platform
            // reclaim the task. This one line is what distinguishes a self-reap from
            // a crash in the task logs.
            tracing::info!(
                idle_secs = report.idle_for.as_secs(),
                "idle with no coordinator control connection past the exit threshold; exiting",
            );
            // Zero sessions is the precondition, so there is nothing to drain and no
            // coordinator to exchange a drain with — just flush any pending flight
            // recordings before the process goes away.
            shutdown::flush_flight_recordings(&flight).await;
        }
    }
    Ok(())
}

fn init_tracing() {
    use std::io::IsTerminal;

    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // Color only when stdout is a real terminal: container logs (docker, CloudWatch)
    // otherwise fill with raw ANSI escape sequences.
    fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal())
        .init();
}

/// Whether the mesh accept path must fail closed on peer identity. Always true
/// for a coordinator-driven relay: it will receive a fleet-peer push and must
/// never serve an unauthenticated mesh accept, not even during the startup gap
/// before the first push lands. Otherwise it is on only when the operator passed
/// `--require-mesh-peer-auth` — the dev/static `--mesh-peer` path, which has no
/// coordinator to ever populate a fleet set, stays default-off.
fn mesh_peer_auth_required(require_flag: bool, has_coordinator: bool) -> bool {
    require_flag || has_coordinator
}

/// Whether a supplied `--tenant-pubkey` is ignored. In coordinator mode the tenant
/// verifying keys arrive over the control connection, so a statically pinned pubkey
/// has no role and is ignored (with a warning); a dev/static relay (no coordinator)
/// uses it. `true` only when the coordinator drives the relay *and* a pubkey was
/// supplied — the case that warrants the warning.
fn tenant_pubkey_ignored(has_coordinator: bool, tenant_pubkey_supplied: bool) -> bool {
    has_coordinator && tenant_pubkey_supplied
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_coordinator_driven_relay_always_requires_mesh_peer_auth() {
        // A relay with both a relay id and a coordinator URL (has_coordinator) will
        // receive fleet-peer pushes, so it fails closed whether or not the operator
        // set the flag — closing the boot-to-first-push window an unset flag left open.
        assert!(mesh_peer_auth_required(false, true));
        assert!(mesh_peer_auth_required(true, true));
    }

    #[test]
    fn a_dev_static_relay_follows_the_flag() {
        // No coordinator: the empty fleet map stays unenforced unless the operator
        // opts in with --require-mesh-peer-auth.
        assert!(!mesh_peer_auth_required(false, false));
        assert!(mesh_peer_auth_required(true, false));
    }

    #[test]
    fn coordinator_mode_ignores_a_supplied_tenant_pubkey() {
        // A coordinator-driven relay receives its tenant verifying keys over the
        // control connection, so a pinned --tenant-pubkey is ignored (and warned
        // about) rather than seeding a static registry.
        assert!(tenant_pubkey_ignored(true, true));
        // No pubkey supplied: nothing to ignore, so no warning.
        assert!(!tenant_pubkey_ignored(true, false));
    }

    #[test]
    fn dev_static_mode_uses_a_supplied_tenant_pubkey() {
        // With no coordinator, --tenant-pubkey seeds the fixed registry — it is not
        // ignored, whether or not one is supplied.
        assert!(!tenant_pubkey_ignored(false, true));
        assert!(!tenant_pubkey_ignored(false, false));
    }
}
