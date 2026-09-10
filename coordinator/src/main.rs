//! Entry point for the multi-tenant netcode v2 coordinator.
//!
//! Thin wiring: parses CLI args, builds the coordinator's shared state, and
//! serves the HTTP control-plane API from [`rally_point_coordinator::api`].
//! The binary adds no logic of its own — every failure mode is in the library
//! where it's testable, mirroring the relay binary.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use color_eyre::eyre::{Context, Result, eyre};
use rally_point_coordinator::api::{self, ControlAuth, CoordinatorState};
use rally_point_coordinator::ledger::RelayLedger;
use rally_point_coordinator::lifecycle::Lifecycle;
use rally_point_coordinator::provision::{
    EcsConfig, EcsProvisioner, ProcessConfig, ProcessProvisioner, ProvisionConfig, ProvisionLoop,
    Provisioner, WarmTargets,
};
use rally_point_coordinator::session::SessionSetup;
use rally_point_coordinator::tenant::NotifyConfig;
use rally_point_coordinator::{
    acme, flight_store, metrics, notify, pair_rtts, regions, registry, session, tenant,
    tenant_config,
};
use rally_point_proto::control::{RegionId, TenantId};
use rally_point_proto::token::KeyId;

mod cli;
use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    init_tracing();

    let cli = Cli::parse();
    tracing::info!(listen = %cli.listen, "rally-point coordinator starting");

    // Exactly one launch substrate may be configured. Clap already refuses both
    // (`--provision-ecs-config` conflicts with `--provision-relay-bin`); this is
    // the single flag that turns the provisioning loop — and its create-hold gate —
    // on, whichever substrate backs it.
    let provisioning_enabled =
        cli.provision_relay_bin.is_some() || cli.provision_ecs_config.is_some();

    // Load the region config if one was given. Fail startup on an invalid file:
    // a coordinator that cannot trust its region list would mis-place or wrongly
    // refuse relays. No `--regions` = an empty config, region behavior dormant.
    let regions = match &cli.regions {
        Some(path) => {
            let config = regions::RegionsConfig::load(path)
                .with_context(|| format!("loading region config {}", path.display()))?;
            tracing::info!(
                path = %path.display(),
                count = config.regions().len(),
                "loaded region config",
            );
            config
        }
        None => regions::RegionsConfig::default(),
    };

    // Tenant sources are mutually exclusive (clap enforces `--tenants` conflicts
    // with `--dev-tenant`). With neither, no tenants are enrolled and every
    // tenant request is refused — a valid, if inert, coordinator.
    let tenants = tenant::new_store();
    if cli.dev_tenant {
        enroll_dev_tenant(&tenants, &cli)?;
    } else if let Some(path) = &cli.tenants {
        let config = tenant_config::load(path)
            .with_context(|| format!("loading tenant registry {}", path.display()))?;
        tenant_config::enroll_all(&tenants, &config, |name| std::env::var(name).ok())
            .context("enrolling tenants from the registry")?;
        tracing::info!(
            path = %path.display(),
            count = config.len(),
            "loaded tenant registry",
        );
    }

    // The shared warm-demand store: written by `POST /regions/warm` and by a
    // hold-until-ready create, read by the reconcile loop. Built once here and
    // handed (as clones sharing one map) to both the loop and the session setup's
    // provisioning gate, so demand raised on the API side is the demand the loop
    // reconciles. Only meaningful when the loop runs; a coordinator with no loop
    // leaves the store unread.
    let warm = WarmTargets::new();

    // Install the provisioning gate on the setup only when the loop will run (a
    // substrate is configured). Present ⇒ hold-until-ready create is on and the
    // warm endpoint's demand is shared with the loop. Absent ⇒ the setup keeps its
    // dormant gate and every hold-until-ready behavior is off.
    let mut setup = session::SessionSetup::new(registry::new_registry(), tenants)
        .with_session_ceiling(cli.max_sessions)
        .with_finalized_drops(cli.enable_finalized_drops);
    if let Some(ceiling) = cli.max_sessions {
        tracing::info!(ceiling, "global live-session ceiling enabled");
    }
    if cli.enable_finalized_drops {
        tracing::info!("finalized-drop handshake enabled for new capable-cohort sessions");
    }
    if provisioning_enabled {
        setup = setup.with_provision_gate(session::ProvisionGate::provisioning(
            warm.clone(),
            Duration::from_secs(cli.warm_ttl_secs),
            Duration::from_secs(cli.provision_create_hold_secs),
        ));
    }

    // A launched relay presents the same bootstrap secret to open its control
    // connection, so keep a copy before the auth resolution consumes the original.
    let provision_bootstrap_secret = cli.bootstrap_secret.clone();

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

    // Open the provisioned-relay ledger when one is configured. Fail startup if
    // it cannot be opened: a coordinator asked to run in ledger mode must not
    // silently fall back to accepting unprovisioned enrolls.
    let ledger = match &cli.relay_ledger {
        Some(path) => {
            let ledger = rally_point_coordinator::ledger::RelayLedger::open(path)
                .with_context(|| format!("opening the relay ledger at {}", path.display()))?;
            tracing::info!(
                path = %path.display(),
                "relay ledger opened — only provisioned relay ids may enroll",
            );
            Some(std::sync::Arc::new(ledger))
        }
        None => {
            tracing::info!(
                "no --relay-ledger configured; relay id claims are accepted as presented"
            );
            None
        }
    };

    // The backbone-RTT pair table: relays report measured region-pair round-trips on
    // their heartbeats, the coordinator aggregates them here, and `GET /regions` serves
    // them. Seeded from the ledger at startup so last-known values survive a restart or
    // a scale-to-zero; memory-only (still functional within a process lifetime) when no
    // ledger is configured. A read failure is logged and left empty rather than failing
    // startup — the table is informational telemetry, not a serving prerequisite.
    let pair_rtts = pair_rtts::new_store();
    if let Some(ledger) = &ledger {
        match ledger.direction_rtts() {
            Ok(rows) => {
                let count = rows.len();
                pair_rtts.seed(rows);
                tracing::info!(count, "seeded the backbone-RTT table from the ledger");
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "loading backbone RTTs from the ledger failed; starting with an empty table",
                );
            }
        }
    }

    // Load and connect the flight-recorder durable sink when one is configured. Fail
    // startup on a malformed config, an unset credential variable, or an unreachable
    // bucket: a coordinator told to persist recordings but unable to reach its store
    // must not silently drop every one, the same fail-closed posture as the tenant
    // registry. Absent = no store, and shipped recordings are dropped with a
    // rate-limited warn.
    let flight_store = match &cli.flight_store {
        Some(path) => {
            let config = flight_store::load(path)
                .with_context(|| format!("loading flight store config {}", path.display()))?;
            let resolved = config
                .resolve_secrets(|name| std::env::var(name).ok())
                .context("resolving flight store credentials from the environment")?;
            let store = flight_store::S3FlightStore::connect(resolved)
                .await
                .with_context(|| {
                    format!(
                        "connecting to the flight store configured at {}",
                        path.display()
                    )
                })?;
            tracing::info!(path = %path.display(), "flight store configured");
            Some(std::sync::Arc::new(store))
        }
        None => {
            tracing::info!("no --flight-store configured; shipped flight recordings are dropped");
            None
        }
    };

    let lifecycle = Lifecycle::new(setup.clone());
    let notices = notify::new_dedup();
    // Let the lifecycle prune these dedup sets when it removes a session's state,
    // so they don't grow for the process lifetime.
    lifecycle.attach_dedup(notices.clone());

    // Capture the handles the provisioning loop reconciles over before they move
    // into the served state: it shares the same setup, ledger, and region list the
    // API does.
    let provision_setup = setup.clone();
    let provision_ledger = ledger.clone();
    let provision_regions: Vec<RegionId> = regions.regions().iter().map(|r| r.id.clone()).collect();
    // The provisioning loop reads the same pair table the API serves, so it can spot
    // configured pairs still lacking a measurement and bootstrap relays to fill them.
    let provision_pair_rtts = pair_rtts.clone();

    // Clamp the configured token lifetime to the fleet-wide ceiling. The relay
    // retains a retired session's tombstone only long enough to outlast the
    // longest-lived token this constant permits; minting past it would let a
    // stale token re-dial a session after its tombstone was pruned.
    let player_token_lifetime_secs = if cli.player_token_lifetime_secs
        > rally_point_proto::control::MAX_PLAYER_TOKEN_LIFETIME_SECS
    {
        tracing::warn!(
            configured = cli.player_token_lifetime_secs,
            ceiling = rally_point_proto::control::MAX_PLAYER_TOKEN_LIFETIME_SECS,
            "player token lifetime exceeds the fleet ceiling; clamping",
        );
        rally_point_proto::control::MAX_PLAYER_TOKEN_LIFETIME_SECS
    } else {
        cli.player_token_lifetime_secs
    };
    let state = CoordinatorState {
        setup,
        notices,
        lifecycle,
        control_auth,
        hello_timeout: api::HELLO_TIMEOUT,
        liveness_timeout: api::LIVENESS_TIMEOUT,
        regions,
        player_token_lifetime: Duration::from_secs(player_token_lifetime_secs),
        ledger,
        pair_rtts,
        flight_store,
    };

    // Bring up the plaintext metrics listener before the primary serve, when one
    // is configured. It serves Prometheus `/metrics` over a separate, never-TLS,
    // never-published listener reachable only over the box's private sidecar. The
    // bind is awaited here so an occupied port fails startup loudly; the serve
    // itself is spawned so it runs alongside the primary API server. Absent ⇒ no
    // listener and zero behavior change.
    if let Some(metrics_addr) = cli.metrics_listen {
        let metrics_router = metrics::router(state.clone());
        let listener = tokio::net::TcpListener::bind(metrics_addr)
            .await
            .context("binding the metrics listen address")?;
        tracing::info!("coordinator metrics listening on {} (HTTP)", metrics_addr);
        tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, metrics_router.into_make_service()).await {
                tracing::error!(%error, "the metrics listener ended with an error");
            }
        });
    }

    let app = api::router(state);

    // Start the provisioning loop when a substrate is configured. It keeps each
    // region's relay count matched to warm demand; a region with no warm demand
    // idles, so a fleet that nothing has warmed yet is valid and does nothing.
    // Provisioning requires the ledger, so refuse to start without one. The loop is
    // identical whichever substrate backs it — only the provisioner differs.
    if provisioning_enabled {
        let Some(provision_ledger) = provision_ledger else {
            return Err(eyre!(
                "refusing to start: relay provisioning requires --relay-ledger \
                 (COORDINATOR_RELAY_LEDGER); a provisioned relay identity is only sound \
                 when it is minted and bound through the ledger",
            ));
        };
        validate_provision_tick_secs(cli.provision_tick_secs)?;
        let config = ProvisionConfig {
            regions: provision_regions,
            tick_interval: Duration::from_secs(cli.provision_tick_secs),
            launch_deadline: Duration::from_secs(cli.provision_launch_deadline_secs),
            idle_grace: Duration::from_secs(cli.relay_idle_secs),
        };
        tracing::info!(
            regions = config.regions.len(),
            tick_secs = cli.provision_tick_secs,
            launch_deadline_secs = cli.provision_launch_deadline_secs,
            relay_idle_secs = cli.relay_idle_secs,
            "starting the relay provisioning loop",
        );
        if let Some(relay_bin) = cli.provision_relay_bin {
            let coordinator_url = cli
                .provision_coordinator_url
                .unwrap_or_else(|| format!("http://127.0.0.1:{}", cli.listen.port()));
            tracing::info!("provisioning substrate: local relay processes");
            let provisioner = ProcessProvisioner::new(ProcessConfig {
                relay_bin,
                coordinator_url,
                bootstrap_secret: provision_bootstrap_secret,
            });
            spawn_provision_loop(
                config,
                provision_setup,
                provision_ledger,
                warm.clone(),
                provision_pair_rtts.clone(),
                provisioner,
            );
        } else if let Some(ecs_config_path) = cli.provision_ecs_config {
            let ecs_config = EcsConfig::load(&ecs_config_path).with_context(|| {
                format!(
                    "loading ECS provisioner config {}",
                    ecs_config_path.display()
                )
            })?;
            tracing::info!(
                started_by = %ecs_config.started_by,
                aws_regions = ecs_config.regions.len(),
                "provisioning substrate: AWS Fargate (ECS)",
            );
            let provisioner = EcsProvisioner::new(ecs_config).await;
            spawn_provision_loop(
                config,
                provision_setup,
                provision_ledger,
                warm.clone(),
                provision_pair_rtts.clone(),
                provisioner,
            );
        }
    } else {
        tracing::info!("no provisioning substrate configured; the provisioning loop is off");
    }

    // Serve with connect-info so the relay control handler can read each
    // connection's transport-level peer address for the ledger's expected-address
    // check. This presumes the coordinator is directly exposed — a reverse proxy
    // in front of it would replace the peer address with its own.
    //
    // With an ACME domain configured the coordinator terminates TLS itself and
    // obtains/renews its Let's Encrypt certificate in-process; the same router and
    // the same connect-info wiring ride behind the TLS acceptor, which runs the
    // handshake only after the real peer address has been recorded. Absent a
    // domain, it serves plain HTTP — the dev / loopback path.
    if let Some(domain) = cli.acme_domain.clone() {
        let settings = acme::AcmeSettings {
            domain,
            contact: cli
                .acme_contact
                .clone()
                .expect("--acme-contact is required with --acme-domain (clap `requires`)"),
            cache_dir: cli
                .acme_cache
                .clone()
                .expect("--acme-cache is required with --acme-domain (clap `requires`)"),
            staging: cli.acme_staging,
        };
        tracing::info!(
            domain = %settings.domain,
            cache = %settings.cache_dir.display(),
            staging = settings.staging,
            "coordinator TLS enabled; obtaining a Let's Encrypt certificate via ACME TLS-ALPN-01",
        );
        let state = acme::build_state(&settings).context("preparing the ACME certificate cache")?;
        let acceptor = state.axum_acceptor(state.default_rustls_config());
        tokio::spawn(acme::log_certificate_events(state));
        tracing::info!("coordinator API listening on {} (HTTPS)", cli.listen);
        axum_server::bind(cli.listen)
            .acceptor(acceptor)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .context("coordinator API server ended with an error")?;
    } else {
        let listener = tokio::net::TcpListener::bind(cli.listen)
            .await
            .context("binding coordinator listen address")?;
        tracing::info!("coordinator API listening on {}", cli.listen);
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .context("coordinator API server ended with an error")?;
    }
    Ok(())
}

/// Rejects a zero provisioning tick interval before [`ProvisionConfig`] is ever
/// built. `tokio::time::interval` panics on a zero duration, and the
/// provisioning loop runs as a detached task — a panic there kills only
/// provisioning while the API keeps serving, so a misconfigured interval would
/// otherwise fail silent rather than loud. Called only when provisioning is
/// enabled; a coordinator with no provisioning substrate configured never
/// builds an interval from this value at all.
fn validate_provision_tick_secs(secs: u64) -> Result<()> {
    if secs == 0 {
        return Err(eyre!(
            "refusing to start: --provision-tick-secs (COORDINATOR_PROVISION_TICK_SECS) \
             must be greater than zero",
        ));
    }
    Ok(())
}

/// Builds the reconcile loop over the shared coordinator handles and the chosen
/// provisioner, then spawns it. The loop is generic over the substrate, so this is
/// the single construction point both the process and the ECS substrate funnel
/// through — only the provisioner value differs.
fn spawn_provision_loop<P: Provisioner + 'static>(
    config: ProvisionConfig,
    setup: SessionSetup,
    ledger: Arc<RelayLedger>,
    warm: WarmTargets,
    pair_rtts: pair_rtts::PairRttStore,
    provisioner: P,
) {
    let registry = setup.registry().clone();
    let provision_loop = ProvisionLoop::new(
        config,
        registry,
        setup,
        ledger,
        warm,
        pair_rtts,
        provisioner,
    );
    tokio::spawn(provision_loop.run());
}

/// Enrolls the `--dev-tenant` tenant into `tenants`, logging the public
/// (verifying) key so a relay can be seeded with it (`--tenant-pubkey`).
fn enroll_dev_tenant(tenants: &tenant::TenantStore, cli: &Cli) -> Result<()> {
    let kid =
        KeyId::new(cli.kid.clone()).map_err(|e| eyre!("kid too long (max 255 bytes): {e}"))?;
    let tenant_id = TenantId::new(cli.tenant.clone())
        .map_err(|e| eyre!("tenant id too long (max 255 bytes): {e}"))?;

    let verifying_key = match &cli.tenant_key {
        Some(input) => {
            let pkcs8 = read_hex_input(input, "tenant key")?;
            tenant::enroll_from_pkcs8(
                tenants,
                kid,
                tenant_id.clone(),
                tenant::default_bounds(),
                &pkcs8,
            )
            .context("enrolling dev tenant from --tenant-key")?
        }
        None => {
            let generated =
                tenant::enroll_generated(tenants, kid, tenant_id.clone(), tenant::default_bounds())
                    .context("enrolling dev tenant")?;
            tracing::warn!(
                pkcs8_hex = %hex::encode(&generated.pkcs8),
                "generated a dev tenant keypair — pass --tenant-key <pkcs8_hex> to keep the \
                 public key stable across restarts",
            );
            generated.verifying_key
        }
    };

    // Derive and store the dev tenant's inbound-request verifying key (the
    // public half of the app server's client key). Required: inbound request
    // auth fails closed, so a dev tenant with no client key could never mint a
    // session. A pinned seed (`--dev-tenant-client-key`) keeps the app server's
    // key valid across restarts; otherwise a fresh seed is generated and logged
    // for the app server's `SB_RP2_CLIENT_KEY`.
    let client_pubkey = match &cli.dev_tenant_client_key {
        Some(input) => {
            let seed = read_hex_input(input, "dev tenant client key")?;
            tenant::client_pubkey_from_seed(&seed)
                .context("deriving dev tenant client pubkey from --dev-tenant-client-key")?
        }
        None => {
            let seed = tenant::generate_client_key_seed();
            let pubkey = tenant::client_pubkey_from_seed(&seed)
                .expect("a freshly generated 32-byte seed is a valid Ed25519 seed");
            tracing::warn!(
                client_key_seed_hex = %hex::encode(seed),
                "generated a dev tenant client key — set the app server's \
                 SB_RP2_CLIENT_KEY to this seed hex, and pass --dev-tenant-client-key \
                 <seed_hex> to keep it stable across restarts",
            );
            pubkey
        }
    };
    tenant::set_client_pubkeys(tenants, &tenant_id, vec![client_pubkey]);

    // Wire the dev tenant's departure webhook, if configured. `--dev-notify-url`
    // requires `--dev-tenant` (clap), so this only runs for the enrolled tenant.
    if let Some(url) = &cli.dev_notify_url {
        tenant::set_notify(tenants, &tenant_id, Some(NotifyConfig { url: url.clone() }));
        tracing::info!(
            tenant = %cli.tenant,
            url = %url,
            "dev tenant departure webhook configured",
        );
    }

    tracing::info!(
        tenant = %cli.tenant,
        kid = %cli.kid,
        public_key_hex = %hex::encode(verifying_key),
        client_pubkey_hex = %hex::encode(client_pubkey),
        "dev tenant enrolled — feed public_key_hex to the relay's --tenant-pubkey; the app \
         server signs requests with the client key (SB_RP2_CLIENT_KEY)",
    );
    Ok(())
}

/// Resolves a hex-input value to raw bytes: if the value names an existing
/// file, the file's (whitespace-trimmed) contents are the hex; otherwise the
/// value itself is.
fn read_hex_input(input: &str, label: &str) -> Result<Vec<u8>> {
    let hex_str = if std::path::Path::new(input).exists() {
        std::fs::read_to_string(input)
            .map(|contents| contents.trim().to_owned())
            .map_err(|e| eyre!("reading {label} file {input}: {e}"))?
    } else {
        input.to_owned()
    };
    hex::decode(&hex_str).map_err(|e| eyre!("decoding {label} hex: {e}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_provision_tick_is_rejected() {
        // `tokio::time::interval(Duration::ZERO)` panics, and the provisioning loop
        // runs detached, so a zero tick must fail startup rather than reach the loop.
        assert!(validate_provision_tick_secs(0).is_err());
    }

    #[test]
    fn a_nonzero_provision_tick_is_accepted() {
        assert!(validate_provision_tick_secs(1).is_ok());
        assert!(validate_provision_tick_secs(5).is_ok());
    }
}
