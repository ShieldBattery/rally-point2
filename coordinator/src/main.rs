//! Entry point for the multi-tenant netcode v2 coordinator.
//!
//! Thin wiring: parses CLI args, builds the coordinator's shared state, and
//! serves the HTTP control-plane API from [`rally_point_coordinator::api`].
//! The binary adds no logic of its own — every failure mode is in the library
//! where it's testable, mirroring the relay binary.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
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
use rally_point_coordinator::{acme, notify, regions, registry, session, tenant, tenant_config};
use rally_point_proto::control::{RegionId, TenantId};
use rally_point_proto::token::KeyId;

/// Multi-tenant netcode v2 coordinator.
#[derive(Debug, Parser)]
#[command(name = "rally-point-coordinator", version, about)]
struct Cli {
    /// Address to serve the app-server + relay control API on. With
    /// `--acme-domain` set the coordinator terminates TLS here and answers the
    /// ACME TLS-ALPN-01 challenge on this same port, so the host must be publicly
    /// reachable on it (443 in production) at the ACME domain; no port 80 is used.
    #[arg(long, env = "COORDINATOR_LISTEN", default_value_t = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), rally_point_coordinator::DEFAULT_PORT))]
    listen: SocketAddr,

    /// Public hostname the coordinator obtains a Let's Encrypt certificate for and
    /// terminates TLS under. Present ⇒ TLS mode: the coordinator serves HTTPS on
    /// `--listen`, obtaining and renewing its certificate in-process over the ACME
    /// TLS-ALPN-01 challenge. Absent ⇒ plain HTTP, the dev / loopback posture. TLS
    /// terminates in the coordinator by design — relay enrollment checks a control
    /// connection's transport peer address, and a TLS-terminating proxy in front
    /// would replace it.
    #[arg(
        long,
        env = "COORDINATOR_ACME_DOMAIN",
        requires = "acme_contact",
        requires = "acme_cache"
    )]
    acme_domain: Option<String>,

    /// Contact email for the ACME account (a bare address gains a `mailto:` prefix
    /// in code); the CA uses it for expiry and policy notices. Required with
    /// `--acme-domain`.
    #[arg(long, env = "COORDINATOR_ACME_CONTACT")]
    acme_contact: Option<String>,

    /// Directory the ACME account key and issued certificates are persisted to,
    /// created if absent. Required with `--acme-domain`, and a startup failure if
    /// it cannot be created and written: a coordinator that cannot persist its
    /// certificate would re-request one on every start and quickly exhaust the CA's
    /// issuance rate limit.
    #[arg(long, env = "COORDINATOR_ACME_CACHE")]
    acme_cache: Option<std::path::PathBuf>,

    /// Draw certificates from Let's Encrypt's staging directory instead of
    /// production. Staging issues browser-untrusted certificates under far higher
    /// rate limits — for standing a host up without spending production issuance
    /// budget. Only meaningful with `--acme-domain`.
    #[arg(long, env = "COORDINATOR_ACME_STAGING", default_value_t = false)]
    acme_staging: bool,

    /// Shared bootstrap secret a relay must present (`Authorization: Bearer
    /// <secret>`) to open its control connection. Production injects one so a
    /// rogue relay cannot subscribe to another relay's mesh topology. Without it
    /// the coordinator refuses to start unless `--allow-insecure-control` is set.
    #[arg(long, env = "COORDINATOR_BOOTSTRAP_SECRET")]
    bootstrap_secret: Option<String>,

    /// Path to a JSON file listing the placement regions this coordinator allows
    /// (`{"regions": [{"id", "display_name", "beacon", "fallback"}, ...]}`). The
    /// file order is the client's display order. Loaded and validated at startup;
    /// an invalid file (empty list, duplicate id, malformed id, empty field)
    /// fails the coordinator to start. Absent = no regions configured: relay
    /// region tags are refused and every session slot falls back to the
    /// region-blind pick — the dev / loopback posture.
    #[arg(long, env = "COORDINATOR_REGIONS")]
    regions: Option<std::path::PathBuf>,

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

    /// Lifetime, in seconds, of the per-player authorization tokens minted for
    /// each session. A client presents its token to a relay at every
    /// (re)connection — the initial connect, a same-relay reconnect after a
    /// network blip, and a re-home onto a replacement relay — and the relay
    /// rejects one whose expiry has passed at handshake. So the lifetime must
    /// cover the whole span in which a client might still need to (re)connect:
    /// the create→first-connect lead time, plus the longest plausible game, plus
    /// any mid-game reconnect or re-home. Expiry while a connection is already up
    /// is harmless — the token is checked only at handshake, never per-turn — so
    /// an overly generous value costs only how long an abandoned, never-started
    /// session lingers before the never-started reaper retires it. Default 6
    /// hours.
    #[arg(
        long,
        env = "COORDINATOR_PLAYER_TOKEN_LIFETIME_SECS",
        default_value_t = 21600
    )]
    player_token_lifetime_secs: u64,

    /// Path to a JSON tenant registry (`{"tenants": [...]}`) — the production
    /// tenant source. Each entry carries a tenant's id, operational state
    /// (active / suspended / revoked), signing-key `kid`, the NAME of the
    /// environment variable holding its base64 PKCS#8 signing key (so the secret
    /// stays in the deployment's environment, not the file), its inbound-request
    /// verification public keys (one or two, so an app server rotates its
    /// request key with no downtime), an optional webhook URL, and optional
    /// buffer bounds. Loaded and validated at startup; an invalid file — a
    /// malformed field, a duplicate id or kid, an unset signing-key variable —
    /// fails the coordinator to start. Mutually exclusive with the
    /// `--dev-tenant` flags, which enroll one tenant from the command line
    /// instead. Absent, and with no dev tenant, no tenants are configured: every
    /// tenant request is refused — the dev / loopback posture.
    #[arg(long, env = "COORDINATOR_TENANTS", conflicts_with = "dev_tenant")]
    tenants: Option<std::path::PathBuf>,

    /// Enroll a single tenant at startup so `POST /session/create` can mint
    /// tokens without any provisioning flow. Dev/loopback only: the signing key
    /// lives in memory, so a restart regenerates it (invalidating the public
    /// key any relay was seeded with) unless `--tenant-key` pins one.
    #[arg(long, env = "COORDINATOR_DEV_TENANT", default_value_t = false)]
    dev_tenant: bool,

    /// Tenant id the dev tenant enrolls under. Must match the relay's
    /// `--tenant` and the app server's configured tenant.
    #[arg(
        long,
        env = "COORDINATOR_TENANT",
        default_value = "sb-dev",
        requires = "dev_tenant"
    )]
    tenant: String,

    /// Key id (`kid`) naming the dev tenant's signing key in tokens. Must
    /// match the relay's `--kid`.
    #[arg(
        long,
        env = "COORDINATOR_KID",
        default_value = "dev-key-1",
        requires = "dev_tenant"
    )]
    kid: String,

    /// Hex-encoded PKCS#8 Ed25519 keypair for the dev tenant — either a file
    /// path containing the hex or the hex itself. Pins the signing key so the
    /// public key stays stable across coordinator restarts. If absent, a fresh
    /// keypair is generated and both halves are logged (the public for the
    /// relay's `--tenant-pubkey`, the private so it can be pinned next run).
    #[arg(long, env = "COORDINATOR_TENANT_KEY", requires = "dev_tenant")]
    tenant_key: Option<String>,

    /// Hex-encoded raw 32-byte Ed25519 *seed* for the dev tenant's inbound
    /// request-signing key — either a file path containing the hex or the hex
    /// itself. This is the app server's client key (`SB_RP2_CLIENT_KEY`); the
    /// coordinator derives and stores only its public half to verify inbound
    /// `POST /session/create` / `POST /sessions/alive` signatures. Pins it so
    /// the app server's key stays valid across coordinator restarts. If absent,
    /// a fresh seed is generated and logged so it can be fed to the app server
    /// (and pinned next run). Dev-only, same shape as `--tenant-key`.
    #[arg(
        long,
        env = "COORDINATOR_DEV_TENANT_CLIENT_KEY",
        requires = "dev_tenant"
    )]
    dev_tenant_client_key: Option<String>,

    /// Webhook URL the coordinator POSTs game-event notifications (player
    /// departures and desyncs) to for the dev tenant (e.g.
    /// `http://localhost:5555/webhooks/netcode-v2/game-events`, or `https://...` —
    /// the webhook client handles both). Only meaningful with `--dev-tenant`;
    /// unset = game-event notifications off (everything else unchanged). Each POST
    /// is signed with the dev tenant's own Ed25519 key (`x-rp2-timestamp` +
    /// `x-rp2-signature`) — no separate secret to configure.
    #[arg(long, env = "COORDINATOR_DEV_NOTIFY_URL", requires = "dev_tenant")]
    dev_notify_url: Option<String>,

    /// Path to the provisioned-relay ledger's SQLite database (created if
    /// absent). Present ⇒ **ledger mode**: a relay may enroll only under an id
    /// this coordinator minted, presenting its one-time enroll token at first
    /// enroll and its bound certificate on every reconnect; a token-less or
    /// otherwise unauthorized enroll is refused. Absent ⇒ the dev / loopback
    /// posture, where a relay's id claim in its `Hello` is accepted as presented.
    #[arg(long, env = "COORDINATOR_RELAY_LEDGER")]
    relay_ledger: Option<std::path::PathBuf>,

    /// Path to the relay binary the provisioning loop launches. Present ⇒ the loop
    /// runs, minting ids and spawning local relay processes to match each region's
    /// warm demand. Requires `--relay-ledger`: a provisioned relay's identity is
    /// only sound when it is minted and bound through the ledger, so the
    /// coordinator refuses to start a provisioning loop without one. Absent ⇒ the
    /// loop is off (relays are enrolled and managed out of band).
    #[arg(long, env = "COORDINATOR_PROVISION_RELAY_BIN")]
    provision_relay_bin: Option<std::path::PathBuf>,

    /// Path to the ECS/Fargate provisioner config JSON (`started_by` plus one entry
    /// per region mapping it to its AWS region, cluster, task definition, and
    /// `awsvpc` networking). Present ⇒ the provisioning loop launches relays as
    /// Fargate tasks via ECS and resolves each task's public addresses from its
    /// network interface. Mutually exclusive with `--provision-relay-bin` — exactly
    /// one substrate may be configured — and requires `--relay-ledger` for the same
    /// reason the process substrate does. Absent ⇒ the ECS substrate is off.
    #[arg(
        long,
        env = "COORDINATOR_PROVISION_ECS_CONFIG",
        conflicts_with = "provision_relay_bin"
    )]
    provision_ecs_config: Option<std::path::PathBuf>,

    /// Base URL a provisioned relay dials to reach this coordinator, injected into
    /// each launched relay's environment. Defaults to `http://127.0.0.1:<port>` of
    /// the listen address — correct for local process provisioning, where relays
    /// run on the same host. Set it when the coordinator is reachable at another
    /// address.
    #[arg(long, env = "COORDINATOR_PROVISION_COORDINATOR_URL")]
    provision_coordinator_url: Option<String>,

    /// How long, in seconds, a provisioned relay has to enroll before its launch is
    /// abandoned: the lifetime of the one-time enroll token minted for it. A launch
    /// that has not enrolled by then is swept — its task stopped, its id retired —
    /// and a fresh one minted. Default 300.
    #[arg(
        long,
        env = "COORDINATOR_PROVISION_LAUNCH_DEADLINE_SECS",
        default_value_t = 300
    )]
    provision_launch_deadline_secs: u64,

    /// How long, in seconds, an enrolled relay must be continuously session-free
    /// before the provisioning loop may drain it in a scale-down. Default 600.
    #[arg(long, env = "COORDINATOR_RELAY_IDLE_SECS", default_value_t = 600)]
    relay_idle_secs: u64,

    /// How often, in seconds, the provisioning loop reconciles each region's relay
    /// count against warm demand. Default 5.
    #[arg(long, env = "COORDINATOR_PROVISION_TICK_SECS", default_value_t = 5)]
    provision_tick_secs: u64,

    /// TTL, in seconds, of warm demand raised via `POST /regions/warm` or a
    /// hold-until-ready create. A region stays warm this long after each warm; the
    /// app server re-warms before it lapses to hold a region, and stops simply by
    /// going quiet. Comfortably larger than the create-hold cap so a region a
    /// pending create warmed stays warm through the launch. Default 600.
    #[arg(long, env = "COORDINATOR_WARM_TTL_SECS", default_value_t = 600)]
    warm_ttl_secs: u64,

    /// How long, in seconds, `POST /session/create` holds a create naming a region
    /// with no live relay — warming the region and answering `202 provisioning` —
    /// before falling back to region-blind placement. Bounds the wait so a game is
    /// never refused because a region stayed cold. Only meaningful when a
    /// provisioning substrate is configured; with no provisioning loop, create
    /// never holds. Default 75.
    #[arg(
        long,
        env = "COORDINATOR_PROVISION_CREATE_HOLD_SECS",
        default_value_t = 75
    )]
    provision_create_hold_secs: u64,
}

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
    let mut setup = session::SessionSetup::new(registry::new_registry(), tenants);
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

    let state = CoordinatorState {
        setup,
        notices,
        lifecycle,
        control_auth,
        hello_timeout: api::HELLO_TIMEOUT,
        liveness_timeout: api::LIVENESS_TIMEOUT,
        regions,
        player_token_lifetime: Duration::from_secs(cli.player_token_lifetime_secs),
        ledger,
    };

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

/// Builds the reconcile loop over the shared coordinator handles and the chosen
/// provisioner, then spawns it. The loop is generic over the substrate, so this is
/// the single construction point both the process and the ECS substrate funnel
/// through — only the provisioner value differs.
fn spawn_provision_loop<P: Provisioner + 'static>(
    config: ProvisionConfig,
    setup: SessionSetup,
    ledger: Arc<RelayLedger>,
    warm: WarmTargets,
    provisioner: P,
) {
    let registry = setup.registry().clone();
    let provision_loop = ProvisionLoop::new(config, registry, setup, ledger, warm, provisioner);
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
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn player_token_lifetime_defaults_to_six_hours() {
        // With no flag and no env var, the mint lifetime falls back to 6 hours.
        let cli = Cli::parse_from(["rally-point-coordinator"]);
        assert_eq!(cli.player_token_lifetime_secs, 21600);
    }

    #[test]
    fn no_acme_flags_leaves_tls_off() {
        // The default posture is plain HTTP: no domain, so no TLS configuration.
        let cli = Cli::try_parse_from(["rally-point-coordinator"]).expect("no acme flags is valid");
        assert!(cli.acme_domain.is_none());
        assert!(!cli.acme_staging);
    }

    #[test]
    fn acme_domain_requires_contact_and_cache() {
        // A domain names TLS mode but cannot stand alone: the account contact and
        // the certificate cache are both mandatory, enforced by clap `requires`.
        assert!(
            Cli::try_parse_from([
                "rally-point-coordinator",
                "--acme-domain",
                "coord.example.com",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "rally-point-coordinator",
                "--acme-domain",
                "coord.example.com",
                "--acme-contact",
                "ops@example.com",
            ])
            .is_err()
        );
    }

    #[test]
    fn tenants_file_and_dev_tenant_are_mutually_exclusive() {
        // The production registry and the dev single-tenant flags are two ways to
        // configure the same thing, so clap refuses both at once.
        assert!(
            Cli::try_parse_from([
                "rally-point-coordinator",
                "--tenants",
                "tenants.json",
                "--dev-tenant",
            ])
            .is_err(),
            "a registry file and --dev-tenant together must be rejected",
        );

        // Either source alone parses.
        assert!(
            Cli::try_parse_from(["rally-point-coordinator", "--tenants", "tenants.json"]).is_ok(),
            "a registry file alone is valid",
        );
        assert!(
            Cli::try_parse_from(["rally-point-coordinator", "--dev-tenant"]).is_ok(),
            "the dev tenant alone is valid",
        );
    }

    #[test]
    fn acme_domain_with_contact_and_cache_parses() {
        let cli = Cli::try_parse_from([
            "rally-point-coordinator",
            "--acme-domain",
            "coord.example.com",
            "--acme-contact",
            "ops@example.com",
            "--acme-cache",
            "/var/lib/rp2-acme",
        ])
        .expect("a domain with a contact and a cache is a valid TLS configuration");
        assert_eq!(cli.acme_domain.as_deref(), Some("coord.example.com"));
        assert_eq!(cli.acme_contact.as_deref(), Some("ops@example.com"));
        assert!(!cli.acme_staging);
    }
}
