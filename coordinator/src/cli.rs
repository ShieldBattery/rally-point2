//! The coordinator binary's command-line surface: every `--flag` and
//! `COORDINATOR_*` environment variable `main` reads at startup, parsed by clap.
//!
//! `Cli` and its fields are `pub(super)` — `main.rs` is `cli`'s parent module (the
//! crate root) and reads every field directly to build the coordinator's state.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use clap::Parser;

/// Multi-tenant netcode v2 coordinator.
#[derive(Debug, Parser)]
#[command(name = "rally-point-coordinator", version, about)]
pub(super) struct Cli {
    /// Address to serve the app-server + relay control API on. With
    /// `--acme-domain` set the coordinator terminates TLS here and answers the
    /// ACME TLS-ALPN-01 challenge on this same port, so the host must be publicly
    /// reachable on it (443 in production) at the ACME domain; no port 80 is used.
    #[arg(long, env = "COORDINATOR_LISTEN", default_value_t = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), rally_point_coordinator::DEFAULT_PORT))]
    pub(super) listen: SocketAddr,

    /// Address to serve the Prometheus `/metrics` endpoint on, over plain HTTP. A
    /// second, dedicated listener kept off the public control-plane port: it is
    /// meant to be reachable only over the box's private sidecar (a tailnet TCP
    /// forward), never published, so it carries no TLS and no peer-address
    /// connect-info. Absent ⇒ no metrics listener and zero behavior change.
    #[arg(long, env = "COORDINATOR_METRICS_LISTEN")]
    pub(super) metrics_listen: Option<SocketAddr>,

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
    pub(super) acme_domain: Option<String>,

    /// Contact email for the ACME account (a bare address gains a `mailto:` prefix
    /// in code); the CA uses it for expiry and policy notices. Required with
    /// `--acme-domain`.
    #[arg(long, env = "COORDINATOR_ACME_CONTACT")]
    pub(super) acme_contact: Option<String>,

    /// Directory the ACME account key and issued certificates are persisted to,
    /// created if absent. Required with `--acme-domain`, and a startup failure if
    /// it cannot be created and written: a coordinator that cannot persist its
    /// certificate would re-request one on every start and quickly exhaust the CA's
    /// issuance rate limit.
    #[arg(long, env = "COORDINATOR_ACME_CACHE")]
    pub(super) acme_cache: Option<std::path::PathBuf>,

    /// Draw certificates from Let's Encrypt's staging directory instead of
    /// production. Staging issues browser-untrusted certificates under far higher
    /// rate limits — for standing a host up without spending production issuance
    /// budget. Only meaningful with `--acme-domain`.
    #[arg(long, env = "COORDINATOR_ACME_STAGING", default_value_t = false)]
    pub(super) acme_staging: bool,

    /// Shared bootstrap secret a relay must present (`Authorization: Bearer
    /// <secret>`) to open its control connection. Production injects one so a
    /// rogue relay cannot subscribe to another relay's mesh topology. Without it
    /// the coordinator refuses to start unless `--allow-insecure-control` is set.
    #[arg(long, env = "COORDINATOR_BOOTSTRAP_SECRET")]
    pub(super) bootstrap_secret: Option<String>,

    /// Path to a JSON file listing the placement regions this coordinator allows
    /// (`{"regions": [{"id", "display_name", "beacon", "fallback"}, ...]}`). The
    /// file order is the client's display order. Loaded and validated at startup;
    /// an invalid file (empty list, duplicate id, malformed id, empty field)
    /// fails the coordinator to start. Absent = no regions configured: relay
    /// region tags are refused and every session slot falls back to the
    /// region-blind pick — the dev / loopback posture.
    #[arg(long, env = "COORDINATOR_REGIONS")]
    pub(super) regions: Option<std::path::PathBuf>,

    /// Run the relay control endpoint with **no authentication**. Required to
    /// start without `--bootstrap-secret`; for trusted dev/loopback only. The
    /// coordinator fails closed (refuses to start) if neither is set, so an
    /// unauthenticated control endpoint is never the silent default.
    #[arg(
        long,
        env = "COORDINATOR_ALLOW_INSECURE_CONTROL",
        default_value_t = false
    )]
    pub(super) allow_insecure_control: bool,

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
    /// hours; values above the fleet ceiling
    /// (`rally_point_proto::control::MAX_PLAYER_TOKEN_LIFETIME_SECS`, 24 hours)
    /// are clamped with a warning — the relay's retired-session tombstones are
    /// sized against that ceiling, and a longer-lived token could re-dial a
    /// session after its tombstone was pruned.
    #[arg(
        long,
        env = "COORDINATOR_PLAYER_TOKEN_LIFETIME_SECS",
        default_value_t = 21600
    )]
    pub(super) player_token_lifetime_secs: u64,

    /// Enables the finalized-drop handshake for new sessions placed on
    /// capable relay cohorts. Off by default: the handshake's remaining
    /// exposure is a partition-delayed finalization result deciding a count
    /// after the slot re-homed and played on — closable only by a
    /// coordinated rehome fence (all serving relays ack the resumed
    /// descriptor before the replacement home admits), which does not exist
    /// yet. Until it does, dropped leaves use the frame-scheduled fallback.
    /// Placement still keeps capability cohorts apart either way, so
    /// flipping this on later changes only newly created sessions.
    #[arg(long, env = "COORDINATOR_ENABLE_FINALIZED_DROPS")]
    pub(super) enable_finalized_drops: bool,

    /// Global ceiling on concurrently live sessions across every tenant. At the
    /// cap, fresh session creates are refused (503) until sessions close — an
    /// emergency brake so a runaway caller or an abuse burst degrades into
    /// refused creates instead of unbounded coordinator state. Idempotent
    /// retries of already-live sessions are unaffected. Absent = uncapped.
    #[arg(long, env = "COORDINATOR_MAX_SESSIONS")]
    pub(super) max_sessions: Option<usize>,

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
    pub(super) tenants: Option<std::path::PathBuf>,

    /// Enroll a single tenant at startup so `POST /session/create` can mint
    /// tokens without any provisioning flow. Dev/loopback only: the signing key
    /// lives in memory, so a restart regenerates it (invalidating the public
    /// key any relay was seeded with) unless `--tenant-key` pins one.
    #[arg(long, env = "COORDINATOR_DEV_TENANT", default_value_t = false)]
    pub(super) dev_tenant: bool,

    /// Tenant id the dev tenant enrolls under. Must match the relay's
    /// `--tenant` and the app server's configured tenant.
    #[arg(
        long,
        env = "COORDINATOR_TENANT",
        default_value = "sb-dev",
        requires = "dev_tenant"
    )]
    pub(super) tenant: String,

    /// Key id (`kid`) naming the dev tenant's signing key in tokens. Must
    /// match the relay's `--kid`.
    #[arg(
        long,
        env = "COORDINATOR_KID",
        default_value = "dev-key-1",
        requires = "dev_tenant"
    )]
    pub(super) kid: String,

    /// Hex-encoded PKCS#8 Ed25519 keypair for the dev tenant — either a file
    /// path containing the hex or the hex itself; the v1 (openssl/Node) and v2
    /// (ring) document forms are both accepted. Pins the signing key so the
    /// public key stays stable across coordinator restarts. If absent, a fresh
    /// keypair is generated and both halves are logged (the public for the
    /// relay's `--tenant-pubkey`, the private so it can be pinned next run).
    #[arg(long, env = "COORDINATOR_TENANT_KEY", requires = "dev_tenant")]
    pub(super) tenant_key: Option<String>,

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
    pub(super) dev_tenant_client_key: Option<String>,

    /// Webhook URL the coordinator POSTs game-event notifications (player
    /// departures and desyncs) to for the dev tenant (e.g.
    /// `http://localhost:5555/webhooks/netcode-v2/game-events`, or `https://...` —
    /// the webhook client handles both). Only meaningful with `--dev-tenant`;
    /// unset = game-event notifications off (everything else unchanged). Each POST
    /// is signed with the dev tenant's own Ed25519 key (`x-rp2-timestamp` +
    /// `x-rp2-signature`) — no separate secret to configure.
    #[arg(long, env = "COORDINATOR_DEV_NOTIFY_URL", requires = "dev_tenant")]
    pub(super) dev_notify_url: Option<String>,

    /// Path to the provisioned-relay ledger's SQLite database (created if
    /// absent). Present ⇒ **ledger mode**: a relay may enroll only under an id
    /// this coordinator minted, presenting its one-time enroll token at first
    /// enroll and its bound certificate on every reconnect; a token-less or
    /// otherwise unauthorized enroll is refused. Absent ⇒ the dev / loopback
    /// posture, where a relay's id claim in its `Hello` is accepted as presented.
    #[arg(long, env = "COORDINATOR_RELAY_LEDGER")]
    pub(super) relay_ledger: Option<std::path::PathBuf>,

    /// Path to the relay binary the provisioning loop launches. Present ⇒ the loop
    /// runs, minting ids and spawning local relay processes to match each region's
    /// warm demand. Requires `--relay-ledger`: a provisioned relay's identity is
    /// only sound when it is minted and bound through the ledger, so the
    /// coordinator refuses to start a provisioning loop without one. Absent ⇒ the
    /// loop is off (relays are enrolled and managed out of band).
    #[arg(long, env = "COORDINATOR_PROVISION_RELAY_BIN")]
    pub(super) provision_relay_bin: Option<std::path::PathBuf>,

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
    pub(super) provision_ecs_config: Option<std::path::PathBuf>,

    /// Base URL a provisioned relay dials to reach this coordinator, injected into
    /// each launched relay's environment. Defaults to `http://127.0.0.1:<port>` of
    /// the listen address — correct for local process provisioning, where relays
    /// run on the same host. Set it when the coordinator is reachable at another
    /// address.
    #[arg(long, env = "COORDINATOR_PROVISION_COORDINATOR_URL")]
    pub(super) provision_coordinator_url: Option<String>,

    /// How long, in seconds, a provisioned relay has to enroll before its launch is
    /// abandoned: the lifetime of the one-time enroll token minted for it. A launch
    /// that has not enrolled by then is swept — its task stopped, its id retired —
    /// and a fresh one minted. Default 300.
    #[arg(
        long,
        env = "COORDINATOR_PROVISION_LAUNCH_DEADLINE_SECS",
        default_value_t = 300
    )]
    pub(super) provision_launch_deadline_secs: u64,

    /// How long, in seconds, an enrolled relay must be continuously session-free
    /// before the provisioning loop may drain it in a scale-down. Default 600.
    #[arg(long, env = "COORDINATOR_RELAY_IDLE_SECS", default_value_t = 600)]
    pub(super) relay_idle_secs: u64,

    /// How often, in seconds, the provisioning loop reconciles each region's relay
    /// count against warm demand. Default 5.
    #[arg(long, env = "COORDINATOR_PROVISION_TICK_SECS", default_value_t = 5)]
    pub(super) provision_tick_secs: u64,

    /// TTL, in seconds, of warm demand raised via `POST /regions/warm` or a
    /// hold-until-ready create. A region stays warm this long after each warm; the
    /// app server re-warms before it lapses to hold a region, and stops simply by
    /// going quiet. Comfortably larger than the create-hold cap so a region a
    /// pending create warmed stays warm through the launch. Default 600.
    #[arg(long, env = "COORDINATOR_WARM_TTL_SECS", default_value_t = 600)]
    pub(super) warm_ttl_secs: u64,

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
    pub(super) provision_create_hold_secs: u64,

    /// Path to the flight-recorder durable sink config JSON (`endpoint`, `region`,
    /// `bucket`, and the NAMES of the environment variables holding the store's access
    /// and secret keys — `accessKeyEnv` / `secretKeyEnv`, the same env-name indirection
    /// the tenant registry uses so the keys stay out of the file). Present ⇒ the
    /// observability blobs relays ship up their control connections are stored in the
    /// bucket, and the flight read endpoints serve them. Loaded and validated at
    /// startup; a malformed file or an unset credential variable fails the coordinator
    /// to start (fail closed, like the tenant registry). Absent ⇒ no store: a shipped
    /// recording is dropped with a rate-limited warn — the dev / no-store posture.
    #[arg(long, env = "COORDINATOR_FLIGHT_STORE")]
    pub(super) flight_store: Option<std::path::PathBuf>,
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
