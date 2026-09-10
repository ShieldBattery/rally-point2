//! Command-line surface for the relay binary: every `--flag` / `RELAY_*` env
//! var `main` reads before it wires anything up. Kept apart from `main.rs`
//! so the wiring logic isn't buried under a couple hundred lines of clap
//! attributes and doc comments.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use clap::Parser;
use rally_point_relay::DEFAULT_PORT;

/// Validating netcode v2 relay.
#[derive(Debug, Parser)]
#[command(name = "rally-point-relay", version, about)]
pub(crate) struct Cli {
    /// Address to listen on for client + mesh QUIC connections (dual-stack by
    /// default — IPv6-primary ingress).
    #[arg(long, env = "RELAY_LISTEN", default_value_t = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DEFAULT_PORT))]
    pub(crate) listen: SocketAddr,

    /// TLS certificate chain for the relay's identity — either a PEM file path
    /// (local dev, Docker volume mount) or inline PEM content (Fargate secret
    /// injection). If absent, a self-signed cert is generated (dev/loopback
    /// only — clients must trust it out-of-band).
    #[arg(long, env = "RELAY_CERT")]
    pub(crate) cert: Option<String>,

    /// PEM private key matching `--cert` — either a file path or inline PEM
    /// content, same as `--cert`. Required when `--cert` is set; ignored (a
    /// fresh key is generated) when `--cert` is absent.
    #[arg(long, env = "RELAY_KEY", requires = "cert")]
    pub(crate) key: Option<String>,

    /// Hex-encoded Ed25519 *public* (verifying) key for the tenant signing key.
    /// The relay verifies client tokens against this; the matching private key
    /// stays with the token issuer, never on the relay. If absent, a keypair is
    /// generated and both halves are logged (the public is registered, the
    /// private is printed so a client can mint matching tokens for loopback).
    #[arg(long, env = "RELAY_TENANT_PUBKEY")]
    pub(crate) tenant_pubkey: Option<String>,

    /// Key id (`kid`) naming the tenant signing key in the registry.
    #[arg(long, env = "RELAY_KID", default_value = "dev-key-1")]
    pub(crate) kid: String,

    /// Tenant id bound to the signing key.
    #[arg(long, env = "RELAY_TENANT", default_value = "sb-dev")]
    pub(crate) tenant: String,

    /// This relay's id in the mesh (dev/loopback). The mesh link-establishment
    /// tie-break is "lower id dials higher": when two relays could each dial
    /// the other, exactly one must, so each compares its own id to a peer's
    /// configured id and dials only when it is the lower. Leave absent to run
    /// without a mesh edge (single-relay `C–S–C`). In production the
    /// coordinator assigns the relay id (Phase 3).
    #[arg(long, env = "RELAY_ID")]
    pub(crate) relay_id: Option<u64>,

    /// A peer relay to mesh with (dev/loopback): `ADDR#ID`, where ADDR is the
    /// peer's listen endpoint and ID is its `--relay-id`. Repeatable. When this
    /// relay's id is lower than a peer's, it dials that peer; when higher, it
    /// waits for the peer to dial. Both sides of a relay-pair must list each
    /// other. In production the coordinator pushes peer topology at runtime
    /// (relays churn under scale-to-zero, so the peer set is unknowable at
    /// startup), and the dial side needs the peer's id before connecting.
    #[arg(long, env = "RELAY_MESH_PEER", value_name = "ADDR#ID")]
    pub(crate) mesh_peers: Vec<String>,

    /// PEM CA certificate(s) to trust when dialing mesh peers — either a file
    /// path or inline PEM content, same form as `--cert`. For dev/loopback
    /// with two relays sharing one self-signed cert, pass that same cert here;
    /// if absent, the relay's own leaf cert is trusted (the shared-cert dev
    /// case). In production, relay-to-relay trust comes from an internal CA
    /// (both relays trust the same CA root) — Phase 3.
    #[arg(long, env = "RELAY_MESH_ROOTS")]
    pub(crate) mesh_roots: Option<String>,

    /// TLS server name (SNI) to verify on mesh peer certificates. Defaults to
    /// `localhost` for self-signed dev certs. Set to the hostname on the peer's
    /// production cert otherwise.
    #[arg(long, env = "RELAY_MESH_SERVER_NAME", default_value = "localhost")]
    pub(crate) mesh_server_name: String,

    /// Fail closed on the mesh accept path: refuse every dialing peer's
    /// connection until the coordinator's fleet-peer set has arrived, rather
    /// than treating an empty set as not-yet-enforced. This flag only matters
    /// for the dev/static `--mesh-peer` path (no coordinator, so no fleet push
    /// ever arrives): off by default there, that path keeps meshing with no
    /// peer-identity checks at all; set it to fail closed instead. A
    /// coordinator-driven relay (a relay id plus a coordinator URL) always fails
    /// closed regardless of this flag — it will receive a fleet-peer push and
    /// must never serve an unauthenticated mesh accept, not even during the
    /// startup window before its first push lands (genuine peers' dial
    /// supervisors redial through that brief window).
    #[arg(long, env = "RELAY_REQUIRE_MESH_PEER_AUTH", default_value_t = false)]
    pub(crate) require_mesh_peer_auth: bool,

    /// Base URL of the coordinator's control-plane API (e.g.
    /// `http://coordinator.internal:14910`). When set together with `--relay-id`,
    /// the relay holds a control connection open to the coordinator and applies
    /// the session descriptors it pushes — the production source of mesh
    /// `Join`/`Leave`. Absent (pure dev/loopback), mesh membership is driven only
    /// by tests or by links establishing; no coordinator is contacted.
    #[arg(long, env = "RELAY_COORDINATOR_URL")]
    pub(crate) coordinator_url: Option<String>,

    /// Bootstrap secret presented to the coordinator (`Authorization: Bearer
    /// <secret>`) when opening the control connection. Must match the
    /// coordinator's `--bootstrap-secret`. Absent for dev/loopback against an
    /// open coordinator.
    #[arg(long, env = "RELAY_COORDINATOR_SECRET")]
    pub(crate) coordinator_secret: Option<String>,

    /// One-time enrollment token, presented in the enroll `Hello` so a
    /// coordinator that runs a provisioned-relay ledger can bind this relay id to
    /// its certificate at first enroll. The coordinator mints it when it launches
    /// this relay's task and injects it here (its launch environment). Absent for
    /// dev/loopback against a coordinator with no ledger. The token rides every
    /// enroll this process sends — the environment does not change between
    /// redials — and the coordinator ignores it once the certificate is bound:
    /// the bound certificate, not the token, authorizes reconnects.
    #[arg(long, env = "RELAY_ENROLL_TOKEN")]
    pub(crate) enroll_token: Option<String>,

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
    pub(crate) advertise_addr: Vec<SocketAddr>,

    /// How long the coordinated-drain shutdown path waits for in-flight sessions to
    /// finish before exiting and abandoning any that remain to coordinator-mediated
    /// failover. Deliberately under Fargate's 120s `stopTimeout`, so the drain always
    /// completes before the platform SIGKILLs the process.
    #[arg(long, env = "RELAY_DRAIN_TIMEOUT_SECS", default_value_t = 90)]
    pub(crate) drain_timeout_secs: u64,

    /// Directory the flight recorder flushes per-session blobs into
    /// (`<dir>/<tenant>/<session>/<relay_id>.json`) — the dev/loopback sink, and a
    /// deliberate override: when set it wins even on a coordinator-connected relay,
    /// which otherwise ships each flushed recording to the coordinator over its
    /// control connection. Absent on a standalone relay (no coordinator), the
    /// recorder still records — cheap and bounded — but a flush discards the
    /// recording with a log line.
    #[arg(long, env = "RELAY_FLIGHT_DIR")]
    pub(crate) flight_dir: Option<std::path::PathBuf>,

    /// The region this relay serves, sent to the coordinator in the enroll
    /// `Hello`. Must be one of the coordinator's configured region ids, or the
    /// coordinator refuses the control connection (close code 4002) — a typo'd tag
    /// that silently serves nobody is worse than a failed enroll. Absent = an
    /// untagged relay (dev/loopback, or a coordinator with no region config): it
    /// enrolls unconditionally and is only ever the region-blind fallback pick.
    #[arg(long, env = "RELAY_REGION")]
    pub(crate) region: Option<String>,

    /// How often the task-stats reporter reads this relay's own ECS Task
    /// Metadata `/stats` endpoint and logs a CPU/memory/network line — a
    /// load-test and production observability signal independent of
    /// CloudWatch Container Insights, since it reads the task-local metadata
    /// endpoint directly rather than any AWS-side aggregation. `0` disables
    /// it. Fargate-only regardless of this value: the reporter is a no-op
    /// unless `ECS_CONTAINER_METADATA_URI_V4` is set in the environment
    /// (absent in dev/loopback and any non-Fargate run), so leaving this at
    /// its default is harmless outside Fargate.
    #[arg(long, env = "RELAY_TASK_STATS_INTERVAL_SECS", default_value_t = 10)]
    pub(crate) task_stats_interval_secs: u64,

    /// How long the relay must continuously hold zero sessions AND no coordinator
    /// control connection before it exits on its own, so the task platform can
    /// reclaim an idle task whose coordinator vanished (died, restarted with ledger
    /// loss, or left this task orphaned). `0` disables the self-exit. A relay with
    /// no coordinator configured never self-exits regardless of this value — a
    /// standalone/dev relay has no enrollment to lose and serves for as long as it
    /// runs.
    #[arg(long, env = "RELAY_IDLE_UNENROLLED_EXIT_SECS", default_value_t = 900)]
    pub(crate) idle_unenrolled_exit_secs: u64,

    /// How long a slot this relay homes may send this relay's local clients no
    /// turns, having stopped before every other slot in its session did, before
    /// the relay closes its link so the other players can drop it. Covers the
    /// client whose game thread hung or whose process was suspended: its QUIC
    /// link keeps answering keepalives, so nothing else ever sees it leave, and
    /// lockstep holds every other player still behind it. `0` disables the watch
    /// entirely — the session then stalls until everyone quits, which is what
    /// this exists to prevent.
    #[arg(long, env = "RELAY_SILENT_SLOT_WINDOW_SECS", default_value_t = 10)]
    pub(crate) silent_slot_window_secs: u64,
}
