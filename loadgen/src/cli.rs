//! Command-line surface, matching the README's usage block.

use std::path::PathBuf;

use clap::Parser;

/// Synthetic load harness for the netcode v2 stack: drives many concurrent
/// sessions through a real coordinator and relays without running any game
/// clients.
#[derive(Debug, Parser)]
#[command(name = "rally-point-loadgen", version, about)]
pub struct Cli {
    /// The coordinator's control-plane base URL, e.g. `http://[::1]:14910`.
    #[arg(long)]
    pub coordinator_url: String,

    /// The tenant to create sessions for (the coordinator holds its keys).
    #[arg(long)]
    pub tenant: String,

    /// The tenant's request-signing Ed25519 seed, 64 hex chars (32 bytes). The
    /// coordinator must hold the public half (for a loopback coordinator, the
    /// `--dev-tenant-client-key` seed).
    #[arg(long)]
    pub client_key: String,

    /// Total sessions to run.
    #[arg(long, default_value_t = 10)]
    pub sessions: usize,

    /// Session creates per second (the ramp rate).
    #[arg(long, default_value_t = 2.0)]
    pub arrival_rate: f64,

    /// Players per session.
    #[arg(long, default_value_t = 2)]
    pub players: usize,

    /// How long each session pumps turns, in seconds.
    #[arg(long, default_value_t = 30)]
    pub game_secs: u64,

    /// Turns per second per player.
    #[arg(long, default_value_t = 24)]
    pub turn_rate: u32,

    /// Approximate command payload per turn, in bytes (floored at the 7-byte sync
    /// command).
    #[arg(long, default_value_t = 16)]
    pub turn_bytes: usize,

    /// Per-slot region tags, round-robin across slots (drives cross-relay mesh
    /// when the regions map to different relays). Comma-separated.
    #[arg(long, value_delimiter = ',')]
    pub slot_regions: Vec<String>,

    /// Fraction of sessions that deliberately diverge (one player perturbs its
    /// sync hashes), exercising the desync verdict + webhook path.
    #[arg(long, default_value_t = 0.0)]
    pub desync_fraction: f64,

    /// Write the run's aggregate metrics as JSON to this path.
    #[arg(long)]
    pub json_out: Option<PathBuf>,

    /// A namespacing id for session `external_id`s, so a rerun never collides
    /// with a live run's idempotency entries. Defaults to a time-derived value.
    #[arg(long)]
    pub run_id: Option<String>,

    /// The TLS server name to validate relay certificates against. The session
    /// response pins the relay's cert but carries no server name; a loopback/dev
    /// relay's self-signed cert names `localhost`.
    #[arg(long, default_value = "localhost")]
    pub relay_server_name: String,
}
