//! `rally-point-loadgen` — synthetic load harness for the netcode v2 stack.
//!
//! One process stands in for a fleet of app servers + game DLLs: it creates
//! sessions over the signed tenant API, dials relays with real minted tokens over
//! the same client crate the game DLL links, and pumps validator-clean turn
//! streams at game cadence. A conductor task ramps session creation at a
//! configured arrival rate; each session runs one player task per slot; the run
//! ends with a percentile summary (and optional JSON aggregates).

mod cli;
mod create;
mod metrics;
mod player;
mod session;
mod signing;
mod turn;

use std::io::{self, Write};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use color_eyre::eyre::{Result, WrapErr, bail, eyre};
use ring::signature::Ed25519KeyPair;
use tokio::task::JoinSet;

use crate::cli::Cli;
use crate::metrics::{RunReport, SessionReport, Workload};
use crate::session::{SessionConfig, run_session};

/// Multiplier that spreads per-session seeds apart (the odd 64-bit golden ratio).
const SEED_STRIDE: u64 = 0x9E37_79B9_7F4A_7C15;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    validate(&cli)?;

    let signing_key = Arc::new(load_signing_key(&cli.client_key)?);
    let client = create::build_client();
    let run_id = cli.run_id.clone().unwrap_or_else(default_run_id);
    let run_salt = fnv1a64(&run_id);

    tracing::info!(
        coordinator = %cli.coordinator_url,
        tenant = %cli.tenant,
        run_id = %run_id,
        sessions = cli.sessions,
        arrival_rate = cli.arrival_rate,
        players = cli.players,
        game_secs = cli.game_secs,
        turn_rate = cli.turn_rate,
        turn_bytes = cli.turn_bytes,
        desync_fraction = cli.desync_fraction,
        "starting load run",
    );

    let run_started = Instant::now();
    let reports = conduct(&cli, client, signing_key, &run_id, run_salt).await;
    let report = RunReport::aggregate(
        Workload {
            run_id: run_id.clone(),
            sessions: cli.sessions,
            arrival_rate: cli.arrival_rate,
            players_per_session: cli.players,
            game_secs: cli.game_secs,
            turn_rate: cli.turn_rate,
            turn_bytes: cli.turn_bytes,
            slot_regions: cli.slot_regions.clone(),
            desync_fraction: cli.desync_fraction,
            ipv4_only: cli.ipv4_only,
        },
        run_started.elapsed(),
        reports,
    );

    if let Some(path) = &cli.json_out {
        let json = serde_json::to_string_pretty(&report).wrap_err("serializing the run report")?;
        std::fs::write(path, json).wrap_err_with(|| format!("writing {}", path.display()))?;
        tracing::info!(path = %path.display(), "wrote JSON aggregates");
    }

    // Persist the machine-readable artifact before touching stdout. Remote
    // benchmark runners commonly stream the human summary over SSH, and a
    // dropped terminal must not discard an otherwise completed run. A closed
    // pipe is an ordinary detached-run outcome; other stdout failures remain
    // real errors.
    let summary = report.render();
    if let Err(error) = io::stdout().lock().write_all(summary.as_bytes())
        && error.kind() != io::ErrorKind::BrokenPipe
    {
        return Err(error).wrap_err("writing the run summary");
    }

    Ok(())
}

/// Ramps session creation at the arrival rate and awaits every session task.
async fn conduct(
    cli: &Cli,
    client: create::HttpClient,
    signing_key: Arc<Ed25519KeyPair>,
    run_id: &str,
    run_salt: u64,
) -> Vec<SessionReport> {
    let mut set: JoinSet<SessionReport> = JoinSet::new();
    let period = Duration::from_secs_f64(1.0 / cli.arrival_rate);
    let mut ticker = tokio::time::interval(period);
    // Distribute the desync fraction evenly: accumulate the fraction each session
    // and flip one whenever a whole unit has built up.
    let mut desync_budget = 0.0f64;

    for index in 0..cli.sessions {
        ticker.tick().await;
        desync_budget += cli.desync_fraction;
        let is_desync = desync_budget >= 1.0;
        if is_desync {
            desync_budget -= 1.0;
        }

        let config = SessionConfig {
            client: client.clone(),
            coordinator_url: cli.coordinator_url.clone(),
            signing_key: Arc::clone(&signing_key),
            tenant: cli.tenant.clone(),
            run_id: run_id.to_owned(),
            session_index: index,
            session_seed: run_salt ^ (index as u64).wrapping_mul(SEED_STRIDE),
            players: cli.players,
            game_secs: cli.game_secs,
            turn_rate: cli.turn_rate,
            turn_bytes: cli.turn_bytes,
            slot_regions: cli.slot_regions.clone(),
            server_name: cli.relay_server_name.clone(),
            ipv4_only: cli.ipv4_only,
            is_desync,
        };
        set.spawn(run_session(config));
    }

    let mut reports = Vec::with_capacity(cli.sessions);
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(report) => reports.push(report),
            Err(err) => {
                tracing::error!(error = %err, "a session task panicked");
                reports.push(SessionReport::CreateFailed { status: None });
            }
        }
    }
    reports
}

/// Rejects nonsensical numeric arguments up front, so a run fails fast rather than
/// after ramping.
fn validate(cli: &Cli) -> Result<()> {
    if cli.arrival_rate <= 0.0 {
        bail!("--arrival-rate must be greater than 0");
    }
    if cli.players == 0 {
        bail!("--players must be at least 1");
    }
    if cli.turn_rate == 0 {
        bail!("--turn-rate must be at least 1");
    }
    if !(0.0..=1.0).contains(&cli.desync_fraction) {
        bail!("--desync-fraction must be between 0 and 1");
    }
    Ok(())
}

/// Decodes the tenant request-signing seed (64 hex chars) into an Ed25519 keypair.
fn load_signing_key(client_key: &str) -> Result<Ed25519KeyPair> {
    let seed = hex::decode(client_key.trim())
        .map_err(|_| eyre!("--client-key must be hex (64 characters)"))?;
    if seed.len() != 32 {
        bail!(
            "--client-key must be 32 bytes (64 hex characters), got {} bytes",
            seed.len()
        );
    }
    Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|err| eyre!("--client-key is not a valid Ed25519 seed: {err}"))
}

/// A time-derived default run id (unix milliseconds), namespacing this run's
/// session `external_id`s away from any other run's.
fn default_run_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{millis}")
}

/// FNV-1a over the run id, seeding per-session hash streams deterministically.
fn fnv1a64(input: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
