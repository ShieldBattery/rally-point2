//! One synthetic session: mint per-player keypairs, sign and POST the create,
//! then run one player task per slot and fold their metrics together.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use rally_point_proto::control::{
    PlayerHandoff, RegionId, RelayEndpoint, SessionRequest, SessionResponse,
};
use rally_point_proto::ids::SlotId;
use rally_point_proto::token::ClientPublicKey;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::create::{self, CreateOutcome, HttpClient};
use crate::lifecycle::{LifecycleOutcome, SessionLifecycle};
use crate::metrics::{DeliveryReport, Ending, PlayerReport, SessionReport};
use crate::player::{self, PlayerConfig, SendTimes};
use crate::turn::{DESYNC_FROM_ORDINAL, TurnBuilder};

/// The tenant's estimate of the worst pairwise one-way path latency, forwarded to
/// the relay's initial buffer sizing. A realistic single value for the harness.
const LATENCY_ESTIMATE_MS: u32 = 40;

/// Everything a session task needs, cloned from the run config per session.
pub struct SessionConfig {
    pub client: HttpClient,
    pub coordinator_url: String,
    pub signing_key: Arc<Ed25519KeyPair>,
    pub tenant: String,
    pub run_id: String,
    pub session_index: usize,
    pub session_seed: u64,
    pub players: usize,
    pub game_secs: u64,
    pub turn_rate: u32,
    pub turn_bytes: usize,
    pub slot_regions: Vec<String>,
    pub server_name: String,
    /// Dial only IPv4 relay addresses (see `Cli::ipv4_only`).
    pub ipv4_only: bool,
    /// Whether this session should deliberately diverge (one player perturbs its
    /// sync hashes).
    pub is_desync: bool,
}

/// Runs one session end to end, returning its metrics contribution.
pub async fn run_session(config: SessionConfig) -> SessionReport {
    // Generate one ephemeral keypair per slot, keeping the PKCS#8 for the player
    // task and handing off the public half in the create request.
    let rng = SystemRandom::new();
    let mut handoffs = Vec::with_capacity(config.players);
    let mut pkcs8_by_slot: HashMap<SlotId, Vec<u8>> = HashMap::new();

    for index in 0..config.players {
        let slot = SlotId(index as u8);
        let pkcs8 = match Ed25519KeyPair::generate_pkcs8(&rng) {
            Ok(document) => document.as_ref().to_vec(),
            Err(_) => {
                tracing::error!("generating a player keypair failed");
                return SessionReport::CreateFailed { status: None };
            }
        };
        let keypair = match Ed25519KeyPair::from_pkcs8(&pkcs8) {
            Ok(keypair) => keypair,
            Err(_) => return SessionReport::CreateFailed { status: None },
        };
        let client_pubkey = match ClientPublicKey::from_slice(keypair.public_key().as_ref()) {
            Some(key) => key,
            None => return SessionReport::CreateFailed { status: None },
        };
        let region = region_for_slot(&config.slot_regions, index);

        handoffs.push(PlayerHandoff {
            slot,
            client_pubkey,
            external_ref: None,
            observer: false,
            region,
        });
        pkcs8_by_slot.insert(slot, pkcs8);
    }

    let request = SessionRequest {
        tenant: rally_point_proto::control::TenantId(config.tenant.clone()),
        players: handoffs,
        external_id: Some(format!(
            "loadgen-{}-{}",
            config.run_id, config.session_index
        )),
        latency_estimate_ms: Some(LATENCY_ESTIMATE_MS),
    };
    let body = match serde_json::to_vec(&request) {
        Ok(bytes) => Bytes::from(bytes),
        Err(err) => {
            tracing::error!(error = %err, "serializing the session request failed");
            return SessionReport::CreateFailed { status: None };
        }
    };

    let outcome = create::create_session(
        &config.client,
        &config.coordinator_url,
        &config.signing_key,
        body,
    )
    .await;

    let (response, latency_us, provisioning_holds) = match outcome {
        CreateOutcome::Created {
            response,
            latency_us,
            provisioning_holds,
        } => (response, latency_us, provisioning_holds),
        CreateOutcome::Failed { status } => return SessionReport::CreateFailed { status },
    };
    let create_done = Instant::now();

    let (players, lifecycle) = run_players(&config, &response, &pkcs8_by_slot, create_done).await;
    let measured_turns = config.game_secs.saturating_mul(u64::from(config.turn_rate));
    let expected = (config.players as u64)
        .saturating_mul(config.players.saturating_sub(1) as u64)
        .saturating_mul(measured_turns);
    let distinct = players.iter().fold(0u64, |total, player| {
        total.saturating_add(player.turn_deliveries_distinct)
    });
    let duplicate = players.iter().fold(0u64, |total, player| {
        total.saturating_add(player.turn_deliveries_duplicate)
    });
    let missing = expected.saturating_sub(distinct);
    let exact_workload_sent = players.len() == config.players
        && players
            .iter()
            .all(|player| player.turns_sent == measured_turns);
    let delivery = DeliveryReport {
        expected,
        distinct,
        missing,
        duplicate,
        complete: lifecycle.complete && exact_workload_sent && missing == 0 && duplicate == 0,
        timed_out: lifecycle.timed_out,
    };
    if !delivery.complete {
        tracing::warn!(
            session_index = config.session_index,
            expected = delivery.expected,
            distinct = delivery.distinct,
            missing = delivery.missing,
            duplicate = delivery.duplicate,
            timed_out = delivery.timed_out,
            lifecycle_aborted = lifecycle.aborted,
            "session ended without exact delivery completeness"
        );
    }

    SessionReport::Created {
        create_latency_us: latency_us,
        provisioning_holds,
        players,
        delivery,
    }
}

/// Spawns and awaits one player task per minted token, returning their reports.
async fn run_players(
    config: &SessionConfig,
    response: &SessionResponse,
    pkcs8_by_slot: &HashMap<SlotId, Vec<u8>>,
    create_done: Instant,
) -> (Vec<PlayerReport>, LifecycleOutcome) {
    let send_times: SendTimes = Arc::new(Mutex::new(HashMap::new()));
    let lifecycle = SessionLifecycle::new(config.players);
    let measured_turns = config.game_secs.saturating_mul(u64::from(config.turn_rate));
    // The one player chosen to diverge in a desync session — the highest slot, so
    // it is distinct from slot 0's home-relay authority.
    let desyncer = config.players.saturating_sub(1);

    let mut handles = Vec::with_capacity(response.tokens.len());
    for token in &response.tokens {
        let slot = token.slot;
        let Some(pkcs8) = pkcs8_by_slot.get(&slot).cloned() else {
            tracing::warn!(slot = slot.0, "no keypair for a minted token slot");
            continue;
        };
        let relay = relay_for_slot(response, slot);
        let builder = if config.is_desync && usize::from(slot.0) == desyncer {
            TurnBuilder::desyncing(config.session_seed, config.turn_bytes, DESYNC_FROM_ORDINAL)
        } else {
            TurnBuilder::new(config.session_seed, config.turn_bytes)
        };

        let player_config = PlayerConfig {
            slot,
            token_bytes: token.token.clone(),
            pkcs8,
            relay,
            server_name: config.server_name.clone(),
            ipv4_only: config.ipv4_only,
            turn_rate: config.turn_rate,
            measured_turns,
            players: config.players,
            builder,
            send_times: Arc::clone(&send_times),
            create_done,
            lifecycle: lifecycle.clone(),
        };
        handles.push(tokio::spawn(player::run_player(player_config)));
    }

    // A malformed create response or a missing local keypair means no complete
    // rendezvous is possible. Release every task rather than leaving the players
    // that did receive tokens parked at the readiness gate.
    if handles.len() != config.players {
        tracing::warn!(
            expected = config.players,
            spawned = handles.len(),
            "created session did not yield one runnable token per player"
        );
        lifecycle.abort();
    }

    let mut reports = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(report) => reports.push(report),
            Err(err) => {
                tracing::warn!(error = %err, "a player task panicked");
                reports.push(PlayerReport {
                    ending: Ending::Errored,
                    ..PlayerReport::default()
                });
            }
        }
    }
    (reports, lifecycle.outcome())
}

/// The relay a slot homes on: its `slot_homes` override, else the primary home relay.
fn relay_for_slot(response: &SessionResponse, slot: SlotId) -> RelayEndpoint {
    response
        .slot_homes
        .iter()
        .find(|home| home.slot == slot)
        .map(|home| home.relay.clone())
        .unwrap_or_else(|| response.home_relay.clone())
}

/// The region tag for a slot: round-robin over `slot_regions`, or none when no
/// regions were configured.
fn region_for_slot(slot_regions: &[String], index: usize) -> Option<RegionId> {
    if slot_regions.is_empty() {
        None
    } else {
        Some(RegionId(slot_regions[index % slot_regions.len()].clone()))
    }
}
