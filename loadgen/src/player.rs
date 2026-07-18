//! One synthetic player: dial the relay with a minted token, pump validator-clean
//! turns at game cadence, drain everything the driver hands back, and leave
//! cleanly when the game window ends.
//!
//! This mirrors how the ShieldBattery game DLL wires the same client crate
//! (`shieldbattery/game/src/netcode_v2/{credentials,session}.rs`): build a
//! pinned-trust [`RootCertStore`] from the relay's cert, bind a
//! [`ClientEndpoint`], dial the home relay across its candidate addresses,
//! [`Identity::from_pkcs8`] the token + keypair, and run a [`LinkDriver`] over the
//! link. It uses plain [`LinkDriver::run`] rather than `run_reconnecting`: v1 has
//! no rehome provider, so a dropped link ends the player rather than re-homing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rally_point_client::proto::messages::Payload;
use rally_point_client::proto::token::SignedToken;
use rally_point_client::transport::rustls::RootCertStore;
use rally_point_client::transport::rustls::pki_types::CertificateDer;
use rally_point_client::{ClientEndpoint, DriverError, Identity, LinkDriver};
use rally_point_proto::control::RelayEndpoint;
use rally_point_proto::ids::SlotId;
use tokio::task::JoinError;
use tokio::time::{
    Duration, Instant as TokioInstant, MissedTickBehavior, interval, sleep_until, timeout,
};

use crate::metrics::{Ending, PlayerReport};
use crate::turn::TurnBuilder;

/// Per-session shared map from a turn's `(origin slot, frame)` to the process
/// instant the origin player sent it. A sender writes its own entry right before
/// sending; every other player of the session reads it on receipt to compute
/// fan-out latency against the one shared process clock.
pub type SendTimes = Arc<Mutex<HashMap<(u32, u32), Instant>>>;

/// How long a player waits for the relay's session-start directive before giving
/// up on the session.
const SESSION_START_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a player waits for its driver to end after signaling a clean leave,
/// before abandoning it as an errored ending.
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(15);
/// Multiple of the turn interval an inbound gap must exceed to count as a stall.
const STALL_GAP_MULTIPLE: u64 = 3;

/// Everything one player task needs to run its slot.
pub struct PlayerConfig {
    pub slot: SlotId,
    /// The `SignedToken` wire bytes the create response minted for this slot.
    pub token_bytes: Vec<u8>,
    /// The PKCS#8 document of the keypair whose public half was handed off for
    /// this slot.
    pub pkcs8: Vec<u8>,
    /// The relay this slot homes on, with the cert to pin.
    pub relay: RelayEndpoint,
    pub server_name: String,
    /// Dial only IPv4 relay addresses, skipping advertised IPv6.
    pub ipv4_only: bool,
    pub turn_rate: u32,
    pub game_secs: u64,
    pub builder: TurnBuilder,
    pub send_times: SendTimes,
    /// The instant session-create completed, the baseline for time-to-session-start.
    pub create_done: Instant,
}

/// Runs one player's whole lifecycle, returning its metrics contribution.
///
/// A failure to build credentials, bind an endpoint, or dial the relay returns a
/// [`PlayerReport::dial_failed`]; past that, the report carries the player's turn
/// stats and how its driver ended.
pub async fn run_player(config: PlayerConfig) -> PlayerReport {
    let PlayerConfig {
        slot,
        token_bytes,
        pkcs8,
        relay,
        server_name,
        ipv4_only,
        turn_rate,
        game_secs,
        builder,
        send_times,
        create_done,
    } = config;

    // Pin exactly this relay's leaf cert — no webpki/system roots — the same
    // fail-closed trust the game DLL builds (see credentials.rs).
    let mut roots = RootCertStore::empty();
    if roots
        .add(CertificateDer::from(relay.cert_der.clone()))
        .is_err()
    {
        tracing::warn!(slot = slot.0, "relay cert could not be pinned");
        return PlayerReport::dial_failed();
    }

    // One endpoint (one UDP socket) per player. Sharing one endpoint per session
    // would cut socket count to one per session, but a single endpoint carries a
    // single pinned trust store — fine for a same-relay session, but a
    // cross-region session's slots pin different relay certs, so per-player
    // endpoints keep v1 uniform.
    let endpoint = match ClientEndpoint::bind(roots) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            tracing::warn!(slot = slot.0, error = %err, "binding the client endpoint failed");
            return PlayerReport::dial_failed();
        }
    };

    let token = match SignedToken::decode(&token_bytes) {
        Ok(token) => token,
        Err(_) => {
            tracing::warn!(slot = slot.0, "minted token did not decode");
            return PlayerReport::dial_failed();
        }
    };
    let identity = match Identity::from_pkcs8(token, &pkcs8) {
        Ok(identity) => identity,
        Err(err) => {
            tracing::warn!(slot = slot.0, error = %err, "building the client identity failed");
            return PlayerReport::dial_failed();
        }
    };

    // Dial the relay's candidate addresses in advertised order, first that connects.
    // With `ipv4_only`, skip any advertised IPv6 address rather than burn a connect
    // timeout on it from a host that has no IPv6 route.
    let mut link = None;
    for addr in relay.addrs() {
        if ipv4_only && !addr.is_ipv4() {
            continue;
        }
        match endpoint.connect(addr, &server_name, &identity).await {
            Ok(established) => {
                link = Some(established);
                break;
            }
            Err(err) => {
                tracing::debug!(slot = slot.0, %addr, error = %err, "relay dial failed");
            }
        }
    }
    let Some(link) = link else {
        tracing::warn!(slot = slot.0, "every relay address failed to connect");
        return PlayerReport::dial_failed();
    };

    let (driver, mut channels) = LinkDriver::new(link);
    let mut handle = tokio::spawn(driver.run());

    let mut stats = PlayerReport {
        ending: Ending::Errored,
        ..PlayerReport::default()
    };
    let own_slot = u32::from(slot.0);

    // Gate turn pumping on the relay's session-start directive: the relay fires it
    // once every expected slot has connected. Without it, the relay is not yet
    // fanning turns out, so pumping early measures nothing.
    let session_started = matches!(
        timeout(SESSION_START_TIMEOUT, channels.session_start.recv()).await,
        Ok(Some(_))
    );
    if session_started {
        stats.time_to_session_start_us = Some(create_done.elapsed().as_micros() as u64);
    } else {
        tracing::warn!(slot = slot.0, "session-start not observed before timeout");
    }

    let turn_interval = Duration::from_micros((1_000_000 / u64::from(turn_rate.max(1))).max(1));
    let stall_threshold_us = STALL_GAP_MULTIPLE * turn_interval.as_micros() as u64;
    let mut last_recv: HashMap<u32, Instant> = HashMap::new();

    if session_started {
        pump_turns(
            &mut channels,
            &builder,
            &send_times,
            own_slot,
            turn_interval,
            game_secs,
            stall_threshold_us,
            &mut last_recv,
            &mut stats,
        )
        .await;
    }

    // Signal a clean leave and wait for the relay to close the link (which ends
    // the driver with `Ok`). Keeping every sender in `channels` alive means the
    // driver ends because the relay closed after the leave, not because the game
    // seam dropped out from under it.
    let _ = channels.leave_intent.send(()).await;
    let ending = drain_until_driver_ends(
        &mut channels,
        &mut handle,
        &send_times,
        stall_threshold_us,
        &mut last_recv,
        &mut stats,
    )
    .await;

    // The endpoint held the UDP socket for the whole session; drop it now.
    drop(endpoint);

    stats.ending = if session_started {
        ending
    } else {
        Ending::NoSessionStart
    };
    stats
}

/// The steady-state loop: emit a turn every interval and drain everything the
/// driver hands back, until the game window closes or the driver ends (the latter
/// closes the inbound channel, so its `None` breaks the loop).
#[allow(clippy::too_many_arguments)]
async fn pump_turns(
    channels: &mut rally_point_client::TurnChannels,
    builder: &TurnBuilder,
    send_times: &SendTimes,
    own_slot: u32,
    turn_interval: Duration,
    game_secs: u64,
    stall_threshold_us: u64,
    last_recv: &mut HashMap<u32, Instant>,
    stats: &mut PlayerReport,
) {
    let mut ticker = interval(turn_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let deadline = TokioInstant::now() + Duration::from_secs(game_secs);
    let mut ordinal: u64 = 0;

    loop {
        tokio::select! {
            biased;
            _ = sleep_until(deadline) => break,
            _ = ticker.tick() => {
                let frame = ordinal as u32;
                let commands = builder.turn(ordinal);
                // Record the send instant before handing the turn off, so a peer's
                // receipt always finds it.
                if let Ok(mut map) = send_times.lock() {
                    map.insert((own_slot, frame), Instant::now());
                }
                // seq/slot are left zero: the driver stamps seq, the relay rebinds slot.
                let payload = Payload {
                    seq: 0,
                    slot: 0,
                    commands: commands.into(),
                    game_frame_count: Some(frame),
                    buffer_directive: None,
                };
                if channels.outbound.send(payload).await.is_err() {
                    break;
                }
                stats.turns_sent += 1;
                ordinal += 1;
            }
            maybe = channels.inbound.recv() => {
                match maybe {
                    Some(payload) => record_inbound(&payload, send_times, stall_threshold_us, last_recv, stats),
                    None => break,
                }
            }
            maybe = channels.leaves.recv() => if maybe.is_none() { break },
            maybe = channels.connectivity.recv() => if maybe.is_none() { break },
            maybe = channels.chat_in.recv() => if maybe.is_none() { break },
            maybe = channels.lobby_in.recv() => if maybe.is_none() { break },
        }
    }
}

/// Waits for the driver to end after a leave, still draining inbound so a late
/// turn can't stall it, and classifies the ending. Bounded by [`TEARDOWN_TIMEOUT`].
async fn drain_until_driver_ends(
    channels: &mut rally_point_client::TurnChannels,
    handle: &mut tokio::task::JoinHandle<Result<(), DriverError>>,
    send_times: &SendTimes,
    stall_threshold_us: u64,
    last_recv: &mut HashMap<u32, Instant>,
    stats: &mut PlayerReport,
) -> Ending {
    let deadline = TokioInstant::now() + TEARDOWN_TIMEOUT;
    loop {
        tokio::select! {
            biased;
            res = &mut *handle => return classify_ending(res),
            _ = sleep_until(deadline) => {
                handle.abort();
                return Ending::Errored;
            }
            maybe = channels.inbound.recv() => {
                if let Some(payload) = maybe {
                    record_inbound(&payload, send_times, stall_threshold_us, last_recv, stats);
                }
            }
            maybe = channels.leaves.recv() => { let _ = maybe; }
            maybe = channels.connectivity.recv() => { let _ = maybe; }
            maybe = channels.chat_in.recv() => { let _ = maybe; }
            maybe = channels.lobby_in.recv() => { let _ = maybe; }
        }
    }
}

/// Folds one received peer turn into the player's stats: fan-out latency (against
/// the shared send instant for its `(slot, frame)`) and inter-arrival gap/stall
/// accounting per source slot.
fn record_inbound(
    payload: &Payload,
    send_times: &SendTimes,
    stall_threshold_us: u64,
    last_recv: &mut HashMap<u32, Instant>,
    stats: &mut PlayerReport,
) {
    stats.turns_received += 1;
    let now = Instant::now();

    if let Some(frame) = payload.game_frame_count {
        let sent = send_times
            .lock()
            .ok()
            .and_then(|map| map.get(&(payload.slot, frame)).copied());
        if let Some(sent) = sent {
            stats
                .fan_out_latency_us
                .push(now.saturating_duration_since(sent).as_micros() as u64);
        }
    }

    if let Some(prev) = last_recv.get(&payload.slot).copied() {
        let gap = now.saturating_duration_since(prev).as_micros() as u64;
        stats.inter_arrival_gap_us.push(gap);
        if gap > stall_threshold_us {
            stats.stalls += 1;
        }
    }
    last_recv.insert(payload.slot, now);
}

/// Maps a joined driver result to an [`Ending`]: a clean `Ok(Ok(()))` is the only
/// clean ending; a driver error or a task join failure is errored.
fn classify_ending(res: Result<Result<(), DriverError>, JoinError>) -> Ending {
    match res {
        Ok(Ok(())) => Ending::Clean,
        Ok(Err(err)) => {
            tracing::debug!(error = %err, "driver ended with an error");
            Ending::Errored
        }
        Err(err) => {
            tracing::debug!(error = %err, "driver task failed to join");
            Ending::Errored
        }
    }
}
