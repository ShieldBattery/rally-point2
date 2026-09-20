//! One synthetic player: dial the relay with a minted token, pump validator-clean
//! an exact turn count at game cadence, drain every expected peer frame, and
//! leave cleanly with the rest of the session.
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

use rally_point_client::proto::token::SignedToken;
use rally_point_client::transport::rustls::RootCertStore;
use rally_point_client::transport::rustls::pki_types::CertificateDer;
use rally_point_client::{ClientEndpoint, Identity, LinkDriver, TurnChannels};
use rally_point_proto::control::RelayEndpoint;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;
use tokio::time::{Duration, timeout};

use crate::lifecycle::SessionLifecycle;
use crate::metrics::{Ending, PlayerReport};
use crate::turn::TurnBuilder;

use drain::{drain_delivery_phase, drain_until_driver_ends};
use measure::{DeliveryTracker, Measurement};
use pump::{Workload, pump_turns};

mod drain;
mod measure;
mod pump;

#[cfg(test)]
mod tests;

/// Per-session shared map from a turn's `(origin slot, frame)` to the process
/// instant the origin player sent it. A sender writes its own entry right before
/// sending; every other player of the session reads it on receipt to compute
/// fan-out latency against the one shared process clock.
pub type SendTimes = Arc<Mutex<HashMap<(u32, u32), Instant>>>;

/// How long a player waits for the relay's session-start directive before giving
/// up on the session.
const SESSION_START_TIMEOUT: Duration = Duration::from_secs(30);
/// Multiple of the turn interval an inbound gap must exceed to count as a stall.
const STALL_GAP_MULTIPLE: u32 = 3;

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
    /// Exact number of measured frames this player must emit.
    pub measured_turns: u64,
    pub players: usize,
    pub builder: TurnBuilder,
    pub send_times: SendTimes,
    /// The instant session-create completed, the baseline for time-to-session-start.
    pub create_done: Instant,
    pub lifecycle: SessionLifecycle,
    /// How far after the session's shared start this player anchors its turn
    /// ticker — a deliberate send-phase offset (see `Cli::phase_spread_ms`).
    pub phase_offset: Duration,
}

/// Aborts the shared phase machine if a player task fails or panics before it
/// reaches a terminal shared drain result. Once the result is known, teardown is
/// per-link and no longer needs to hold the other players hostage.
struct LifecycleParticipant {
    lifecycle: SessionLifecycle,
    armed: bool,
}

impl LifecycleParticipant {
    fn new(lifecycle: SessionLifecycle) -> Self {
        Self {
            lifecycle,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for LifecycleParticipant {
    fn drop(&mut self) {
        if self.armed {
            self.lifecycle.abort();
        }
    }
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
        measured_turns,
        players,
        builder,
        send_times,
        create_done,
        lifecycle,
        phase_offset,
    } = config;
    let mut participant = LifecycleParticipant::new(lifecycle.clone());

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
    let deliveries = DeliveryTracker::new(slot, players, measured_turns);

    // Gate turn pumping on the relay's session-start directive: the relay fires it
    // once every expected slot has connected. Without it, the relay is not yet
    // fanning turns out, so pumping early measures nothing.
    let mut start_changes = lifecycle.subscribe();
    let session_started = tokio::select! {
        biased;
        _ = lifecycle.wait_for_abort(&mut start_changes) => false,
        result = timeout(SESSION_START_TIMEOUT, channels.session_start.recv()) => {
            matches!(result, Ok(Some(_)))
        }
    };
    if session_started {
        stats.time_to_session_start_us = Some(create_done.elapsed().as_micros() as u64);
    } else {
        tracing::warn!(
            slot = slot.0,
            "session-start not observed before the session aborted or timed out"
        );
    }

    let turn_interval = Duration::from_secs_f64(1.0 / f64::from(turn_rate.max(1)));
    let stall_threshold_us = turn_interval.saturating_mul(STALL_GAP_MULTIPLE).as_micros() as u64;
    let mut measure = Measurement::new(&send_times, stall_threshold_us, stats, deliveries);

    let common_start = if session_started {
        lifecycle.ready_and_wait_for_start().await
    } else {
        lifecycle.abort();
        None
    };
    if let Some(common_start) = common_start {
        let workload = Workload {
            builder: &builder,
            own_slot,
            turn_interval,
            start: common_start + phase_offset,
            measured_turns,
        };
        let sent_all = pump_turns(&mut channels, &workload, &mut measure, &lifecycle).await;
        if sent_all {
            lifecycle.sender_done();
            let _ = drain_delivery_phase(&mut channels, &mut measure, &lifecycle).await;
        } else {
            lifecycle.abort();
        }
    }

    // Every shared waiter has now been released by completeness, timeout, or an
    // abort. Link teardown can no longer strand a peer at a session barrier.
    participant.disarm();

    // Signal a clean leave and wait for the relay to close the link (which ends
    // the driver with `Ok`). Keeping every sender in `channels` alive means the
    // driver ends because the relay closed after the leave, not because the game
    // seam dropped out from under it.
    let _ = channels.leave_intent.send(()).await;
    let ending = drain_until_driver_ends(&mut channels, &mut handle, &mut measure).await;

    // The endpoint held the UDP socket for the whole session; drop it now.
    drop(endpoint);

    let Measurement {
        mut stats,
        deliveries,
        ..
    } = measure;
    stats.ending = if session_started {
        ending
    } else {
        Ending::NoSessionStart
    };
    stats.turn_deliveries_distinct = deliveries.distinct;
    stats.turn_deliveries_duplicate = deliveries.duplicate;
    stats
}

/// Awaits the next peer turn on `channels.inbound`, receiving and discarding
/// whatever arrives meanwhile on the directive channels (`leaves`,
/// `connectivity`, `chat_in`, `lobby_in`, `skin_in`). Returns `None` once any
/// of those has closed, which is how the driver ending surfaces here.
///
/// Only a load generator may do this: a discarded `LeaveDirective` never
/// clears the departed slot, so a real game reads the directive channels
/// itself. Draining them is still mandatory, because a directive channel left
/// to fill backs up the driver's control-stream dispatch. Cancel-safe, so it
/// can sit in a `select!` arm: each underlying `recv` is cancel-safe and a
/// turn is only consumed by returning it.
pub(super) async fn recv_turn(channels: &mut TurnChannels) -> Option<Payload> {
    loop {
        tokio::select! {
            payload = channels.inbound.recv() => return payload,
            maybe = channels.leaves.recv() => maybe.is_some().then_some(())?,
            maybe = channels.connectivity.recv() => maybe.is_some().then_some(())?,
            maybe = channels.chat_in.recv() => maybe.is_some().then_some(())?,
            maybe = channels.lobby_in.recv() => maybe.is_some().then_some(())?,
            maybe = channels.skin_in.recv() => maybe.is_some().then_some(())?,
        }
    }
}
