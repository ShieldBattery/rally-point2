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

use rally_point_client::proto::messages::Payload;
use rally_point_client::proto::token::SignedToken;
use rally_point_client::transport::rustls::RootCertStore;
use rally_point_client::transport::rustls::pki_types::CertificateDer;
use rally_point_client::{ClientEndpoint, DriverError, Identity, LinkDriver};
use rally_point_proto::control::RelayEndpoint;
use rally_point_proto::ids::SlotId;
use tokio::task::JoinError;
use tokio::time::{
    Duration, Instant as TokioInstant, MissedTickBehavior, interval_at, sleep_until, timeout,
};

use crate::lifecycle::{DrainResolution, SessionLifecycle};
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
/// A wedged driver must not strand the other players before the shared drain
/// deadline exists. Normal sends enter the bounded driver queue immediately.
const OUTBOUND_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a player waits for its driver to end after signaling a clean leave,
/// before abandoning it as an errored ending.
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(15);
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

/// Compact exact-delivery ledger for one destination player. Each bit names one
/// measured `(origin slot, frame)`; the own-slot range remains unused so indexing
/// stays a cheap multiply/add on the receive path.
struct DeliveryTracker {
    own_slot: usize,
    players: usize,
    measured_turns: usize,
    seen: Vec<bool>,
    distinct: u64,
    duplicate: u64,
}

impl DeliveryTracker {
    fn new(own_slot: SlotId, players: usize, measured_turns: u64) -> Self {
        let measured_turns =
            usize::try_from(measured_turns).expect("validated measured turn count must fit usize");
        let entries = players
            .checked_mul(measured_turns)
            .expect("validated delivery ledger size must fit usize");
        Self {
            own_slot: usize::from(own_slot.0),
            players,
            measured_turns,
            seen: vec![false; entries],
            distinct: 0,
            duplicate: 0,
        }
    }

    fn observe(&mut self, payload: &Payload) {
        let Ok(origin) = usize::try_from(payload.slot) else {
            return;
        };
        let Some(frame) = payload
            .game_frame_count
            .and_then(|frame| usize::try_from(frame).ok())
        else {
            return;
        };
        if origin >= self.players || origin == self.own_slot || frame >= self.measured_turns {
            return;
        }
        let index = origin * self.measured_turns + frame;
        if self.seen[index] {
            self.duplicate += 1;
        } else {
            self.seen[index] = true;
            self.distinct += 1;
        }
    }

    fn expected(&self) -> u64 {
        (self.players.saturating_sub(1) as u64).saturating_mul(self.measured_turns as u64)
    }

    fn is_complete(&self) -> bool {
        self.distinct == self.expected()
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
    let mut deliveries = DeliveryTracker::new(slot, players, measured_turns);

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
    let mut last_recv: HashMap<u32, Instant> = HashMap::new();

    let common_start = if session_started {
        lifecycle.ready_and_wait_for_start().await
    } else {
        lifecycle.abort();
        None
    };
    if let Some(common_start) = common_start {
        let sent_all = pump_turns(
            &mut channels,
            &builder,
            &send_times,
            own_slot,
            turn_interval,
            common_start,
            measured_turns,
            stall_threshold_us,
            &mut last_recv,
            &mut stats,
            &mut deliveries,
            &lifecycle,
        )
        .await;
        if sent_all {
            lifecycle.sender_done();
            let _ = drain_delivery_phase(
                &mut channels,
                &send_times,
                stall_threshold_us,
                &mut last_recv,
                &mut stats,
                &mut deliveries,
                &lifecycle,
            )
            .await;
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
    let ending = drain_until_driver_ends(
        &mut channels,
        &mut handle,
        &send_times,
        stall_threshold_us,
        &mut last_recv,
        &mut stats,
        &mut deliveries,
    )
    .await;

    // The endpoint held the UDP socket for the whole session; drop it now.
    drop(endpoint);

    stats.ending = if session_started {
        ending
    } else {
        Ending::NoSessionStart
    };
    stats.turn_deliveries_distinct = deliveries.distinct;
    stats.turn_deliveries_duplicate = deliveries.duplicate;
    stats
}

/// The steady-state loop: emit the exact measured turn count at the configured
/// interval while draining everything the driver hands back. A driver ending
/// early closes the inbound channel and makes the workload incomplete.
#[allow(clippy::too_many_arguments)]
async fn pump_turns(
    channels: &mut rally_point_client::TurnChannels,
    builder: &TurnBuilder,
    send_times: &SendTimes,
    own_slot: u32,
    turn_interval: Duration,
    common_start: TokioInstant,
    measured_turns: u64,
    stall_threshold_us: u64,
    last_recv: &mut HashMap<u32, Instant>,
    stats: &mut PlayerReport,
    deliveries: &mut DeliveryTracker,
    lifecycle: &SessionLifecycle,
) -> bool {
    let mut ticker = interval_at(common_start, turn_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut lifecycle_changes = lifecycle.subscribe();
    let mut ordinal: u64 = 0;

    while ordinal < measured_turns {
        tokio::select! {
            biased;
            _ = lifecycle.wait_for_abort(&mut lifecycle_changes) => return false,
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
                let send_result = tokio::select! {
                    biased;
                    _ = lifecycle.wait_for_abort(&mut lifecycle_changes) => return false,
                    result = timeout(OUTBOUND_SEND_TIMEOUT, channels.outbound.send(payload)) => result,
                };
                if !matches!(send_result, Ok(Ok(()))) {
                    tracing::warn!(slot = own_slot, frame, "outbound turn send stalled or closed");
                    return false;
                }
                stats.turns_sent += 1;
                ordinal += 1;
            }
            maybe = channels.inbound.recv() => {
                match maybe {
                    Some(payload) => record_inbound(
                        &payload,
                        send_times,
                        stall_threshold_us,
                        last_recv,
                        stats,
                        deliveries,
                    ),
                    None => return false,
                }
            }
            maybe = channels.leaves.recv() => if maybe.is_none() { return false },
            maybe = channels.connectivity.recv() => if maybe.is_none() { return false },
            maybe = channels.chat_in.recv() => if maybe.is_none() { return false },
            maybe = channels.lobby_in.recv() => if maybe.is_none() { return false },
            maybe = channels.skin_in.recv() => if maybe.is_none() { return false },
        }
    }
    true
}

/// Keeps the live link draining after this player's exact send stream finishes.
/// Completion is per destination and exact by `(origin, frame)`; the first
/// player to hit the shared deadline releases the whole session together.
async fn drain_delivery_phase(
    channels: &mut rally_point_client::TurnChannels,
    send_times: &SendTimes,
    stall_threshold_us: u64,
    last_recv: &mut HashMap<u32, Instant>,
    stats: &mut PlayerReport,
    deliveries: &mut DeliveryTracker,
    lifecycle: &SessionLifecycle,
) -> DrainResolution {
    let mut reported_complete = false;
    let mut lifecycle_changes = lifecycle.subscribe();
    loop {
        if deliveries.is_complete() && !reported_complete {
            lifecycle.receiver_done();
            reported_complete = true;
        }

        tokio::select! {
            biased;
            resolution = lifecycle.wait_for_drain_resolution(&mut lifecycle_changes) => {
                return resolution;
            },
            maybe = channels.inbound.recv() => {
                match maybe {
                    Some(payload) => record_inbound(
                        &payload,
                        send_times,
                        stall_threshold_us,
                        last_recv,
                        stats,
                        deliveries,
                    ),
                    None => {
                        lifecycle.abort();
                        return DrainResolution::Aborted;
                    }
                }
            }
            maybe = channels.leaves.recv() => if maybe.is_none() {
                lifecycle.abort();
                return DrainResolution::Aborted;
            },
            maybe = channels.connectivity.recv() => if maybe.is_none() {
                lifecycle.abort();
                return DrainResolution::Aborted;
            },
            maybe = channels.chat_in.recv() => if maybe.is_none() {
                lifecycle.abort();
                return DrainResolution::Aborted;
            },
            maybe = channels.lobby_in.recv() => if maybe.is_none() {
                lifecycle.abort();
                return DrainResolution::Aborted;
            },
            maybe = channels.skin_in.recv() => if maybe.is_none() {
                lifecycle.abort();
                return DrainResolution::Aborted;
            },
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
    deliveries: &mut DeliveryTracker,
) -> Ending {
    let deadline = TokioInstant::now() + TEARDOWN_TIMEOUT;
    let mut inbound_alive = true;
    loop {
        tokio::select! {
            biased;
            res = &mut *handle => {
                drain_buffered_inbound(
                    &mut channels.inbound,
                    send_times,
                    stall_threshold_us,
                    last_recv,
                    stats,
                    deliveries,
                );
                return classify_ending(res);
            },
            _ = sleep_until(deadline) => {
                handle.abort();
                let _ = (&mut *handle).await;
                drain_buffered_inbound(
                    &mut channels.inbound,
                    send_times,
                    stall_threshold_us,
                    last_recv,
                    stats,
                    deliveries,
                );
                return Ending::Errored;
            }
            maybe = channels.inbound.recv(), if inbound_alive => {
                match maybe {
                    Some(payload) => record_inbound(
                        &payload,
                        send_times,
                        stall_threshold_us,
                        last_recv,
                        stats,
                        deliveries,
                    ),
                    None => inbound_alive = false,
                }
            }
            maybe = channels.leaves.recv() => { let _ = maybe; }
            maybe = channels.connectivity.recv() => { let _ = maybe; }
            maybe = channels.chat_in.recv() => { let _ = maybe; }
            maybe = channels.lobby_in.recv() => { let _ = maybe; }
            maybe = channels.skin_in.recv() => { let _ = maybe; }
        }
    }
}

/// Counts payloads the driver already handed to the game channel before its task
/// completed. A Tokio receiver retains buffered values after the sender drops;
/// returning on the joined driver first would otherwise manufacture terminal
/// delivery loss in the harness's own accounting.
fn drain_buffered_inbound(
    inbound: &mut tokio::sync::mpsc::Receiver<Payload>,
    send_times: &SendTimes,
    stall_threshold_us: u64,
    last_recv: &mut HashMap<u32, Instant>,
    stats: &mut PlayerReport,
    deliveries: &mut DeliveryTracker,
) {
    while let Ok(payload) = inbound.try_recv() {
        record_inbound(
            &payload,
            send_times,
            stall_threshold_us,
            last_recv,
            stats,
            deliveries,
        );
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
    deliveries: &mut DeliveryTracker,
) {
    stats.turns_received += 1;
    deliveries.observe(payload);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(origin: u32, frame: u32) -> Payload {
        Payload {
            seq: u64::from(frame),
            slot: origin,
            commands: Default::default(),
            game_frame_count: Some(frame),
            buffer_directive: None,
        }
    }

    #[test]
    fn delivery_tracker_counts_exact_frames_and_duplicates() {
        let mut tracker = DeliveryTracker::new(SlotId(0), 2, 3);
        tracker.observe(&payload(1, 2));
        tracker.observe(&payload(1, 0));
        tracker.observe(&payload(1, 2));
        // Own-slot, unknown-slot, and post-measurement frames are not expected
        // fan-out deliveries and cannot make the ledger look complete.
        tracker.observe(&payload(0, 1));
        tracker.observe(&payload(2, 1));
        tracker.observe(&payload(1, 3));

        assert_eq!(tracker.expected(), 3);
        assert_eq!(tracker.distinct, 2);
        assert_eq!(tracker.duplicate, 1);
        assert!(!tracker.is_complete());

        tracker.observe(&payload(1, 1));
        assert!(tracker.is_complete());
    }

    #[tokio::test]
    async fn buffered_inbound_is_counted_after_the_driver_ends() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        tx.send(payload(1, 0)).await.unwrap();
        drop(tx);

        let send_times: SendTimes = Arc::new(Mutex::new(HashMap::new()));
        let mut last_recv = HashMap::new();
        let mut stats = PlayerReport::default();
        let mut deliveries = DeliveryTracker::new(SlotId(0), 2, 1);
        drain_buffered_inbound(
            &mut rx,
            &send_times,
            1_000,
            &mut last_recv,
            &mut stats,
            &mut deliveries,
        );

        assert_eq!(stats.turns_received, 1);
        assert_eq!(deliveries.distinct, 1);
        assert!(deliveries.is_complete());
    }
}
