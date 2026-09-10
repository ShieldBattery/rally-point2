//! Relay-measured backbone round-trips: ping each region's always-up UDP echo
//! beacon, keep the latest measured medians, and let the heartbeat builder report
//! them up the control connection.
//!
//! The coordinator pushes the fleet's [`RegionBeaconTarget`] set down the control
//! connection ([`crate::coordinator::client`] stores it into [`RegionPingTargets`]);
//! this module's [`run_region_ping`] loop measures a backbone round-trip to each
//! region's beacon and folds the result into a [`RegionRttCache`] the heartbeat
//! builder snapshots. Together they turn the region-pair backbone table from static
//! config into telemetry the fleet measures itself.
//!
//! # What a measurement is
//!
//! Each attempt sends a fresh 8-byte random nonce as the whole UDP datagram and
//! waits for the beacon to echo it back verbatim — the same shape a game client
//! uses to rank regions. A reply counts only when it byte-equals the nonce just
//! sent, so a late echo from an already-timed-out attempt can never be mistaken for
//! a live reply. A region's reported round-trip is the median of its successful
//! attempts; a region with no successful attempt is dropped from the cache
//! (absence, never a zero), and the coordinator retains its last-known value.
//!
//! # Cadence and politeness
//!
//! A relay sweeps once as soon as a non-empty target set arrives, then only every
//! `RESWEEP_INTERVAL` as a backstop — backbone RTTs are stable and relay churn
//! re-measures naturally, so a typical relay sweeps once in its lifetime. Regions
//! are swept strictly serially and attempts are paced `ATTEMPT_SPACING` apart,
//! because the beacons are third-party endpoints that rate-limit inbound datagrams
//! per sender.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rally_point_proto::control::{RegionBeaconTarget, RegionId};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::Instant;

/// Nonce-matched echo attempts per region per sweep. The median of the successful
/// ones is the region's reported round-trip: enough attempts that a single delayed
/// or dropped datagram does not swing the median, few enough to stay polite against
/// a rate-limited beacon.
const ATTEMPTS: usize = 5;

/// Minimum spacing between the *starts* of two consecutive attempts to one beacon.
/// Beacons rate-limit inbound datagrams per sender (~3/sec), so the sweep paces
/// itself under that ceiling. Measured from attempt start, so a fast reply waits
/// out the remainder rather than firing the next attempt early.
const ATTEMPT_SPACING: Duration = Duration::from_millis(400);

/// How long a single attempt waits for its nonce to echo back before giving up on
/// it. Generous next to any real backbone round-trip, so only a genuinely lost
/// datagram times out.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// How often a long-lived relay re-sweeps after its first measurement. Only a
/// backstop: backbone RTTs are stable and relay churn re-measures naturally (every
/// task launch sweeps), so a typical relay never reaches even one re-sweep.
const RESWEEP_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Any measured sample above this is discarded as nonsense — a scheduling stall or
/// a clock artifact, never a real backbone round-trip. A region left with no sane
/// sample is reported absent, not as a garbage value.
const SANITY_CAP: Duration = Duration::from_secs(10);

/// The nonce length, in bytes: the whole payload of a ping datagram, echoed back
/// verbatim by the beacon and matched byte-for-byte on the way in.
const NONCE_LEN: usize = 8;

/// The region ping-beacon targets as the coordinator last pushed them — the set
/// [`run_region_ping`] measures backbone round-trips against.
///
/// A cloneable handle over a `watch` channel, mirroring
/// [`crate::coordinator::client::FleetMeshPeers`]: the coordinator client holds the
/// sender and [`store`](Self::store)s each pushed set, and the ping loop holds a
/// [`subscribe`](Self::subscribe)r that wakes on an actual change. The stored set
/// starts empty — a relay on a region-blind fleet receives no push and measures
/// nothing.
#[derive(Clone)]
pub struct RegionPingTargets {
    targets: Arc<watch::Sender<Vec<RegionBeaconTarget>>>,
}

impl Default for RegionPingTargets {
    fn default() -> Self {
        Self {
            targets: Arc::new(watch::channel(Vec::new()).0),
        }
    }
}

impl RegionPingTargets {
    /// Creates an empty target set (a relay that has received no push).
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the stored set with the coordinator's latest push, waking the ping
    /// loop only when it actually changed. The push is declarative complete state,
    /// so a wholesale replace is correct; a reconnect re-push of an unchanged set
    /// signals nothing, so it does not retrigger a sweep.
    pub fn store(&self, targets: Vec<RegionBeaconTarget>) {
        self.targets.send_if_modified(|current| {
            if *current == targets {
                false
            } else {
                *current = targets;
                true
            }
        });
    }

    /// A receiver the ping loop waits on for the next changed target set. Also used
    /// by tests to observe whether a `store` signaled a change.
    pub fn subscribe(&self) -> watch::Receiver<Vec<RegionBeaconTarget>> {
        self.targets.subscribe()
    }
}

/// The relay's latest measured backbone round-trips, keyed by region — shared
/// between the ping loop (which writes each sweep's results) and the heartbeat
/// builder (which snapshots it onto every beat).
///
/// A plain (non-async) mutex: every critical section is a short, await-free map
/// edit, following the same rule as the relay's other rosters. A region present in
/// the map has a current median; a region the last sweep could not measure is
/// absent, never stored as a zero.
#[derive(Clone, Default)]
pub struct RegionRttCache {
    inner: Arc<Mutex<HashMap<RegionId, u32>>>,
}

impl RegionRttCache {
    /// Creates an empty cache (a relay that has measured nothing yet).
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `region`'s latest measured median round-trip, in milliseconds.
    pub fn record(&self, region: RegionId, rtt_ms: u32) {
        self.inner.lock().insert(region, rtt_ms);
    }

    /// Drops `region` from the cache — a sweep that measured nothing reachable
    /// reports the region as absent, never as a zero.
    fn forget(&self, region: &RegionId) {
        self.inner.lock().remove(region);
    }

    /// A snapshot of the cache as a plain map, cloned under the lock. The heartbeat
    /// builder sorts it into a deterministic wire order.
    pub fn snapshot(&self) -> HashMap<RegionId, u32> {
        self.inner.lock().clone()
    }
}

/// Drives backbone-RTT measurement for the lifetime of the relay: waits for the
/// coordinator's beacon targets, sweeps them once as soon as a non-empty set
/// arrives (and again on any actual change), and otherwise re-sweeps every
/// `RESWEEP_INTERVAL` as a backstop. Each sweep's results land in `cache`, which
/// the heartbeat builder reports up the control connection.
///
/// `own_region` is the region this relay serves (`cli.region`), skipped every sweep
/// — a region's round-trip to itself is zero by definition. `None` (an untagged
/// relay) pings every target. Spawned only for a coordinator-driven relay; a
/// static/dev relay receives no targets and never sweeps.
pub async fn run_region_ping(
    targets: RegionPingTargets,
    cache: RegionRttCache,
    own_region: Option<RegionId>,
) {
    let mut changes = targets.subscribe();
    // Consume the interval's immediate first tick; the backstop fires one interval
    // later. A push-driven sweep is what happens first on a fresh relay.
    let mut resweep = tokio::time::interval(RESWEEP_INTERVAL);
    resweep.tick().await;

    loop {
        // Mark the current set seen, so the `changed()` below waits for a *later*
        // push rather than returning immediately on the set just read.
        let current = changes.borrow_and_update().clone();
        if !current.is_empty() {
            sweep_once(
                &current,
                &cache,
                own_region.as_ref(),
                ATTEMPTS,
                ATTEMPT_SPACING,
                ATTEMPT_TIMEOUT,
                SANITY_CAP,
            )
            .await;
        }
        tokio::select! {
            changed = changes.changed() => {
                if changed.is_err() {
                    // The targets sender was dropped (relay shutdown); no further
                    // push will arrive, so there is nothing left to measure.
                    return;
                }
            }
            _ = resweep.tick() => {}
        }
    }
}

/// Measures every target region once, serially, folding each result into `cache`:
/// a region with at least one good sample gets its median, a region with none is
/// dropped (absence, not a zero). The relay's own region is skipped.
///
/// The attempt count, spacing, per-attempt timeout, and sanity cap are parameters
/// (the loop passes the module constants) so a test can drive a sweep with short
/// timings.
async fn sweep_once(
    targets: &[RegionBeaconTarget],
    cache: &RegionRttCache,
    own_region: Option<&RegionId>,
    attempts: usize,
    spacing: Duration,
    timeout: Duration,
    sanity_cap: Duration,
) {
    for target in targets {
        if own_region == Some(&target.region) {
            continue;
        }
        match measure_region(&target.beacon, attempts, spacing, timeout, sanity_cap).await {
            Some(rtt_ms) => cache.record(target.region.clone(), rtt_ms),
            None => cache.forget(&target.region),
        }
    }
}

/// Measures one region's backbone round-trip: resolves `host:port`, binds an
/// ephemeral UDP socket of the resolved address's family (relays run dual-stack, so
/// a v4 beacon needs a v4 socket and a v6 beacon a v6 socket), and runs `attempts`
/// nonce-matched echoes paced `spacing` apart. Returns the median of the successful
/// attempts in milliseconds, or `None` when the beacon could not be reached or no
/// attempt succeeded.
async fn measure_region(
    beacon: &str,
    attempts: usize,
    spacing: Duration,
    timeout: Duration,
    sanity_cap: Duration,
) -> Option<u32> {
    let mut resolved = match tokio::net::lookup_host(beacon).await {
        Ok(addrs) => addrs,
        Err(error) => {
            tracing::debug!(%beacon, %error, "resolving a region beacon failed; skipping it this sweep");
            return None;
        }
    };
    let Some(addr) = resolved.next() else {
        tracing::debug!(%beacon, "a region beacon resolved to no addresses; skipping it this sweep");
        return None;
    };

    let bind: SocketAddr = if addr.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) => {
            tracing::debug!(%beacon, %error, "binding a region-ping socket failed; skipping it this sweep");
            return None;
        }
    };
    if let Err(error) = socket.connect(addr).await {
        tracing::debug!(%beacon, %addr, %error, "connecting a region-ping socket failed; skipping it this sweep");
        return None;
    }

    let rng = ring::rand::SystemRandom::new();
    let mut samples: Vec<u32> = Vec::with_capacity(attempts);
    for attempt in 0..attempts {
        let started = Instant::now();
        if let Some(rtt) = ping_once(&socket, &rng, timeout).await
            && rtt <= sanity_cap
        {
            samples.push(u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX));
        }
        // Space attempts by their start: a fast reply waits out the remainder of
        // `spacing` so the beacon's per-sender rate limit is never exceeded. No wait
        // after the final attempt — nothing follows it.
        if attempt + 1 < attempts
            && let Some(remaining) = spacing.checked_sub(started.elapsed())
        {
            tokio::time::sleep(remaining).await;
        }
    }
    median(&mut samples)
}

/// Sends one fresh nonce and waits up to `timeout` for the beacon to echo *that*
/// nonce back, returning the round-trip measured from just before the send.
///
/// A reply whose bytes are not the nonce just sent — a late echo of an earlier,
/// already-timed-out attempt — is ignored, and the wait continues under the same
/// deadline, so a stale datagram can never be counted as this attempt's reply. A
/// send/receive error, or the deadline lapsing with no matching reply, yields
/// `None`: a failed attempt, excluded from the median.
async fn ping_once(
    socket: &UdpSocket,
    rng: &ring::rand::SystemRandom,
    timeout: Duration,
) -> Option<Duration> {
    let mut nonce = [0u8; NONCE_LEN];
    if ring::rand::SecureRandom::fill(rng, &mut nonce).is_err() {
        return None;
    }
    let started = Instant::now();
    if socket.send(&nonce).await.is_err() {
        return None;
    }
    let deadline = started + timeout;
    // A little larger than the nonce, so an over-long reply is seen at its true
    // length (and thus fails the byte-equality) rather than being truncated to a
    // false match.
    let mut buf = [0u8; NONCE_LEN * 4];
    loop {
        match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                if buf[..len] == nonce[..] {
                    return Some(started.elapsed());
                }
                // A non-matching reply; keep waiting under the same deadline.
            }
            // A socket error, or the deadline lapsed with no matching reply.
            Ok(Err(_)) | Err(_) => return None,
        }
    }
}

/// The median of the measured samples: sort ascending and take the middle element
/// (the upper-middle for an even count). `None` for no samples — the caller reports
/// the region as absent rather than inventing a zero.
fn median(samples: &mut [u32]) -> Option<u32> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    Some(samples[samples.len() / 2])
}

#[cfg(test)]
mod tests;
