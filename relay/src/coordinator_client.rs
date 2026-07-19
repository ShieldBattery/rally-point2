//! The relay's coordinator client: hold a control connection open and drive the
//! Join source from the descriptors the coordinator pushes down it.
//!
//! This is the relay side of the persistent coordinator↔relay control connection.
//! The relay dials the coordinator's control endpoint (a WebSocket), presents its
//! bootstrap secret, and **enrolls** by sending its `Hello` (id + reachable
//! address) as the first frame — registering itself over the same authenticated
//! connection rather than a separate phone-home. It then receives the
//! coordinator's pushes: the relay's current [`SessionDescriptor`] set, sent on
//! connect and again whenever it changes. Each set is fed to the [`MeshControl`]
//! Join source, which turns it into targeted mesh `Join`/`Leave`.
//!
//! # Why a held connection, not polling
//!
//! The relay reaches *out* to the coordinator (one connection, dialed by the
//! relay) rather than the coordinator reaching into a relay that churns under
//! scale-to-zero and may sit behind a firewall. Holding the connection open means
//! the coordinator pushes a change the instant it happens — no poll interval of
//! staleness — and the connection itself is a liveness signal: when it drops, each
//! side knows immediately. The relay also sends a periodic heartbeat up the
//! connection so the coordinator can tell a live relay from one whose connection
//! died silently (a half-open socket that never delivered a close). Heartbeats go
//! up, descriptors come down. One connection, authenticated once.
//!
//! # Declarative sets, reconnect, and removals
//!
//! Each pushed message is the relay's **whole current set**, not a delta. The set
//! is declarative — re-applying a descriptor already in effect is a no-op on the
//! Join source — so a reconnect (the coordinator re-sends the full set first
//! thing) converges rather than double-applies, and a dropped message is corrected
//! by the next one. The one thing a full set must do that a delta would carry
//! explicitly is detect *removals*: a session gone from the set is one to leave.
//! That is what [`AppliedSessions`] tracks — the sessions delivered on the last
//! set — and it is kept **across reconnects** so a session removed while the relay
//! was disconnected is left when the next connection's full set arrives without it.
//! It is a shared handle (not loop-local state) because the coordinated-drain
//! shutdown path reads it too: a session the coordinator assigned whose clients
//! have not dialed yet holds no local slot, so the applied set is the only signal
//! that the relay is still spoken for (see [`drained_idle`]).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use rally_point_proto::control::{
    CoordinatorToRelay, ENROLL_POP_CONTEXT, FlightRecordingNotice, MeshPeerIdentity,
    RegionRttReport, RelayHello, RelayToCoordinator, SessionDescriptor, SessionPresence,
};
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::{
    CONTROL_CLOSE_DUPLICATE_RELAY_ID, CONTROL_CLOSE_ENROLL_UNAUTHORIZED,
    CONTROL_CLOSE_IDENTITY_UNPROVEN, CONTROL_CLOSE_PROTOCOL_MISMATCH, CONTROL_CLOSE_UNKNOWN_REGION,
};
use rally_point_transport::rustls::pki_types::PrivateKeyDer;
use tokio::sync::mpsc::{Receiver, UnboundedReceiver};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;

use crate::auth::SharedRegistry;
use crate::consensus::RelayNotice;
use crate::flight_recorder::FlightShipment;
use crate::mesh_control::MeshControl;
use crate::region_ping::{RegionPingTargets, RegionRttCache};
use crate::routing::{SessionKey, Sessions};

/// How long to wait before redialing after the control connection drops. The
/// control plane is not latency-critical and a running game does not depend on
/// the connection, so a couple of seconds avoids hammering a coordinator that is
/// restarting or briefly unreachable.
pub const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// How often the relay sends a heartbeat up its control connection, so the
/// coordinator can tell a live relay from one whose connection died silently. Well
/// under the coordinator's liveness deadline, so a single dropped beat or ordinary
/// jitter never trips it. The send doubles as the relay's own dead-coordinator
/// detector: a heartbeat on a half-open socket eventually errors, ending the
/// connection so the relay redials.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// How long to wait before redialing after the coordinator refused the connection
/// over a protocol-version mismatch
/// ([`CONTROL_CLOSE_PROTOCOL_MISMATCH`]). Much longer than [`RECONNECT_DELAY`]:
/// a mismatch is fixed by deploying a compatible build on one side, not by
/// retrying, so hot-redialing every couple of seconds would only re-run the same
/// refused handshake as log noise. Still finite — the deploy that fixes the skew
/// needs no relay restart to take effect.
pub const VERSION_REFUSED_RECONNECT_DELAY: Duration = Duration::from_secs(60);

/// How one control connection ended, when it ended without an error — what the
/// reconnect loop keys its next-dial delay on.
enum ControlDisconnect {
    /// The connection closed ordinarily (a coordinator restart, a plain close, the
    /// stream ending). Redial after [`RECONNECT_DELAY`].
    Ordinary,
    /// The coordinator refused the connection over a protocol-version mismatch
    /// (close code [`CONTROL_CLOSE_PROTOCOL_MISMATCH`]). Redial only after the far
    /// longer [`VERSION_REFUSED_RECONNECT_DELAY`] — nothing changes until a deploy.
    VersionRefused,
    /// The coordinator refused the connection because this relay's `--region` is
    /// not in its configured region list (close code
    /// [`CONTROL_CLOSE_UNKNOWN_REGION`]). Like a version mismatch, hot-retrying
    /// changes nothing — the fix is a config/deploy correction — so it backs off
    /// the same [`VERSION_REFUSED_RECONNECT_DELAY`] rather than the ordinary delay.
    RegionRefused,
    /// The coordinator refused the connection because this relay's enroll
    /// proof-of-possession failed (close code
    /// [`CONTROL_CLOSE_IDENTITY_UNPROVEN`]). A bad signature (or none at all) is
    /// a config/implementation fault — a mismatched key, a broken signer — not a
    /// transient condition a redial fixes, so this backs off the same
    /// [`VERSION_REFUSED_RECONNECT_DELAY`] as a version or region refusal.
    IdentityUnproven,
    /// The coordinator refused the connection because its provisioned-relay
    /// ledger did not authorize this enroll (close code
    /// [`CONTROL_CLOSE_ENROLL_UNAUTHORIZED`]): the id was not minted, is retired,
    /// or the presented token/certificate is invalid. Redialing changes nothing —
    /// the provisioner must reissue an identity or token — so this backs off the
    /// same [`VERSION_REFUSED_RECONNECT_DELAY`] as a version, region, or identity
    /// refusal.
    EnrollUnauthorized,
}

/// The sessions the last-applied descriptor set named — the subscriber's removal
/// detector, shared as a handle so the drain path can read it.
///
/// `reconcile` replaces its contents on every pushed set (and it persists across
/// reconnects, so a session removed while disconnected is left on the next full-set
/// re-sync). The coordinated-drain sequence reads it through [`drained_idle`]: a
/// session the coordinator assigned to this relay appears here the moment its
/// descriptor push is applied — *before* any client dials — so an empty applied set
/// at DrainAck time means the coordinator's post-mark truth names this relay in no
/// session at all. The DrainAck contract guarantees the pre-ack descriptor push is
/// processed (through `apply_message`/`reconcile`, updating this set) before
/// the ack flips the drain-acked signal — both frames applied in arrival order by
/// the single read-half frame processor, so the descriptor push lands before the
/// ack — so the set is authoritative at exactly the moment the drain sequence
/// consults it.
///
/// A plain (non-async) mutex: every critical section is a short, await-free set
/// read or replace, following the same rule as the roster and mesh registries.
#[derive(Clone, Default)]
pub struct AppliedSessions {
    inner: Arc<Mutex<HashSet<SessionKey>>>,
}

impl AppliedSessions {
    /// Creates an empty applied set (a relay that has received no descriptor push).
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the last-applied descriptor set named no session — the coordinator
    /// currently assigns this relay nothing.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// The applied set's current contents, for test assertions.
    #[cfg(test)]
    fn snapshot(&self) -> HashSet<SessionKey> {
        self.inner.lock().clone()
    }
}

/// The fleet's currently-enrolled mesh peers as the coordinator last pushed them:
/// each relay id mapped to the SHA-256 fingerprint of the TLS leaf certificate it
/// enrolled with. The mesh acceptor pins a dialing peer's TLS client certificate
/// against this map, so only a relay the coordinator has enrolled — presenting the
/// exact certificate it enrolled with — is admitted as a mesh peer, with no
/// certificate authority and no out-of-band distribution.
///
/// The coordinator sends the whole set on every control-connection start and again
/// whenever fleet membership changes; the relay replaces its stored map wholesale
/// on each push (declarative current state, like the descriptor set). The map is
/// empty until the first push lands — a coordinator that never sends the set (one
/// predating it) leaves it empty, and the accept-path pin treats an empty map as
/// "pin nothing".
///
/// `watch`-backed so the map is observable: the writer is held by the coordinator
/// client, and [`reader`](Self::reader) hands out cheap, cloneable read handles for
/// the mesh acceptor to consult.
#[derive(Clone)]
pub struct FleetMeshPeers {
    peers: Arc<watch::Sender<HashMap<RelayId, [u8; 32]>>>,
}

impl Default for FleetMeshPeers {
    fn default() -> Self {
        Self {
            peers: Arc::new(watch::channel(HashMap::new()).0),
        }
    }
}

impl FleetMeshPeers {
    /// Creates an empty fleet mesh-peer map (a relay that has received no push).
    pub fn new() -> Self {
        Self::default()
    }

    /// A cheap, cloneable read handle onto the map, for the mesh acceptor to pin a
    /// dialing peer's certificate against.
    pub fn reader(&self) -> FleetMeshPeersReader {
        FleetMeshPeersReader {
            peers: self.peers.subscribe(),
        }
    }

    /// Replaces the stored map with the coordinator's latest full set, waking
    /// observers only when it actually changed. The pushed set is declarative
    /// current state, so a wholesale replace — not a merge — is correct.
    ///
    /// `pub` so a test can seed the map directly — standing in for the
    /// coordinator's control-connection push — without driving a real WebSocket
    /// transport just to get a fingerprint into the map.
    pub fn store(&self, peers: Vec<MeshPeerIdentity>) {
        let next: HashMap<RelayId, [u8; 32]> = peers
            .into_iter()
            .map(|p| (p.relay_id, p.cert_sha256))
            .collect();
        self.peers.send_if_modified(|current| {
            if *current == next {
                false
            } else {
                *current = next;
                true
            }
        });
    }
}

/// A read handle onto the fleet mesh-peer map the coordinator client maintains
/// ([`FleetMeshPeers`]). Cheap to clone; every clone observes the same watch-backed
/// map. The mesh acceptor holds one to pin a dialing peer's TLS client certificate
/// against the coordinator's enrolled-fleet truth.
#[derive(Clone)]
pub struct FleetMeshPeersReader {
    peers: watch::Receiver<HashMap<RelayId, [u8; 32]>>,
}

impl FleetMeshPeersReader {
    /// The fingerprint the coordinator last published for `relay_id`, or `None`
    /// when the fleet map names no such relay — including before the first push,
    /// when the map is empty.
    pub fn fingerprint(&self, relay_id: RelayId) -> Option<[u8; 32]> {
        self.peers.borrow().get(&relay_id).copied()
    }

    /// Whether the fleet map is currently empty — no push has landed yet (or a
    /// coordinator that never sends one).
    pub fn is_empty(&self) -> bool {
        self.peers.borrow().is_empty()
    }
}

/// Point-in-time depths of the coordinator control connection's outbound queues,
/// published for the task-stats reporter to log next to its resource sample.
/// These are the load-test observables for control-plane pressure: how many
/// notices and flight recordings are queued to go up the connection, and how many
/// bytes the one blob currently parked for sending holds.
///
/// The connection's writer refreshes them as it works the queues; the reporter
/// reads a [`snapshot`](Self::snapshot). All zero on a relay with no coordinator
/// connection — nothing writes them — which reads correctly as "no pressure".
/// Relaxed atomics: each field is an independent counter a single writer stores
/// and a single reader loads, with no cross-field invariant to protect.
#[derive(Clone, Default)]
pub struct ControlQueueDepths {
    inner: Arc<ControlQueueDepthsInner>,
}

#[derive(Default)]
struct ControlQueueDepthsInner {
    notices: AtomicUsize,
    flights: AtomicUsize,
    pending_blob_bytes: AtomicUsize,
}

impl ControlQueueDepths {
    /// Creates a fresh, all-zero handle (a relay that has not connected yet, or
    /// one that never will).
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the current queue depths: `notices` and `flights` count everything
    /// waiting to go up the connection (each includes the one item parked mid-send,
    /// if any), and `pending_blob_bytes` is the serialized size of the flight blob
    /// currently parked for sending, or zero when none is.
    fn store(&self, notices: usize, flights: usize, pending_blob_bytes: usize) {
        self.inner.notices.store(notices, Ordering::Relaxed);
        self.inner.flights.store(flights, Ordering::Relaxed);
        self.inner
            .pending_blob_bytes
            .store(pending_blob_bytes, Ordering::Relaxed);
    }

    /// The latest recorded depths, for the task-stats reporter to log.
    pub fn snapshot(&self) -> ControlQueueSnapshot {
        ControlQueueSnapshot {
            notices: self.inner.notices.load(Ordering::Relaxed),
            flights: self.inner.flights.load(Ordering::Relaxed),
            pending_blob_bytes: self.inner.pending_blob_bytes.load(Ordering::Relaxed),
        }
    }
}

/// A snapshot of the coordinator control connection's outbound queue depths (see
/// [`ControlQueueDepths`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ControlQueueSnapshot {
    /// Notices queued to go up the connection, including one parked mid-send.
    pub notices: usize,
    /// Flight recordings queued to go up the connection, including one parked
    /// mid-send.
    pub flights: usize,
    /// Serialized bytes of the flight blob currently parked for sending, or zero.
    pub pending_blob_bytes: usize,
}

/// How the relay reaches and enrolls with the coordinator: where it dials, the
/// optional bootstrap secret the upgrade request presents, the `Hello` it enrolls
/// with, and the private key it proves possession of when challenged. The dial and
/// enroll handshake consume all four; afterward `relay_hello.relay_id` labels every
/// log line and close classification, and `identity_key` answers a mid-stream
/// re-challenge.
pub struct EnrollConfig {
    /// The coordinator base URL; the control endpoint path and `ws(s)` scheme are
    /// derived from it.
    pub coordinator_url: String,
    /// The bootstrap secret the WebSocket upgrade presents as a bearer token, when
    /// one is configured. Absent on a relay the coordinator authenticates another
    /// way.
    pub bootstrap_secret: Option<String>,
    /// The relay's identity + reachable address, sent as the first frame to enroll.
    pub relay_hello: RelayHello,
    /// The private key matching `relay_hello`'s certificate; signs the coordinator's
    /// enroll proof-of-possession challenge.
    pub identity_key: PrivateKeyDer<'static>,
}

/// The shared handles the connection's read half applies coordinator pushes into.
/// Each store holds declarative current state the coordinator re-sends in full on
/// connect, so a push replaces (or, for the descriptor set, reconciles) wholesale.
/// Held across reconnects so the mesh acceptor, client edge, region-ping loop, and
/// drain predicate keep observing the same handles.
pub struct ControlApplyTargets {
    /// The Join source a descriptor set drives to targeted mesh `Join`/`Leave`, and
    /// the reconcile target that keeps `applied` in step with the pushed set.
    pub control: MeshControl,
    /// The last-applied session set, reconciled on every descriptor push. Its
    /// interior is mutated in place across reconnects, so a session removed while
    /// disconnected is left when the next full-set re-sync arrives without it. The
    /// drain sequence reads it through [`drained_idle`] to tell an
    /// assigned-but-undialed session from a provably unassigned relay.
    pub applied: AppliedSessions,
    /// The fleet mesh-peer map, replaced wholesale on every `MeshPeers` push; the
    /// mesh acceptor pins a dialing peer's certificate against it.
    pub fleet: FleetMeshPeers,
    /// The tenant verifying-key registry, replaced wholesale on every `TenantKeys`
    /// push; the client edge checks authorization tokens against it. The coordinator
    /// sends it before the first descriptor, so a session's clients are verifiable by
    /// the time its descriptor lands.
    pub verifying_keys: SharedRegistry,
    /// The region ping-beacon targets, replaced wholesale on every `RegionBeacons`
    /// push; the region-ping loop measures a backbone round-trip to each.
    pub region_targets: RegionPingTargets,
    /// Flipped to `true` when a `DrainAck` is read, unblocking the drain sequence.
    /// Because the read half applies inbound frames in arrival order, the pre-ack
    /// descriptor push has already reconciled `applied` by the time this fires.
    pub drain_acked: watch::Sender<bool>,
}

/// The relay's outbound work queues and the depth handle that reports their
/// occupancy. Each pipe is a channel plus the one in-flight slot holding the item
/// pulled from it but not yet confirmed sent.
///
/// **Caller-owned across reconnects.** The subscriber owns this and lends `&mut`
/// per connection: an item parked in a slot when a connection dies stays parked and
/// rides the next connection's flush rather than being lost. The write half sets a
/// slot *before* the send await and clears it only *after* the send returns, with
/// no await between — so a dropped or errored send leaves the undelivered item
/// parked, while a completed send's item is already cleared and never re-sent.
pub struct OutboundQueues {
    /// The unbounded notice pipe: departure/desync/result/session-closed notices to
    /// forward up the connection. Drained strictly FIFO through `pending`, which is
    /// what keeps `SessionClosed`'s "no earlier notice for the session still in
    /// flight" guarantee.
    pub notices: UnboundedReceiver<RelayNotice>,
    /// The one notice pulled but not yet confirmed sent.
    pub pending: Option<RelayNotice>,
    /// The bounded flight pipe: flushed recordings to ship up the connection.
    /// Deliberately separate from `notices` so a blob frame never delays a notice;
    /// bounded so a wedged connection drops recordings rather than growing unbounded.
    pub flight: Receiver<FlightShipment>,
    /// The one flight shipment pulled but not yet confirmed sent; its `sent` ack
    /// fires only once the frame is on the socket, so the sink's await bounds real
    /// delivery.
    pub pending_flight: Option<FlightShipment>,
    /// Publishes the two queue depths (and the parked blob's byte count) for the
    /// task-stats reporter.
    pub depths: ControlQueueDepths,
}

impl OutboundQueues {
    /// Builds the queues over the given channels and depth reporter, with both
    /// in-flight slots empty.
    pub fn new(
        notices: UnboundedReceiver<RelayNotice>,
        flight: Receiver<FlightShipment>,
        depths: ControlQueueDepths,
    ) -> Self {
        Self {
            notices,
            pending: None,
            flight,
            pending_flight: None,
            depths,
        }
    }
}

/// What each heartbeat carries and how often it goes up. A beat snapshots the live
/// roster and the measured region round-trips at send time; both handles are held
/// across reconnects so a beat reads current state independent of any reconnect.
pub struct HeartbeatConfig {
    /// The live roster; each beat carries its connected slots as [`SessionPresence`]
    /// entries (tenant/session/slot only — the relay holds no user identity to leak).
    pub sessions: Sessions,
    /// The measured region round-trip cache the ping loop writes; each beat carries
    /// its current medians.
    pub region_rtt_cache: RegionRttCache,
    /// How often a beat goes up. Well under the coordinator's liveness deadline, and
    /// the send doubles as the relay's own dead-coordinator detector.
    pub interval: Duration,
}

/// The two redial delays the reconnect loop keys its next dial on: the ordinary
/// delay after a plain close, and the far longer delay after an
/// operator-fix-not-redial refusal (protocol version, region, identity, or
/// enrollment) where hot-retrying changes nothing until a deploy.
pub struct ReconnectBackoff {
    /// Delay after an ordinary close, an error, or a duplicate-relay-id refusal that
    /// resolves on its own.
    pub ordinary: Duration,
    /// Delay after a version/region/identity/enrollment refusal.
    pub version_refused: Duration,
}

/// Whether the relay is drained-idle — safe to exit without abandoning anyone: it
/// holds **no local slot** ([`crate::routing::holds_any_slots`]) *and* its
/// last-applied descriptor set is **empty**.
///
/// Both halves are load-bearing. Slot liveness alone misses a session the
/// coordinator committed to this relay just before the drain mark whose clients
/// have not dialed yet — exiting then strands them dialing a dead relay pre-start,
/// which the client driver cannot recover (it escalates to re-home only after
/// `SessionStart`). The applied set alone would over-wait: it can linger for a
/// multi-relay session a *peer* still serves after our players left, or a session
/// whose clients never dial. So the drain sequence waits on both, bounded by the
/// drain timeout — an empty set at ack time exits immediately (the truly-idle
/// scale-in case), a non-empty one waits so not-yet-dialed clients can connect and
/// be served, and whatever outlives the timeout is abandoned to the
/// coordinator-mediated failover.
pub fn drained_idle(sessions: &Sessions, applied: &AppliedSessions) -> bool {
    !crate::routing::holds_any_slots(sessions) && applied.is_empty()
}

/// Why a control-connection attempt ended.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// Building the request, dialing, the handshake, or a read on the WebSocket
    /// failed — including a rejected auth handshake (a non-101 response). Boxed
    /// because `tungstenite::Error` is large and would bloat every `Result`.
    #[error("coordinator control connection failed: {0}")]
    WebSocket(Box<tokio_tungstenite::tungstenite::Error>),
    /// A pushed control message did not decode.
    #[error("decoding a coordinator control message failed: {0}")]
    Decode(#[from] serde_json::Error),
    /// The `Authorization` header value could not be built from the secret.
    #[error("building the control request authorization failed: {0}")]
    Authorization(#[from] tokio_tungstenite::tungstenite::http::header::InvalidHeaderValue),
    /// The loaded identity private key is not an algorithm the enroll
    /// proof-of-possession signer supports, so the coordinator's identity
    /// challenge cannot be answered. A configuration/build fault — a key this
    /// relay's own certificate loading could never have produced — not a
    /// transient condition, so it ends the connection rather than leaving the
    /// challenge silently unanswered.
    #[error("the loaded identity key cannot sign the enroll proof-of-possession challenge")]
    UnsupportedIdentityKey,
}

impl From<tokio_tungstenite::tungstenite::Error> for ControlError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        ControlError::WebSocket(Box::new(error))
    }
}

/// Holds the coordinator control connection open and drives the Join source,
/// reconnecting whenever it drops. Spawned as a task on the relay when a
/// coordinator URL is configured; never returns.
///
/// The relay dials `enroll.coordinator_url`, enrolls with `enroll.relay_hello`, and
/// proves possession of `enroll.identity_key` when the coordinator challenges — a
/// challenge that always happens, since the relay's advertised protocol window
/// bottoms out at or above the proof-of-possession minimum, so any coordinator it
/// shares a version with reaches the challenge.
///
/// `apply_targets` are the shared handles inbound coordinator pushes are applied
/// into ([`ControlApplyTargets`]); `outbound` is the caller-owned notice and flight
/// queues the connection ships up ([`OutboundQueues`], which documents the
/// park-across-reconnect discipline); `sessions` and `region_rtt_cache` are what
/// each heartbeat carries; `drain` (with `apply_targets.drain_acked`) is the
/// coordinated-drain seam; `control_connected` reports whether the connection is
/// currently established, so the provisional-admission sweep
/// ([`crate::provisional::run_sweep`]) arms only while it is `true` rather than
/// reaping across a reconnect gap.
///
/// This entry injects the production reconnect delays and heartbeat interval;
/// [`run_descriptor_subscriber_with`] takes them explicitly so a test need not wait
/// the production intervals.
pub async fn run_descriptor_subscriber(
    enroll: EnrollConfig,
    apply_targets: ControlApplyTargets,
    outbound: OutboundQueues,
    sessions: Sessions,
    region_rtt_cache: RegionRttCache,
    drain: watch::Receiver<bool>,
    control_connected: watch::Sender<bool>,
) {
    run_descriptor_subscriber_with(
        enroll,
        apply_targets,
        outbound,
        HeartbeatConfig {
            sessions,
            region_rtt_cache,
            interval: HEARTBEAT_INTERVAL,
        },
        drain,
        control_connected,
        ReconnectBackoff {
            ordinary: RECONNECT_DELAY,
            version_refused: VERSION_REFUSED_RECONNECT_DELAY,
        },
    )
    .await
}

/// [`run_descriptor_subscriber`] with the reconnect delays and heartbeat interval
/// injected via `heartbeat` and `backoff`, so a test need not wait the production
/// intervals.
pub async fn run_descriptor_subscriber_with(
    enroll: EnrollConfig,
    apply_targets: ControlApplyTargets,
    // Caller-owned across reconnects: this loop owns the outbound queues and lends
    // `&mut` per connection, so a notice or shipment parked when a connection dies
    // rides the next connection's flush rather than being lost.
    mut outbound: OutboundQueues,
    heartbeat: HeartbeatConfig,
    mut drain: watch::Receiver<bool>,
    control_connected: watch::Sender<bool>,
    backoff: ReconnectBackoff,
) {
    let relay_id = enroll.relay_hello.relay_id;

    loop {
        let delay = match connect_and_stream(
            &enroll,
            &apply_targets,
            &mut outbound,
            &heartbeat,
            &mut drain,
            &control_connected,
        )
        .await
        {
            Ok(ControlDisconnect::Ordinary) => {
                tracing::info!(
                    relay_id = relay_id.0,
                    "coordinator control connection closed; reconnecting",
                );
                backoff.ordinary
            }
            // Already logged (with the coordinator's reason) where the close frame
            // was read; only the far longer backoff is decided here. A version
            // mismatch, an unknown region, an unproven identity, and a ledger
            // enrollment refusal are all operator/provisioner-fix-not-redial
            // refusals, so they share the long backoff. A duplicate-relay-id
            // refusal is deliberately absent from this list — it resolves on its
            // own as the stale entry ages out, so it takes the `Ordinary` path's
            // short delay instead.
            Ok(
                ControlDisconnect::VersionRefused
                | ControlDisconnect::RegionRefused
                | ControlDisconnect::IdentityUnproven
                | ControlDisconnect::EnrollUnauthorized,
            ) => backoff.version_refused,
            Err(error) => {
                tracing::warn!(
                    %error,
                    relay_id = relay_id.0,
                    "coordinator control connection failed; reconnecting",
                );
                backoff.ordinary
            }
        };
        // The connection just ended, however it ended -- report it down
        // uniformly here rather than at each of `connect_and_stream`'s several
        // exit points, so the provisional-admission sweep never observes a
        // stale "connected" reading across a reconnect gap.
        let _ = control_connected.send(false);
        tokio::time::sleep(delay).await;
    }
}

/// Dials the coordinator's control endpoint, enrolls by sending the relay's
/// `Hello` as the first frame, then applies every descriptor set the coordinator
/// pushes while sending a periodic heartbeat up the connection — until it closes
/// or errors. `applied` is updated in place across the connection's lifetime (and
/// persists into the next one). A clean ending reports *how* the connection ended
/// ([`ControlDisconnect`]), so the caller can back off a version refusal far
/// longer than an ordinary close.
///
/// Everything through the enroll handshake and its immediately-following flushes
/// runs sequentially on the whole socket. After that the socket is split into a
/// read half and a write half driven **concurrently**, so a large outbound frame
/// (a heartbeat, a close notice, or a multi-megabyte flight blob) can never stall
/// the reader while it is being sent: coordinator pushes keep applying while a blob
/// goes up. The two halves cooperate on one task — dropping either when the other
/// ends closes the connection with no task to leak — and every send is owned by the
/// write half, keeping the notice pipe strictly ordered and the caller-owned
/// `pending`/`pending_flight` slots the single source of undelivered state across a
/// reconnect.
///
/// A heartbeat send that fails ends the connection so the caller redials: on a
/// half-open socket (a silently dead coordinator) the periodic send is what
/// eventually surfaces the failure, since no inbound frame arrives to reveal it.
async fn connect_and_stream(
    enroll: &EnrollConfig,
    apply_targets: &ControlApplyTargets,
    outbound: &mut OutboundQueues,
    heartbeat: &HeartbeatConfig,
    drain: &mut watch::Receiver<bool>,
    control_connected: &watch::Sender<bool>,
) -> Result<ControlDisconnect, ControlError> {
    let relay_id = enroll.relay_hello.relay_id;
    let request = build_request(&enroll.coordinator_url, enroll.bootstrap_secret.as_deref())?;
    let (mut socket, _response) = tokio_tungstenite::connect_async(request).await?;

    // Enroll: the first frame is this relay's Hello, registering it on the same
    // authenticated connection that then carries descriptor pushes back.
    let hello = serde_json::to_string(&RelayToCoordinator::Hello(enroll.relay_hello.clone()))
        .expect("a relay hello always serializes");
    socket.send(Message::Text(hello.into())).await?;
    tracing::info!(
        relay_id = relay_id.0,
        "coordinator control connection established",
    );
    // Reported established the instant the Hello is on the wire, matching
    // this connection's own "on connect, the full descriptor set resyncs
    // immediately" contract: the provisional-admission sweep arming here is
    // exactly what lets it restart every mark's window right as that resync
    // is about to land, rather than waiting on it.
    let _ = control_connected.send(true);

    // Complete the enroll proof-of-possession handshake before sending any
    // application frame. The coordinator sends an `IdentityChallenge` as the
    // first frame after the Hello and reads exactly one frame back expecting the
    // `IdentityProof`; if a pending notice or a drain re-assert reached the wire
    // first, the coordinator would read that instead and refuse the enroll — and
    // a pending notice persists across reconnects, locking the relay out of
    // re-enrolling indefinitely. Read frames until the challenge is answered.
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                match serde_json::from_str::<CoordinatorToRelay>(text.as_str())? {
                    CoordinatorToRelay::IdentityChallenge { nonce } => {
                        answer_identity_challenge(
                            &mut socket,
                            &enroll.identity_key,
                            &nonce,
                            relay_id,
                        )
                        .await?;
                        break;
                    }
                    // The coordinator always challenges first, so any other frame
                    // here is a protocol violation. End the connection rather than
                    // proceed un-enrolled; the caller redials.
                    _ => {
                        tracing::warn!(
                            relay_id = relay_id.0,
                            "coordinator sent a control frame before the enroll challenge; \
                             disconnecting",
                        );
                        return Ok(ControlDisconnect::Ordinary);
                    }
                }
            }
            // A refusal that arrives before the challenge: the coordinator
            // validates version and region before challenging and closes on
            // failure. Classify it with the same helper the steady-state loop uses.
            Some(Ok(Message::Close(frame))) => {
                return Ok(classify_control_close(frame, relay_id));
            }
            // Ping/pong (and any other non-text frame) carry no enrollment content;
            // keep reading for the challenge.
            Some(Ok(_)) => continue,
            // A read error ends the connection with that error.
            Some(Err(error)) => return Err(error.into()),
            // The stream ended before the challenge; let the caller redial.
            None => return Ok(ControlDisconnect::Ordinary),
        }
    }

    // The enroll handshake is complete, so application frames may now go out.
    // Flush a notice held over from a prior connection first: one decided while
    // the coordinator was down (or one a failed send left pending) must go out on
    // this fresh connection before anything else, so it is not lost to the
    // reconnect. On send failure it stays pending and rides the next reconnect.
    if let Some(notice) = outbound.pending.as_ref() {
        send_notice(&mut socket, notice).await?;
        outbound.pending = None;
    }

    // Re-assert a drain that is already in progress. A re-enroll clears the
    // coordinator-side draining flag, so if we are mid-drain this fresh connection
    // must re-send `Draining` (right after enrolling, ahead of the steady-state
    // loop) or the coordinator would treat us as available again.
    // `borrow_and_update` also marks the current value seen, so the loop's
    // `drain.changed()` below fires only on a *new* transition.
    if *drain.borrow_and_update() {
        send_draining(&mut socket).await?;
    }

    // Flush a flight shipment held over from a prior connection, after the pending
    // notice and the drain re-assert. The flight pipe is deliberately separate
    // from the notice pipe: `SessionClosed`'s "no earlier notice for the session
    // still in flight" ordering is a property of the notice channel alone, and a
    // blob frame must never delay a webhook-bearing notice. On send failure the
    // shipment stays in `pending_flight` and rides the next reconnect; the ack
    // fires only after the frame is on the socket.
    if outbound.pending_flight.is_some() {
        send_flight(
            &mut socket,
            &outbound
                .pending_flight
                .as_ref()
                .expect("just checked")
                .notice,
        )
        .await?;
        if let Some(shipment) = outbound.pending_flight.take() {
            let _ = shipment.sent.send(());
        }
    }

    // Split the enrolled socket into a read half and a write half, driven
    // concurrently. The write half owns every send, so a large frame in flight
    // (a heartbeat, a notice, or a multi-megabyte flight blob) never stalls the
    // read half — coordinator pushes keep applying while a blob goes up.
    let (sink, stream) = socket.split();

    // A mid-stream identity challenge's answer is a *send*, and only the write
    // half may send, so the read half routes the nonce here for the writer to
    // answer. The coordinator does not re-challenge after enroll, so this is a
    // rarely-if-ever-used defensive path.
    let (challenge_tx, challenge_rx) = tokio::sync::mpsc::unbounded_channel();

    // Run both halves until either ends; the first to finish is the connection's
    // outcome, and dropping the other closes its half of the socket. There is no
    // spawned task to leak, and the caller-owned `outbound` slots — mutated in place
    // by the writer through `&mut` — carry whatever stayed undelivered straight back
    // to the caller no matter which half ended the connection.
    tokio::select! {
        result = read_control_frames(stream, apply_targets, relay_id, challenge_tx) => result,
        result = write_control_frames(
            sink,
            outbound,
            drain,
            heartbeat,
            &enroll.identity_key,
            relay_id,
            challenge_rx,
        ) => result,
    }
}

/// The read half of an enrolled control connection: receives coordinator frames
/// one at a time and applies each synchronously, in arrival order. A descriptor
/// push reconciles the Join source and the applied set; `MeshPeers`/`TenantKeys`/
/// `RegionBeacons` replace their stores; a `DrainAck` flips the drain-acked
/// signal. Because frames apply strictly in arrival order, a descriptor push the
/// coordinator sends just before a `DrainAck` has already updated the applied set
/// by the time the ack fires.
///
/// A mid-stream `IdentityChallenge`'s answer is a send, so it is routed to the
/// write half through `challenge_tx` rather than answered here. A `Close` (or the
/// stream ending, or a read/decode error) ends the connection with the same
/// classification a close carries anywhere.
async fn read_control_frames(
    mut stream: impl futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
    + Unpin,
    apply_targets: &ControlApplyTargets,
    relay_id: RelayId,
    challenge_tx: tokio::sync::mpsc::UnboundedSender<[u8; 32]>,
) -> Result<ControlDisconnect, ControlError> {
    loop {
        // The stream ended (no close frame): let the caller redial.
        let Some(message) = stream.next().await else {
            return Ok(ControlDisconnect::Ordinary);
        };
        match message? {
            Message::Text(text) => {
                let message: CoordinatorToRelay = serde_json::from_str(text.as_str())?;
                match message {
                    CoordinatorToRelay::DrainAck => {
                        // The coordinator has marked us ineligible and pushed our
                        // current descriptor set just before this ack; signal the
                        // drain sequence it may proceed (empty set ⇒ unassigned).
                        let _ = apply_targets.drain_acked.send(true);
                    }
                    CoordinatorToRelay::MeshPeers { peers } => {
                        // The fleet's currently-enrolled mesh peers: store the whole
                        // set, replacing the prior one. Declarative current state — a
                        // reconnect re-syncs the full set — so a wholesale replace is
                        // correct.
                        apply_targets.fleet.store(peers);
                    }
                    CoordinatorToRelay::TenantKeys { keys } => {
                        // The tenant verifying keys the client edge checks
                        // authorization tokens against: replace the whole registry,
                        // skipping any malformed entry. Declarative current state,
                        // sent before the first descriptor, so the relay can always
                        // verify a session's clients by the time its descriptor
                        // arrives.
                        apply_targets.verifying_keys.apply(keys);
                    }
                    CoordinatorToRelay::RegionBeacons { beacons } => {
                        // The region ping-beacon targets: store the whole set,
                        // replacing the prior one. Declarative current state — a
                        // reconnect re-syncs the full set — so a wholesale replace is
                        // correct, and an unchanged re-push wakes no sweep.
                        apply_targets.region_targets.store(beacons);
                    }
                    CoordinatorToRelay::IdentityChallenge { nonce } => {
                        // Answering is a send, which only the write half may do, so
                        // route the nonce there. A dropped receiver means the write
                        // half is already gone and the connection is ending, so a
                        // failed route is a harmless no-op.
                        let _ = challenge_tx.send(nonce);
                    }
                    other => apply_message(&apply_targets.control, other, &apply_targets.applied),
                }
            }
            Message::Close(frame) => {
                // Classify the refusal (and log its stated reason) with the same
                // helper the enroll handshake uses, so a close is read identically
                // wherever it arrives.
                return Ok(classify_control_close(frame, relay_id));
            }
            // The coordinator sends no pings today and the relay reads only
            // descriptor text frames; any other frame is ignored.
            Message::Ping(_) | Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => {}
        }
    }
}

/// The write half of an enrolled control connection: owns every send and drives a
/// `biased` priority order so bulk can never delay control. Highest first: a drain
/// re-assert, then queued notices, then a routed identity-proof answer, then the
/// periodic heartbeat, and last the flight blobs — so a close-bearing notice
/// always outruns a multi-megabyte recording.
///
/// The caller-owned `outbound` slots (`pending`, `pending_flight`) are this half's
/// only durable state across a reconnect. A notice or shipment is parked in its
/// slot *before* the send await and cleared only *after* the send returns, with no
/// await in between: if this future is dropped (the read half ended the connection)
/// or a send errors mid-frame, the slot still holds the undelivered item and the
/// next connection's flush delivers it, while an item whose send completed is
/// already cleared and never re-sent.
async fn write_control_frames(
    mut sink: impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    outbound: &mut OutboundQueues,
    drain: &mut watch::Receiver<bool>,
    heartbeat: &HeartbeatConfig,
    identity_key: &PrivateKeyDer<'static>,
    relay_id: RelayId,
    mut challenge_rx: UnboundedReceiver<[u8; 32]>,
) -> Result<ControlDisconnect, ControlError> {
    // Split the caller-owned queues into their fields. The park/clear discipline
    // below mutates these in place, so whatever stays parked in a slot here is
    // exactly what the caller's `outbound` holds when this future ends.
    let OutboundQueues {
        notices,
        pending,
        flight,
        pending_flight,
        depths,
    } = outbound;

    // The Hello already proved liveness at t=0, so skip the immediate first tick
    // and send the first heartbeat one interval later.
    let mut heartbeat_tick = tokio::time::interval(heartbeat.interval);
    heartbeat_tick.tick().await;

    // Once the notifier's senders are all dropped (relay shutdown) `recv` yields
    // `None` forever; stop selecting on it so the loop doesn't spin.
    let mut notifier_open = true;
    // Likewise for the flight channel: a standalone relay never installs the
    // coordinator sink, so its sender is dropped and `recv` yields `None` forever;
    // disable the arm on the first `None` rather than spin.
    let mut flight_open = true;
    // Likewise for the drain watch: if its sender is dropped (a relay with no drain
    // sequence wired), `changed()` errors forever, so disable the arm on the first
    // error rather than spin.
    let mut drain_open = true;
    // The read half holds the challenge sender for the connection's life, so this
    // normally stays open until both halves are dropped together; the guard is a
    // belt-and-suspenders against a closed channel busy-looping the biased select.
    let mut challenge_open = true;

    loop {
        // Publish the current queue depths for the task-stats reporter. Each count
        // includes the one item parked mid-send, so a blob in flight is visible for
        // its whole send rather than only in the instant between sends.
        depths.store(
            notices.len() + usize::from(pending.is_some()),
            flight.len() + usize::from(pending_flight.is_some()),
            pending_flight
                .as_ref()
                .map_or(0, |shipment| shipment.notice.payload.len()),
        );

        tokio::select! {
            biased;

            // The drain sequence flipped the flag: ask the coordinator to stop
            // assigning us new sessions. A send error ends the connection; the next
            // reconnect re-asserts the drain right after its Hello.
            changed = drain.changed(), if drain_open => {
                match changed {
                    Ok(()) => {
                        if *drain.borrow_and_update() {
                            send_draining(&mut sink).await?;
                        }
                    }
                    // The drain sender was dropped: no drain will ever come.
                    Err(_) => drain_open = false,
                }
            }

            // Drain one notice at a time: pull the next only once the current one
            // is confirmed sent (the `pending.is_none()` guard), so an undelivered
            // notice always sits in `pending` where the reconnect flush picks it up.
            // Strictly ordered — one ordered pipe, one in-flight slot — which is what
            // keeps `SessionClosed`'s "no earlier notice for the session still in
            // flight" guarantee.
            notice = notices.recv(), if pending.is_none() && notifier_open => {
                match notice {
                    Some(notice) => {
                        *pending = Some(notice);
                        // A send error ends the connection (via `?`) with the notice
                        // still pending, so the next connection flushes it.
                        send_notice(&mut sink, pending.as_ref().expect("just set")).await?;
                        *pending = None;
                    }
                    None => notifier_open = false,
                }
            }

            // A mid-stream identity challenge the read half routed here: answering
            // is a send, so it happens on this half. A dropped sender means the read
            // half has ended and this half is about to be dropped too.
            nonce = challenge_rx.recv(), if challenge_open => {
                match nonce {
                    Some(nonce) => {
                        answer_identity_challenge(&mut sink, identity_key, &nonce, relay_id).await?;
                    }
                    None => challenge_open = false,
                }
            }

            _ = heartbeat_tick.tick() => {
                // Every beat carries the full current roster — declarative and
                // self-healing (a lost or reordered beat is corrected by the next
                // one), bounded by the relay's live slots. A delta scheme is a
                // scale option, not needed at these payload sizes.
                let frame = serde_json::to_string(&RelayToCoordinator::Heartbeat {
                    sessions: heartbeat_presence(&heartbeat.sessions),
                    region_rtts: heartbeat_region_rtts(&heartbeat.region_rtt_cache),
                })
                .expect("a heartbeat always serializes");
                sink.send(Message::Text(frame.into())).await?;
            }

            // Ship one flight recording at a time: pull the next only once the
            // current is confirmed sent (the `pending_flight.is_none()` guard), so an
            // unsent shipment always sits in `pending_flight` for the reconnect flush.
            // Deliberately below the notices arm: a blob frame — larger and never
            // webhook-bearing — must never delay a notice, which is why the priority
            // order sits it here.
            shipment = flight.recv(), if pending_flight.is_none() && flight_open => {
                match shipment {
                    Some(shipment) => {
                        *pending_flight = Some(shipment);
                        // Republish now that the blob is parked, so its byte count is
                        // visible for the whole send rather than only after it returns.
                        depths.store(
                            notices.len() + usize::from(pending.is_some()),
                            flight.len() + usize::from(pending_flight.is_some()),
                            pending_flight
                                .as_ref()
                                .map_or(0, |shipment| shipment.notice.payload.len()),
                        );
                        // A send error ends the connection (via `?`) with the shipment
                        // still pending, so the next connection flushes it.
                        send_flight(
                            &mut sink,
                            &pending_flight.as_ref().expect("just set").notice,
                        )
                        .await?;
                        // Fire the ack (and clear the slot) only after the frame is on
                        // the socket, so the sink's await resolves to delivered only
                        // for a shipment that truly went out.
                        if let Some(shipment) = pending_flight.take() {
                            let _ = shipment.sent.send(());
                        }
                    }
                    None => flight_open = false,
                }
            }
        }
    }
}

/// Snapshots the relay's live roster into the [`SessionPresence`] entries a
/// heartbeat carries — one per session with a connected slot, tenant/session/slot
/// only (the relay holds no user identity to leak).
fn heartbeat_presence(sessions: &Sessions) -> Vec<SessionPresence> {
    crate::routing::live_slots(sessions)
        .into_iter()
        .map(|(key, slots)| SessionPresence {
            tenant: key.tenant,
            session: key.session,
            slots,
        })
        .collect()
}

/// Snapshots the region-ping cache into the [`RegionRttReport`] entries a heartbeat
/// carries — one per region the relay currently has a measured median for, sorted
/// by region id so the beat's wire output is deterministic. Empty until the relay
/// has measured anything, and empty entries are omitted from the wire.
fn heartbeat_region_rtts(cache: &RegionRttCache) -> Vec<RegionRttReport> {
    let mut reports: Vec<RegionRttReport> = cache
        .snapshot()
        .into_iter()
        .map(|(region, rtt_ms)| RegionRttReport { region, rtt_ms })
        .collect();
    reports.sort_by(|a, b| a.region.0.cmp(&b.region.0));
    reports
}

/// Sends a [`RelayToCoordinator::Draining`] up the control connection, asking the
/// coordinator to stop assigning this relay new sessions.
async fn send_draining(
    socket: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
) -> Result<(), ControlError> {
    let frame =
        serde_json::to_string(&RelayToCoordinator::Draining).expect("a draining frame serializes");
    socket.send(Message::Text(frame.into())).await?;
    Ok(())
}

/// Sends one relay notice up the control connection as a tagged JSON frame,
/// wrapping it into the matching [`RelayToCoordinator`] variant by kind.
async fn send_notice(
    socket: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    notice: &RelayNotice,
) -> Result<(), ControlError> {
    let frame = match notice {
        RelayNotice::Departure(notice) => RelayToCoordinator::Departure(notice.clone()),
        RelayNotice::Desync(notice) => RelayToCoordinator::Desync(notice.clone()),
        RelayNotice::Result(notice) => RelayToCoordinator::Result(notice.clone()),
        RelayNotice::SessionClosed { tenant, session } => RelayToCoordinator::SessionClosed {
            tenant: tenant.clone(),
            session: *session,
        },
    };
    let text = serde_json::to_string(&frame).expect("a relay notice always serializes");
    socket.send(Message::Text(text.into())).await?;
    Ok(())
}

/// Sends one flushed flight recording up the control connection as a tagged
/// [`RelayToCoordinator::FlightRecording`] JSON frame.
async fn send_flight(
    socket: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    notice: &FlightRecordingNotice,
) -> Result<(), ControlError> {
    let frame = serde_json::to_string(&RelayToCoordinator::FlightRecording(notice.clone()))
        .expect("a flight recording frame always serializes");
    socket.send(Message::Text(frame.into())).await?;
    Ok(())
}

/// Answers the coordinator's enroll proof-of-possession challenge: signs
/// `ENROLL_POP_CONTEXT ++ nonce` with the relay's identity key (see
/// [`sign_enroll_proof`]) and sends the [`RelayToCoordinator::IdentityProof`] up
/// the connection, so the coordinator's verification against the certificate the
/// `Hello` presented succeeds.
///
/// A key this relay's own certificate loading could never have produced cannot
/// sign the challenge; that surfaces as [`ControlError::UnsupportedIdentityKey`],
/// ending the connection rather than proceeding un-enrolled. Both the enroll
/// handshake and the steady-state loop's defensive re-answer route through here,
/// so a challenge is answered identically wherever it arrives.
async fn answer_identity_challenge(
    socket: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    identity_key: &PrivateKeyDer<'static>,
    nonce: &[u8; 32],
    relay_id: RelayId,
) -> Result<(), ControlError> {
    match sign_enroll_proof(identity_key, nonce) {
        Some(signature) => {
            let frame = serde_json::to_string(&RelayToCoordinator::IdentityProof { signature })
                .expect("an identity-proof frame always serializes");
            socket.send(Message::Text(frame.into())).await?;
            Ok(())
        }
        None => {
            tracing::error!(
                relay_id = relay_id.0,
                "cannot answer the coordinator's enroll proof-of-possession challenge: \
                 the loaded private key is not a supported algorithm",
            );
            Err(ControlError::UnsupportedIdentityKey)
        }
    }
}

/// Classifies a coordinator control-connection close into the
/// [`ControlDisconnect`] the reconnect loop backs its next-dial delay on, logging
/// the coordinator's stated reason at the level each code warrants. Shared by the
/// enroll handshake and the steady-state loop so a close is read identically
/// whether it lands before or after the identity challenge.
///
/// A version mismatch, an unknown region, and an unproven identity are
/// operator-fix-not-redial refusals — each maps to its own long-backoff variant.
/// A duplicate-relay-id refusal (a stale predecessor entry that ages out on its
/// own) is logged distinctly but takes the ordinary short delay, as does every
/// other close, so retrying is exactly what lets the enroll converge once the
/// stale entry expires.
fn classify_control_close(frame: Option<CloseFrame>, relay_id: RelayId) -> ControlDisconnect {
    let Some(frame) = frame else {
        return ControlDisconnect::Ordinary;
    };
    match u16::from(frame.code) {
        CONTROL_CLOSE_PROTOCOL_MISMATCH => {
            tracing::error!(
                relay_id = relay_id.0,
                reason = %frame.reason,
                "coordinator refused our protocol version; backing off until a deploy resolves the skew",
            );
            ControlDisconnect::VersionRefused
        }
        CONTROL_CLOSE_UNKNOWN_REGION => {
            tracing::error!(
                relay_id = relay_id.0,
                reason = %frame.reason,
                "coordinator refused our region; backing off until the region config is fixed",
            );
            ControlDisconnect::RegionRefused
        }
        CONTROL_CLOSE_IDENTITY_UNPROVEN => {
            tracing::error!(
                relay_id = relay_id.0,
                reason = %frame.reason,
                "coordinator rejected our enroll proof of possession; backing off until the key/cert mismatch is fixed",
            );
            ControlDisconnect::IdentityUnproven
        }
        CONTROL_CLOSE_ENROLL_UNAUTHORIZED => {
            tracing::error!(
                relay_id = relay_id.0,
                reason = %frame.reason,
                "coordinator's ledger did not authorize our enrollment; backing off until the provisioner reissues our identity/token",
            );
            ControlDisconnect::EnrollUnauthorized
        }
        CONTROL_CLOSE_DUPLICATE_RELAY_ID => {
            tracing::warn!(
                relay_id = relay_id.0,
                reason = %frame.reason,
                "coordinator refused our relay id as already enrolled under a different certificate; retrying",
            );
            ControlDisconnect::Ordinary
        }
        _ => ControlDisconnect::Ordinary,
    }
}

/// Signs `nonce` for the enroll proof-of-possession exchange: the exact bytes
/// `ENROLL_POP_CONTEXT ++ nonce`, using the relay's TLS private key — the same
/// key backing the certificate its `Hello` presented, so the coordinator's
/// verification against that certificate's public key succeeds. `pub` so the
/// coordinator's own tests can cross-verify this signer against its verifier
/// without reimplementing signing there.
///
/// The key is always PKCS#8 in this codebase — `config::self_signed_cert`'s
/// `rcgen` key and `config::load_cert`'s PEM parser both only ever produce
/// [`PrivateKeyDer::Pkcs8`] — and its algorithm is either ECDSA P-256 (the
/// `rcgen` self-signed default) or Ed25519 (a PEM-supplied key), the same two
/// algorithms the coordinator's verifier accepts. A PKCS#8 blob doesn't
/// self-announce which one it encodes, so this tries ECDSA first, then
/// Ed25519. Returns `None` for a key this relay's own cert loading could never
/// have produced (not PKCS#8, or PKCS#8 bytes neither loader accepts) — there
/// is no proof to offer, so the caller leaves the challenge unanswered and the
/// coordinator's own timeout refuses the connection.
pub fn sign_enroll_proof(
    identity_key: &PrivateKeyDer<'static>,
    nonce: &[u8; 32],
) -> Option<Vec<u8>> {
    let PrivateKeyDer::Pkcs8(pkcs8) = identity_key else {
        return None;
    };
    let mut message = ENROLL_POP_CONTEXT.to_vec();
    message.extend_from_slice(nonce);

    let rng = ring::rand::SystemRandom::new();
    if let Ok(pair) = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8.secret_pkcs8_der(),
        &rng,
    ) {
        return pair
            .sign(&rng, &message)
            .ok()
            .map(|signature| signature.as_ref().to_vec());
    }
    if let Ok(pair) = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.secret_pkcs8_der()) {
        return Some(pair.sign(&message).as_ref().to_vec());
    }
    None
}

/// Applies one decoded control message to the Join source.
///
/// A descriptor set reconciles membership; an unrecognized message kind (one a
/// newer coordinator sent that this build predates) is skipped, not an error —
/// the [`CoordinatorToRelay::Unknown`] catch-all already kept the decode from
/// failing, so the connection stays up and later descriptors keep flowing. A
/// *malformed* known message still surfaces as a decode error at the call site,
/// closing the connection so the next one re-syncs — that is a coordinator bug,
/// not a forward-compatible addition, and should not be silently swallowed.
fn apply_message(control: &MeshControl, message: CoordinatorToRelay, applied: &AppliedSessions) {
    match message {
        CoordinatorToRelay::Descriptors { descriptors } => {
            reconcile(control, &descriptors, applied);
        }
        CoordinatorToRelay::CloseSlot {
            tenant,
            session,
            slots,
        } => {
            let key = SessionKey { tenant, session };
            control.close_slots(&key, &slots);
        }
        // The connection loop intercepts DrainAck (it drives the drain seam) before
        // delegating here, so this arm is only a defensive no-op for a stray one.
        CoordinatorToRelay::DrainAck => {
            tracing::debug!("ignoring a DrainAck received outside a drain exchange");
        }
        // The connection loop intercepts MeshPeers (it stores the set into the fleet
        // map) before delegating here, so this arm is only a defensive no-op.
        CoordinatorToRelay::MeshPeers { .. } => {
            tracing::debug!("ignoring a MeshPeers frame received outside the fleet-map store");
        }
        // The connection loop intercepts TenantKeys (it replaces the tenant-key
        // registry) before delegating here, so this arm is only a defensive no-op.
        CoordinatorToRelay::TenantKeys { .. } => {
            tracing::debug!("ignoring a TenantKeys frame received outside the registry replace");
        }
        // The connection loop intercepts IdentityChallenge (it signs and replies
        // immediately) before delegating here, so this arm is only a defensive
        // no-op for a stray one.
        CoordinatorToRelay::IdentityChallenge { .. } => {
            tracing::debug!(
                "ignoring an IdentityChallenge received outside the enroll proof exchange"
            );
        }
        // The connection loop intercepts RegionBeacons (it stores the set into the
        // region-ping targets) before delegating here, so this arm is only a
        // defensive no-op.
        CoordinatorToRelay::RegionBeacons { .. } => {
            tracing::debug!(
                "ignoring a RegionBeacons frame received outside the region-ping store"
            );
        }
        CoordinatorToRelay::Unknown => {
            tracing::debug!("ignoring an unrecognized coordinator control message");
        }
    }
}

/// Builds the WebSocket upgrade request: the control URL plus, when a secret is
/// configured, the `Authorization: Bearer <secret>` header the coordinator
/// checks before upgrading. The relay's identity rides the enroll `Hello`, not
/// the URL, so the path carries no relay id.
fn build_request(
    coordinator_url: &str,
    secret: Option<&str>,
) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request, ControlError> {
    let base = to_ws_scheme(coordinator_url);
    let url = format!("{}/relay/control", base.trim_end_matches('/'));
    let mut request = url.into_client_request()?;
    if let Some(secret) = secret {
        let value = format!("Bearer {secret}").parse()?;
        request.headers_mut().insert(AUTHORIZATION, value);
    }
    Ok(request)
}

/// Rewrites an `http(s)://` coordinator base URL to its `ws(s)://` equivalent so
/// the same `--coordinator-url` works for both the JSON endpoints and the
/// WebSocket. A value already using a `ws` scheme passes through.
///
/// A `wss://` URL connects over rustls (this workspace's ring provider) and
/// validates the coordinator's certificate against the public web PKI roots —
/// fine for a publicly-trusted coordinator cert. Trusting an internal-CA or
/// self-signed coordinator cert (a custom root store, as the mesh edge takes via
/// `--mesh-roots`) is part of the deferred relay-trust / internal-CA work; until
/// then a `wss://` coordinator must present a publicly-trusted cert, or the
/// secret-bearing channel must run on trusted transport as `ws://`.
fn to_ws_scheme(base: &str) -> String {
    if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_owned()
    }
}

/// Drives the Join source to exactly the pushed descriptor set: applies each
/// descriptor, then leaves any session that was applied before but is no longer
/// present. Replaces `applied`'s contents with the new set, so the shared handle
/// the drain predicate reads always reflects the last push.
///
/// Apply-then-leave, both idempotent on the Join source: a descriptor already in
/// effect re-applies as a no-op, and a `Leave` for a session already gone is a
/// no-op. So a re-sync of an unchanged set issues no commands, and a shrunk set
/// issues only the leaves for what dropped.
///
/// The `applied` lock is held across the (sync, await-free) Join-source calls so
/// the set and the issued commands can never be observed out of step; `MeshControl`
/// takes its own lock nested under it, and nothing acquires them in the other order.
fn reconcile(control: &MeshControl, descriptors: &[SessionDescriptor], applied: &AppliedSessions) {
    let present: HashSet<SessionKey> = descriptors
        .iter()
        .map(|d| SessionKey {
            tenant: d.tenant.clone(),
            session: d.session,
        })
        .collect();

    let mut applied = applied.inner.lock();
    for descriptor in descriptors {
        control.apply_descriptor(descriptor);
    }
    for key in applied.difference(&present) {
        control.end_session(key);
    }

    *applied = present;
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use crate::flight_recorder::FLIGHT_SHIP_QUEUE;
    use crate::mesh::MeshCommand;
    use rally_point_proto::control::{
        BufferBounds, DepartureNotice, DesyncNotice, DivergedSlot, RegionBeaconTarget, RegionId,
        RelayPeer, TenantId,
    };
    use rally_point_proto::ids::{RelayId, SessionId};
    use tokio::sync::{mpsc, oneshot};

    const TENANT: &str = "sb-test";

    fn key(session: u64) -> SessionKey {
        SessionKey {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(session),
        }
    }

    fn descriptor(session: u64, peers: &[u64]) -> SessionDescriptor {
        SessionDescriptor {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(session),
            peers: peers
                .iter()
                .map(|&id| RelayPeer {
                    relay_id: RelayId(id),
                    relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900 + id as u16)),
                    cert_der: vec![id as u8; 4],
                    relay_addrs: vec![],
                })
                .collect(),
            bounds: BufferBounds::new(1, 6).unwrap(),
            authority_order: vec![],
            external_id: None,
            slot_refs: vec![],
            observer_slots: vec![],
            expected_slots: vec![],
            homed_slots: vec![],
            resumed: false,
            departed_slots: vec![],
            latency_estimate_ms: None,
        }
    }

    #[test]
    fn reconcile_applies_descriptors_then_leaves_dropped_sessions() {
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        control.register_link(RelayId(2), tx2);
        let applied = AppliedSessions::new();

        // First push: session 1 names peer 2 → Join.
        reconcile(&control, &[descriptor(1, &[2])], &applied);
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
        assert!(applied.snapshot().contains(&key(1)));

        // Second push: the session has dropped out of the set → Leave.
        reconcile(&control, &[], &applied);
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
        assert!(applied.is_empty());
    }

    #[test]
    fn reconcile_is_idempotent_on_a_repeated_set() {
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        control.register_link(RelayId(2), tx2);
        let applied = AppliedSessions::new();

        reconcile(&control, &[descriptor(1, &[2])], &applied);
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));

        // A re-sync of the same set (e.g. on reconnect) issues no further commands.
        reconcile(&control, &[descriptor(1, &[2])], &applied);
        assert!(rx2.try_recv().is_err(), "an unchanged set is a no-op");
    }

    #[test]
    fn reconcile_tracks_multiple_sessions_and_leaves_only_the_one_that_dropped() {
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        control.register_link(RelayId(2), tx2);
        let applied = AppliedSessions::new();

        // Two sessions on the link to peer 2.
        reconcile(
            &control,
            &[descriptor(1, &[2]), descriptor(2, &[2])],
            &applied,
        );
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(2)));

        // Session 1 ends; session 2 remains. Only session 1 is left.
        reconcile(&control, &[descriptor(2, &[2])], &applied);
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
        assert!(rx2.try_recv().is_err(), "session 2 stays joined");
        assert_eq!(applied.snapshot(), HashSet::from([key(2)]));
    }

    #[tokio::test]
    async fn a_close_slot_message_signals_the_named_held_slot() {
        // A CloseSlot down-frame reaches the roster: the named slot's shutdown
        // signal fires (its link task would then close and deregister), and a slot
        // the relay does not hold is a harmless no-op.
        let sessions: crate::routing::Sessions = std::sync::Arc::default();
        let mesh_links = crate::mesh::new_mesh_links();
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        )
        .with_broadcast(sessions.clone(), mesh_links);

        let (mut guard, inbox) =
            crate::routing::register(&sessions, &key(1), rally_point_proto::ids::SlotId(0))
                .expect("slot 0 registers");
        guard.disarm();
        let shutdown = inbox.shutdown_handle();

        let applied = AppliedSessions::new();
        apply_message(
            &control,
            CoordinatorToRelay::CloseSlot {
                tenant: TenantId(TENANT.to_owned()),
                session: SessionId(1),
                // Name a held slot and one the relay does not hold.
                slots: vec![
                    rally_point_proto::ids::SlotId(0),
                    rally_point_proto::ids::SlotId(7),
                ],
            },
            &applied,
        );

        tokio::time::timeout(Duration::from_millis(100), shutdown.notified())
            .await
            .expect("the held slot was signaled to close");
    }

    #[test]
    fn an_unknown_message_is_skipped_and_does_not_disturb_state_or_later_messages() {
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        control.register_link(RelayId(2), tx2);
        let applied = AppliedSessions::new();

        // A known message joins session 1.
        apply_message(
            &control,
            CoordinatorToRelay::Descriptors {
                descriptors: vec![descriptor(1, &[2])],
            },
            &applied,
        );
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));

        // An unknown message is a no-op: no commands, applied state untouched.
        apply_message(&control, CoordinatorToRelay::Unknown, &applied);
        assert!(rx2.try_recv().is_err(), "an unknown message issues nothing");
        assert_eq!(applied.snapshot(), HashSet::from([key(1)]));

        // A later known message still applies — the unknown one did not break the
        // stream's state.
        apply_message(
            &control,
            CoordinatorToRelay::Descriptors {
                descriptors: vec![],
            },
            &applied,
        );
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
    }

    #[test]
    fn an_unknown_frame_decodes_and_skips_rather_than_closing_the_stream() {
        // The exact rolling-deploy path: a frame a newer coordinator sent that
        // this build predates decodes to `Unknown` (not the serde error that
        // would propagate and close the connection), and applies as a no-op.
        let json = r#"{"type":"future_thing","whatever":true}"#;
        let message: CoordinatorToRelay =
            serde_json::from_str(json).expect("an unknown type must not be a decode error");
        assert_eq!(message, CoordinatorToRelay::Unknown);

        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        control.register_link(RelayId(2), tx2);
        let applied = AppliedSessions::new();
        apply_message(&control, message, &applied);
        assert!(rx2.try_recv().is_err());
        assert!(applied.is_empty());
    }

    #[test]
    fn to_ws_scheme_rewrites_http_and_passes_ws_through() {
        assert_eq!(to_ws_scheme("http://host:14910"), "ws://host:14910");
        assert_eq!(to_ws_scheme("https://host:14910"), "wss://host:14910");
        assert_eq!(to_ws_scheme("ws://host:14910"), "ws://host:14910");
    }

    #[test]
    fn build_request_targets_the_control_path_and_sets_the_bearer() {
        let request = build_request("http://host:14910/", Some("s3cret")).unwrap();
        assert_eq!(request.uri().path(), "/relay/control");
        assert_eq!(request.uri().scheme_str(), Some("ws"));
        assert_eq!(
            request.headers().get(AUTHORIZATION).unwrap(),
            "Bearer s3cret",
        );
    }

    #[test]
    fn build_request_without_a_secret_sets_no_authorization() {
        let request = build_request("http://host:14910", None).unwrap();
        assert!(request.headers().get(AUTHORIZATION).is_none());
    }

    fn dropped_notice() -> DepartureNotice {
        DepartureNotice {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(42),
            slot: rally_point_proto::ids::SlotId(2),
            kind: rally_point_proto::control::DepartureKind::Dropped,
            reason: 0x4000_0006,
            leave_seq: 3,
            external_id: None,
            external_ref: None,
            result: None,
        }
    }

    fn desync_notice() -> DesyncNotice {
        DesyncNotice {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(42),
            sync_ordinal: 91,
            game_frame: Some(3000),
            detected_at_ms: 1_700_000_000_000,
            no_majority: false,
            diverged: vec![DivergedSlot {
                slot: rally_point_proto::ids::SlotId(1),
                external_ref: Some("sb-user-1".to_owned()),
            }],
            external_id: Some("game-42".to_owned()),
        }
    }

    /// Captures every frame a `send_notice` writes, so a test can assert exactly
    /// what went on the wire. The sink carries the WebSocket's error type, so the
    /// generic bound is satisfied exactly as the live socket satisfies it.
    async fn capture_sent(notice: &RelayNotice) -> Vec<Message> {
        use std::sync::{Arc, Mutex};

        let captured: Arc<Mutex<Vec<Message>>> = Arc::default();
        let for_sink = Arc::clone(&captured);
        let mut sink = Box::pin(futures_util::sink::unfold(
            (),
            move |(), message: Message| {
                let for_sink = Arc::clone(&for_sink);
                async move {
                    for_sink.lock().unwrap().push(message);
                    Ok::<(), tokio_tungstenite::tungstenite::Error>(())
                }
            },
        ));
        send_notice(&mut sink, notice).await.unwrap();
        let frames = captured.lock().unwrap();
        frames.clone()
    }

    #[tokio::test]
    async fn send_notice_emits_one_tagged_departure_frame() {
        let notice = RelayNotice::Departure(dropped_notice());
        let frames = capture_sent(&notice).await;
        assert_eq!(frames.len(), 1, "exactly one frame");
        let Message::Text(text) = &frames[0] else {
            panic!("a text frame");
        };
        let decoded: RelayToCoordinator = serde_json::from_str(text).unwrap();
        assert_eq!(decoded, RelayToCoordinator::Departure(dropped_notice()));
    }

    #[tokio::test]
    async fn send_notice_emits_one_tagged_desync_frame() {
        // The desync kind rides the same pipe and wraps into the matching frame.
        let notice = RelayNotice::Desync(desync_notice());
        let frames = capture_sent(&notice).await;
        assert_eq!(frames.len(), 1, "exactly one frame");
        let Message::Text(text) = &frames[0] else {
            panic!("a text frame");
        };
        assert!(text.contains("\"type\":\"desync\""));
        let decoded: RelayToCoordinator = serde_json::from_str(text).unwrap();
        assert_eq!(decoded, RelayToCoordinator::Desync(desync_notice()));
    }

    /// A notice queued while the coordinator is unreachable is delivered on the
    /// next successful connection, not lost. The first dial fails at the handshake
    /// (the server drops the socket), so the relay never touches the channel; the
    /// second dial completes, and the queued notice flushes right after the Hello.
    /// Run for both notice kinds, since they share the one buffered pipe.
    async fn a_queued_notice_is_delivered_after_a_reconnect(queued: RelayNotice) {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frame_tx, frame_rx) = tokio::sync::oneshot::channel();

        // The stand-in coordinator: fail the first dial, then accept the second
        // and capture the frame that follows the enroll Hello.
        tokio::spawn(async move {
            // First connection: drop it mid-handshake so the relay's connect
            // fails and it redials — without ever entering its send loop, so the
            // queued notice stays in the channel rather than being consumed here.
            let (first, _) = listener.accept().await.unwrap();
            drop(first);

            // Second connection: complete the WebSocket handshake and the enroll
            // proof exchange, then read the flushed notice — which the relay sends
            // only after the proof.
            let (second, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(second).await.unwrap();
            let hello = accept_enroll(&mut ws).await;
            let Message::Text(hello) = hello else {
                panic!("first frame is the Hello");
            };
            assert!(hello.contains("\"type\":\"hello\""));
            let notice = ws.next().await.unwrap().unwrap();
            let _ = frame_tx.send(notice);
        });

        // Queue the notice before the subscriber starts: it sits in the unbounded
        // channel until a live connection can carry it.
        let (notices_tx, notices_rx) = mpsc::unbounded_channel();
        notices_tx.send(queued.clone()).unwrap();

        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (drain_rx, drain_acked) = no_drain();
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(
                addr,
                RelayHello::new(
                    RelayId(1),
                    SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                    rally_point_proto::version::ProtocolVersion::CURRENT,
                    vec![0xAB; 4],
                ),
            ),
            apply_targets(control, drain_acked),
            OutboundQueues::new(notices_rx, no_flight(), ControlQueueDepths::new()),
            heartbeat(Duration::from_secs(3600)), // no heartbeat during the test
            drain_rx,
            no_connected(),
            // Redial fast after the failed first dial.
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        let received = tokio::time::timeout(Duration::from_secs(5), frame_rx)
            .await
            .expect("the queued notice is delivered after the reconnect")
            .unwrap();
        let Message::Text(text) = received else {
            panic!("a text frame");
        };
        let decoded: RelayToCoordinator = serde_json::from_str(&text).unwrap();
        let expected = match queued {
            RelayNotice::Departure(notice) => RelayToCoordinator::Departure(notice),
            RelayNotice::Desync(notice) => RelayToCoordinator::Desync(notice),
            RelayNotice::Result(notice) => RelayToCoordinator::Result(notice),
            RelayNotice::SessionClosed { tenant, session } => {
                RelayToCoordinator::SessionClosed { tenant, session }
            }
        };
        assert_eq!(decoded, expected);
    }

    #[tokio::test]
    async fn a_queued_departure_is_delivered_after_a_reconnect() {
        a_queued_notice_is_delivered_after_a_reconnect(RelayNotice::Departure(dropped_notice()))
            .await;
    }

    #[tokio::test]
    async fn a_queued_desync_is_delivered_after_a_reconnect() {
        a_queued_notice_is_delivered_after_a_reconnect(RelayNotice::Desync(desync_notice())).await;
    }

    // --- Coordinated drain ---

    /// A never-draining `drain` receiver and a throwaway `drain_acked` sender, for
    /// tests that don't exercise the drain seam. The internal channel ends drop
    /// immediately, so the loop's drain arm disables itself and an ack `send` is a
    /// harmless no-op.
    fn no_drain() -> (watch::Receiver<bool>, watch::Sender<bool>) {
        (watch::channel(false).1, watch::channel(false).0)
    }

    /// A throwaway `control_connected` sender for a test that doesn't assert
    /// on the connection-state signal itself.
    fn no_connected() -> watch::Sender<bool> {
        watch::channel(false).0
    }

    /// A closed flight receiver for tests that don't exercise the flight pipe: its
    /// sender is dropped, so the loop's flight arm disables itself and never fires.
    fn no_flight() -> Receiver<FlightShipment> {
        mpsc::channel(1).1
    }

    /// The enroll config for a subscriber pointed at the stand-in coordinator at
    /// `addr`, presenting `relay_hello` and a signable throwaway identity key.
    fn enroll(addr: std::net::SocketAddr, relay_hello: RelayHello) -> EnrollConfig {
        EnrollConfig {
            coordinator_url: format!("http://{addr}"),
            bootstrap_secret: None,
            relay_hello,
            identity_key: throwaway_identity_key(),
        }
    }

    /// Apply targets with default (empty) stores and the given Join source and
    /// drain-ack signal — the common case for tests not asserting on a specific
    /// store.
    fn apply_targets(
        control: MeshControl,
        drain_acked: watch::Sender<bool>,
    ) -> ControlApplyTargets {
        ControlApplyTargets {
            control,
            applied: AppliedSessions::default(),
            fleet: FleetMeshPeers::default(),
            verifying_keys: SharedRegistry::default(),
            region_targets: RegionPingTargets::default(),
            drain_acked,
        }
    }

    /// A heartbeat config over an empty roster and RTT cache at the given interval —
    /// the common case for tests not asserting on heartbeat content.
    fn heartbeat(interval: Duration) -> HeartbeatConfig {
        HeartbeatConfig {
            sessions: Arc::default(),
            region_rtt_cache: RegionRttCache::default(),
            interval,
        }
    }

    /// The two redial delays as a backoff config.
    fn backoff(ordinary: Duration, version_refused: Duration) -> ReconnectBackoff {
        ReconnectBackoff {
            ordinary,
            version_refused,
        }
    }

    /// A flight shipment for the connection-loop tests, paired with the ack
    /// receiver its `sent` half resolves. The stand-in coordinator reads the
    /// `FlightRecording` frame the loop ships for it.
    fn flight_shipment() -> (FlightShipment, oneshot::Receiver<()>) {
        let (sent, ack) = oneshot::channel();
        let shipment = FlightShipment {
            notice: FlightRecordingNotice {
                tenant: TenantId(TENANT.to_owned()),
                session: SessionId(7),
                desynced: false,
                payload: r#"{"version":1}"#.to_owned(),
            },
            sent,
        };
        (shipment, ack)
    }

    #[test]
    fn drained_idle_requires_both_no_slots_and_an_empty_applied_set() {
        let sessions: Sessions = std::sync::Arc::default();
        let applied = AppliedSessions::new();

        // Empty roster + empty applied set: provably unassigned, drained.
        assert!(drained_idle(&sessions, &applied));

        // An applied session with no dialed client (the pre-mark sliver: assigned
        // just before the drain, clients not yet connected) blocks the drain even
        // though no slot is held.
        applied.inner.lock().insert(key(1));
        assert!(
            !drained_idle(&sessions, &applied),
            "an assigned session whose clients have not dialed blocks the drain",
        );
        applied.inner.lock().clear();
        assert!(drained_idle(&sessions, &applied));

        // A held slot blocks the drain even with an empty applied set (e.g. a
        // post-restart session the coordinator no longer tracks).
        let (_guard, _inbox) =
            crate::routing::register(&sessions, &key(1), rally_point_proto::ids::SlotId(0))
                .expect("slot 0 registers");
        assert!(
            !drained_idle(&sessions, &applied),
            "a held slot blocks the drain regardless of the applied set",
        );
    }

    #[test]
    fn reconcile_updates_the_shared_applied_set_the_drain_predicate_reads() {
        // The subscriber-to-drain seam: a descriptor push reconciled into the shared
        // handle flips the drain predicate, and the next push removing the session
        // flips it back — what lets a drain wait out an assigned-but-undialed
        // session and exit the moment the coordinator's set empties.
        let sessions: Sessions = std::sync::Arc::default();
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let applied = AppliedSessions::new();
        assert!(drained_idle(&sessions, &applied));

        reconcile(&control, &[descriptor(1, &[])], &applied);
        assert!(
            !drained_idle(&sessions, &applied),
            "a pushed session is visible through the drain predicate",
        );

        reconcile(&control, &[], &applied);
        assert!(
            drained_idle(&sessions, &applied),
            "the session's removal on the next push re-drains the relay",
        );
    }

    /// The relay's enroll Hello for these drain tests.
    fn drain_hello() -> RelayHello {
        RelayHello::new(
            RelayId(1),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            rally_point_proto::version::ProtocolVersion::CURRENT,
            vec![0xAB; 4],
        )
    }

    /// A private key for the `identity_key` these stand-in-coordinator tests
    /// pass. `rcgen`'s default is an ECDSA P-256 key, which [`sign_enroll_proof`]
    /// can sign, so [`accept_enroll`]'s challenge is answered with a valid
    /// `IdentityProof`. The stand-in coordinators don't *verify* the signature —
    /// they only assert the proof frame arrives in the right order — so any
    /// signable key suffices.
    fn throwaway_identity_key() -> PrivateKeyDer<'static> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap()
    }

    /// Drives the coordinator side of the enroll proof-of-possession handshake on
    /// `ws`: reads the relay's Hello, sends an `IdentityChallenge`, and reads and
    /// asserts the relay's `IdentityProof` answer — leaving `ws` positioned to
    /// read the relay's first post-enroll application frame. Returns the Hello
    /// frame for the caller's own assertions.
    ///
    /// Every stand-in coordinator that reads past the Hello must run this first:
    /// the relay completes the enroll handshake before it sends any application
    /// frame (notice, drain, heartbeat), so a coordinator that skipped the
    /// challenge would leave the relay blocked waiting for one.
    async fn accept_enroll<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> Message
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let hello = ws.next().await.unwrap().unwrap();
        let challenge =
            serde_json::to_string(&CoordinatorToRelay::IdentityChallenge { nonce: [0u8; 32] })
                .expect("an identity-challenge frame serializes");
        ws.send(Message::Text(challenge.into())).await.unwrap();
        let proof = ws.next().await.unwrap().unwrap();
        let Message::Text(proof) = proof else {
            panic!("the relay answers the challenge with a text IdentityProof frame");
        };
        assert!(
            matches!(
                serde_json::from_str::<RelayToCoordinator>(&proof).unwrap(),
                RelayToCoordinator::IdentityProof { .. },
            ),
            "the relay's first post-Hello frame is the IdentityProof",
        );
        hello
    }

    #[tokio::test]
    async fn a_drain_trigger_sends_a_draining_frame_after_the_hello() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

        // Stand-in coordinator: accept, complete the enroll handshake, then read
        // the frame that follows once the relay is told to drain.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let hello = accept_enroll(&mut ws).await;
            let next = ws.next().await.unwrap().unwrap();
            let _ = frames_tx.send((hello, next));
        });

        let (drain_tx, drain_rx) = watch::channel(false);
        let (drain_acked_tx, _drain_acked_rx) = watch::channel(false);
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            apply_targets(control, drain_acked_tx),
            OutboundQueues::new(
                mpsc::unbounded_channel().1,
                no_flight(),
                ControlQueueDepths::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        // Trigger the drain; the relay must send a Draining frame after its Hello.
        drain_tx.send(true).unwrap();

        let (hello, draining) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
            .await
            .expect("the relay sends a Draining frame after the trigger")
            .unwrap();
        let Message::Text(hello) = hello else {
            panic!("the first frame is the Hello");
        };
        assert!(hello.contains("\"type\":\"hello\""));
        let Message::Text(draining) = draining else {
            panic!("the second frame is text");
        };
        assert_eq!(
            serde_json::from_str::<RelayToCoordinator>(&draining).unwrap(),
            RelayToCoordinator::Draining,
        );
    }

    #[tokio::test]
    async fn a_drain_ack_fires_the_acked_signal() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Stand-in coordinator: accept, complete the enroll handshake, then send a
        // DrainAck and hold the connection open.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;
            let ack = serde_json::to_string(&CoordinatorToRelay::DrainAck).unwrap();
            ws.send(Message::Text(ack.into())).await.unwrap();
            // Keep the connection open so the relay doesn't reconnect mid-assert.
            std::future::pending::<()>().await;
        });

        let (_drain_tx, drain_rx) = watch::channel(false);
        let (drain_acked_tx, mut drain_acked_rx) = watch::channel(false);
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            apply_targets(control, drain_acked_tx),
            OutboundQueues::new(
                mpsc::unbounded_channel().1,
                no_flight(),
                ControlQueueDepths::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        // The DrainAck flips the acked watch to true.
        tokio::time::timeout(Duration::from_secs(5), drain_acked_rx.changed())
            .await
            .expect("the DrainAck fires the acked signal")
            .unwrap();
        assert!(*drain_acked_rx.borrow());
    }

    #[tokio::test]
    async fn a_reconnect_while_draining_re_sends_draining_after_the_hello() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();

        // Stand-in coordinator: the FIRST connection enrolls then reads Draining and
        // drops; the SECOND (reconnect) must again enroll then read Draining —
        // proving a relay that reconnects mid-drain re-asserts it right after the
        // enroll handshake completes.
        tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                let hello = accept_enroll(&mut ws).await;
                let Message::Text(hello) = hello else {
                    panic!("first frame is the Hello");
                };
                assert!(hello.contains("\"type\":\"hello\""));
                let draining = ws.next().await.unwrap().unwrap();
                let Message::Text(draining) = draining else {
                    panic!("second frame is text");
                };
                assert_eq!(
                    serde_json::from_str::<RelayToCoordinator>(&draining).unwrap(),
                    RelayToCoordinator::Draining,
                );
                // Drop the first connection to force a reconnect; signal after the
                // second one re-sent its Draining.
                drop(ws);
            }
            let _ = done_tx.send(());
        });

        // Draining is already requested before the subscriber starts, so it must be
        // re-asserted on every connection right after the Hello.
        let (_drain_tx, drain_rx) = watch::channel(true);
        let (drain_acked_tx, _drain_acked_rx) = watch::channel(false);
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            apply_targets(control, drain_acked_tx),
            OutboundQueues::new(
                mpsc::unbounded_channel().1,
                no_flight(),
                ControlQueueDepths::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        tokio::time::timeout(Duration::from_secs(5), done_rx)
            .await
            .expect("the reconnect re-sends Draining after the Hello")
            .unwrap();
    }

    #[tokio::test]
    async fn the_enroll_proof_precedes_a_pending_notice_and_a_drain() {
        use tokio::net::TcpListener;

        // The coordinator sends the IdentityChallenge as the first post-Hello
        // frame and reads exactly one frame back expecting the IdentityProof. A
        // relay that reconnects with a queued notice AND mid-drain would, without
        // an enroll handshake that completes first, send that notice (or the
        // Draining) ahead of the proof and be refused. This asserts the proof is
        // the first frame after the challenge, with the notice and Draining
        // strictly behind it.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            // Read the Hello, then challenge and read the very next frame — the
            // proof must be it, ahead of the queued notice and the drain re-assert.
            let hello = ws.next().await.unwrap().unwrap();
            let Message::Text(hello) = hello else {
                panic!("first frame is the Hello");
            };
            assert!(hello.contains("\"type\":\"hello\""));
            let challenge =
                serde_json::to_string(&CoordinatorToRelay::IdentityChallenge { nonce: [7u8; 32] })
                    .unwrap();
            ws.send(Message::Text(challenge.into())).await.unwrap();

            // Capture the next three frames in wire order: proof, then the notice
            // and the Draining (in whichever order the relay flushes them).
            let first = ws.next().await.unwrap().unwrap();
            let second = ws.next().await.unwrap().unwrap();
            let third = ws.next().await.unwrap().unwrap();
            let _ = frames_tx.send((first, second, third));
        });

        // Queue a notice AND set the relay mid-drain before it starts, so both
        // would race the proof if enrollment did not complete first.
        let (notices_tx, notices_rx) = mpsc::unbounded_channel();
        notices_tx
            .send(RelayNotice::Departure(dropped_notice()))
            .unwrap();
        let (_drain_tx, drain_rx) = watch::channel(true);
        let (drain_acked_tx, _drain_acked_rx) = watch::channel(false);

        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            apply_targets(control, drain_acked_tx),
            OutboundQueues::new(notices_rx, no_flight(), ControlQueueDepths::new()),
            heartbeat(Duration::from_secs(3600)), // no heartbeat during the test
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        let (first, second, third) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
            .await
            .expect("the relay sends the proof then the queued frames")
            .unwrap();

        let decode = |message: Message| -> RelayToCoordinator {
            let Message::Text(text) = message else {
                panic!("a text frame");
            };
            serde_json::from_str(&text).unwrap()
        };

        assert!(
            matches!(decode(first), RelayToCoordinator::IdentityProof { .. }),
            "the identity proof must be the first frame after the challenge",
        );
        let rest = [decode(second), decode(third)];
        assert!(
            rest.contains(&RelayToCoordinator::Departure(dropped_notice())),
            "the queued notice goes out only after the proof",
        );
        assert!(
            rest.contains(&RelayToCoordinator::Draining),
            "the drain re-assert goes out only after the proof",
        );
    }

    #[tokio::test]
    async fn a_heartbeat_carries_the_live_roster_as_presence() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frame_tx, frame_rx) = tokio::sync::oneshot::channel();

        // Stand-in coordinator: complete the enroll handshake, then read the first
        // heartbeat.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let hello = accept_enroll(&mut ws).await;
            let Message::Text(hello) = hello else {
                panic!("first frame is the Hello");
            };
            assert!(hello.contains("\"type\":\"hello\""));
            let beat = ws.next().await.unwrap().unwrap();
            let _ = frame_tx.send(beat);
        });

        // A slot registered in the roster before the subscriber starts, so the
        // first beat already carries it. The guard is disarmed and the inbox held
        // so the slot stays registered for the test's duration.
        let sessions: Sessions = Arc::default();
        let (mut guard, _inbox) =
            crate::routing::register(&sessions, &key(7), rally_point_proto::ids::SlotId(3))
                .expect("slot 3 registers");
        guard.disarm();

        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (drain_rx, drain_acked) = no_drain();
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            apply_targets(control, drain_acked),
            OutboundQueues::new(
                mpsc::unbounded_channel().1,
                no_flight(),
                ControlQueueDepths::new(),
            ),
            HeartbeatConfig {
                sessions: Arc::clone(&sessions),
                region_rtt_cache: RegionRttCache::default(),
                interval: Duration::from_millis(50), // beat quickly so the test observes one
            },
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        let beat = tokio::time::timeout(Duration::from_secs(5), frame_rx)
            .await
            .expect("a heartbeat arrives")
            .unwrap();
        let Message::Text(text) = beat else {
            panic!("the heartbeat is a text frame");
        };
        let decoded: RelayToCoordinator = serde_json::from_str(&text).unwrap();
        assert_eq!(
            decoded,
            RelayToCoordinator::Heartbeat {
                sessions: vec![SessionPresence {
                    tenant: TenantId(TENANT.to_owned()),
                    session: SessionId(7),
                    slots: vec![rally_point_proto::ids::SlotId(3)],
                }],
                region_rtts: vec![],
            },
            "the beat names the registered (tenant, session, slot)",
        );
    }

    // --- Protocol-version refusal backoff ---

    /// Spawns a stand-in coordinator that, for every control connection, reads the
    /// enroll Hello and then closes with `close_frame` — reporting the instant each
    /// connection was accepted, so a test can measure the redial gap.
    async fn spawn_closing_coordinator(
        close_frame: Option<tokio_tungstenite::tungstenite::protocol::CloseFrame>,
    ) -> (
        std::net::SocketAddr,
        mpsc::UnboundedReceiver<std::time::Instant>,
    ) {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (times_tx, times_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let _ = times_tx.send(std::time::Instant::now());
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    continue;
                };
                let _hello = ws.next().await;
                let _ = ws.close(close_frame.clone()).await;
                // Drain until the client answers the close, so it completes cleanly.
                while let Some(Ok(_)) = ws.next().await {}
            }
        });
        (addr, times_rx)
    }

    /// Spawns the subscriber against `addr` with a fast ordinary reconnect delay
    /// and the given version-refusal delay, returning nothing — the stand-in
    /// coordinator's accept times are the observable.
    fn spawn_subscriber_with_delays(
        addr: std::net::SocketAddr,
        reconnect_delay: Duration,
        version_refused_delay: Duration,
    ) {
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (drain_rx, drain_acked) = no_drain();
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            apply_targets(control, drain_acked),
            OutboundQueues::new(
                mpsc::unbounded_channel().1,
                no_flight(),
                ControlQueueDepths::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(reconnect_delay, version_refused_delay),
        ));
    }

    #[tokio::test]
    async fn a_version_refusal_close_waits_the_refusal_backoff_before_redialing() {
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

        // The coordinator refuses every connection with the version-mismatch close.
        let (addr, mut times_rx) = spawn_closing_coordinator(Some(CloseFrame {
            code: CloseCode::from(CONTROL_CLOSE_PROTOCOL_MISMATCH),
            reason: "no common protocol version: local supports v2..=v2, \
                     peer supports v1..=v1"
                .into(),
        }))
        .await;

        // Ordinary reconnect would redial in ~20ms; the refusal backoff is 500ms.
        spawn_subscriber_with_delays(addr, Duration::from_millis(20), Duration::from_millis(500));

        let first = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
            .await
            .expect("the first dial arrives")
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
            .await
            .expect("the relay eventually redials")
            .unwrap();
        let gap = second.duration_since(first);
        assert!(
            gap >= Duration::from_millis(400),
            "a version refusal must wait the refusal backoff, not the ordinary \
             reconnect delay (observed gap: {gap:?})",
        );
    }

    #[tokio::test]
    async fn an_unknown_region_close_waits_the_refusal_backoff_before_redialing() {
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

        // The coordinator refuses every connection with the unknown-region close —
        // like a version mismatch, a redial changes nothing until the config is
        // fixed, so the relay must wait the long refusal backoff, not the ordinary
        // reconnect delay.
        let (addr, mut times_rx) = spawn_closing_coordinator(Some(CloseFrame {
            code: CloseCode::from(CONTROL_CLOSE_UNKNOWN_REGION),
            reason: "unknown region: region-z".into(),
        }))
        .await;

        spawn_subscriber_with_delays(addr, Duration::from_millis(20), Duration::from_millis(500));

        let first = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
            .await
            .expect("the first dial arrives")
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
            .await
            .expect("the relay eventually redials")
            .unwrap();
        let gap = second.duration_since(first);
        assert!(
            gap >= Duration::from_millis(400),
            "an unknown-region refusal must wait the refusal backoff, not the ordinary \
             reconnect delay (observed gap: {gap:?})",
        );
    }

    #[tokio::test]
    async fn an_identity_unproven_close_waits_the_refusal_backoff_before_redialing() {
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

        // The coordinator refuses every connection with the identity-unproven
        // close — a bad signature or key mismatch is a config/implementation
        // fault, not something a redial fixes, so it takes the long backoff like
        // a version or region refusal.
        let (addr, mut times_rx) = spawn_closing_coordinator(Some(CloseFrame {
            code: CloseCode::from(CONTROL_CLOSE_IDENTITY_UNPROVEN),
            reason: "enroll proof-of-possession failed".into(),
        }))
        .await;

        spawn_subscriber_with_delays(addr, Duration::from_millis(20), Duration::from_millis(500));

        let first = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
            .await
            .expect("the first dial arrives")
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
            .await
            .expect("the relay eventually redials")
            .unwrap();
        let gap = second.duration_since(first);
        assert!(
            gap >= Duration::from_millis(400),
            "an identity-unproven refusal must wait the refusal backoff, not the \
             ordinary reconnect delay (observed gap: {gap:?})",
        );
    }

    #[tokio::test]
    async fn a_duplicate_relay_id_close_redials_at_the_normal_delay() {
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

        // Unlike identity-unproven, a duplicate-relay-id refusal resolves on its
        // own (the stale entry ages out via the coordinator's liveness deadline),
        // so it must take the ordinary short delay, not the long refusal backoff
        // — proven the same way the plain-close test proves it: the refusal
        // backoff is set absurdly long, so a prompt redial proves the ordinary
        // path was taken.
        let (addr, mut times_rx) = spawn_closing_coordinator(Some(CloseFrame {
            code: CloseCode::from(CONTROL_CLOSE_DUPLICATE_RELAY_ID),
            reason: "relay id already enrolled under a different certificate".into(),
        }))
        .await;
        spawn_subscriber_with_delays(addr, Duration::from_millis(20), Duration::from_secs(3600));

        tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
            .await
            .expect("the first dial arrives")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), times_rx.recv())
            .await
            .expect(
                "a duplicate-relay-id refusal redials at the normal delay, \
                 not the long refusal backoff",
            )
            .unwrap();
    }

    #[tokio::test]
    async fn an_ordinary_close_redials_at_the_normal_delay() {
        // The coordinator closes normally (no version refusal). With the refusal
        // backoff set absurdly long, a redial arriving promptly proves the ordinary
        // path took the ordinary delay — the wrong branch would blow the timeout.
        let (addr, mut times_rx) = spawn_closing_coordinator(None).await;
        spawn_subscriber_with_delays(addr, Duration::from_millis(20), Duration::from_secs(3600));

        tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
            .await
            .expect("the first dial arrives")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), times_rx.recv())
            .await
            .expect("an ordinary close redials at the normal delay, not the refusal backoff")
            .unwrap();
    }

    // --- Fleet mesh-peer map ---

    #[test]
    fn store_replaces_the_fleet_map_wholesale_and_the_reader_reflects_it() {
        let fleet = FleetMeshPeers::new();
        let reader = fleet.reader();
        assert!(reader.is_empty(), "a fresh map is empty");

        fleet.store(vec![
            MeshPeerIdentity {
                relay_id: RelayId(1),
                cert_sha256: [0x11; 32],
            },
            MeshPeerIdentity {
                relay_id: RelayId(2),
                cert_sha256: [0x22; 32],
            },
        ]);
        assert_eq!(reader.fingerprint(RelayId(1)), Some([0x11; 32]));
        assert_eq!(reader.fingerprint(RelayId(2)), Some([0x22; 32]));
        assert!(!reader.is_empty());

        // A later push is declarative current state: relay 1 drops out and relay
        // 2's cert rotates, replacing the map wholesale rather than merging.
        fleet.store(vec![MeshPeerIdentity {
            relay_id: RelayId(2),
            cert_sha256: [0xEE; 32],
        }]);
        assert_eq!(
            reader.fingerprint(RelayId(1)),
            None,
            "a wholesale replace drops the absent relay",
        );
        assert_eq!(
            reader.fingerprint(RelayId(2)),
            Some([0xEE; 32]),
            "the rotated cert is reflected",
        );
    }

    #[tokio::test]
    async fn a_mesh_peers_push_updates_the_fleet_map_the_reader_exposes() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Stand-in coordinator: accept, complete the enroll handshake, push a
        // MeshPeers set, then hold the connection open so the relay does not
        // reconnect mid-assert.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;
            let frame = serde_json::to_string(&CoordinatorToRelay::MeshPeers {
                peers: vec![
                    MeshPeerIdentity {
                        relay_id: RelayId(2),
                        cert_sha256: [0x22; 32],
                    },
                    MeshPeerIdentity {
                        relay_id: RelayId(3),
                        cert_sha256: [0x33; 32],
                    },
                ],
            })
            .unwrap();
            ws.send(Message::Text(frame.into())).await.unwrap();
            std::future::pending::<()>().await;
        });

        // The reader is taken before the writer moves into the subscriber, so it
        // observes exactly the map the received push stores.
        let fleet = FleetMeshPeers::new();
        let reader = fleet.reader();
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (drain_rx, drain_acked) = no_drain();
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            ControlApplyTargets {
                control,
                applied: AppliedSessions::default(),
                fleet,
                verifying_keys: SharedRegistry::default(),
                region_targets: RegionPingTargets::default(),
                drain_acked,
            },
            OutboundQueues::new(
                mpsc::unbounded_channel().1,
                no_flight(),
                ControlQueueDepths::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        // The pushed set lands in the shared map the reader observes.
        let landed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if reader.fingerprint(RelayId(2)) == Some([0x22; 32])
                    && reader.fingerprint(RelayId(3)) == Some([0x33; 32])
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            landed.is_ok(),
            "the reader exposes the coordinator's pushed fleet map",
        );
        assert_eq!(
            reader.fingerprint(RelayId(9)),
            None,
            "a relay absent from the pushed set has no fingerprint",
        );
    }

    // --- Region ping targets + heartbeat RTT report ---

    fn beacon(region: &str, host_port: &str) -> RegionBeaconTarget {
        RegionBeaconTarget {
            region: RegionId(region.to_owned()),
            beacon: host_port.to_owned(),
        }
    }

    #[test]
    fn heartbeat_region_rtts_snapshots_the_cache_sorted_by_region() {
        let cache = RegionRttCache::new();
        // An empty cache reports no RTTs — the beat's field stays off the wire.
        assert!(heartbeat_region_rtts(&cache).is_empty());

        // Insert out of region order; the snapshot is sorted by region id, so the
        // beat's wire output is deterministic regardless of map iteration order.
        cache.record(RegionId("us-east".to_owned()), 87);
        cache.record(RegionId("ap-southeast".to_owned()), 210);
        cache.record(RegionId("eu-central".to_owned()), 42);
        assert_eq!(
            heartbeat_region_rtts(&cache),
            vec![
                RegionRttReport {
                    region: RegionId("ap-southeast".to_owned()),
                    rtt_ms: 210,
                },
                RegionRttReport {
                    region: RegionId("eu-central".to_owned()),
                    rtt_ms: 42,
                },
                RegionRttReport {
                    region: RegionId("us-east".to_owned()),
                    rtt_ms: 87,
                },
            ],
        );
    }

    #[test]
    fn a_region_beacons_push_lands_in_the_store_and_an_unchanged_repush_signals_nothing() {
        let targets = RegionPingTargets::new();
        let mut watch = targets.subscribe();

        let set = vec![
            beacon("eu-central", "eu.example:20000"),
            beacon("us-east", "us.example:20000"),
        ];
        targets.store(set.clone());
        assert!(
            watch.has_changed().unwrap(),
            "the first push signals the ping loop",
        );
        assert_eq!(
            *watch.borrow_and_update(),
            set,
            "the pushed set lands in the store"
        );

        // A reconnect re-push of the identical set is declarative current state:
        // `send_if_modified` sees no change, so it wakes no sweep.
        targets.store(set.clone());
        assert!(
            !watch.has_changed().unwrap(),
            "an unchanged re-push does not re-signal the watch",
        );

        // A genuinely different set does signal again.
        targets.store(vec![beacon("eu-central", "eu.example:20000")]);
        assert!(
            watch.has_changed().unwrap(),
            "a changed set signals the ping loop",
        );
    }

    // --- Flight recording shipments ---

    #[tokio::test]
    async fn a_flight_shipment_is_delivered_after_enroll_as_a_tagged_frame() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frame_tx, frame_rx) = tokio::sync::oneshot::channel();

        // Stand-in coordinator: complete the enroll handshake, then read the flight
        // frame the relay ships once it is enrolled.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let hello = accept_enroll(&mut ws).await;
            let Message::Text(hello) = hello else {
                panic!("first frame is the Hello");
            };
            assert!(hello.contains("\"type\":\"hello\""));
            let frame = ws.next().await.unwrap().unwrap();
            let _ = frame_tx.send(frame);
        });

        // Queue a shipment before the subscriber starts: it ships right after enroll.
        let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        let (shipment, ack) = flight_shipment();
        flight_tx.try_send(shipment).unwrap();

        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (drain_rx, drain_acked) = no_drain();
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            apply_targets(control, drain_acked),
            OutboundQueues::new(
                mpsc::unbounded_channel().1,
                flight_rx,
                ControlQueueDepths::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        let received = tokio::time::timeout(Duration::from_secs(5), frame_rx)
            .await
            .expect("the flight frame is delivered")
            .unwrap();
        let Message::Text(text) = received else {
            panic!("a text frame");
        };
        let RelayToCoordinator::FlightRecording(notice) = serde_json::from_str(&text).unwrap()
        else {
            panic!("the frame is a flight recording");
        };
        assert_eq!(notice.session, SessionId(7));
        assert_eq!(notice.payload, r#"{"version":1}"#);
        // The ack fires once the frame is on the socket, unblocking the sink's await.
        tokio::time::timeout(Duration::from_secs(5), ack)
            .await
            .expect("the ack resolves after the send")
            .unwrap();
    }

    #[tokio::test]
    async fn a_queued_flight_shipment_is_delivered_after_a_reconnect() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frame_tx, frame_rx) = tokio::sync::oneshot::channel();

        // Stand-in coordinator: drop the first dial mid-handshake so the relay
        // redials without touching the flight channel, then enroll and read the
        // shipment on the second connection.
        tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            drop(first);
            let (second, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(second).await.unwrap();
            let hello = accept_enroll(&mut ws).await;
            let Message::Text(hello) = hello else {
                panic!("first frame is the Hello");
            };
            assert!(hello.contains("\"type\":\"hello\""));
            let frame = ws.next().await.unwrap().unwrap();
            let _ = frame_tx.send(frame);
        });

        let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        let (shipment, _ack) = flight_shipment();
        flight_tx.try_send(shipment).unwrap();

        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (drain_rx, drain_acked) = no_drain();
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            apply_targets(control, drain_acked),
            OutboundQueues::new(
                mpsc::unbounded_channel().1,
                flight_rx,
                ControlQueueDepths::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        let received = tokio::time::timeout(Duration::from_secs(5), frame_rx)
            .await
            .expect("the queued shipment is delivered after the reconnect")
            .unwrap();
        let Message::Text(text) = received else {
            panic!("a text frame");
        };
        assert!(matches!(
            serde_json::from_str::<RelayToCoordinator>(&text).unwrap(),
            RelayToCoordinator::FlightRecording(_),
        ));
    }

    #[tokio::test]
    async fn the_enroll_proof_precedes_a_pending_flight_shipment() {
        use tokio::net::TcpListener;

        // A relay that reconnects with a queued flight shipment must send its
        // IdentityProof first: a blob frame ahead of the proof would be read as the
        // proof and refused. Assert the proof is the first frame after the
        // challenge, with the shipment strictly behind it.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let hello = ws.next().await.unwrap().unwrap();
            let Message::Text(hello) = hello else {
                panic!("first frame is the Hello");
            };
            assert!(hello.contains("\"type\":\"hello\""));
            let challenge =
                serde_json::to_string(&CoordinatorToRelay::IdentityChallenge { nonce: [7u8; 32] })
                    .unwrap();
            ws.send(Message::Text(challenge.into())).await.unwrap();
            let first = ws.next().await.unwrap().unwrap();
            let second = ws.next().await.unwrap().unwrap();
            let _ = frames_tx.send((first, second));
        });

        let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        let (shipment, _ack) = flight_shipment();
        flight_tx.try_send(shipment).unwrap();

        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (drain_rx, drain_acked) = no_drain();
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            apply_targets(control, drain_acked),
            OutboundQueues::new(
                mpsc::unbounded_channel().1,
                flight_rx,
                ControlQueueDepths::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        let (first, second) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
            .await
            .expect("the relay sends the proof then the shipment")
            .unwrap();
        let decode = |message: Message| -> RelayToCoordinator {
            let Message::Text(text) = message else {
                panic!("a text frame");
            };
            serde_json::from_str(&text).unwrap()
        };
        assert!(
            matches!(decode(first), RelayToCoordinator::IdentityProof { .. }),
            "the identity proof precedes the flight shipment",
        );
        assert!(
            matches!(decode(second), RelayToCoordinator::FlightRecording(_)),
            "the flight shipment goes out only after the proof",
        );
    }

    #[tokio::test]
    async fn the_notice_and_flight_pipes_do_not_block_each_other() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

        // Stand-in coordinator: enroll, then read two frames — a notice and a
        // flight shipment, in whichever order the two independent pipes flush them.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;
            let first = ws.next().await.unwrap().unwrap();
            let second = ws.next().await.unwrap().unwrap();
            let _ = frames_tx.send((first, second));
        });

        let (notices_tx, notices_rx) = mpsc::unbounded_channel();
        notices_tx
            .send(RelayNotice::Departure(dropped_notice()))
            .unwrap();
        let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        let (shipment, _ack) = flight_shipment();
        flight_tx.try_send(shipment).unwrap();

        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (drain_rx, drain_acked) = no_drain();
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            apply_targets(control, drain_acked),
            OutboundQueues::new(notices_rx, flight_rx, ControlQueueDepths::new()),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        let (first, second) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
            .await
            .expect("both pipes deliver")
            .unwrap();
        let decode = |message: Message| -> RelayToCoordinator {
            let Message::Text(text) = message else {
                panic!("a text frame");
            };
            serde_json::from_str(&text).unwrap()
        };
        let frames = [decode(first), decode(second)];
        assert!(
            frames
                .iter()
                .any(|f| matches!(f, RelayToCoordinator::Departure(_))),
            "the notice pipe delivered",
        );
        assert!(
            frames
                .iter()
                .any(|f| matches!(f, RelayToCoordinator::FlightRecording(_))),
            "the flight pipe delivered",
        );
    }

    /// A flight shipment carrying a caller-sized payload, for the split's
    /// concurrency tests: a payload larger than the socket buffers makes the write
    /// half's send block against a coordinator that stops reading, so the read
    /// half's independence and the pending-slot survival can be observed.
    fn flight_shipment_with_payload(payload: String) -> (FlightShipment, oneshot::Receiver<()>) {
        let (sent, ack) = oneshot::channel();
        let shipment = FlightShipment {
            notice: FlightRecordingNotice {
                tenant: TenantId(TENANT.to_owned()),
                session: SessionId(7),
                desynced: false,
                payload,
            },
            sent,
        };
        (shipment, ack)
    }

    /// A sink whose sends never complete: `poll_ready`/`poll_flush` stay Pending
    /// forever, modeling a coordinator that never drains what the write half sends.
    /// Once the writer parks an item and begins sending, it is stuck mid-send —
    /// exactly the state the read half ending the connection would drop it in.
    struct StalledSink;

    impl futures_util::Sink<Message> for StalledSink {
        type Error = tokio_tungstenite::tungstenite::Error;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }

        fn start_send(self: std::pin::Pin<&mut Self>, _: Message) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }
    }

    #[tokio::test]
    async fn a_notice_parked_mid_send_survives_the_write_half_being_dropped() {
        // The split's new exit path: the read half ends the connection while the
        // write half holds a notice parked mid-send. The notice must stay in the
        // caller-owned slot so the next connection's flush delivers it. Drive the
        // write half against a sink that never completes a send, so it parks the
        // notice and blocks, then drop it — the caller's slot must still hold it.
        let (notices_tx, notices_rx) = mpsc::unbounded_channel();
        notices_tx
            .send(RelayNotice::Departure(dropped_notice()))
            .unwrap();
        let (_flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        // Live senders so the drain and challenge arms stay pending (not disabled),
        // leaving the notices arm the one that fires.
        let (_drain_tx, mut drain_rx) = watch::channel(false);
        let (_challenge_tx, challenge_rx) = mpsc::unbounded_channel::<[u8; 32]>();

        let mut outbound = OutboundQueues::new(notices_rx, flight_rx, ControlQueueDepths::new());
        let heartbeat = heartbeat(Duration::from_secs(3600));
        let identity_key = throwaway_identity_key();

        // The write half never completes (the sink stalls), so a short timeout drops
        // it exactly as the read half ending the connection would.
        let writer = write_control_frames(
            StalledSink,
            &mut outbound,
            &mut drain_rx,
            &heartbeat,
            &identity_key,
            RelayId(1),
            challenge_rx,
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), writer)
                .await
                .is_err(),
            "the write half stays parked on the stalled send",
        );

        // The notice is back in the caller-owned slot — parked before the send await
        // and never cleared — ready for the next connection's flush.
        assert_eq!(
            outbound.pending,
            Some(RelayNotice::Departure(dropped_notice())),
            "a notice parked mid-send survives the write half being dropped",
        );
        assert_eq!(
            outbound.depths.snapshot().notices,
            1,
            "the parked notice is reflected in the reported queue depth",
        );
    }

    #[tokio::test]
    async fn a_queued_flight_blob_does_not_delay_a_queued_notice() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

        // Stand-in coordinator: enroll, then read the first two frames. With both a
        // notice and a large flight blob queued, the write half's priority order
        // must put the notice first — if the flight arm outranked it, the
        // coordinator would read the blob ahead of the notice.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;
            let first = ws.next().await.unwrap().unwrap();
            let second = ws.next().await.unwrap().unwrap();
            let _ = frames_tx.send((first, second));
        });

        // Queue the notice AND a large flight blob before the subscriber starts.
        let (notices_tx, notices_rx) = mpsc::unbounded_channel();
        notices_tx
            .send(RelayNotice::Departure(dropped_notice()))
            .unwrap();
        let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        let (shipment, _ack) = flight_shipment_with_payload("x".repeat(256 * 1024));
        flight_tx.try_send(shipment).unwrap();

        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (drain_rx, drain_acked) = no_drain();
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            apply_targets(control, drain_acked),
            OutboundQueues::new(notices_rx, flight_rx, ControlQueueDepths::new()),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        let (first, second) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
            .await
            .expect("both frames arrive")
            .unwrap();
        let decode = |message: Message| -> RelayToCoordinator {
            let Message::Text(text) = message else {
                panic!("a text frame");
            };
            serde_json::from_str(&text).unwrap()
        };
        assert_eq!(
            decode(first),
            RelayToCoordinator::Departure(dropped_notice()),
            "the notice ships before the queued flight blob",
        );
        assert!(
            matches!(decode(second), RelayToCoordinator::FlightRecording(_)),
            "the flight blob ships after the notice",
        );
    }

    #[tokio::test]
    async fn the_read_half_applies_a_descriptor_while_a_large_flight_blob_is_in_flight() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Stand-in coordinator: enroll, push a descriptor set, then STOP reading.
        // The relay has a large flight blob queued, so its write half blocks sending
        // the blob once our receive buffer fills — but its read half must still
        // apply the descriptor. If reads were coupled to writes, the descriptor
        // would never land (we never drain the blob) and the applied set stays empty.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;
            let descriptors = serde_json::to_string(&CoordinatorToRelay::Descriptors {
                descriptors: vec![descriptor(1, &[])],
            })
            .unwrap();
            ws.send(Message::Text(descriptors.into())).await.unwrap();
            // Never read the queued blob; hold the connection open.
            std::future::pending::<()>().await;
        });

        // A large flight blob queued (under the 16 MiB WebSocket frame limit but
        // well past the socket send buffer): against a coordinator that stops
        // reading, its send parks the write half mid-frame. A single read+write
        // select would then be stuck in that send and never process the descriptor;
        // the split's independent read half applies it regardless.
        let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        let (shipment, _ack) = flight_shipment_with_payload("x".repeat(13 * 1024 * 1024));
        flight_tx.try_send(shipment).unwrap();

        // The shared applied set the read half reconciles is the observable.
        let applied = AppliedSessions::new();
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (drain_rx, drain_acked) = no_drain();
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            ControlApplyTargets {
                control,
                applied: applied.clone(),
                fleet: FleetMeshPeers::default(),
                verifying_keys: SharedRegistry::default(),
                region_targets: RegionPingTargets::default(),
                drain_acked,
            },
            OutboundQueues::new(
                mpsc::unbounded_channel().1,
                flight_rx,
                ControlQueueDepths::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        // The read half applies the pushed descriptor even though the write half is
        // blocked sending the large blob to a coordinator that stopped reading.
        let landed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if applied.snapshot().contains(&key(1)) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            landed.is_ok(),
            "the read half applied the descriptor while a blob was in flight",
        );
    }
}
