//! The relay's coordinator client: hold a control connection open and drive the
//! Join source from the descriptors the coordinator pushes down it.
//!
//! This is the relay side of the persistent coordinator↔relay control connection.
//! The relay dials the coordinator's control endpoint (a WebSocket), presents its
//! bootstrap secret, and **enrolls** by sending its `Hello` (id + reachable
//! address) as the first frame — registering itself over the same authenticated
//! connection rather than a separate phone-home. It then receives the
//! coordinator's pushes: the relay's current [`SessionDescriptor`](rally_point_proto::control::SessionDescriptor) set, sent on
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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use rally_point_proto::control::{MeshPeerIdentity, RelayHello};
use rally_point_proto::ids::RelayId;
use rally_point_transport::rustls::pki_types::PrivateKeyDer;
use tokio::sync::mpsc::{Receiver, UnboundedReceiver};
use tokio::sync::watch;

use crate::auth::SharedRegistry;
use crate::consensus::RelayNotice;
use crate::coordinator::region_ping::{RegionPingTargets, RegionRttCache};
use crate::mesh::control::MeshControl;
use crate::observability::flight_recorder::FlightShipment;
use crate::routing::{SessionKey, Sessions};

mod connect;
mod heartbeat;
mod reader;
mod writer;

#[cfg(test)]
mod tests;

pub use connect::{
    new_boot_id, run_descriptor_subscriber, run_descriptor_subscriber_with, sign_enroll_proof,
};

use writer::PendingFlight;

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
/// ([`CONTROL_CLOSE_PROTOCOL_MISMATCH`](rally_point_proto::version::CONTROL_CLOSE_PROTOCOL_MISMATCH)). Much longer than [`RECONNECT_DELAY`]:
/// a mismatch is fixed by deploying a compatible build on one side, not by
/// retrying, so hot-redialing every couple of seconds would only re-run the same
/// refused handshake as log noise. Still finite — the deploy that fixes the skew
/// needs no relay restart to take effect.
pub const VERSION_REFUSED_RECONNECT_DELAY: Duration = Duration::from_secs(60);

/// How long the relay waits for a coordinator's
/// [`FlightUploadGrant`](rally_point_proto::control::CoordinatorToRelay::FlightUploadGrant) (or
/// [`FlightUploadRefused`](rally_point_proto::control::CoordinatorToRelay::FlightUploadRefused)) after sending a
/// [`FlightUploadRequest`](rally_point_proto::control::RelayToCoordinator::FlightUploadRequest) before it gives up
/// on that recording. Bounds the wait so a parked shipment can never wedge the flight
/// pipe: flight data is observability, never backpressure. Also covers an *older*
/// coordinator that decodes the request as an unknown frame and silently drops it — no
/// grant will ever come, so the timeout drops the recording and unparks the slot.
pub const FLIGHT_GRANT_TIMEOUT: Duration = Duration::from_secs(30);

/// How many flight recordings the control connection ships at once. Each shipment
/// runs its own request→grant→PUT→done cycle independently, so a mass session
/// teardown (dozens of sessions closing together) drains the bounded shipment queue
/// several times faster than shipping strictly one at a time — which is what keeps
/// the queue from overflowing and shedding recordings under that burst. Kept small:
/// flight data is observability, so a handful of concurrent uploads is enough to
/// clear a teardown burst without turning a background pipe into a bandwidth spike.
pub const MAX_INFLIGHT_FLIGHT_UPLOADS: usize = 4;

/// How long a load-state answer waits for its fence probes' acknowledgements
/// before snapshotting with whatever came back.
///
/// A probe is one small frame each way on a stream the client is already holding
/// open, so a healthy client answers within a round-trip's worth of scheduling.
/// This is sized for a client that is momentarily busy rather than one that is
/// gone, and it must fit comfortably *inside* the coordinator's own attestation
/// window: past that window the coordinator has stopped waiting, so a longer
/// fence would only turn a would-be fenced answer into no answer at all.
pub const LOAD_STATE_FENCE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Depth of the read half → write half load-state ask channel.
///
/// Bounded, and deliberately: the coordinator fans a read out to every relay
/// serving a session, and a relay whose writer is momentarily behind must not
/// accumulate questions a caller has long stopped waiting for. A full channel
/// drops the ask, which the coordinator reads as this relay not having attested
/// — the same reading a slow or disconnected relay gets — rather than blocking
/// the read half, which would stall descriptor application behind a load-state
/// read.
const LOAD_STATE_ASK_CAPACITY: usize = 64;

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

/// Point-in-time observables of the coordinator control connection, published for
/// the task-stats reporter to log next to its resource sample. These are the
/// load-test observables for control-plane pressure and delivery lag: how many
/// notices and flight recordings are queued or in flight up the connection and how
/// many blob bytes those in-flight recordings hold (outbound pressure), plus how far
/// the last descriptor set applied behind the coordinator's staging clock and how
/// large that set was (inbound apply lag).
///
/// The connection's writer refreshes the outbound-pressure fields as it works the
/// queues, and its reader refreshes the apply-lag fields as descriptor sets apply;
/// the task-stats reporter reads a [`snapshot`](Self::snapshot). All zero on a relay
/// with no coordinator connection — nothing writes them — which reads correctly as
/// "no pressure, no lag sample". Relaxed atomics: each field is an independent
/// value a single writer stores and a single reader loads, with no cross-field
/// invariant to protect.
#[derive(Clone, Default)]
pub struct ControlConnStats {
    inner: Arc<ControlConnStatsInner>,
}

#[derive(Default)]
struct ControlConnStatsInner {
    notices: AtomicUsize,
    flights: AtomicUsize,
    pending_blob_bytes: AtomicUsize,
    descriptor_apply_lag_ms: AtomicU64,
    descriptor_set_len: AtomicUsize,
}

impl ControlConnStats {
    /// Creates a fresh, all-zero handle (a relay that has not connected yet, or
    /// one that never will).
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the current outbound-queue occupancy: `notices` and `flights` count
    /// everything queued or in flight up the connection (each includes the items
    /// parked mid-cycle), and `pending_blob_bytes` is the summed compressed size of
    /// every flight recording currently in flight, or zero when none is.
    fn store(&self, notices: usize, flights: usize, pending_blob_bytes: usize) {
        self.inner.notices.store(notices, Ordering::Relaxed);
        self.inner.flights.store(flights, Ordering::Relaxed);
        self.inner
            .pending_blob_bytes
            .store(pending_blob_bytes, Ordering::Relaxed);
    }

    /// Records a descriptor set apply: `set_len` is the size of the set just
    /// applied, and — when the push carried a staging stamp — the observed apply
    /// lag is `now - staged_at`, clamped at zero so a backward cross-host clock skew
    /// never reads as a negative lag. A push with no stamp (a coordinator predating
    /// the field) still updates the set length but leaves the last lag sample
    /// unchanged, so the stat holds its most recent real reading rather than
    /// resetting.
    fn record_descriptor_apply(&self, set_len: usize, staged_at_unix_ms: Option<u64>) {
        self.inner
            .descriptor_set_len
            .store(set_len, Ordering::Relaxed);
        if let Some(staged_at) = staged_at_unix_ms {
            let lag = now_unix_ms().saturating_sub(staged_at);
            self.inner
                .descriptor_apply_lag_ms
                .store(lag, Ordering::Relaxed);
        }
    }

    /// The latest recorded observables, for the task-stats reporter to log.
    pub fn snapshot(&self) -> ControlConnStatsSnapshot {
        ControlConnStatsSnapshot {
            notices: self.inner.notices.load(Ordering::Relaxed),
            flights: self.inner.flights.load(Ordering::Relaxed),
            pending_blob_bytes: self.inner.pending_blob_bytes.load(Ordering::Relaxed),
            descriptor_apply_lag_ms: self.inner.descriptor_apply_lag_ms.load(Ordering::Relaxed),
            descriptor_set_len: self.inner.descriptor_set_len.load(Ordering::Relaxed),
        }
    }
}

/// Wall clock as unix epoch milliseconds — the base the descriptor apply-lag
/// measurement differences the coordinator's staging stamp against.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// A snapshot of the coordinator control connection's observables (see
/// [`ControlConnStats`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ControlConnStatsSnapshot {
    /// Notices queued or in flight up the connection, including one parked mid-send.
    pub notices: usize,
    /// Flight recordings queued or in flight up the connection, including those
    /// mid-upload.
    pub flights: usize,
    /// Summed compressed bytes of the flight recordings currently in flight, or zero.
    pub pending_blob_bytes: usize,
    /// The last observed descriptor apply lag, in milliseconds: the wall-clock gap
    /// between the coordinator staging a descriptor set and the relay applying it,
    /// clamped at zero for a backward clock skew. Coarse cross-host measurement,
    /// meaningful at seconds scale. Holds its last real reading across pushes that
    /// carry no stamp; zero until the first stamped set applies.
    pub descriptor_apply_lag_ms: u64,
    /// The size of the last applied descriptor set.
    pub descriptor_set_len: usize,
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

/// The relay's outbound work queues and the stats handle that reports their
/// occupancy. The notice pipe is a channel plus the one in-flight slot holding the
/// notice pulled but not yet confirmed sent; the flight pipe is a channel plus a
/// small in-flight table of the recordings currently cycling their uploads.
///
/// **Caller-owned across reconnects.** The subscriber owns this and lends `&mut`
/// per connection: an item parked when a connection dies stays parked and rides the
/// next connection's flush rather than being lost. For a notice, the write half sets
/// `pending` *before* the send await and clears it only *after* the send returns,
/// with no await between — so a dropped or errored send leaves it parked, while a
/// completed send's notice is already cleared and never re-sent. For a flight
/// recording, its shipment is pushed onto `pending_flights` before its request is
/// sent and removed only when it is stored (ack fired) or dropped, so a connection
/// death leaves every undelivered shipment findable; the next connection re-requests
/// each with a fresh id.
pub struct OutboundQueues {
    /// The unbounded notice pipe: departure/desync/result/session-closed notices to
    /// forward up the connection. Drained strictly FIFO through `pending`, which is
    /// what keeps `SessionClosed`'s "no earlier notice for the session still in
    /// flight" guarantee.
    notices: UnboundedReceiver<RelayNotice>,
    /// The one notice pulled but not yet confirmed sent.
    pending: Option<RelayNotice>,
    /// The bounded flight pipe: flushed recordings to ship up the connection.
    /// Deliberately separate from `notices` so a blob frame never delays a notice;
    /// bounded so a wedged connection drops recordings rather than growing unbounded.
    flight: Receiver<FlightShipment>,
    /// The recordings currently in flight, up to [`MAX_INFLIGHT_FLIGHT_UPLOADS`] at
    /// once. Each entry's shipment is durable across a reconnect (its per-connection
    /// request id and stage are re-armed on the next connection); an entry is removed
    /// only once its recording is stored (ack fired) or dropped. Order carries no
    /// meaning — recordings are independent — so entries are removed by swap.
    pending_flights: Vec<PendingFlight>,
    /// Publishes the outbound-queue occupancy (and, from the reader, the descriptor
    /// apply lag) for the task-stats reporter.
    stats: ControlConnStats,
}

impl OutboundQueues {
    /// Builds the queues over the given channels and stats reporter, with the notice
    /// slot empty and no recording in flight.
    pub fn new(
        notices: UnboundedReceiver<RelayNotice>,
        flight: Receiver<FlightShipment>,
        stats: ControlConnStats,
    ) -> Self {
        Self {
            notices,
            pending: None,
            flight,
            pending_flights: Vec::new(),
            stats,
        }
    }
}

/// The live state each heartbeat reports on. Every handle is held across
/// reconnects, so a beat reads current state independent of any reconnect, and a
/// beat snapshots all of it at send time.
pub struct HeartbeatSources {
    /// The live roster; each beat carries a session's connected slots on its
    /// [`SessionPresence`](rally_point_proto::control::SessionPresence) entry (tenant/session/slot only — the relay holds no
    /// user identity to leak).
    pub sessions: Sessions,
    /// The per-session decision-makers. These, not the live roster, decide which
    /// sessions a beat names — a maker outlives the links that fed it, so a
    /// session whose local slots have all left keeps restating what it learned
    /// while they were here. Each entry's load state is read from its maker:
    /// which of the session's slots ever connected
    /// here, which ever reported their game loop running, and when this relay
    /// learned the session started. Restating it every beat is what makes it
    /// durable — the matching notices are dropped once sent, so a coordinator that
    /// lost one, or restarted, recovers within a beat.
    pub decision_makers: Arc<crate::consensus::DecisionMakers>,
    /// The measured region round-trip cache the ping loop writes; each beat carries
    /// its current medians.
    pub region_rtt_cache: RegionRttCache,
    /// The load-state fence broker the slot-link tasks resolve clients' probe
    /// acknowledgements against. A heartbeat never touches it — only an attested
    /// load-state answer fences — but it lives here because it is read from
    /// exactly the same handles, and against exactly the same session state, the
    /// snapshot beside it is built from.
    pub load_fence: crate::coordinator::load_fence::LoadStateFence,
}

/// What each heartbeat carries and how often it goes up.
pub struct HeartbeatConfig {
    /// The state a beat reports.
    pub sources: HeartbeatSources,
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
