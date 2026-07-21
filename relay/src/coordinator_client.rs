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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use rally_point_proto::control::{
    CoordinatorToRelay, DescriptorKey, ENROLL_POP_CONTEXT, MeshPeerIdentity, RegionRttReport,
    RelayHello, RelayToCoordinator, SessionDescriptor, SessionPresence,
};
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::{
    CONTROL_CLOSE_DUPLICATE_RELAY_ID, CONTROL_CLOSE_ENROLL_UNAUTHORIZED,
    CONTROL_CLOSE_IDENTITY_UNPROVEN, CONTROL_CLOSE_PROTOCOL_MISMATCH, CONTROL_CLOSE_UNKNOWN_REGION,
};
use rally_point_transport::rustls::pki_types::PrivateKeyDer;
use tokio::sync::mpsc::{Receiver, UnboundedReceiver, UnboundedSender};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::flight_upload::{self, PutOutcome};
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

/// How long the relay waits for a coordinator's
/// [`FlightUploadGrant`](CoordinatorToRelay::FlightUploadGrant) (or
/// [`FlightUploadRefused`](CoordinatorToRelay::FlightUploadRefused)) after sending a
/// [`FlightUploadRequest`](RelayToCoordinator::FlightUploadRequest) before it gives up
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

/// The reader→writer routes on one control connection: frames the read half received
/// but the write half must send (every send is owned by the write half). A mid-stream
/// identity challenge's nonce — answering is a send — and the coordinator's flight-upload
/// grant/refusal, which the writer acts on because it holds the parked shipment and
/// drives the upload.
struct WriterRoutes {
    /// A routed identity-challenge nonce for the writer to answer with a proof send.
    challenge_rx: UnboundedReceiver<[u8; 32]>,
    /// A routed flight-upload grant or refusal for the writer's upload machinery.
    flight_grant_rx: UnboundedReceiver<FlightGrant>,
}

/// A coordinator's answer to a [`FlightUploadRequest`](RelayToCoordinator::FlightUploadRequest),
/// routed from the read half to the write half (which owns the upload lifecycle).
/// Carries the request's correlation id so the writer matches it to the shipment it
/// still holds and ignores an answer for one it has already resolved (a stale answer
/// from a prior connection).
enum FlightGrant {
    /// The coordinator minted a presigned upload URL; the writer PUTs the recording.
    Granted {
        /// The correlation id of the request this grants.
        request: u64,
        /// The presigned PUT URL.
        url: String,
    },
    /// The coordinator refused; the writer drops the recording.
    Refused {
        /// The correlation id of the request this refuses.
        request: u64,
    },
}

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

/// One flight recording in flight on the control connection: the parked shipment
/// plus where it is in its request→grant→upload→done cycle. The connection ships up
/// to [`MAX_INFLIGHT_FLIGHT_UPLOADS`] of these at once, each cycling independently.
///
/// **The shipment is the durable part.** It lives in the caller-owned
/// [`OutboundQueues::pending_flights`] from the moment it is pulled until it is
/// stored (its `sent` ack fires) or dropped (refused/failed/timeout), so a
/// connection death leaves it parked for the next connection to re-request.
/// `request` and `stage` are current-connection scratch: request ids are minted per
/// connection, so the next connection re-arms every parked shipment with a fresh id
/// (a stale grant from the dead connection can never match) at its flight-flush
/// entry.
struct PendingFlight {
    /// The parked shipment: its compressed bytes, and the `sent` ack fired only once
    /// the recording is stored.
    shipment: FlightShipment,
    /// The correlation id of the upload request outstanding for this shipment on the
    /// CURRENT connection. Re-minted on every (re)request.
    request: u64,
    /// Where this shipment is in its upload cycle on the current connection.
    stage: FlightStage,
}

/// Where a [`PendingFlight`] is in its request→grant→upload→done cycle on the
/// current connection.
enum FlightStage {
    /// The upload request is sent; waiting for the coordinator's grant or refusal
    /// until `deadline`, after which the recording is dropped (flight data is never
    /// backpressure).
    AwaitingGrant { deadline: Instant },
    /// The grant arrived and a detached PUT is uploading the compressed bytes; the
    /// PUT reports its outcome over the connection's shared completion channel.
    Uploading,
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
/// coordinated-drain seam; `control_connected` reports whether this relay is
/// enrolled and receiving coordinator pushes — set `true` on the first inbound
/// application frame (which an accepted enroll always sends and a refusal never
/// does), cleared on every disconnect — so the provisional-admission sweep
/// ([`crate::provisional::run_sweep`]) arms only while it is `true` rather than
/// reaping across a reconnect gap, and the idle self-exit
/// ([`crate::idle_exit::run`]) reads it as the "not enrolled" half of its exit
/// condition.
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
/// `pending` slot and `pending_flights` table the single source of undelivered
/// state across a reconnect.
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

    // Shipments held over from a prior connection are NOT flushed here: their bytes
    // never ride the socket. They stay parked in `pending_flights`, and the write half
    // re-sends each one's small `FlightUploadRequest` at its own entry (below), so a
    // shipment orphaned by a dead connection simply re-requests an upload URL on the
    // next one.

    // Split the enrolled socket into a read half and a write half, driven
    // concurrently. The write half owns every send, so a stalled send never stalls the
    // read half — coordinator pushes keep applying while the writer works its queues
    // and drives its uploads' request/grant/done handshakes.
    let (sink, stream) = socket.split();

    // The reader records the descriptor apply lag into the same stats handle the
    // writer refreshes the queue depths on; a clone points at the shared atomics, so
    // the reader can write it without contending with the writer's `&mut outbound`.
    let read_stats = outbound.stats.clone();

    // A mid-stream identity challenge's answer is a *send*, and only the write
    // half may send, so the read half routes the nonce here for the writer to
    // answer. The coordinator does not re-challenge after enroll, so this is a
    // rarely-if-ever-used defensive path.
    let (challenge_tx, challenge_rx) = tokio::sync::mpsc::unbounded_channel();

    // A flight-upload grant or refusal is read on the read half but acted on by the
    // write half (which owns the parked shipment and its upload lifecycle), so the read
    // half routes it here — the same shape as the challenge channel.
    let (flight_grant_tx, flight_grant_rx) = tokio::sync::mpsc::unbounded_channel();

    // Run both halves until either ends; the first to finish is the connection's
    // outcome, and dropping the other closes its half of the socket. There is no
    // spawned task to leak, and the caller-owned `outbound` slots — mutated in place
    // by the writer through `&mut` — carry whatever stayed undelivered straight back
    // to the caller no matter which half ended the connection.
    tokio::select! {
        result = read_control_frames(stream, apply_targets, relay_id, challenge_tx, flight_grant_tx, read_stats, control_connected) => result,
        result = write_control_frames(
            sink,
            outbound,
            drain,
            heartbeat,
            &enroll.identity_key,
            relay_id,
            WriterRoutes {
                challenge_rx,
                flight_grant_rx,
            },
        ) => result,
    }
}

/// The read half of an enrolled control connection: receives coordinator frames
/// one at a time and applies each synchronously, in arrival order. A descriptor
/// push reconciles the Join source and the applied set (and records its apply lag
/// and set size into `stats`); `MeshPeers`/`TenantKeys`/`RegionBeacons` replace
/// their stores; a `DrainAck` flips the drain-acked signal. Because frames apply
/// strictly in arrival order, a descriptor push the coordinator sends just before a
/// `DrainAck` has already updated the applied set by the time the ack fires.
///
/// A mid-stream `IdentityChallenge`'s answer is a send, so it is routed to the
/// write half through `challenge_tx` rather than answered here. A `Close` (or the
/// stream ending, or a read/decode error) ends the connection with the same
/// classification a close carries anywhere.
///
/// The first successfully decoded application frame reports the control connection
/// established through `control_connected`: an accepted enroll always leads with a
/// connect-time push (tenant keys first), while every refusal — version, region,
/// identity, or ledger enrollment — closes without ever pushing one, so the first
/// inbound frame here is precisely the "this enroll was accepted" signal, and a
/// refusal loop never reads as connected.
async fn read_control_frames(
    mut stream: impl futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
    + Unpin,
    apply_targets: &ControlApplyTargets,
    relay_id: RelayId,
    challenge_tx: tokio::sync::mpsc::UnboundedSender<[u8; 32]>,
    flight_grant_tx: UnboundedSender<FlightGrant>,
    stats: ControlConnStats,
    control_connected: &watch::Sender<bool>,
) -> Result<ControlDisconnect, ControlError> {
    // Set once, on the first decoded application frame: it is the accepted-enroll
    // signal (see this function's doc). The reconnect loop clears it uniformly on
    // disconnect, so it never carries a stale reading into the next connection.
    let mut connected_reported = false;
    loop {
        // The stream ended (no close frame): let the caller redial.
        let Some(message) = stream.next().await else {
            return Ok(ControlDisconnect::Ordinary);
        };
        match message? {
            Message::Text(text) => {
                let message: CoordinatorToRelay = serde_json::from_str(text.as_str())?;
                if !connected_reported {
                    let _ = control_connected.send(true);
                    connected_reported = true;
                }
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
                    CoordinatorToRelay::FlightUploadGrant { request, url } => {
                        // The coordinator minted an upload URL: route it to the write
                        // half, which holds the parked shipment and drives the PUT. A
                        // dropped receiver means the write half is gone (the connection
                        // is ending), so a failed route is a harmless no-op.
                        let _ = flight_grant_tx.send(FlightGrant::Granted { request, url });
                    }
                    CoordinatorToRelay::FlightUploadRefused { request } => {
                        // The coordinator refused the upload: route the refusal so the
                        // write half drops the parked recording and unparks the slot.
                        let _ = flight_grant_tx.send(FlightGrant::Refused { request });
                    }
                    other => apply_message(
                        &apply_targets.control,
                        other,
                        &apply_targets.applied,
                        &stats,
                    ),
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
/// flight-upload arms (a routed grant/refusal, a completed upload, an expired grant
/// wait), then the periodic heartbeat, and last a fresh flight shipment — so a
/// close-bearing notice always outruns flight work, and a small upload request never
/// rides ahead of a webhook-bearing notice.
///
/// **Flight recordings' bytes never ride this connection, and up to
/// [`MAX_INFLIGHT_FLIGHT_UPLOADS`] ship concurrently.** Each parked shipment gets a
/// small [`FlightUploadRequest`](RelayToCoordinator::FlightUploadRequest) carrying its
/// own per-connection correlation id; the read half routes back the coordinator's
/// grant or refusal for that id, and on a grant this half spawns a detached PUT of the
/// compressed bytes straight to the object store (see [`crate::flight_upload`]), which
/// reports its outcome over one shared per-connection completion channel. Only after a
/// PUT stores the object does this half fire that shipment's `sent` ack (delivery
/// means *stored*) and send a
/// [`FlightUploadDone`](RelayToCoordinator::FlightUploadDone). A refusal, an upload
/// failure, or no grant within [`FLIGHT_GRANT_TIMEOUT`] (which also covers an older
/// coordinator that drops the request as unknown) drops that one recording with a log
/// — flight data is observability, never backpressure. Because each shipment carries
/// its own id and cycle stage, several can be awaiting grants or uploading at once
/// without interfering.
///
/// The caller-owned `outbound` state (`pending`, `pending_flights`) is this half's
/// only durable state across a reconnect. A notice is parked *before* its send await
/// and cleared only *after* it returns; a shipment is pushed onto `pending_flights`
/// *before* its request send and removed only on ack (stored) or drop (lost) — so if
/// this future is dropped (the read half ended the connection) or a send errors
/// mid-frame, every undelivered item stays parked and the next connection re-delivers
/// it (a shipment re-*requests* an upload URL with a fresh id), while a
/// delivered/stored item is already cleared and never re-run.
async fn write_control_frames(
    mut sink: impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    outbound: &mut OutboundQueues,
    drain: &mut watch::Receiver<bool>,
    heartbeat: &HeartbeatConfig,
    identity_key: &PrivateKeyDer<'static>,
    relay_id: RelayId,
    routes: WriterRoutes,
) -> Result<ControlDisconnect, ControlError> {
    let WriterRoutes {
        mut challenge_rx,
        mut flight_grant_rx,
    } = routes;
    // Split the caller-owned queues into their fields. The park/clear discipline
    // below mutates these in place, so whatever stays parked here is exactly what the
    // caller's `outbound` holds when this future ends.
    let OutboundQueues {
        notices,
        pending,
        flight,
        pending_flights,
        stats,
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
    // The read half likewise holds the flight-grant sender for the connection's life.
    let mut flight_grant_open = true;

    // The flight uploads' per-connection state. `next_request` mints a fresh
    // correlation id per request on THIS connection, so a stale grant from a prior one
    // can never match a live request; every granted PUT reports its outcome over
    // `put_done`, one shared completion channel this half owns so waiting on many
    // uploads at once is a single select arm rather than a fan of per-upload futures.
    // This half holds `put_done_tx` for the connection's whole life, so `put_done_rx`
    // yields a real completion or pends — never `None` — and its arm needs no guard.
    let mut next_request: u64 = 0;
    let (put_done_tx, mut put_done_rx) =
        tokio::sync::mpsc::unbounded_channel::<flight_upload::FlightPutDone>();

    // Re-request every shipment parked from a prior connection: mint a fresh id and
    // grant deadline for each and re-send its small upload request. This re-arms the
    // per-connection scratch (`request`/`stage`) a reconnect invalidated, so a grant
    // meant for the dead connection can never be mistaken for one of these.
    for flight in pending_flights.iter_mut() {
        next_request += 1;
        flight.request = next_request;
        flight.stage = FlightStage::AwaitingGrant {
            deadline: Instant::now() + FLIGHT_GRANT_TIMEOUT,
        };
        // A send error ends the connection (via `?`) with the shipment still parked,
        // so the next connection re-requests it.
        send_flight_request(&mut sink, flight.request, &flight.shipment).await?;
    }

    loop {
        // Publish the current queue occupancy for the task-stats reporter. Each count
        // includes items parked mid-cycle, so a shipment is visible for its whole
        // upload lifetime rather than only between sends; the blob-bytes figure sums
        // every in-flight recording's compressed size.
        stats.store(
            notices.len() + usize::from(pending.is_some()),
            flight.len() + pending_flights.len(),
            pending_flights
                .iter()
                .map(|f| f.shipment.payload.len())
                .sum(),
        );

        // The nearest grant-wait deadline across shipments still awaiting a grant, if
        // any — the sleep the timeout arm races. An uploading shipment has no such
        // deadline (its detached PUT owns its own retry budget), so it does not figure.
        let earliest_grant_deadline = pending_flights
            .iter()
            .filter_map(|f| match f.stage {
                FlightStage::AwaitingGrant { deadline } => Some(deadline),
                FlightStage::Uploading => None,
            })
            .min();

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

            // A grant or refusal the read half routed here, matched to its shipment by
            // request id. Above the heartbeat so it gates the flight pipe promptly, but
            // below notices so it never delays a webhook-bearing frame.
            grant = flight_grant_rx.recv(), if flight_grant_open => {
                match grant {
                    None => flight_grant_open = false,
                    // A grant for a shipment still awaiting one: spawn the detached PUT
                    // of its compressed bytes and mark it uploading. The shipment stays
                    // parked (its `sent` ack fires only on a stored PUT), so a
                    // connection death mid-upload re-requests it on the next connection.
                    Some(FlightGrant::Granted { request, url }) => {
                        if let Some(flight) = pending_flights.iter_mut().find(|f| {
                            f.request == request
                                && matches!(f.stage, FlightStage::AwaitingGrant { .. })
                        }) {
                            flight_upload::spawn_put(
                                url,
                                flight.shipment.payload.clone(),
                                relay_id,
                                request,
                                put_done_tx.clone(),
                            );
                            flight.stage = FlightStage::Uploading;
                        }
                        // else: a stale grant — its shipment already resolved, or the id
                        // is from a prior connection — so ignore it.
                    }
                    // A refusal for a shipment still awaiting a grant: drop it.
                    Some(FlightGrant::Refused { request }) => {
                        if let Some(index) = pending_flights.iter().position(|f| {
                            f.request == request
                                && matches!(f.stage, FlightStage::AwaitingGrant { .. })
                        }) {
                            let flight = pending_flights.swap_remove(index);
                            drop_flight(flight, relay_id, "coordinator refused the upload");
                        }
                        // else: a stale refusal — ignore it.
                    }
                }
            }

            // A detached PUT reported its outcome over the shared completion channel.
            // On stored, fire the ack (delivery means stored) and tell the coordinator
            // so it runs its post-store bookkeeping; on failure, drop the recording.
            done = put_done_rx.recv() => {
                let flight_upload::FlightPutDone { request, outcome } = done
                    .expect("the write half holds a completion sender for the connection's life");
                if let Some(index) = pending_flights
                    .iter()
                    .position(|f| f.request == request && matches!(f.stage, FlightStage::Uploading))
                {
                    match outcome {
                        PutOutcome::Stored => {
                            let flight = pending_flights.swap_remove(index);
                            let _ = flight.shipment.sent.send(());
                            send_flight_done(&mut sink, request).await?;
                        }
                        PutOutcome::Failed => {
                            let flight = pending_flights.swap_remove(index);
                            drop_flight(flight, relay_id, "upload failed");
                        }
                    }
                }
                // else: a completion for a shipment no longer in the table (already
                // resolved) — ignore it.
            }

            // A grant did not arrive within the timeout for one or more shipments — a
            // coordinator that never answers, or an older one that dropped the request
            // as an unknown frame. Drop every shipment whose grant deadline has now
            // elapsed so the pipe keeps moving; the rest keep waiting.
            _ = async {
                tokio::time::sleep_until(earliest_grant_deadline.expect("guarded by is_some")).await
            }, if earliest_grant_deadline.is_some() => {
                let now = Instant::now();
                let mut index = 0;
                while index < pending_flights.len() {
                    match pending_flights[index].stage {
                        FlightStage::AwaitingGrant { deadline } if deadline <= now => {
                            let flight = pending_flights.swap_remove(index);
                            drop_flight(flight, relay_id, "no upload grant within the timeout");
                            // swap_remove moved the last entry into `index`; re-check it
                            // rather than advancing past it.
                        }
                        _ => index += 1,
                    }
                }
            }

            _ = heartbeat_tick.tick() => {
                // Every beat carries the full current roster — declarative and
                // self-healing (a lost or reordered beat is corrected by the next
                // one), bounded by the relay's live slots. A delta scheme is a
                // scale option, not needed at these payload sizes.
                let frame = serde_json::to_string(&RelayToCoordinator::Heartbeat {
                    roster_complete: true,
                    sessions: heartbeat_presence(&heartbeat.sessions),
                    region_rtts: heartbeat_region_rtts(&heartbeat.region_rtt_cache),
                })
                .expect("a heartbeat always serializes");
                sink.send(Message::Text(frame.into())).await?;
            }

            // Pull the next shipment while under the concurrency cap, then send its
            // small upload request. Below every control arm: the request is small, but
            // it must never ride ahead of a webhook-bearing notice.
            shipment = flight.recv(),
                if pending_flights.len() < MAX_INFLIGHT_FLIGHT_UPLOADS && flight_open =>
            {
                match shipment {
                    Some(shipment) => {
                        next_request += 1;
                        let request = next_request;
                        pending_flights.push(PendingFlight {
                            shipment,
                            request,
                            stage: FlightStage::AwaitingGrant {
                                deadline: Instant::now() + FLIGHT_GRANT_TIMEOUT,
                            },
                        });
                        // A send error ends the connection (via `?`) with the shipment
                        // still parked, so the next connection re-requests it.
                        send_flight_request(
                            &mut sink,
                            request,
                            &pending_flights.last().expect("just pushed").shipment,
                        )
                        .await?;
                    }
                    None => flight_open = false,
                }
            }
        }
    }
}

/// Drops an in-flight flight shipment that will not be stored (refused, upload
/// failed, or no grant in time), logging the loss. Dropping the entry drops its
/// shipment's `sent` ack, which resolves the sink's await as not-stored — flight data
/// is observability, never backpressure on a session teardown.
fn drop_flight(flight: PendingFlight, relay_id: RelayId, reason: &str) {
    let shipment = flight.shipment;
    tracing::warn!(
        relay_id = relay_id.0,
        tenant = shipment.tenant.as_ref(),
        session = shipment.session.0,
        bytes = shipment.payload.len(),
        reason,
        "dropping a flight recording; flight data is never backpressure",
    );
    // `shipment` drops here, dropping its `sent` ack so the sink await resolves as
    // not-stored.
}

/// Wall clock as unix epoch milliseconds — the base the descriptor apply-lag
/// measurement differences the coordinator's staging stamp against.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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

/// Sends a [`RelayToCoordinator::FlightUploadRequest`] up the control connection: asks
/// the coordinator to mint a presigned upload URL for the parked shipment, naming the
/// per-connection correlation id and the exact compressed byte count the coordinator
/// binds into the URL's signature. The recording's bytes stay off the socket.
async fn send_flight_request(
    socket: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    request: u64,
    shipment: &FlightShipment,
) -> Result<(), ControlError> {
    let frame = serde_json::to_string(&RelayToCoordinator::FlightUploadRequest {
        request,
        tenant: shipment.tenant.clone(),
        session: shipment.session,
        desynced: shipment.desynced,
        bytes: shipment.payload.len() as u64,
    })
    .expect("a flight upload request always serializes");
    socket.send(Message::Text(frame.into())).await?;
    Ok(())
}

/// Sends a [`RelayToCoordinator::FlightUploadDone`] up the control connection after a
/// successful upload, so the coordinator runs its post-store bookkeeping. `request`
/// echoes the correlation id of the completed upload.
async fn send_flight_done(
    socket: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    request: u64,
) -> Result<(), ControlError> {
    let frame = serde_json::to_string(&RelayToCoordinator::FlightUploadDone { request })
        .expect("a flight upload done always serializes");
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
/// A descriptor set reconciles membership and records its apply lag and size into
/// `stats`; an unrecognized message kind (one a newer coordinator sent that this
/// build predates) is skipped, not an error — the [`CoordinatorToRelay::Unknown`]
/// catch-all already kept the decode from failing, so the connection stays up and
/// later descriptors keep flowing. A *malformed* known message still surfaces as a
/// decode error at the call site, closing the connection so the next one re-syncs —
/// that is a coordinator bug, not a forward-compatible addition, and should not be
/// silently swallowed.
fn apply_message(
    control: &MeshControl,
    message: CoordinatorToRelay,
    applied: &AppliedSessions,
    stats: &ControlConnStats,
) {
    match message {
        CoordinatorToRelay::Descriptors {
            descriptors,
            staged_at_unix_ms,
        } => {
            // Record the apply lag before reconciling so the sample reflects the
            // moment the set is applied, and the set size regardless of whether the
            // push carried a stamp.
            stats.record_descriptor_apply(descriptors.len(), staged_at_unix_ms);
            reconcile(control, &descriptors, applied);
        }
        CoordinatorToRelay::DescriptorDelta {
            staged_at_unix_ms,
            upserts,
            removals,
        } => {
            // A delta is only meaningful against the applied state the connect-time
            // full set established. Ordering on the single control connection
            // guarantees that re-sync precedes every delta (the coordinator sends the
            // full set before any delta, and a reconnect re-syncs the full set
            // first), so the relay needs no version or sequence tracking of its own to
            // apply one safely. Apply first, then record the lag and the resulting
            // applied-set size — the size of what this relay now holds, not the
            // delta's entry count.
            let applied_len = reconcile_delta(control, &upserts, &removals, applied);
            stats.record_descriptor_apply(applied_len, staged_at_unix_ms);
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
        // The connection loop intercepts the flight-upload grant/refusal (it routes
        // them to the write half) before delegating here, so these arms are only
        // defensive no-ops for a stray one.
        CoordinatorToRelay::FlightUploadGrant { .. } => {
            tracing::debug!("ignoring a FlightUploadGrant received outside the upload handshake");
        }
        CoordinatorToRelay::FlightUploadRefused { .. } => {
            tracing::debug!("ignoring a FlightUploadRefused received outside the upload handshake");
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

/// Applies a descriptor delta against the already-applied full set: each upsert
/// goes through the same per-descriptor apply a full-set [`reconcile`] uses — which
/// is what preserves the roster-reconcile-on-apply that resolves a dial race for a
/// session arriving as a delta upsert — and each removal through the same
/// per-session leave a descriptor vanishing from a full set takes. Returns the
/// applied set's size after the delta, so the caller records it as the descriptor
/// set length (the size of what this relay now holds, not the delta's entry count).
///
/// A delta is meaningful only against the state a full set established; the single
/// ordered control connection guarantees that full-set re-sync precedes every delta
/// (a reconnect re-syncs the full set first), so no version or sequence tracking is
/// needed here. The `applied` lock is held across the (sync, await-free) Join-source
/// calls so the set and the issued commands can never be observed out of step, the
/// same discipline [`reconcile`] follows.
fn reconcile_delta(
    control: &MeshControl,
    upserts: &[SessionDescriptor],
    removals: &[DescriptorKey],
    applied: &AppliedSessions,
) -> usize {
    let mut applied = applied.inner.lock();
    for descriptor in upserts {
        control.apply_descriptor(descriptor);
        applied.insert(SessionKey {
            tenant: descriptor.tenant.clone(),
            session: descriptor.session,
        });
    }
    for removal in removals {
        let key = SessionKey {
            tenant: removal.tenant.clone(),
            session: removal.session,
        };
        control.end_session(&key);
        applied.remove(&key);
    }
    applied.len()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use bytes::Bytes;

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
        let _ = control.register_link(RelayId(2), 1, tx2);
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
        let _ = control.register_link(RelayId(2), 1, tx2);
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
        let _ = control.register_link(RelayId(2), 1, tx2);
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

    #[test]
    fn a_delta_adds_removes_and_mutates_converging_to_a_full_reconcile() {
        // The delta path and a full-set reconcile of the same target leave the relay
        // in the same applied state — a delta is only a cheaper way to reach it.
        let delta_control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (d2_tx, mut d2_rx) = mpsc::unbounded_channel();
        let (d3_tx, mut d3_rx) = mpsc::unbounded_channel();
        let _ = delta_control.register_link(RelayId(2), 1, d2_tx);
        let _ = delta_control.register_link(RelayId(3), 1, d3_tx);
        let delta_applied = AppliedSessions::new();

        // Connect-time full set: sessions 1 and 2 both mesh peer 2.
        reconcile(
            &delta_control,
            &[descriptor(1, &[2]), descriptor(2, &[2])],
            &delta_applied,
        );
        // Drain the baseline joins so the post-delta command stream is clean.
        while d2_rx.try_recv().is_ok() {}
        while d3_rx.try_recv().is_ok() {}

        // One delta: add session 3 (meshing peer 2), remove session 1, and mutate
        // session 2 in place to mesh peer 3 instead of peer 2.
        apply_message(
            &delta_control,
            CoordinatorToRelay::DescriptorDelta {
                staged_at_unix_ms: None,
                upserts: vec![descriptor(3, &[2]), descriptor(2, &[3])],
                removals: vec![DescriptorKey {
                    tenant: TenantId(TENANT.to_owned()),
                    session: SessionId(1),
                }],
            },
            &delta_applied,
            &ControlConnStats::new(),
        );

        let d2: Vec<MeshCommand> = std::iter::from_fn(|| d2_rx.try_recv().ok()).collect();
        let d3: Vec<MeshCommand> = std::iter::from_fn(|| d3_rx.try_recv().ok()).collect();
        assert!(
            d2.contains(&MeshCommand::Join(key(3))),
            "the added session joins peer 2: {d2:?}",
        );
        assert!(
            d2.contains(&MeshCommand::Leave(key(1))),
            "the removed session leaves peer 2: {d2:?}",
        );
        assert!(
            d3.contains(&MeshCommand::Join(key(2))),
            "the mutated session re-applies and joins its new peer 3: {d3:?}",
        );

        // A full-set reconcile straight to the same target set on a fresh relay.
        let full_control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let full_applied = AppliedSessions::new();
        reconcile(
            &full_control,
            &[descriptor(2, &[3]), descriptor(3, &[2])],
            &full_applied,
        );

        assert_eq!(
            delta_applied.snapshot(),
            full_applied.snapshot(),
            "the delta converges to the same applied set as the full reconcile",
        );
        assert_eq!(delta_applied.snapshot(), HashSet::from([key(2), key(3)]));
    }

    #[test]
    fn a_delta_records_the_applied_set_size_after_the_delta_and_its_apply_lag() {
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let applied = AppliedSessions::new();
        let stats = ControlConnStats::new();

        // Seed a four-session baseline via the connect-time full set.
        apply_message(
            &control,
            CoordinatorToRelay::Descriptors {
                descriptors: vec![
                    descriptor(1, &[]),
                    descriptor(2, &[]),
                    descriptor(3, &[]),
                    descriptor(4, &[]),
                ],
                staged_at_unix_ms: None,
            },
            &applied,
            &stats,
        );

        // A delta that only removes one session, staged ~1.5s ago.
        let staged = now_unix_ms().saturating_sub(1_500);
        apply_message(
            &control,
            CoordinatorToRelay::DescriptorDelta {
                staged_at_unix_ms: Some(staged),
                upserts: vec![],
                removals: vec![DescriptorKey {
                    tenant: TenantId(TENANT.to_owned()),
                    session: SessionId(1),
                }],
            },
            &applied,
            &stats,
        );

        let snap = stats.snapshot();
        assert_eq!(
            snap.descriptor_set_len, 3,
            "the recorded length is the applied-set size after the delta, not the delta's one entry",
        );
        assert!(
            (1_500..10_000).contains(&snap.descriptor_apply_lag_ms),
            "the delta's stamp yields an apply-lag sample exactly like a full set (observed {}ms)",
            snap.descriptor_apply_lag_ms,
        );
    }

    #[test]
    fn a_delta_upsert_reconciles_dials_that_raced_it_and_starts_the_session() {
        // The dial-race fix must still fire when the session's descriptor arrives as
        // a delta upsert, not only as a full set: both clients register before the
        // descriptor lands, their maker-less announces drop, and the delta's
        // per-descriptor apply reconciles the roster it already holds, reaches
        // coverage, and delivers the start directive to the connected clients.
        use rally_point_proto::ids::SlotId;

        let makers = std::sync::Arc::new(crate::consensus::new_decision_makers());
        let sessions: crate::routing::Sessions = std::sync::Arc::default();
        let mesh_links = crate::mesh::new_mesh_links();

        let (_reg0, mut inbox0) = crate::routing::register(&sessions, &key(1), SlotId(0))
            .expect("slot 0 registers into an empty roster");
        let (_reg1, mut inbox1) = crate::routing::register(&sessions, &key(1), SlotId(1))
            .expect("slot 1 registers into an empty roster");
        assert!(
            !crate::consensus::note_slot_present(&makers, &key(1), SlotId(0)),
            "an announce with no maker yet drops the presence",
        );
        assert!(
            !crate::consensus::note_slot_present(&makers, &key(1), SlotId(1)),
            "an announce with no maker yet drops the presence",
        );

        let control = MeshControl::new(RelayId(1), makers.clone(), std::sync::Arc::default())
            .with_broadcast(sessions.clone(), mesh_links);
        let applied = AppliedSessions::new();

        // The session's descriptor arrives as a delta upsert (single relay, no peers).
        let mut desc = descriptor(1, &[]);
        desc.expected_slots = vec![SlotId(0), SlotId(1)];
        apply_message(
            &control,
            CoordinatorToRelay::DescriptorDelta {
                staged_at_unix_ms: None,
                upserts: vec![desc],
                removals: vec![],
            },
            &applied,
            &ControlConnStats::new(),
        );

        assert!(
            makers.lock().get(&key(1)).unwrap().is_started(),
            "the delta upsert reconciles the already-registered roster and covers the expected set",
        );
        assert!(
            inbox0.try_recv_start().is_some(),
            "slot 0's connected client receives the start directive",
        );
        assert!(
            inbox1.try_recv_start().is_some(),
            "slot 1's connected client receives the start directive",
        );
        assert!(
            applied.snapshot().contains(&key(1)),
            "the delta upsert records the session into the applied set",
        );
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
            &ControlConnStats::new(),
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
        let _ = control.register_link(RelayId(2), 1, tx2);
        let applied = AppliedSessions::new();

        // A known message joins session 1.
        apply_message(
            &control,
            CoordinatorToRelay::Descriptors {
                descriptors: vec![descriptor(1, &[2])],
                staged_at_unix_ms: None,
            },
            &applied,
            &ControlConnStats::new(),
        );
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));

        // An unknown message is a no-op: no commands, applied state untouched.
        apply_message(
            &control,
            CoordinatorToRelay::Unknown,
            &applied,
            &ControlConnStats::new(),
        );
        assert!(rx2.try_recv().is_err(), "an unknown message issues nothing");
        assert_eq!(applied.snapshot(), HashSet::from([key(1)]));

        // A later known message still applies — the unknown one did not break the
        // stream's state.
        apply_message(
            &control,
            CoordinatorToRelay::Descriptors {
                descriptors: vec![],
                staged_at_unix_ms: None,
            },
            &applied,
            &ControlConnStats::new(),
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
        let _ = control.register_link(RelayId(2), 1, tx2);
        let applied = AppliedSessions::new();
        apply_message(&control, message, &applied, &ControlConnStats::new());
        assert!(rx2.try_recv().is_err());
        assert!(applied.is_empty());
    }

    #[test]
    fn an_applied_descriptor_set_records_its_apply_lag_and_length() {
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let applied = AppliedSessions::new();
        let stats = ControlConnStats::new();

        // A set staged ~1.5s ago applies with a lag at least that large — the apply
        // clock is never earlier than the staging stamp we synthesize here.
        let staged = now_unix_ms().saturating_sub(1_500);
        apply_message(
            &control,
            CoordinatorToRelay::Descriptors {
                descriptors: vec![descriptor(1, &[]), descriptor(2, &[])],
                staged_at_unix_ms: Some(staged),
            },
            &applied,
            &stats,
        );
        let snap = stats.snapshot();
        assert!(
            (1_500..10_000).contains(&snap.descriptor_apply_lag_ms),
            "the apply lag reflects the staging gap (observed {}ms)",
            snap.descriptor_apply_lag_ms,
        );
        assert_eq!(snap.descriptor_set_len, 2, "the last applied set's size");

        // A backward clock skew (a set stamped in the future) clamps to zero rather
        // than reading as a huge lag, and still updates the set length.
        apply_message(
            &control,
            CoordinatorToRelay::Descriptors {
                descriptors: vec![descriptor(1, &[])],
                staged_at_unix_ms: Some(now_unix_ms() + 60_000),
            },
            &applied,
            &stats,
        );
        let snap = stats.snapshot();
        assert_eq!(
            snap.descriptor_apply_lag_ms, 0,
            "a backward clock skew clamps the lag to zero",
        );
        assert_eq!(snap.descriptor_set_len, 1);

        // An unstamped set (an older coordinator) holds the last lag sample but still
        // updates the set length.
        apply_message(
            &control,
            CoordinatorToRelay::Descriptors {
                descriptors: vec![],
                staged_at_unix_ms: None,
            },
            &applied,
            &stats,
        );
        let snap = stats.snapshot();
        assert_eq!(
            snap.descriptor_apply_lag_ms, 0,
            "an unstamped push leaves the last lag sample untouched",
        );
        assert_eq!(snap.descriptor_set_len, 0);
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
            OutboundQueues::new(notices_rx, no_flight(), ControlConnStats::new()),
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

    /// A flight shipment for the connection-loop tests, paired with the ack receiver
    /// its `sent` half resolves once the recording is stored. The stand-in coordinator
    /// reads the `FlightUploadRequest` frame the loop sends for it.
    fn flight_shipment() -> (FlightShipment, oneshot::Receiver<()>) {
        flight_shipment_with_payload(Bytes::from_static(b"compressed-bytes"))
    }

    /// A flight shipment carrying `payload` (the compressed recording bytes), paired
    /// with the ack receiver its `sent` half resolves once stored.
    fn flight_shipment_with_payload(payload: Bytes) -> (FlightShipment, oneshot::Receiver<()>) {
        let (sent, ack) = oneshot::channel();
        let shipment = FlightShipment {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(7),
            desynced: false,
            payload,
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
                ControlConnStats::new(),
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
                ControlConnStats::new(),
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
                ControlConnStats::new(),
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
            OutboundQueues::new(notices_rx, no_flight(), ControlConnStats::new()),
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

    // --- Control-connected reporting ---

    #[tokio::test]
    async fn an_enroll_refused_after_the_proof_never_reports_control_connected() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Stand-in coordinator: accept, complete the enroll challenge/proof, then
        // refuse the enrollment with the ledger-unauthorized close — the refusal
        // that lands only AFTER the proof round trip, so it exercises the path
        // where an application frame could otherwise be mistaken for acceptance.
        // No application frame is ever pushed, so the connection must never report
        // connected.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;
            let _ = ws
                .close(Some(CloseFrame {
                    code: CloseCode::from(CONTROL_CLOSE_ENROLL_UNAUTHORIZED),
                    reason: "not authorized by the ledger".into(),
                }))
                .await;
            while let Some(Ok(_)) = ws.next().await {}
        });

        let (connected_tx, mut connected_rx) = watch::channel(false);
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
                ControlConnStats::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            connected_tx,
            // A long refusal backoff so the relay does not redial and re-drive the
            // handshake during the observation window (an enroll-unauthorized close
            // takes the refusal backoff).
            backoff(Duration::from_millis(20), Duration::from_secs(3600)),
        ));

        // Actively wait for connected to flip true across the whole attempt; the
        // wait must time out, since a post-proof refusal never pushes the
        // application frame that would report it.
        let observed = tokio::time::timeout(
            Duration::from_millis(500),
            connected_rx.wait_for(|connected| *connected),
        )
        .await;
        assert!(
            observed.is_err(),
            "a post-proof enroll refusal must never report the control connection connected",
        );
    }

    #[tokio::test]
    async fn a_post_proof_application_frame_reports_control_connected() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Stand-in coordinator: accept, complete the enroll handshake, then push a
        // TenantKeys frame — the connect-time application frame an accepted enroll
        // always leads with. Hold the connection open so the relay does not redial.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;
            let keys =
                serde_json::to_string(&CoordinatorToRelay::TenantKeys { keys: vec![] }).unwrap();
            ws.send(Message::Text(keys.into())).await.unwrap();
            std::future::pending::<()>().await;
        });

        let (connected_tx, mut connected_rx) = watch::channel(false);
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
                ControlConnStats::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            connected_tx,
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        // The relay reports connected once it reads the first post-proof
        // application frame (the TenantKeys push).
        tokio::time::timeout(
            Duration::from_secs(5),
            connected_rx.wait_for(|connected| *connected),
        )
        .await
        .expect("the relay reports the control connection connected on the first push")
        .unwrap();
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
                ControlConnStats::new(),
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
                roster_complete: true,
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
                ControlConnStats::new(),
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
                ControlConnStats::new(),
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

    // --- Flight recording uploads ---

    /// A minimal in-process object store: an HTTP server that records every request's
    /// method and exact body and answers 200, standing in for the presigned-URL target
    /// a relay PUTs a recording to. Returns its base URL and the receive end of the
    /// recorded requests.
    async fn spawn_object_store() -> (String, mpsc::UnboundedReceiver<(String, Vec<u8>)>) {
        use tokio::net::TcpListener;
        let (put_tx, put_rx) = mpsc::unbounded_channel::<(String, Vec<u8>)>();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().fallback(
            move |method: axum::http::Method, body: axum::body::Bytes| {
                let put_tx = put_tx.clone();
                async move {
                    let _ = put_tx.send((method.to_string(), body.to_vec()));
                    axum::http::StatusCode::OK
                }
            },
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/desync/sb-test/7/1.json.zst"), put_rx)
    }

    #[tokio::test]
    async fn a_flight_recording_uploads_to_the_store_then_reports_done() {
        use tokio::net::TcpListener;

        // The object store the relay PUTs the compressed recording to.
        let (store_url, mut store_puts) = spawn_object_store().await;

        // The stand-in coordinator: enroll, read the upload request, grant the store
        // URL, then read the Done the relay sends after a successful PUT.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;

            let request = ws.next().await.unwrap().unwrap();
            let Message::Text(text) = request else {
                panic!("a text frame");
            };
            let RelayToCoordinator::FlightUploadRequest {
                request,
                session,
                bytes,
                ..
            } = serde_json::from_str(&text).unwrap()
            else {
                panic!("the frame is an upload request");
            };
            assert_eq!(session, SessionId(7));
            // The request carries the exact compressed byte count, not the blob.
            assert_eq!(bytes, "compressed-bytes".len() as u64);

            let grant = serde_json::to_string(&CoordinatorToRelay::FlightUploadGrant {
                request,
                url: store_url,
            })
            .unwrap();
            ws.send(Message::Text(grant.into())).await.unwrap();

            let done = ws.next().await.unwrap().unwrap();
            let _ = done_tx.send(done);
        });

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
                ControlConnStats::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        // The store received a PUT of exactly the compressed bytes.
        let (method, body) = tokio::time::timeout(Duration::from_secs(5), store_puts.recv())
            .await
            .expect("the store received the upload")
            .expect("a PUT arrived");
        assert_eq!(method, "PUT", "the recording is uploaded with PUT");
        assert_eq!(
            body, b"compressed-bytes",
            "the exact compressed bytes are stored"
        );

        // The ack resolves only after the object is stored (delivery means stored).
        tokio::time::timeout(Duration::from_secs(5), ack)
            .await
            .expect("the ack resolves after storage")
            .unwrap();

        // The relay reports Done, and only after the successful PUT.
        let done = tokio::time::timeout(Duration::from_secs(5), done_rx)
            .await
            .expect("a done frame is sent")
            .unwrap();
        let Message::Text(text) = done else {
            panic!("a text frame");
        };
        assert!(
            matches!(
                serde_json::from_str::<RelayToCoordinator>(&text).unwrap(),
                RelayToCoordinator::FlightUploadDone { .. },
            ),
            "the relay reports the upload done",
        );
    }

    #[tokio::test]
    async fn a_refused_upload_drops_its_recording_while_the_other_stays_in_flight() {
        use tokio::net::TcpListener;

        // The stand-in coordinator refuses the FIRST request, reads the second (both
        // are in flight at once), and holds the connection open so the relay processes
        // the refusal on it rather than re-requesting on a reconnect.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (second_tx, second_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;

            let first = ws.next().await.unwrap().unwrap();
            let Message::Text(text) = first else {
                panic!("a text frame");
            };
            let RelayToCoordinator::FlightUploadRequest { request, .. } =
                serde_json::from_str(&text).unwrap()
            else {
                panic!("the frame is an upload request");
            };
            let refused =
                serde_json::to_string(&CoordinatorToRelay::FlightUploadRefused { request })
                    .unwrap();
            ws.send(Message::Text(refused.into())).await.unwrap();

            // The other shipment's request is already on the wire (both ship at once).
            let second = ws.next().await.unwrap().unwrap();
            let _ = second_tx.send(second);
            // Hold the connection open so the relay drops the refused recording on it,
            // rather than the read half ending the connection first (which would
            // re-request the shipment on the next connection instead of dropping it).
            std::future::pending::<()>().await;
        });

        let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        let (first_shipment, first_ack) = flight_shipment();
        let (second_shipment, _second_ack) =
            flight_shipment_with_payload(Bytes::from_static(b"second-blob"));
        flight_tx.try_send(first_shipment).unwrap();
        flight_tx.try_send(second_shipment).unwrap();

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
                ControlConnStats::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        // The refused recording's ack resolves as not-stored (the sender is dropped).
        assert!(
            tokio::time::timeout(Duration::from_secs(5), first_ack)
                .await
                .expect("the ack resolves promptly")
                .is_err(),
            "a refused upload reports the recording lost, not stored",
        );

        // The other shipment's request went out too — it ships concurrently rather
        // than waiting for the first to resolve.
        let second = tokio::time::timeout(Duration::from_secs(5), second_rx)
            .await
            .expect("the second request arrives")
            .unwrap();
        let Message::Text(text) = second else {
            panic!("a text frame");
        };
        let RelayToCoordinator::FlightUploadRequest { bytes, .. } =
            serde_json::from_str(&text).unwrap()
        else {
            panic!("the frame is an upload request");
        };
        assert_eq!(
            bytes,
            "second-blob".len() as u64,
            "the other shipment's request is in flight alongside the refused one",
        );
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
                ControlConnStats::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        let received = tokio::time::timeout(Duration::from_secs(5), frame_rx)
            .await
            .expect("the queued shipment re-requests after the reconnect")
            .unwrap();
        let Message::Text(text) = received else {
            panic!("a text frame");
        };
        // The shipment parked when the first connection died re-requests an upload URL
        // on the next connection — its small request, not the blob.
        assert!(matches!(
            serde_json::from_str::<RelayToCoordinator>(&text).unwrap(),
            RelayToCoordinator::FlightUploadRequest { .. },
        ));
    }

    #[tokio::test]
    async fn the_enroll_proof_precedes_a_pending_flight_request() {
        use tokio::net::TcpListener;

        // A relay that reconnects with a parked flight shipment must send its
        // IdentityProof first: an upload-request frame ahead of the proof would be read
        // as the proof and refused. Assert the proof is the first frame after the
        // challenge, with the request strictly behind it.
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
                ControlConnStats::new(),
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
            "the identity proof precedes the flight upload request",
        );
        assert!(
            matches!(
                decode(second),
                RelayToCoordinator::FlightUploadRequest { .. }
            ),
            "the flight upload request goes out only after the proof",
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
            OutboundQueues::new(notices_rx, flight_rx, ControlConnStats::new()),
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
                .any(|f| matches!(f, RelayToCoordinator::FlightUploadRequest { .. })),
            "the flight pipe delivered",
        );
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
        // Live senders so the drain, challenge, and flight-grant arms stay pending (not
        // disabled), leaving the notices arm the one that fires.
        let (_drain_tx, mut drain_rx) = watch::channel(false);
        let (_challenge_tx, challenge_rx) = mpsc::unbounded_channel::<[u8; 32]>();
        let (_flight_grant_tx, flight_grant_rx) = mpsc::unbounded_channel::<FlightGrant>();

        let mut outbound = OutboundQueues::new(notices_rx, flight_rx, ControlConnStats::new());
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
            WriterRoutes {
                challenge_rx,
                flight_grant_rx,
            },
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
            outbound.stats.snapshot().notices,
            1,
            "the parked notice is reflected in the reported queue depth",
        );
    }

    #[tokio::test]
    async fn a_queued_flight_upload_does_not_delay_a_queued_notice() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

        // Stand-in coordinator: enroll, then read the first two frames. With both a
        // notice and a flight shipment queued, the write half's priority order must put
        // the notice first — if the flight arm outranked it, the coordinator would read
        // the upload request ahead of the notice.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;
            let first = ws.next().await.unwrap().unwrap();
            let second = ws.next().await.unwrap().unwrap();
            let _ = frames_tx.send((first, second));
        });

        // Queue the notice AND a flight shipment before the subscriber starts.
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
            OutboundQueues::new(notices_rx, flight_rx, ControlConnStats::new()),
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
            "the notice ships before the queued flight upload request",
        );
        assert!(
            matches!(
                decode(second),
                RelayToCoordinator::FlightUploadRequest { .. }
            ),
            "the flight upload request ships after the notice",
        );
    }

    #[tokio::test]
    async fn the_read_half_applies_a_descriptor_while_an_upload_awaits_its_grant() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Stand-in coordinator: enroll, read the flight upload request but grant
        // nothing, then push a descriptor set and hold the connection open. The relay's
        // write half is parked awaiting the grant, so its read half must still apply
        // the descriptor — if reads were coupled to the writer's flight work, the
        // descriptor would never land and the applied set would stay empty.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;
            // Read (and never answer) the upload request.
            let _request = ws.next().await.unwrap().unwrap();
            let descriptors = serde_json::to_string(&CoordinatorToRelay::Descriptors {
                descriptors: vec![descriptor(1, &[])],
                staged_at_unix_ms: None,
            })
            .unwrap();
            ws.send(Message::Text(descriptors.into())).await.unwrap();
            std::future::pending::<()>().await;
        });

        let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        let (shipment, _ack) = flight_shipment();
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
                ControlConnStats::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        // The read half applies the pushed descriptor even though the write half is
        // still waiting for the upload grant.
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
            "the read half applied the descriptor while an upload awaited its grant",
        );
    }

    #[tokio::test]
    async fn two_shipments_ship_concurrently_rather_than_one_at_a_time() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

        // Stand-in coordinator: enroll, then read TWO upload requests without granting
        // either. A strictly serial pipe would not send the second request until the
        // first shipment's whole grant→PUT→Done cycle finished, so reading both — with
        // no grant sent — proves the two proceed concurrently.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;
            let first = ws.next().await.unwrap().unwrap();
            let second = ws.next().await.unwrap().unwrap();
            let _ = frames_tx.send((first, second));
        });

        let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        let (first_shipment, _first_ack) = flight_shipment();
        let (second_shipment, _second_ack) =
            flight_shipment_with_payload(Bytes::from_static(b"second-blob"));
        flight_tx.try_send(first_shipment).unwrap();
        flight_tx.try_send(second_shipment).unwrap();

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
                ControlConnStats::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        let (first, second) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
            .await
            .expect("both upload requests go out before either is granted")
            .unwrap();
        let decode = |message: Message| -> RelayToCoordinator {
            let Message::Text(text) = message else {
                panic!("a text frame");
            };
            serde_json::from_str(&text).unwrap()
        };
        let mut requests = Vec::new();
        let mut byte_counts = HashSet::new();
        for frame in [decode(first), decode(second)] {
            let RelayToCoordinator::FlightUploadRequest { request, bytes, .. } = frame else {
                panic!("both frames are flight upload requests, got {frame:?}");
            };
            requests.push(request);
            byte_counts.insert(bytes);
        }
        assert_ne!(
            requests[0], requests[1],
            "each in-flight shipment carries a distinct correlation id",
        );
        assert_eq!(
            byte_counts,
            HashSet::from(["compressed-bytes".len() as u64, "second-blob".len() as u64,]),
            "both shipments' requests are on the wire at once",
        );
    }

    #[tokio::test]
    async fn a_connection_death_re_requests_every_in_flight_shipment() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

        // Stand-in coordinator: on the FIRST connection, enroll and read both upload
        // requests (granting neither), then drop the socket with both shipments still
        // in flight. On the SECOND (reconnect), enroll and read both re-requests —
        // proving a connection death re-requests BOTH parked shipments, not just one.
        tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(first).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;
            let _r1 = ws.next().await.unwrap().unwrap();
            let _r2 = ws.next().await.unwrap().unwrap();
            drop(ws);

            let (second, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(second).await.unwrap();
            let _hello = accept_enroll(&mut ws).await;
            let re1 = ws.next().await.unwrap().unwrap();
            let re2 = ws.next().await.unwrap().unwrap();
            let _ = frames_tx.send((re1, re2));
        });

        let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
        let (first_shipment, _first_ack) = flight_shipment();
        let (second_shipment, _second_ack) =
            flight_shipment_with_payload(Bytes::from_static(b"second-blob"));
        flight_tx.try_send(first_shipment).unwrap();
        flight_tx.try_send(second_shipment).unwrap();

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
                ControlConnStats::new(),
            ),
            heartbeat(Duration::from_secs(3600)),
            drain_rx,
            no_connected(),
            backoff(Duration::from_millis(20), Duration::from_secs(60)),
        ));

        let (re1, re2) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
            .await
            .expect("both shipments re-request after the reconnect")
            .unwrap();
        let decode = |message: Message| -> RelayToCoordinator {
            let Message::Text(text) = message else {
                panic!("a text frame");
            };
            serde_json::from_str(&text).unwrap()
        };
        let mut byte_counts = HashSet::new();
        for frame in [decode(re1), decode(re2)] {
            let RelayToCoordinator::FlightUploadRequest { bytes, .. } = frame else {
                panic!("both re-requests are flight upload requests, got {frame:?}");
            };
            byte_counts.insert(bytes);
        }
        assert_eq!(
            byte_counts,
            HashSet::from(["compressed-bytes".len() as u64, "second-blob".len() as u64,]),
            "the reconnect re-requests both in-flight shipments",
        );
    }
}
