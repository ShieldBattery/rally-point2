//! The coordinator ⇄ relay control-connection message envelopes.
//!
//! [`CoordinatorToRelay`] and [`RelayToCoordinator`] are the two directions of
//! the persistent control connection a relay holds open to the coordinator;
//! [`SessionPresence`] is the roster shape both a heartbeat and an on-demand
//! load-state snapshot carry. Grouped together because they are the actual
//! wire messages — as opposed to `session`'s registry/config payloads that
//! ride inside them.

use serde::{Deserialize, Serialize};

use crate::ids::{SessionId, SlotId};

use super::{
    DepartureNotice, DescriptorKey, DesyncNotice, MeshPeerIdentity, RegionBeaconTarget,
    RegionRttReport, RelayHello, ResultNotice, SessionDescriptor, SessionStartedNotice,
    SlotConnectedNotice, SlotStartedNotice, TenantId, TenantVerifyingKey,
};

/// `serde(skip_serializing_if)` helper: keep a field off the wire when it is
/// `false`, the same convention `Option::is_none` gives an optional field.
fn is_false(value: &bool) -> bool {
    !*value
}

/// The fixed prefix signed (and verified) in the enroll proof-of-possession
/// exchange: the relay signs `ENROLL_POP_CONTEXT ++ nonce` — never the bare
/// nonce — so a signature produced for this purpose can never be replayed as
/// a valid signature for some unrelated protocol that also happens to sign
/// 32-byte messages. Versioned in the literal (`v1`) the same way the
/// connection-binding challenge's own signed contexts are, so a future change
/// to what gets signed is a new, distinguishable prefix rather than a silent
/// reinterpretation of old signatures.
pub const ENROLL_POP_CONTEXT: &[u8] = b"rp2-enroll-pop-v1:";

/// A message the coordinator sends down the persistent control connection a
/// relay holds open to it.
///
/// The connection is the relay's single, authenticated control channel: the
/// coordinator pushes mesh topology down it, and the relay reports liveness (and
/// a drain request) up it. This enum is the **down** direction — descriptor
/// pushes, reap directives, and the [`DrainAck`](Self::DrainAck) that answers a
/// relay's coordinated-drain request. It is
/// tagged so the channel can carry new message kinds without a wire break — a
/// relay and coordinator deploy independently, so during a rolling deploy a newer
/// coordinator may send a message kind an older relay does not know. The
/// [`Unknown`](Self::Unknown) catch-all makes that a *skip* rather than a parse
/// error: an unrecognized `type` deserializes to `Unknown` instead of failing, so
/// an older relay ignores the new message and keeps its connection rather than
/// churning it.
///
/// The descriptor set is **declarative current state**, not a stream of deltas:
/// the coordinator sends the relay's whole current set on connect (so a
/// reconnecting relay re-syncs) and again whenever it changes, and the relay
/// applies it idempotently. Re-sending the same set is a no-op on the relay, so
/// the channel never has to guarantee exactly-once delivery — losing a message
/// to a dropped connection just means the next one (on reconnect) carries the
/// current truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordinatorToRelay {
    /// The relay's full current session-descriptor set — every session this
    /// relay should serve, each naming that session's mesh peers. The relay
    /// joins the named peers' links and leaves any session no longer present.
    Descriptors {
        /// The descriptors, one per session this relay currently serves.
        descriptors: Vec<SessionDescriptor>,
        /// The coordinator's wall-clock, unix epoch milliseconds, at the moment
        /// this whole-set snapshot was taken from its outbox — **not** when any
        /// session in it was created. The relay differences it against its own
        /// clock on apply to observe how far descriptor delivery is lagging behind
        /// staging.
        ///
        /// A coarse cross-host measurement: the coordinator and relay keep
        /// independent wall clocks, so the difference is meaningful at the scale of
        /// seconds (where apply lag actually shows up under a create ramp), not
        /// microseconds. A small clock skew can even make it read slightly negative,
        /// which the relay clamps to zero. Absent from a coordinator that predates
        /// the field, in which case the relay records no fresh lag sample.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        staged_at_unix_ms: Option<u64>,
    },
    /// A steady-state change to the relay's session-descriptor set, carrying only
    /// what changed since the last push on this connection rather than the whole
    /// set — the bandwidth win that keeps a create ramp from re-serializing an
    /// O(N) set on every one of N changes. `upserts` are descriptors to apply (a
    /// session newly assigned to this relay, or an existing one whose descriptor
    /// changed by value); `removals` name sessions to leave. The relay applies each
    /// upsert through the same idempotent per-descriptor path a full
    /// [`Descriptors`](Self::Descriptors) set uses, and leaves each removal the same
    /// way a session vanishing from a full set is left, so a delta and a full set
    /// converge to the same applied state.
    ///
    /// A delta is only meaningful against the state a full set established, so the
    /// coordinator sends deltas **only** in steady state and **only** to a relay
    /// whose negotiated protocol version is at least
    /// [`ProtocolVersion::DESCRIPTOR_DELTA_MIN`](crate::version::ProtocolVersion::DESCRIPTOR_DELTA_MIN):
    /// the connect-time re-sync is always a full [`Descriptors`](Self::Descriptors)
    /// set (which seeds the baseline the deltas build on), and the single ordered
    /// control connection guarantees that re-sync precedes every delta. A relay that
    /// predates this variant decodes it as [`Unknown`](Self::Unknown) and would
    /// silently miss the change — which is exactly why the coordinator gates it on
    /// the negotiated version and falls back to full sets for an older relay. A
    /// relay that reconnects re-syncs the full current set, so a delta lost to a
    /// dropped connection is corrected by the next connection's re-sync, exactly as
    /// for a full set. The drain exchange keeps pushing the full set, never a delta.
    DescriptorDelta {
        /// The coordinator's wall-clock, unix epoch milliseconds, at the moment
        /// this delta left its outbox — the same staging stamp
        /// [`Descriptors`](Self::Descriptors) carries, with the same coarse
        /// cross-host semantics. The coordinator and relay keep independent wall
        /// clocks, so the difference the relay records as apply lag is meaningful at
        /// the scale of seconds, not microseconds, and a small skew that reads
        /// slightly negative is clamped to zero. Absent from a coordinator that
        /// predates the field, in which case the relay records no fresh lag sample.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        staged_at_unix_ms: Option<u64>,
        /// The descriptors to apply — each a session newly assigned to this relay,
        /// or one whose descriptor changed by value since the last push. Applied
        /// through the same per-descriptor path a full set uses. Empty (and omitted
        /// from the wire) for a removal-only delta.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        upserts: Vec<SessionDescriptor>,
        /// The sessions to leave — each named by its `(tenant, session)` key,
        /// dropped from the relay's set since the last push. Left through the same
        /// path a session vanishing from a full set takes. Empty (and omitted from
        /// the wire) for an upsert-only delta.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        removals: Vec<DescriptorKey>,
    },
    /// A reap directive: close the named slots' links so their normal link-death
    /// path (a synced leave, a departure notice) runs. The coordinator arms this
    /// when a session's accounting stalls — a holdout slot silent on a live link,
    /// or reported-but-still-linked stragglers after everyone is accounted. A
    /// relay fires each named slot's own shutdown signal; a slot it does not
    /// currently home or hold is a no-op, so the coordinator can name every slot
    /// without tracking which relay holds which.
    CloseSlot {
        /// The tenant the session belongs to.
        tenant: TenantId,
        /// The session whose slots to close.
        session: SessionId,
        /// The slots to close. A slot this relay does not hold is ignored.
        slots: Vec<SlotId>,
    },
    /// Acknowledges a relay's [`Draining`](RelayToCoordinator::Draining) request:
    /// the coordinator has marked the relay ineligible for new session assignments
    /// **and**, immediately before this frame, pushed the relay's current
    /// descriptor set down the same socket. That ordering is load-bearing — the set
    /// arrives before the ack — so a relay that sees an *empty* descriptor set at
    /// ack time knows it is provably unassigned and can exit at once, while a relay
    /// still holding sessions waits them out (up to its drain timeout) rather than
    /// abandoning a client mid-connect. Payload-free: the acknowledgement is the
    /// whole signal. Sent only when the mark applied under a current connection
    /// generation; a stale connection's Draining draws no ack (its live successor
    /// runs its own drain exchange).
    DrainAck,
    /// The fleet's currently-enrolled mesh peers — every relay the coordinator
    /// holds enrolled, each with the SHA-256 fingerprint of the certificate it
    /// enrolled with. The relay consumes this at mesh-accept time to pin a
    /// dialing peer's TLS client certificate: a peer claiming a relay id in this
    /// set must present the certificate whose fingerprint the set records for it.
    ///
    /// The coordinator sends the whole set on the control connection's start and
    /// again whenever fleet membership changes, and the relay replaces its stored
    /// set wholesale on each push — declarative complete state, exactly like
    /// [`Descriptors`](Self::Descriptors). Re-sending an unchanged set is a
    /// harmless no-op, and a relay that reconnects re-syncs the full current set,
    /// so the channel never has to guarantee exactly-once delivery. A draining
    /// relay stays in the set: it still serves live sessions and holds mesh links,
    /// and the set governs only which peers may open a *new* mesh link.
    MeshPeers {
        /// The complete set of currently-enrolled fleet peers.
        peers: Vec<MeshPeerIdentity>,
    },
    /// The tenant token-verifying keys the relay checks client authorization
    /// tokens against — the full current set as a declarative replacement, one
    /// entry per tenant signing key.
    ///
    /// The coordinator holds every tenant's signing key and pushes the public
    /// (verifying) halves here, so a relay verifies client tokens with no tenant
    /// key material in its own environment. The set is sent once when the control
    /// connection starts, ahead of the first session descriptor — a descriptor
    /// must never reach a relay that cannot yet verify its clients' tokens — and
    /// the relay replaces its stored set wholesale on the push (declarative
    /// complete state, exactly like [`MeshPeers`](Self::MeshPeers) and
    /// [`Descriptors`](Self::Descriptors)). A relay that reconnects re-syncs the
    /// full set, so the channel never has to guarantee exactly-once delivery.
    TenantKeys {
        /// The complete set of tenant verifying keys.
        keys: Vec<TenantVerifyingKey>,
    },
    /// The region ping beacons a relay measures backbone round-trips against —
    /// one entry per region in the coordinator's registry, each naming the
    /// region's always-up UDP ping beacon.
    ///
    /// The coordinator sends the whole set once when the control connection
    /// starts, ahead of the first session descriptor, and the relay replaces its
    /// stored set wholesale on the push — declarative complete state, exactly like
    /// [`MeshPeers`](Self::MeshPeers) and [`TenantKeys`](Self::TenantKeys). The
    /// region registry is immutable per coordinator process, so this is a one-time
    /// connect-time push; a relay that reconnects re-syncs the full set. The set
    /// names every configured region, **including the one the receiving relay
    /// serves** — the relay drops its own before measuring, since a region's
    /// round-trip to itself is zero by definition. A coordinator with no regions
    /// configured omits this frame entirely, so a relay on a region-blind fleet
    /// receives no targets and measures nothing.
    RegionBeacons {
        /// The complete set of region ping beacon targets.
        beacons: Vec<RegionBeaconTarget>,
    },
    /// A random challenge proving the relay holds the private key matching the
    /// certificate its `Hello` presented (enroll proof-of-possession): the
    /// relay must answer with
    /// [`RelayToCoordinator::IdentityProof`], a signature over
    /// [`ENROLL_POP_CONTEXT`] `++ nonce` made with that key. Sent once, after
    /// `Hello` and version negotiation succeed and before the coordinator
    /// enrolls the relay — never on an already-enrolled connection — on every
    /// accepted connection: negotiation refuses any relay advertising a version
    /// below
    /// [`ProtocolVersion::ENROLL_POP_MIN`](crate::version::ProtocolVersion::ENROLL_POP_MIN)
    /// before the challenge, so no un-challenged enroll path exists.
    /// Closes `Hello.cert_der`'s gap: without this, a bootstrap-secret holder
    /// could copy a victim relay's public certificate into its own `Hello` and
    /// enroll as it, since the certificate alone is payload, not proof of
    /// holding the matching key.
    IdentityChallenge {
        /// A fresh random value, unique per connection attempt.
        nonce: [u8; 32],
    },
    /// Grants a relay's [`FlightUploadRequest`](RelayToCoordinator::FlightUploadRequest):
    /// the relay may PUT the compressed recording directly to durable storage using
    /// `url`, a short-lived presigned upload URL the coordinator minted.
    ///
    /// The coordinator — the sole store-credential holder — classifies the request,
    /// decides the object key (retention class included), and presigns a PUT to
    /// exactly that key with the request's exact byte count bound into the signature,
    /// so the URL can neither store under a different key nor a different size. The
    /// relay uploads and then reports [`FlightUploadDone`](RelayToCoordinator::FlightUploadDone);
    /// the blob never rides this control connection. `request` echoes the relay's own
    /// per-connection correlation id so the relay matches the grant to its outstanding
    /// request and ignores one for a request it no longer holds (a stale grant from a
    /// prior connection).
    FlightUploadGrant {
        /// The relay's correlation id from the request this grants.
        request: u64,
        /// A short-lived presigned PUT URL the relay uploads the compressed recording
        /// to. Expires within minutes of minting; a relay that cannot upload before
        /// then drops the recording (flight data is observability, never backpressure).
        url: String,
    },
    /// Refuses a relay's [`FlightUploadRequest`](RelayToCoordinator::FlightUploadRequest):
    /// the coordinator will mint no upload URL for it, so the relay drops the recording.
    /// Sent when the coordinator has no store configured, does not hold the named tenant
    /// enrolled, the byte count exceeds the store's cap, or presigning failed — the same
    /// gate decisions the direct-store path applied, just answered as a refusal here
    /// rather than a silent drop. `request` echoes the relay's correlation id.
    FlightUploadRefused {
        /// The relay's correlation id from the request this refuses.
        request: u64,
    },
    /// Asks the relay to answer, right now, with everything it holds for one
    /// session's load state — the causal barrier behind
    /// `POST /session/load-state`'s completeness claim.
    ///
    /// The relay replies with a [`RelayToCoordinator::LoadStateSnapshot`] carrying
    /// `request_id` back, built from state it already holds, so the reply is
    /// ordered strictly after this request arrived. Anything the relay observed
    /// before the request is therefore in the snapshot, and the coordinator needs
    /// no stamp from either host's clock to know it.
    ///
    /// A relay that does not hold the session answers with empty lists — that is
    /// an attestation of "nothing here", not a refusal. A relay whose build
    /// predates this variant decodes it as [`Unknown`](Self::Unknown) and never
    /// answers at all, which the coordinator must read as *did not attest* rather
    /// than as an empty answer. Answering is stateless, so a repeat request (a
    /// tenant re-reading) just draws a fresh snapshot.
    LoadStateRequest {
        /// The tenant the session belongs to.
        tenant: TenantId,
        /// The session whose load state to snapshot.
        session: SessionId,
        /// The coordinator's correlation id, fresh per request, echoed back on the
        /// snapshot so the coordinator matches an answer to the request it made and
        /// discards one for a request it no longer holds.
        request_id: u64,
    },
    /// A message kind this build does not recognize — a newer coordinator sent
    /// one this relay's protocol version predates. An unknown `type` decodes here
    /// (rather than erroring), so the relay skips it and keeps the connection. The
    /// payload is intentionally dropped: a relay can't act on a message it doesn't
    /// understand, only refrain from breaking on it.
    #[serde(other)]
    Unknown,
}

/// A message a relay sends **up** the persistent control connection it holds to
/// the coordinator — the counterpart to [`CoordinatorToRelay`].
///
/// The first frame a relay sends is its [`Hello`](Self::Hello): it enrolls the
/// relay into the coordinator's registry over the same authenticated connection
/// that then carries descriptor pushes back down, so a relay has one channel to
/// the coordinator rather than a separate phone-home. After enrolling, the relay
/// sends a periodic [`Heartbeat`](Self::Heartbeat) so the coordinator can tell a
/// live relay from one whose connection has silently died, and — once it has
/// received its shutdown signal — a [`Draining`](Self::Draining) frame asking the
/// coordinator to stop assigning it new sessions. Tagged and
/// forward-compatible the same way as the down direction — a message kind a newer
/// relay sends that an older coordinator predates decodes to
/// [`Unknown`](Self::Unknown) and is skipped rather than tearing the connection
/// down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayToCoordinator {
    /// The relay's identity and reachable address, sent as the first frame to
    /// enroll into the coordinator's registry.
    Hello(RelayHello),
    /// The answer to a [`CoordinatorToRelay::IdentityChallenge`]: a signature
    /// over [`ENROLL_POP_CONTEXT`] `++` the challenge's nonce, made with the
    /// private key matching the certificate this connection's `Hello`
    /// presented — proof-of-possession of that key, not just knowledge of the
    /// certificate's public bytes. Sent statelessly the moment a challenge
    /// arrives; the relay tracks no handshake-phase state of its own, since the
    /// coordinator alone decides when to challenge and when to give up waiting.
    IdentityProof {
        /// The signature, in the format the key's algorithm produces (an
        /// ECDSA P-256 signature is ASN.1 DER; an Ed25519 signature is the raw
        /// 64 bytes) — the coordinator tries each algorithm it supports against
        /// `Hello.cert_der`'s public key, so the wire form doesn't need to name
        /// which one this is.
        #[serde(with = "super::serde_bytes")]
        signature: Vec<u8>,
    },
    /// A periodic presence ping proving the control connection is still alive,
    /// carrying the relay's live roster.
    ///
    /// The coordinator resets a per-connection liveness deadline on each one;
    /// when enough are missed — a relay that crashed, or a TCP connection that
    /// died without ever sending a close — the deadline lapses, the coordinator
    /// drops the connection and deregisters the relay.
    ///
    /// `sessions` piggybacks the relay's **connected slots** on the beat the relay
    /// already sends: each entry names one session and the slots whose clients are
    /// connected right now, the whole current truth every time (declarative, so a
    /// lost or reordered beat is corrected by the next one). The coordinator feeds
    /// it into its active-player presence store, which tenant app servers query to
    /// block an in-game player from re-queueing. `roster_complete` lets a newer
    /// coordinator distinguish an authoritative empty roster from the payload-free
    /// heartbeat emitted by a relay build that predates presence. Older
    /// coordinators ignore the additive marker.
    ///
    /// The frame carries only tenant/session/slot — **never user identity**: the
    /// relay stays PII-free, and slots are resolved to the tenant's own user refs
    /// on the coordinator, which already holds them from session creation.
    Heartbeat {
        /// Whether `sessions` is this relay's complete current roster. New relays
        /// always send `true`; absence decodes as `false`, so an older relay's bare
        /// heartbeat can provide liveness and positive entries without its
        /// omissions being mistaken for proof of emptiness during a rolling deploy.
        #[serde(default, skip_serializing_if = "is_false")]
        roster_complete: bool,
        /// The relay's live roster: one entry per session it currently holds a
        /// connected slot for. Empty (and omitted from the wire) on an idle relay.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sessions: Vec<SessionPresence>,
        /// The relay's latest measured backbone round-trips: one entry per region
        /// it has a median for, declarative like `sessions` — the relay repeats
        /// its whole current set of measured medians on every beat, so a lost or
        /// reordered beat is corrected by the next one. Empty (and omitted from the
        /// wire) until the relay has measured anything, which is also exactly what a
        /// relay build that predates the measurement sends, so an older coordinator
        /// reads the beat unchanged.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        region_rtts: Vec<RegionRttReport>,
    },
    /// The relay has received its shutdown signal and asks the coordinator to
    /// **stop assigning it new sessions**. The control connection itself identifies
    /// the relay, so it carries no payload.
    ///
    /// The coordinator marks the relay ineligible for assignment, then answers with
    /// [`DrainAck`](CoordinatorToRelay::DrainAck) after pushing the relay's current
    /// descriptor set (set-before-ack: an empty set at ack time means provably
    /// unassigned). A re-enroll clears the coordinator-side flag, so a relay that
    /// reconnects mid-drain re-sends this frame right after its `Hello`. Idempotent:
    /// re-sending it just draws a fresh set-plus-ack.
    Draining,
    /// A player permanently departed a running game: a synced leave for the slot
    /// just first entered this relay's consensus cache. The relay reports it so
    /// the coordinator can forward the "player X left vs. was dropped" fact to
    /// the tenant. Every relay serving the session reports independently and the
    /// coordinator dedups by `(tenant, session, slot)`, so a single relay's
    /// coordinator link being down never loses the notice.
    Departure(DepartureNotice),
    /// The relay's desync comparator found two live slots whose per-turn sync
    /// checksums disagreed at the same sync ordinal — the two clients' simulations
    /// have diverged. Only the session's authority relay compares, so (unlike a
    /// departure) exactly one relay reports each event; the coordinator still
    /// dedups by `(tenant, session, sync_ordinal)` because at-least-once delivery
    /// can re-send one. The relay forwards it so the coordinator can tell the
    /// tenant "this game desynced at ordinal N; these slots diverged", which the
    /// tenant uses to void or re-adjudicate the result.
    Desync(DesyncNotice),
    /// A client reported its end-of-game result: the relay received the opaque
    /// bytes on its control stream, stamped their arrival against its own timeline,
    /// and forwards them here without parsing. Only the reporting slot's home relay
    /// sends it (results never cross the mesh), and the relay dedups one report per
    /// slot; the coordinator dedups again by `(tenant, session, slot)` because
    /// at-least-once delivery can re-send one. The coordinator relays the bytes to
    /// the tenant as a webhook.
    Result(ResultNotice),
    /// A slot's link became active on this relay: the client connected (or
    /// reconnected) and its slot link is serving. Only the relay that homes the
    /// slot sends it, on every activation, so the coordinator can tell the tenant
    /// which players actually arrived instead of leaving it to infer arrival from
    /// a load-deadline timeout. The coordinator keeps the ever-connected set and
    /// dedups the webhook by `(tenant, session, slot)`, so a reconnect updates its
    /// state without re-firing a notification.
    SlotConnected(SlotConnectedNotice),
    /// The session started: the authority relay's coverage latch fired, every
    /// expected slot being present somewhere in the mesh. Only the authority
    /// reports it — a peer adopting the directive off the mesh does not — so
    /// exactly one relay sends it per session, and the coordinator dedups by
    /// `(tenant, session)` against an at-least-once re-send.
    SessionStarted(SessionStartedNotice),
    /// A client reported that its game loop has started: the relay received the
    /// fieldless frame on its control stream, bound it to the authenticated
    /// connection's slot, and stamped its arrival against its own timeline. Only
    /// the reporting slot's home relay sends it, and the relay accepts one per
    /// slot per link lifetime; the coordinator dedups again by
    /// `(tenant, session, slot)`. Together with `SlotConnected` this is what lets
    /// a tenant attribute a stalled load to the slots that never got there.
    SlotStarted(SlotStartedNotice),
    /// The relay tore down its last local state for a session — every slot it
    /// homed or held is gone. The coordinator, which assigned the session's
    /// serving relay set, waits for every serving relay to report this and then
    /// emits the final `sessionClosed` webhook. Because a relay fires it only
    /// after its own departures went up the same ordered channel, and the
    /// coordinator's per-session dispatch drains in order, a delivered
    /// `sessionClosed` guarantees no earlier notice for the session is still in
    /// flight.
    SessionClosed {
        /// The tenant the session belongs to.
        tenant: TenantId,
        /// The session this relay closed.
        session: SessionId,
    },
    /// Asks the coordinator to mint a presigned URL the relay uploads one flushed
    /// flight recording to directly. The relay compresses each recording and PUTs it
    /// to durable storage itself rather than shipping the bytes up this connection —
    /// so the control socket carries only this small request, the coordinator's
    /// [`FlightUploadGrant`](CoordinatorToRelay::FlightUploadGrant) or
    /// [`FlightUploadRefused`](CoordinatorToRelay::FlightUploadRefused), and a final
    /// [`FlightUploadDone`](Self::FlightUploadDone), never the blob.
    ///
    /// Carries no relay id: the coordinator keys the object on **this connection's
    /// enrolled relay identity**, so a relay can never name another relay's identity
    /// in the key it uploads under. `bytes` is the exact length of the compressed
    /// payload, bound into the presigned URL's signature so the granted URL cannot be
    /// used to store a different-sized object; `desynced` is whether the recording's
    /// own events contain a confirmed desync (the coordinator combines it with its own
    /// desync record to choose the stored blob's retention class). Additive, so an
    /// older coordinator decodes it as [`Unknown`](Self::Unknown) and skips it — the
    /// recording is simply lost against a coordinator that predates this variant,
    /// consistent with the deploy-order rule that coordinator images ship ahead of
    /// relay images.
    FlightUploadRequest {
        /// A per-connection correlation id the relay mints, echoed back on the grant
        /// or refusal so the relay matches the answer to this request (and ignores an
        /// answer for a request it no longer holds).
        request: u64,
        /// The tenant the session belongs to.
        tenant: TenantId,
        /// The coordinator-assigned session id the recording covers.
        session: SessionId,
        /// Whether this recording's own events contain a confirmed desync — the
        /// coordinator combines it with its own desync record to pin the retention
        /// class, so the flag matters when the coordinator's record was lost to a
        /// restart.
        desynced: bool,
        /// The exact byte length of the compressed payload the relay will upload,
        /// bound into the presigned URL so it cannot store a different-sized object.
        bytes: u64,
    },
    /// Reports that the relay finished uploading the recording a prior
    /// [`FlightUploadRequest`](Self::FlightUploadRequest) named, sent only after a
    /// successful PUT. It tells the coordinator the object is now stored, so the
    /// coordinator can run its post-store bookkeeping (metrics, and the pinned-class
    /// convergence sweep for a desynced session). `request` echoes the correlation id
    /// so the coordinator matches it to the grant it minted; a Done for an unknown or
    /// expired request is ignored.
    FlightUploadDone {
        /// The correlation id from the request whose upload completed.
        request: u64,
    },
    /// Answers a [`CoordinatorToRelay::LoadStateRequest`]: everything this relay
    /// holds for the named session, snapshotted after the request arrived.
    ///
    /// The reply is what makes the coordinator's completeness claim causal rather
    /// than clock-based: because the relay builds it from state it already holds
    /// and sends it in place, every fact the relay had observed before the request
    /// landed is in it. A session this relay does not hold answers with empty
    /// lists — it attests that it holds nothing, which is a different statement
    /// from staying silent.
    ///
    /// Additive, so a coordinator that predates the variant decodes it as
    /// [`Unknown`](Self::Unknown) and skips it; such a coordinator never sends the
    /// request in the first place.
    LoadStateSnapshot {
        /// The coordinator's correlation id from the request this answers.
        request_id: u64,
        /// What the relay holds for the session — the same shape a heartbeat's
        /// roster entry carries, so the coordinator merges an attested snapshot
        /// through exactly the path a restated one takes.
        state: SessionPresence,
        /// Whether this relay could rule out a fact still queued *in a client*
        /// when it took the snapshot.
        ///
        /// Observing the relay is not enough on its own. A client's own
        /// `GameStarted` travels its ordered control stream independently of the
        /// coordinator's question, so the relay can snapshot "this slot has not
        /// started" while that slot's report sits in its client's driver. Before
        /// snapshotting, the relay therefore probes every slot it homes that has
        /// connected and not yet started, over that slot's own ordered control
        /// stream, and waits for the echoed acknowledgement: because the stream
        /// is ordered and the client writes any owed report ahead of the ack,
        /// an ack proves nothing is behind it.
        ///
        /// True only when **every** probed slot acked in time *and* no slot the
        /// relay has ever seen connect is currently disconnected without having
        /// started. A disconnected slot cannot be probed, and its client may
        /// hold a report parked for its next stream, so it can never be fenced;
        /// a slot that never connected here holds nothing to fence, so its
        /// absence is attestable. False is not a refusal — the snapshot's facts
        /// are as real as any other's — it only means the *absence* of a slot
        /// from this snapshot must not be read as that slot never having
        /// started.
        ///
        /// Additive: a relay build that predates the fence omits it and reads as
        /// `false`, so it can never claim a fence it did not run.
        #[serde(default, skip_serializing_if = "is_false")]
        fenced: bool,
    },
    /// A message kind this coordinator does not recognize (a newer relay). Decodes
    /// here so the coordinator skips it rather than dropping the connection.
    #[serde(other)]
    Unknown,
}

/// What one relay holds for one session, as carried in a
/// [`RelayToCoordinator::Heartbeat`]'s roster and in the
/// [`RelayToCoordinator::LoadStateSnapshot`] that answers a coordinator's
/// on-demand request. Both carry the same shape because they carry the same
/// claim; they differ only in what ordering the reader may assume about it.
///
/// A slot appears in `slots` exactly while its client's link is registered on the
/// relay — the same liveness the relay's own drain path keys on — so the
/// coordinator's presence store tracks "connected to a relay now", nothing
/// softer. Deliberately slot-granular and PII-free: the relay never learns user
/// identity, and the coordinator resolves slots to the tenant's own user refs
/// from the session request it already holds.
///
/// Beside the live roster it carries the relay's **retained load state** for the
/// session: which slots ever connected, which ever reported their game loop
/// running, and when the relay learned the session started. Those are cumulative
/// facts, not a live view, and every beat restates them in full — which is what
/// makes them durable where the matching notices are not: a notice is dropped
/// once its send succeeds, so a coordinator that dies between receiving one and
/// committing it — or simply restarts — recovers the whole truth from the next
/// beat. All three are optional on the wire: a relay that predates them omits
/// them, a coordinator that predates them ignores them, and a session running
/// without a decision-maker has nothing to report.
///
/// An entry with **no** connected slots is therefore ordinary rather than
/// contradictory: the relay still holds the session (and its retained facts)
/// while every local link is gone. It says the same thing about occupancy that
/// leaving the session out of the roster entirely says — nobody is here — so a
/// coordinator must read the two identically and take the load state as the only
/// added claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPresence {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session the reporting relay is describing.
    pub session: SessionId,
    /// The slots whose clients are connected to the reporting relay right now.
    /// Empty for a session the relay still holds but has no live link into.
    pub slots: Vec<SlotId>,
    /// Every slot whose link has activated on the reporting relay at any point
    /// in the session, ascending. A slot that connected and then dropped stays
    /// here — the question it answers is "did this player ever arrive", which
    /// `slots` (connected *now*) cannot.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ever_connected: Vec<SlotId>,
    /// Every slot that has reported its game loop running to the reporting
    /// relay, ascending. Monotonic for the same reason as `ever_connected`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub started: Vec<SlotId>,
    /// Relay wall-clock (unix epoch milliseconds) for the session's start, as the
    /// reporting relay knows it: its own coverage latch where that fired,
    /// otherwise the moment it adopted the authority's start directive off the
    /// mesh. `None` on a relay that has not seen the session start at all. The
    /// coordinator keeps the first instant reported, so the authority's earlier
    /// stamp wins wherever it arrives and a peer's later one only stands in when
    /// it never does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<u64>,
}
