//! The relay control connection's front door and its per-connection plumbing.
//!
//! Holds the `GET /relay/control` handler, the enroll handshake that runs before
//! a relay reaches the registry (pending-Hello gate, version negotiation, region
//! validation, proof of possession, ledger authorization), and the shared types
//! the reader and writer halves are driven from.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{
        State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use futures_util::stream::{SplitSink, SplitStream};
use rally_point_proto::control::{
    CoordinatorToRelay, MeshPeerIdentity, RegionBeaconTarget, SessionDescriptor, TenantVerifyingKey,
};
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::{
    self, CONTROL_CLOSE_DUPLICATE_RELAY_ID, CONTROL_CLOSE_ENROLL_UNAUTHORIZED,
    CONTROL_CLOSE_PROTOCOL_MISMATCH, CONTROL_CLOSE_UNKNOWN_REGION, ProtocolVersion,
};

use crate::attest::LoadStateAsk;
use crate::descriptors::SlotClose;
use crate::flight_store::S3FlightStore;
use crate::lifecycle::Lifecycle;
use crate::notify::NoticeDedup;
use crate::presence;
use crate::regions::RegionsConfig;
use crate::registry;
use crate::session::{self, SessionSetup};
use crate::tenant;

use super::control_hello::{challenge_and_verify, read_hello};
use super::control_inbound::{RegionRttIngest, run_reader};
use super::control_writer::run_writer;
use super::request_auth::control_auth_ok;
use super::{CoordinatorState, MAX_CONTROL_MESSAGE_BYTES, OptionalPeerAddr};

/// Accepts a relay's persistent control connection (a WebSocket).
///
/// Authenticates against the bootstrap secret before the upgrade — a rejected
/// relay gets a `401` rather than an open socket — then upgrades and serves the
/// connection, which enrolls the relay (from its `Hello`) and pushes descriptors.
///
/// **The claimed relay id is bound to proof of holding its certificate's private
/// key**, not merely trusted from the shared bootstrap secret. After the `Hello`
/// and version negotiation, [`serve_relay_control`] challenges the connection
/// with a random nonce and verifies a signature over it made with the private
/// key matching `Hello.cert_der`, before enrolling — closing the gap where a
/// bootstrap-secret holder could otherwise copy a victim relay's public
/// certificate into its own `Hello` and enroll as it (see [`crate::identity`]).
/// The challenge is mandatory: negotiation refuses any relay advertising a
/// version below
/// [`ProtocolVersion::ENROLL_POP_MIN`](rally_point_proto::version::ProtocolVersion::ENROLL_POP_MIN),
/// so there is no un-challenged enroll path. Proof of possession alone still
/// permits *any* id claim, though: a live registry entry under the claimed id
/// whose certificate differs from the newly-proven one is refused as a duplicate
/// rather than silently evicted (the same certificate replaces it, exactly as a
/// reconnect always has).
///
/// A coordinator started with a provisioned-relay ledger tightens this further:
/// after the proof-of-possession succeeds, the connection is authorized against
/// the ledger (see [`crate::ledger`]) — the id must have been minted, must not be
/// retired, and must present its one-time token (first enroll) or its bound
/// certificate (reconnect), else the connection is closed with
/// [`CONTROL_CLOSE_ENROLL_UNAUTHORIZED`] and never reaches the registry. A
/// coordinator with no ledger skips that step entirely (dev / loopback).
pub(super) async fn relay_control(
    State(state): State<CoordinatorState>,
    headers: HeaderMap,
    OptionalPeerAddr(peer_addr): OptionalPeerAddr,
    ws: WebSocketUpgrade,
) -> Response {
    if !control_auth_ok(&headers, &state.control_auth) {
        tracing::warn!("relay control connection rejected: bad bootstrap secret");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let peer_ip = peer_addr.map(|addr| addr.ip());
    ws.max_message_size(MAX_CONTROL_MESSAGE_BYTES)
        .max_frame_size(MAX_CONTROL_MESSAGE_BYTES)
        .on_upgrade(move |socket| serve_relay_control(socket, state, peer_ip))
}

/// The most control connections allowed to sit between a completed WebSocket
/// upgrade and a verified `Hello` at once. A connection in that window has
/// cleared only the bootstrap secret — proof of *a* relay, not proof of which
/// one — and [`HELLO_TIMEOUT`] bounds how long any single such connection may
/// sit there, but nothing bounds how many can sit there together: a caller
/// that keeps opening connections and never finishing enrollment would
/// otherwise accumulate one parked task and socket per connection, without
/// limit, for as long as it keeps churning. Sized well above a full relay
/// fleet reconnecting at once (a rolling deploy, a coordinator failover), so a
/// legitimate reconnect burst never trips it.
const MAX_PENDING_CONTROL_HELLOS: usize = 512;

/// The process-wide gate [`MAX_PENDING_CONTROL_HELLOS`] enforces.
static PENDING_HELLO_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_PENDING_CONTROL_HELLOS);

/// The standard WebSocket "try again later" close code (RFC 6455 / the IANA
/// close-code registry), used to refuse a connection when
/// [`PENDING_HELLO_PERMITS`] is saturated. Distinct from the
/// `CONTROL_CLOSE_*` codes in [`rally_point_proto::version`]: those name a
/// specific enroll refusal a relay recognizes and reacts to individually
/// (`classify_control_close` on the relay side); this one carries no such
/// meaning; an unrecognized code already falls back to the relay's ordinary
/// short-delay reconnect, which is exactly the right reaction to a transient
/// capacity refusal.
const CONTROL_CLOSE_TRY_AGAIN_LATER: u16 = 1013;

/// Serves one relay's control connection: enroll from its `Hello`, push
/// descriptors, watch the relay's liveness, and deregister it when the connection
/// drops.
///
/// The relay's first frame must be its [`RelayToCoordinator::Hello`], sent within
/// `hello_timeout`. Before it is even read, the connection must claim one of
/// [`MAX_PENDING_CONTROL_HELLOS`] pending-Hello slots — refused outright, never
/// queued, when the gate is saturated, since a connection waiting on a permit
/// would still be exactly the parked, unauthenticated socket the gate exists to
/// bound. The slot is held only across the unauthenticated window: released the
/// moment proof-of-possession succeeds below, so a long-lived enrolled
/// connection never occupies it. After version negotiation and region
/// validation succeed, the connection must prove possession of its
/// certificate's private key (see [`crate::identity`]) and clear the
/// duplicate-id check before [`registry::try_enroll`] runs and yields the
/// connection's generation — negotiation already refused any relay advertising
/// a version below
/// [`ProtocolVersion::ENROLL_POP_MIN`](rally_point_proto::version::ProtocolVersion::ENROLL_POP_MIN),
/// so the challenge runs on every connection that reaches it. The connection
/// then serves descriptors and watches liveness ([`push_and_watch`]) until it
/// ends — the relay closes, the socket errors, the relay goes silent past
/// `liveness_timeout`, or the coordinator's outbox is dropped (shutdown).
///
/// When `ledger` is present, a step runs between the proof-of-possession and the
/// registry insert: the enroll is authorized against the provisioned-relay ledger
/// (see [`crate::ledger`]), refused with [`CONTROL_CLOSE_ENROLL_UNAUTHORIZED`] if
/// the id was not minted, is retired, or presents no valid token / bound
/// certificate. On a first enroll the ledger consumes the id's token and binds it
/// to this certificate; when the ledger recorded a coordinator-resolved advertise
/// set for the id, that set overrides the hello's self-reported addresses before
/// enrollment (coordinator-sourced addresses win, the hello is the fallback).
/// `peer_ip` is the connection's transport-level peer address, enforced against
/// the ledger's expected address for the id when one was recorded. Without a
/// ledger this step is skipped and the hello enrolls with its self-reported id
/// and addresses.
///
/// When the connection drops, the relay is deregistered — but only if this
/// connection is still the current one ([`registry::remove_if_current`]): a relay
/// that already reconnected (a newer connection re-enrolled it) keeps its live
/// entry, so a stale drop racing a reconnect does not evict a relay that is in fact
/// connected.
async fn serve_relay_control(
    mut socket: WebSocket,
    state: CoordinatorState,
    peer_ip: Option<IpAddr>,
) {
    // The per-connection dependencies travel together as the shared coordinator
    // state; unpack the ones this handler drives (the control-auth posture and
    // player-token lifetime are consumed before the upgrade, not here).
    let CoordinatorState {
        setup,
        notices,
        lifecycle,
        hello_timeout,
        liveness_timeout,
        regions,
        ledger,
        pair_rtts,
        flight_store,
        ..
    } = state;
    // Claimed before anything else: a connection that never proves an identity
    // still costs a parked task and socket for up to `hello_timeout`, and
    // nothing else bounds how many of those can pile up at once. `try_acquire`
    // rather than `.acquire().await` — a caller queued on the semaphore is
    // still an unbounded number of parked connections, just parked on the
    // permit instead of on the Hello read.
    let Ok(pending_permit) = PENDING_HELLO_PERMITS.try_acquire() else {
        tracing::warn!("relay control connection refused: too many connections pending a Hello");
        let _ = socket
            .send(Message::Close(Some(CloseFrame {
                code: CONTROL_CLOSE_TRY_AGAIN_LATER,
                reason: "too many pending control connections; retry shortly".into(),
            })))
            .await;
        return;
    };
    // The first frame enrolls the relay, and must arrive within the deadline — a
    // connection that opens the socket but never sends a Hello is dropped rather
    // than left to pin a task. A bad/absent first frame likewise just closes.
    let mut hello = match tokio::time::timeout(hello_timeout, read_hello(&mut socket)).await {
        Ok(Some(hello)) => hello,
        Ok(None) => return,
        Err(_elapsed) => {
            tracing::debug!("control connection sent no Hello within the deadline; closing");
            return;
        }
    };
    // Negotiate before enrolling: the Hello advertises the relay's
    // `[min_protocol, protocol]` window (a relay predating the field advertises
    // the single version in `protocol`). No overlap with this build's window means
    // this coordinator cannot drive the relay at any version — refuse with a close
    // frame naming both windows rather than register a relay every session
    // assignment would then mis-speak to. The relay recognizes the close code and
    // backs off until a deploy fixes the skew.
    let window_min = hello.min_protocol.unwrap_or(hello.protocol);
    let negotiated = match version::negotiate(window_min, hello.protocol) {
        Ok(negotiated) => negotiated,
        Err(error) => {
            tracing::warn!(
                relay_id = hello.relay_id.0,
                %error,
                "refusing relay control connection: no common protocol version",
            );
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: CONTROL_CLOSE_PROTOCOL_MISMATCH,
                    reason: error.to_string().into(),
                })))
                .await;
            return;
        }
    };
    // Validate the relay's advertised region before enrolling: a hello carrying a
    // region the coordinator's config does not list — including the case where no
    // regions are configured at all — is refused, since a typo'd region tag that
    // silently serves nobody is worse than a failed enroll. A hello with no region
    // always enrolls (dev / loopback, or a fleet with no region config). The relay
    // recognizes the close code and backs off long, treating it as a config fix
    // rather than a redial.
    if let Some(region) = &hello.region
        && !regions.contains(region)
    {
        tracing::warn!(
            relay_id = hello.relay_id.0,
            region = region.as_ref(),
            "refusing relay control connection: region not in the coordinator's config",
        );
        let _ = socket
            .send(Message::Close(Some(CloseFrame {
                code: CONTROL_CLOSE_UNKNOWN_REGION,
                reason: format!("unknown region: {}", region.as_ref()).into(),
            })))
            .await;
        return;
    }

    let relay_id = hello.relay_id;
    // The relay's own region — the near end of every backbone pair it measures.
    // Captured before the hello is consumed by enrollment; validated against the
    // config above, so a heartbeat's reports fold against a known region.
    let relay_region = hello.region.clone();
    let registry = setup.registry();

    // Every accepted control connection proves possession of its certificate's
    // key before enrolling: `hello.cert_der` alone is a claim the relay
    // presented, not proof it holds the matching private key — a
    // bootstrap-secret holder could otherwise copy a victim relay's public
    // certificate into its own Hello and enroll as it. Negotiation already
    // refused any relay advertising a version below the challenge threshold, so
    // there is no un-challenged enroll path to reach.
    if !challenge_and_verify(&mut socket, &hello, hello_timeout).await {
        return;
    }
    // The connection has now proven its claimed identity, so it no longer
    // belongs to the anonymous-churn population the pending-Hello gate exists
    // to bound — release the slot regardless of how much longer ledger
    // authorization and enrollment take.
    drop(pending_permit);

    // A ledger-backed coordinator authorizes the enroll against its provisioned
    // record before touching the registry: the id must be one the ledger minted,
    // not retired, and either presenting its one-time token (first enroll, binding
    // this proof-of-possession-verified certificate) or re-presenting the bound
    // certificate (a reconnect). A refusal closes with a single generic reason so a
    // caller cannot probe which ids exist or whether a token was near-valid; the
    // specific class rides only the server-side log. A coordinator with no ledger
    // skips this entirely — the id claim is accepted as presented (dev / loopback).
    // A first enroll carries the relay's cold-start duration (launch to enroll),
    // observed into the histogram once the enroll fully succeeds. A reconnect and a
    // no-ledger enroll carry none.
    let mut cold_start_secs: Option<u64> = None;
    if let Some(ledger) = &ledger {
        let cert_fingerprint = registry::cert_fingerprint(&hello.cert_der);
        match ledger.authorize_enroll(
            relay_id,
            cert_fingerprint,
            hello.enroll_token.as_deref(),
            peer_ip,
        ) {
            Ok(authorized) => {
                if let crate::ledger::Authorized::FirstEnroll {
                    cold_start_secs: cold_start,
                } = authorized
                {
                    cold_start_secs = cold_start;
                }
                // Coordinator-sourced addresses win; the hello's self-report is the
                // fallback. When the ledger recorded an advertise set for this id,
                // override the hello's addresses with it (first entry is the
                // primary) before enrolling, so the registry advertises what the
                // coordinator resolved rather than what the relay claimed. An id
                // with no recorded set enrolls with its self-reported addresses.
                match ledger.advertised_addrs(relay_id) {
                    Ok(Some(addrs)) if !addrs.is_empty() => {
                        hello.relay_addr = addrs[0];
                        hello.relay_addrs = addrs;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(
                            relay_id = relay_id.0,
                            %error,
                            "reading the ledger advertise set failed; enrolling with the hello's addresses",
                        );
                    }
                }
            }
            Err(refusal) => {
                tracing::warn!(
                    relay_id = relay_id.0,
                    %refusal,
                    "refusing relay control connection: ledger did not authorize the enroll",
                );
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: CONTROL_CLOSE_ENROLL_UNAUTHORIZED,
                        reason: "enrollment not authorized for this relay id".into(),
                    })))
                    .await;
                return;
            }
        }
    }

    // Enrollment goes through `registry::try_enroll`, whose duplicate-id refusal
    // is atomic with the insert: a live entry under this id bound to a
    // *different* certificate is a second relay process colliding on the id and
    // is refused, while the same fingerprint is this relay's own control
    // connection redialing (its cert is stable across restarts of one instance)
    // and replaces the entry exactly as it always has. Proof of possession above
    // is what makes the fingerprint trustworthy to compare against.
    let finalize_capable = hello
        .capabilities
        .iter()
        .any(|c| c == rally_point_proto::control::CAPABILITY_FINALIZED_DROP_V1);
    // Read out before the hello is consumed by the enroll below.
    let boot_id = hello.boot_id;
    // The enrollment's registry mutation and the capability-transition
    // snapshot run under the assignment lock, so they land wholly before or
    // wholly after any in-flight rehome's capability-check → descriptor-commit
    // span (which holds the same lock). Without this, a rehome could validate
    // a candidate as capable, this enrollment could downgrade it and find no
    // staged finalized-drops descriptor to evict (the rehome hasn't committed
    // yet), and the commit would then hand a finalized_drops session to a
    // relay that no longer runs the handshake. Ordered either way, one side
    // sees the other: enrollment-first fails the rehome's filter;
    // rehome-first leaves a staged descriptor this snapshot picks up. The
    // eviction rehomes themselves run after the lock drops — each re-acquires
    // it internally.
    let (enroll_result, evict) = {
        let _assign = setup.lock_assignment();
        let result =
            lifecycle.enroll_relay_epoch(relay_id, || registry::try_enroll(registry, hello));
        // Whether this is the process that was here before, or a new one whose
        // memory starts empty. A break costs every session this relay serves its
        // completeness claim: the facts the old process held and never restated are
        // gone, and no snapshot from this one can cover that interval. Judged under
        // the assignment lock so it cannot land between a create's relay pick and
        // its commit and demote a session whose whole life postdates this enroll. A
        // session committed but not yet registered is likewise unaffected: its
        // create has not answered the tenant, so no client holds a token for it and
        // the relay can have observed nothing about it to lose. A refused enroll
        // changes nothing and must not update the memory.
        if result.is_ok()
            && registry::note_boot_id(registry, relay_id, boot_id) == registry::BootLineage::Broken
        {
            lifecycle.on_relay_lineage_break(relay_id);
        }
        let evict = match &result {
            Ok(generation) => {
                // Sessions whose recorded build-class cohort no longer
                // matches this relay's advertised capability — the relay
                // crossed the finalized-drop boundary in EITHER direction
                // while still assigned. Both directions mix build classes
                // that deliver dropped-leave counts differently, so both
                // evict. Only the downgrade additionally drains the relay:
                // an incapable build must take no new capable-cohort work,
                // while an upgraded relay is exactly what new sessions want.
                let mismatched: Vec<_> = setup
                    .descriptors()
                    .current_for(relay_id)
                    .iter()
                    .filter(|d| {
                        session::session_capable_cohort(&setup, &d.tenant, d.session)
                            .is_some_and(|cohort| cohort != finalize_capable)
                    })
                    .map(|d| (d.tenant.clone(), d.session))
                    .collect();
                if !mismatched.is_empty() && !finalize_capable {
                    let _ = registry::mark_draining(setup.registry(), relay_id, *generation);
                }
                mismatched
            }
            Err(_) => Vec::new(),
        };
        (result, evict)
    };
    let generation = match enroll_result {
        Ok(generation) => generation,
        Err(registry::EnrollConflict) => {
            tracing::warn!(
                relay_id = relay_id.0,
                "refusing relay control connection: relay id already enrolled under a different certificate",
            );
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: CONTROL_CLOSE_DUPLICATE_RELAY_ID,
                    reason: "relay id already enrolled under a different certificate".into(),
                })))
                .await;
            return;
        }
    };
    crate::metrics::relay_enrolled(relay_region.as_ref());
    if let Some(secs) = cold_start_secs {
        crate::metrics::observe_relay_cold_start(secs);
    }
    tracing::info!(
        relay_id = relay_id.0,
        negotiated = %negotiated,
        "relay enrolled over control connection"
    );

    // A relay that re-enrolled on the other side of the finalized-drop
    // capability boundary while still assigned sessions of the old cohort
    // must never silently serve them — the two build classes deliver
    // dropped-leave counts differently (one authors/passes the historical
    // counted-drop behavior, the other strips it), so a mixed session hands
    // different clients different leave schedules. The mismatch snapshot
    // (and, for a downgrade, the drain mark) was taken under the assignment
    // lock above; move each mismatched session off it here. A session with
    // no in-cohort replacement ends (Unavailable) rather than continuing
    // mixed. In this deployment upgrades arrive as fresh relay ids, so the
    // upgrade direction firing at all is itself a signal worth the warn.
    if !evict.is_empty() {
        tracing::warn!(
            relay_id = relay_id.0,
            sessions = evict.len(),
            finalize_capable,
            "relay re-enrolled across the finalized-drop capability boundary while assigned                  sessions of the other cohort; evicting them",
        );
        for (tenant, session) in evict {
            let departed = lifecycle.departed_slots(&tenant, session);
            let outcome = session::rehome_evicting(&setup, &tenant, session, relay_id, departed);
            tracing::info!(
                relay_id = relay_id.0,
                tenant = tenant.as_ref(),
                session = session.0,
                ?outcome,
                "evicted a cohort-mismatched session from a capability-changed relay",
            );
        }
    }

    let rtt_ingest = RegionRttIngest {
        relay_region: relay_region.as_ref(),
        regions: &regions,
        store: &pair_rtts,
        ledger: ledger.as_deref(),
    };
    let inbound = ControlInbound {
        setup: &setup,
        notices: &notices,
        lifecycle: &lifecycle,
        relay_id,
        generation,
        rtt: &rtt_ingest,
        flight_store: flight_store.as_ref(),
    };
    push_and_watch(socket, &inbound, &regions, liveness_timeout, negotiated).await;

    // The connection ended: clear the presence this connection reported, so its
    // players read as queueable promptly rather than waiting out the TTL. Fenced
    // by this connection's exact generation — a stale drop racing a reconnect
    // removes only its own entries, never the fresh presence the reconnected
    // connection has already reported — the same race `remove_if_current` closes
    // for the registry entry itself.
    presence::clear_connection(setup.presence(), relay_id, generation);
    if lifecycle.disconnect_relay_epoch(relay_id, generation, || {
        registry::remove_if_current(registry, relay_id, generation)
    }) {
        tracing::info!(
            relay_id = relay_id.0,
            "relay deregistered on control disconnect"
        );
    }
    tracing::info!(relay_id = relay_id.0, "relay control connection closed");
}

/// The send half of a relay's split control socket — every coordinator→relay
/// frame goes out through this, owned solely by the writer.
pub(super) type ControlWrite = SplitSink<WebSocket, Message>;
/// The receive half of a relay's split control socket — every relay→coordinator
/// frame comes in through this, owned solely by the reader.
pub(super) type ControlRead = SplitStream<WebSocket>;

/// A reader→writer directive to run the send half of a coordinated-drain exchange:
/// push the relay's current descriptor set, then a [`CoordinatorToRelay::DrainAck`].
/// Carries no data — the reader already applied the draining mark, and the writer
/// reads the current set from its own descriptor watch — so this is purely the
/// "now emit set-then-ack" signal that must originate from the writer to keep every
/// send on one task.
pub(super) struct DrainSend;

/// The immutable inputs for handling one inbound relay frame: the coordinator state
/// a frame's side effects read and update, this connection's identity and
/// generation, and the RTT-ingest and flight-store handles a heartbeat or recording
/// lands through. Bundled because they travel together from enroll into the reader
/// and on into [`note_inbound`] on every frame, never individually — the borrowed
/// fields let the reader hold them without owning any of the shared state.
pub(super) struct ControlInbound<'a> {
    /// The session-setup context: registry, membership, and outboxes a frame reads
    /// or mutates.
    pub(super) setup: &'a SessionSetup,
    /// The relay-notice dedup sets a departure/desync/result collapses against.
    pub(super) notices: &'a NoticeDedup,
    /// The per-session lifecycle a notice or `SessionClosed` advances.
    pub(super) lifecycle: &'a Lifecycle,
    /// The relay identity this connection enrolled as — the only id a frame may
    /// report under.
    pub(super) relay_id: RelayId,
    /// This connection's enroll generation, fencing a stale connection's late frame
    /// against a reconnect.
    pub(super) generation: u64,
    /// The backbone-RTT ingest a heartbeat's `region_rtts` fold through.
    pub(super) rtt: &'a RegionRttIngest<'a>,
    /// The durable flight sink a shipped recording is stored into, when configured.
    pub(super) flight_store: Option<&'a Arc<S3FlightStore>>,
}

/// The writer half's outbound sources: the per-relay descriptor and reap outboxes,
/// the fleet mesh-peer watch, the reader's drain-exchange directives, and the
/// connect-time payloads led out ahead of any steady-state push. Bundled because
/// they are all consumed by the one writer and nowhere else, so they are moved in
/// together and owned for the connection's life.
pub(super) struct WriterSources {
    /// This relay's current descriptor set, latest-wins, re-synced on connect and
    /// pushed on every change.
    pub(super) descriptors: tokio::sync::watch::Receiver<Vec<SessionDescriptor>>,
    /// The fleet mesh-peer set, shared across every connection and pushed on
    /// membership changes.
    pub(super) mesh_peers: tokio::sync::watch::Receiver<Vec<MeshPeerIdentity>>,
    /// This relay's reap directives, coalesced per session before each is sent.
    pub(super) reaps: tokio::sync::mpsc::UnboundedReceiver<SlotClose>,
    /// Load-state questions addressed to this relay, each answered with one request
    /// frame down the connection.
    pub(super) load_state: tokio::sync::mpsc::Receiver<LoadStateAsk>,
    /// The attestation broker the questions above come from, so the writer can drop
    /// one whose waiter has already gone before spending a frame on it.
    pub(super) attest: crate::attest::LoadStateAttest,
    /// The reader's directives to emit a drain exchange's set-then-ack.
    pub(super) drain: tokio::sync::mpsc::UnboundedReceiver<DrainSend>,
    /// Ready flight-upload grant/refusal frames the reader minted (a presign runs off
    /// the read loop and pushes its result here), forwarded to the relay verbatim.
    pub(super) grants: tokio::sync::mpsc::UnboundedReceiver<CoordinatorToRelay>,
    /// The tenant verifying keys, led out first so a relay can verify a session's
    /// client tokens before that session's descriptor arrives.
    pub(super) tenant_keys: Vec<TenantVerifyingKey>,
    /// The region ping-beacon targets, led out after the keys; empty on a
    /// region-blind coordinator.
    pub(super) beacon_targets: Vec<RegionBeaconTarget>,
}

/// Serves an enrolled relay's control connection by splitting the socket into a
/// reader and a writer that run until either ends. Returns when the connection is
/// over — the relay closes, the socket errors, the relay goes silent past
/// `liveness_timeout`, a send stalls past `liveness_timeout`, or the coordinator's
/// outbox is dropped on shutdown — so the caller then runs the single
/// deregistration path.
///
/// The split lets reading and writing proceed independently: a relay that stops
/// reading can back-pressure the writer's sends without also blocking the reader,
/// so the coordinator keeps processing that relay's inbound frames and — via the
/// writer's own per-send stall bound — still tears the wedged connection down. The
/// reader owns inbound frames and the liveness deadline (every frame pushes it
/// forward; a lapse ends the connection); the writer owns the connect-time lead and
/// every steady-state push. Whichever half ends first drops the other, so no task
/// leaks and every side effect runs on exactly one half.
async fn push_and_watch(
    socket: WebSocket,
    inbound: &ControlInbound<'_>,
    regions: &RegionsConfig,
    liveness_timeout: Duration,
    negotiated: ProtocolVersion,
) {
    let (mut write_half, mut read_half) = socket.split();
    let setup = inbound.setup;
    let relay_id = inbound.relay_id;

    // The reader directs the writer to emit a drain exchange's set-then-ack over
    // this channel once its synchronous draining mark has applied — keeping every
    // send on the writer so set-before-ack holds on the wire.
    let (drain_tx, drain) = tokio::sync::mpsc::unbounded_channel::<DrainSend>();

    // The reader (and the presigns it spawns) push ready flight-upload grant/refusal
    // frames over this channel for the writer to send — keeping every send on the
    // writer while the async presign runs off the read loop.
    let (grants_tx, grants) = tokio::sync::mpsc::unbounded_channel::<CoordinatorToRelay>();

    // Every coordinator→relay source the writer draws from. The descriptor and reap
    // outboxes' fresh subscribes replace any prior sender, so a reconnect owns the
    // live receivers; the mesh-peer watch is shared across every connection. The
    // tenant keys and region beacons are immutable per process, snapshotted here and
    // led out ahead of the first descriptor (a relay that reconnects re-receives
    // them).
    let mut sources = WriterSources {
        descriptors: setup.descriptors().subscribe(relay_id),
        mesh_peers: registry::subscribe_mesh_peers(setup.registry()),
        reaps: setup.reaps().subscribe(relay_id),
        load_state: setup.attest().subscribe(relay_id),
        attest: setup.attest().clone(),
        drain,
        grants,
        tenant_keys: tenant::all_verifying_keys(setup.tenants()),
        beacon_targets: regions.beacon_targets(),
    };

    // The two halves run concurrently until one returns; the other's future is then
    // dropped (cancelled) here. A drop is safe on both sides: the reader only ever
    // awaits between whole synchronous `note_inbound` runs, and the writer only ever
    // awaits mid-send on a connection that is ending anyway — so no effect is left
    // half-applied and nothing is double-run.
    tokio::select! {
        () = run_writer(&mut write_half, &mut sources, relay_id, liveness_timeout, negotiated) => {}
        () = run_reader(&mut read_half, inbound, liveness_timeout, &drain_tx, grants_tx) => {}
    }
}
