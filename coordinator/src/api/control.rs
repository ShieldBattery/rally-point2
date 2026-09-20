//! The relay control connection's front door and its per-connection plumbing.
//!
//! Holds the `GET /relay/control` handler, the socket loop that drives the
//! enroll handshake ([`super::control_enroll`]) before a relay reaches the
//! registry, and the split that runs the reader and writer halves against each
//! other. Each half owns the inputs it is driven from; what lives here is only
//! what both touch — the two socket halves and the reader→writer drain
//! directive.

use std::net::IpAddr;
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
use rally_point_proto::control::{CoordinatorToRelay, RelayToCoordinator};
use rally_point_proto::version::ProtocolVersion;

use crate::lifecycle::RegionRttIngest;
use crate::presence;
use crate::regions::RegionsConfig;
use crate::registry;

use super::control_enroll::{ControlClose, EnrollContext, EnrollHandshake, EnrollStep};
use super::control_hello::{read_hello, read_relay_frame};
use super::control_inbound::{ControlInbound, run_reader};
use super::control_writer::{WriterSources, run_writer};
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

/// Serves one relay's control connection: enroll from its `Hello`, push
/// descriptors, watch the relay's liveness, and deregister it when the connection
/// drops.
///
/// The enroll sequence itself is [`EnrollHandshake`] — permit, `Hello`, version
/// negotiate, region check, proof of possession, permit drop, ledger authorize,
/// registry enroll, in that order and with every refusal decided there. This
/// function is only its socket: it reads the frames the handshake is waiting
/// for, sends what it returns, and closes on a refusal. The relay's first frame
/// must be its [`RelayToCoordinator::Hello`], and every frame the sequence waits
/// for must arrive within `hello_timeout` — a connection that opens the socket
/// and then says nothing is dropped rather than left to pin a task. `peer_ip`
/// is the connection's transport-level peer address, which a ledger's
/// expected-address check compares.
///
/// Once enrolled, the connection serves descriptors and watches liveness
/// ([`push_and_watch`]) until it ends — the relay closes, the socket errors, the
/// relay goes silent past `liveness_timeout`, or the coordinator's outbox is
/// dropped (shutdown).
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
        lifecycle,
        hello_timeout,
        liveness_timeout,
        regions,
        ledger,
        pair_rtts,
        flight_store,
        pending_hellos,
        ..
    } = state;
    let context = EnrollContext::new(&setup, &lifecycle, &regions, ledger.as_deref(), peer_ip);
    let mut handshake = match EnrollHandshake::start(&context, &pending_hellos) {
        Ok(handshake) => handshake,
        Err(close) => return send_close(&mut socket, close).await,
    };
    // The first frame enrolls the relay, and must arrive within the deadline — a
    // connection that opens the socket but never sends a Hello is dropped rather
    // than left to pin a task. A bad/absent first frame likewise just closes.
    let hello = match tokio::time::timeout(hello_timeout, read_hello(&mut socket)).await {
        Ok(Some(hello)) => hello,
        Ok(None) => return,
        Err(_elapsed) => {
            tracing::debug!("control connection sent no Hello within the deadline; closing");
            return;
        }
    };
    // Drive the sequence to its end: each frame it returns goes out, and
    // whatever the relay answers (or nothing, past the deadline) goes back in.
    let mut step = handshake.offer(Some(RelayToCoordinator::Hello(hello)));
    let enrolled = loop {
        match step {
            EnrollStep::Send(frame) => {
                let json = serde_json::to_string(&frame)
                    .expect("a coordinator-to-relay enroll frame always serializes");
                if socket.send(Message::Text(json.into())).await.is_err() {
                    return;
                }
                // Bounded by the same deadline as the initial Hello: a relay
                // silent past it, or one that answers with anything other than
                // the frame the sequence waits for, is exactly as unwelcome
                // here as one that never sent a Hello at all.
                let answer = tokio::time::timeout(hello_timeout, read_relay_frame(&mut socket))
                    .await
                    .ok()
                    .flatten();
                step = handshake.offer(answer);
            }
            EnrollStep::Refuse(close) => {
                if let Some(close) = close {
                    send_close(&mut socket, close).await;
                }
                return;
            }
            EnrollStep::Enrolled(enrolled) => break enrolled,
        }
    };
    let relay_id = enrolled.relay_id;
    let generation = enrolled.generation;

    let rtt_ingest = RegionRttIngest {
        relay_region: enrolled.relay_region.as_ref(),
        regions: &regions,
        store: &pair_rtts,
        ledger: ledger.as_deref(),
    };
    let inbound = ControlInbound::new(
        &setup,
        &lifecycle,
        relay_id,
        generation,
        &rtt_ingest,
        flight_store.as_ref(),
    );
    push_and_watch(
        socket,
        &inbound,
        &regions,
        liveness_timeout,
        enrolled.negotiated,
    )
    .await;

    // The connection ended: clear the presence this connection reported, so its
    // players read as queueable promptly rather than waiting out the TTL. Fenced
    // by this connection's exact generation — a stale drop racing a reconnect
    // removes only its own entries, never the fresh presence the reconnected
    // connection has already reported — the same race `remove_if_current` closes
    // for the registry entry itself.
    presence::clear_connection(setup.presence(), relay_id, generation);
    if lifecycle.disconnect_relay_epoch(relay_id, generation, || {
        registry::remove_if_current(setup.registry(), relay_id, generation)
    }) {
        tracing::info!(
            relay_id = relay_id.0,
            "relay deregistered on control disconnect"
        );
    }
    tracing::info!(relay_id = relay_id.0, "relay control connection closed");
}

/// Sends a refused connection's close frame, ignoring a send failure — the
/// connection is ending either way, and a peer that already went away has
/// nothing left to be told.
async fn send_close(socket: &mut WebSocket, close: ControlClose) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: close.code,
            reason: close.reason.into(),
        })))
        .await;
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

    let mut sources = WriterSources::new(setup, relay_id, regions, drain, grants);

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
