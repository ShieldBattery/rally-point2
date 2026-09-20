//! The reader half of a relay control connection: the liveness deadline and
//! every inbound frame's side effects.
//!
//! Holds the read loop, the per-frame dispatch, and the drain mark. A frame's
//! meaning is decided by the module that owns the state it lands in: a
//! heartbeat is decoded here and handed to [`Lifecycle::ingest_heartbeat`], and
//! each per-session notice to [`Lifecycle::ingest_notice`]. This layer decodes
//! and calls once; it picks none of what either then does.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::Message;
use futures_util::StreamExt;
use rally_point_proto::control::{CoordinatorToRelay, RelayToCoordinator};
use rally_point_proto::ids::RelayId;

use crate::flight_store::S3FlightStore;
use crate::lifecycle::{Lifecycle, RegionRttIngest, RelayHeartbeat, SessionNotice};
use crate::registry;
use crate::session::SessionSetup;

use super::control::{ControlRead, DrainSend};
use super::control_flight::{
    FlightUploadState, handle_flight_upload_done, handle_flight_upload_request,
    handle_load_state_snapshot,
};

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

impl<'a> ControlInbound<'a> {
    /// Bundles one enrolled connection's frame-handling inputs. Taken as
    /// arguments rather than as a struct literal so a new input lands on this
    /// signature and every construction site has to answer for it.
    pub(super) fn new(
        setup: &'a SessionSetup,
        lifecycle: &'a Lifecycle,
        relay_id: RelayId,
        generation: u64,
        rtt: &'a RegionRttIngest<'a>,
        flight_store: Option<&'a Arc<S3FlightStore>>,
    ) -> Self {
        Self {
            setup,
            lifecycle,
            relay_id,
            generation,
            rtt,
            flight_store,
        }
    }
}

/// Owns the read half, the liveness deadline, and every inbound side effect. Runs
/// `note_inbound` synchronously on each frame in arrival order, refreshes the
/// deadline on every frame (any frame proves the relay alive), and — on a
/// `Draining` frame — applies the synchronous draining mark and directs the writer
/// to emit the exchange's set-then-ack. Returns (ending the connection) on a close,
/// a stream end, a read error, or the deadline lapsing with nothing read.
pub(super) async fn run_reader(
    read_half: &mut ControlRead,
    inbound: &ControlInbound<'_>,
    liveness_timeout: Duration,
    drain_tx: &tokio::sync::mpsc::UnboundedSender<DrainSend>,
    grants_tx: tokio::sync::mpsc::UnboundedSender<CoordinatorToRelay>,
) {
    let relay_id = inbound.relay_id;
    // The flight-upload grant state for this connection: the channel to the writer plus
    // the grants awaiting their done. Reader-local, so a stale connection's grants never
    // outlive it.
    let mut flight = FlightUploadState::new(grants_tx);
    // A relay silent past this deadline is treated as dead. Every inbound frame
    // pushes it forward; a heartbeat lands well inside the window, so it only lapses
    // when the relay stops sending at all (a crash or a half-open connection). A
    // relay that keeps sending but stops reading is caught separately, by the
    // writer's per-send stall bound.
    let mut deadline = tokio::time::Instant::now() + liveness_timeout;
    loop {
        tokio::select! {
            frame = read_half.next() => {
                match frame {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(message)) => {
                        let action = note_inbound(inbound, &mut flight, &message);
                        // Any frame proves the relay is alive — push the deadline out.
                        deadline = tokio::time::Instant::now() + liveness_timeout;
                        // A Draining frame applies the synchronous draining mark here,
                        // then hands the send half (its current descriptor set, then a
                        // DrainAck) to the writer so set-before-ack holds on the wire. A
                        // dropped writer (its half ended) means the connection is over.
                        if action == InboundAction::DrainRequested
                            && apply_drain_mark(inbound.setup, relay_id, inbound.generation)
                            && drain_tx.send(DrainSend).is_err()
                        {
                            break;
                        }
                    }
                    Some(Err(error)) => {
                        tracing::debug!(%error, relay_id = relay_id.0, "relay control connection error");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                tracing::info!(
                    relay_id = relay_id.0,
                    "relay control connection went silent past the liveness deadline; dropping",
                );
                crate::metrics::control_connection_ended("liveness_lapse");
                break;
            }
        }
    }
}

/// What an inbound relay frame asks the connection loop to do beyond the liveness
/// refresh every frame already triggers. Most frames drive their webhook/lifecycle
/// side effects inside [`note_inbound`] and ask nothing further ([`None`](Self::None));
/// a [`RelayToCoordinator::Draining`] asks the loop to run the drain exchange
/// ([`DrainRequested`](Self::DrainRequested)), which needs the connection's
/// generation and socket that only the loop holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InboundAction {
    /// Nothing beyond the liveness refresh.
    None,
    /// The relay asked to drain: mark it ineligible and run the set-before-ack
    /// exchange.
    DrainRequested,
}

/// Handles an inbound relay frame, returning what the connection loop should do
/// next. Any frame already counts as the liveness signal; a
/// [`RelayToCoordinator::Draining`] returns [`InboundAction::DrainRequested`] so the
/// loop can run the drain exchange (which needs the socket + generation it owns);
/// anything undecodable is flagged.
///
/// A heartbeat is decoded into a [`RelayHeartbeat`] and handed to
/// [`Lifecycle::ingest_heartbeat`], which owns the wire-shape ceilings, the
/// generation fence, the serving-relay filter and the fan-out. The six
/// per-session notice kinds are decoded into a [`SessionNotice`] and handed to
/// [`Lifecycle::ingest_notice`], which owns the reporter authorization, the
/// lifecycle accounting, and the webhook enqueue. This file picks none of that;
/// it decodes a frame and calls once. `SessionClosed` is the exception and stays
/// here: it is fenced on the connection's generation rather than on session
/// membership, and drives no webhook of its own.
pub(super) fn note_inbound(
    inbound: &ControlInbound<'_>,
    flight: &mut FlightUploadState,
    message: &Message,
) -> InboundAction {
    // `flight_store` is read through `inbound` by the flight-upload handlers below, not
    // bound here.
    let &ControlInbound {
        setup,
        lifecycle,
        relay_id,
        generation,
        rtt,
        ..
    } = inbound;
    let Message::Text(text) = message else {
        return InboundAction::None; // ping/pong/binary: liveness only, nothing to read
    };
    match serde_json::from_str::<RelayToCoordinator>(text) {
        Ok(RelayToCoordinator::Heartbeat {
            roster_complete,
            sessions,
            region_rtts,
        }) => {
            lifecycle.ingest_heartbeat(
                relay_id,
                generation,
                RelayHeartbeat {
                    roster_complete,
                    sessions,
                    region_rtts,
                },
                rtt,
            );
            InboundAction::None
        }
        Ok(RelayToCoordinator::Draining) => {
            // Presence is enough for liveness; the loop runs the set-before-ack drain
            // exchange, which needs the connection's socket and generation.
            InboundAction::DrainRequested
        }
        Ok(RelayToCoordinator::Departure(notice)) => {
            lifecycle.ingest_notice(relay_id, SessionNotice::Departure(notice));
            InboundAction::None
        }
        Ok(RelayToCoordinator::Desync(notice)) => {
            lifecycle.ingest_notice(relay_id, SessionNotice::Desync(notice));
            InboundAction::None
        }
        Ok(RelayToCoordinator::Result(notice)) => {
            lifecycle.ingest_notice(relay_id, SessionNotice::Result(notice));
            InboundAction::None
        }
        Ok(RelayToCoordinator::SlotConnected(notice)) => {
            lifecycle.ingest_notice(relay_id, SessionNotice::SlotConnected(notice));
            InboundAction::None
        }
        Ok(RelayToCoordinator::SessionStarted(notice)) => {
            lifecycle.ingest_notice(relay_id, SessionNotice::SessionStarted(notice));
            InboundAction::None
        }
        Ok(RelayToCoordinator::SlotStarted(notice)) => {
            lifecycle.ingest_notice(relay_id, SessionNotice::SlotStarted(notice));
            InboundAction::None
        }
        Ok(RelayToCoordinator::SessionClosed { tenant, session }) => {
            if !registry::generation_is_current(setup.registry(), relay_id, generation) {
                tracing::debug!(
                    relay_id = relay_id.0,
                    tenant = tenant.as_ref(),
                    session = session.0,
                    "dropping SessionClosed from a stale control connection",
                );
                return InboundAction::None;
            }
            lifecycle.on_session_closed(tenant, session, relay_id, generation);
            InboundAction::None
        }
        Ok(RelayToCoordinator::FlightUploadRequest {
            request,
            tenant,
            session,
            desynced,
            bytes,
        }) => {
            handle_flight_upload_request(
                inbound, flight, request, tenant, session, desynced, bytes,
            );
            InboundAction::None
        }
        Ok(RelayToCoordinator::FlightUploadDone { request }) => {
            handle_flight_upload_done(inbound, flight, request);
            InboundAction::None
        }
        Ok(RelayToCoordinator::LoadStateSnapshot {
            request_id,
            state,
            fenced,
        }) => {
            handle_load_state_snapshot(inbound, request_id, state, fenced);
            InboundAction::None
        }
        // A second Hello or a future up-frame: presence is enough, content unused.
        Ok(_) => InboundAction::None,
        Err(error) => {
            tracing::debug!(%error, relay_id = relay_id.0, "undecodable relay control frame");
            InboundAction::None
        }
    }
}

/// Applies the synchronous part of a relay's coordinated-drain exchange after it
/// sent a [`RelayToCoordinator::Draining`]: mark it ineligible for new assignments,
/// returning whether the mark applied (so the caller then directs the writer to send
/// the set + ack).
///
/// The mark is taken under the assignment lock ([`SessionSetup::lock_assignment`]),
/// so it linearizes against any in-flight `create_session`/`rehome`: after it lands,
/// every session that will ever name this relay has already staged its descriptor in
/// the relay's outbox, so the set the writer then reads is provably complete.
///
/// A mark that does **not** apply — a stale generation, meaning a newer connection
/// re-enrolled this relay (its fresh enroll cleared the flag) — draws no ack: that
/// live connection runs its own drain exchange when its `Draining` arrives.
pub(super) fn apply_drain_mark(setup: &SessionSetup, relay_id: RelayId, generation: u64) -> bool {
    let applied = {
        let _assign = setup.lock_assignment();
        registry::mark_draining(setup.registry(), relay_id, generation)
    };
    if !applied {
        // A stale connection's Draining: the live successor acks its own drain.
        tracing::debug!(
            relay_id = relay_id.0,
            "ignoring a Draining frame from a stale control connection",
        );
        return false;
    }
    let region = registry::entry(setup.registry(), relay_id).and_then(|entry| entry.region);
    crate::metrics::relay_drained(region.as_ref());
    tracing::info!(relay_id = relay_id.0, "relay draining; sending set + ack");
    true
}
