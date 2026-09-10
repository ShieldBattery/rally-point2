//! The write half of an enrolled control connection: every send the relay makes.
//!
//! The biased priority loop that owns the socket's sink — drain re-asserts,
//! notices, identity proofs, the flight-upload request/grant/done cycle, the
//! periodic heartbeat, and load-state answers — plus the small framing helpers each
//! arm sends through and the in-flight shipment bookkeeping that survives a
//! reconnect.

use futures_util::SinkExt;
use rally_point_proto::control::RelayToCoordinator;
use rally_point_proto::ids::RelayId;
use rally_point_transport::rustls::pki_types::PrivateKeyDer;
use tokio::sync::mpsc::{Receiver, UnboundedReceiver};
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

use crate::consensus::RelayNotice;
use crate::observability::flight_recorder::FlightShipment;
use crate::observability::flight_upload::{self, PutOutcome};

use super::connect::{ControlDisconnect, answer_identity_challenge};
use super::heartbeat::{
    LoadStateAnswer, LoadStateAsk, heartbeat_presence, heartbeat_region_rtts,
    start_load_state_answer,
};
use super::{
    ControlError, FLIGHT_GRANT_TIMEOUT, HeartbeatConfig, LOAD_STATE_ASK_CAPACITY,
    MAX_INFLIGHT_FLIGHT_UPLOADS, OutboundQueues,
};

/// The reader→writer routes on one control connection: frames the read half received
/// but the write half must send (every send is owned by the write half). A mid-stream
/// identity challenge's nonce — answering is a send — and the coordinator's flight-upload
/// grant/refusal, which the writer acts on because it holds the parked shipment and
/// drives the upload.
pub(super) struct WriterRoutes {
    /// A routed identity-challenge nonce for the writer to answer with a proof send.
    pub(super) challenge_rx: UnboundedReceiver<[u8; 32]>,
    /// A routed flight-upload grant or refusal for the writer's upload machinery.
    pub(super) flight_grant_rx: UnboundedReceiver<FlightGrant>,
    /// A routed load-state request for the writer to fence and answer with a
    /// snapshot send.
    pub(super) load_state_rx: Receiver<LoadStateAsk>,
}

/// A coordinator's answer to a [`FlightUploadRequest`](RelayToCoordinator::FlightUploadRequest),
/// routed from the read half to the write half (which owns the upload lifecycle).
/// Carries the request's correlation id so the writer matches it to the shipment it
/// still holds and ignores an answer for one it has already resolved (a stale answer
/// from a prior connection).
pub(super) enum FlightGrant {
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
pub(super) struct PendingFlight {
    /// The parked shipment: its compressed bytes, and the `sent` ack fired only once
    /// the recording is stored.
    pub(super) shipment: FlightShipment,
    /// The correlation id of the upload request outstanding for this shipment on the
    /// CURRENT connection. Re-minted on every (re)request.
    pub(super) request: u64,
    /// Where this shipment is in its upload cycle on the current connection.
    pub(super) stage: FlightStage,
}

/// Where a [`PendingFlight`] is in its request→grant→upload→done cycle on the
/// current connection.
pub(super) enum FlightStage {
    /// The upload request is sent; waiting for the coordinator's grant or refusal
    /// until `deadline`, after which the recording is dropped (flight data is never
    /// backpressure).
    AwaitingGrant { deadline: Instant },
    /// The grant arrived and a detached PUT is uploading the compressed bytes; the
    /// PUT reports its outcome over the connection's shared completion channel.
    Uploading,
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
/// compressed bytes straight to the object store (see [`crate::observability::flight_upload`]), which
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
pub(super) async fn write_control_frames(
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
        mut load_state_rx,
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
    // And likewise the load-state sender.
    let mut load_state_open = true;

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

    // Finished load-state answers coming back from the fence tasks this half
    // spawns. Bounded by the same cap the inbound ask channel carries, so the
    // number of answers in flight can never exceed the number of questions that
    // were admitted; a fence whose answer cannot be queued drops it, which the
    // coordinator reads as this relay not having attested.
    let (answers_tx, mut answers_rx) =
        tokio::sync::mpsc::channel::<LoadStateAnswer>(LOAD_STATE_ASK_CAPACITY);

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
                    sessions: heartbeat_presence(&heartbeat.sources),
                    region_rtts: heartbeat_region_rtts(&heartbeat.sources.region_rtt_cache),
                })
                .expect("a heartbeat always serializes");
                sink.send(Message::Text(frame.into())).await?;
            }

            // A fence task finished: send its answer. Ranked with the ask arm
            // below and for the same reason, but deliberately ABOVE it: finishing
            // an answer frees the fence permit its task holds, while taking a
            // fresh ask consumes one. Draining answers first keeps a saturated
            // relay recycling permits instead of preferring new probing over
            // work already paid for. This half holds `answers_tx` for the
            // connection's whole life, so the channel yields a real answer or
            // pends — never `None` — and the arm needs no guard.
            answer = answers_rx.recv() => {
                let answer = answer
                    .expect("the write half holds an answer sender for the connection's life");
                let frame = serde_json::to_string(&RelayToCoordinator::LoadStateSnapshot {
                    request_id: answer.request_id,
                    state: answer.state,
                    fenced: answer.fenced,
                })
                .expect("a load-state snapshot always serializes");
                sink.send(Message::Text(frame.into())).await?;
            }

            // A load-state request the read half routed here. Ranked BELOW the
            // heartbeat and every lifecycle-bearing arm above it deliberately: a
            // load-state read is tenant-driven and can arrive in bursts, while
            // liveness and webhook-bearing frames are what the fleet's own health
            // depends on — a read that waits a scheduling turn costs a caller
            // nothing it cannot recover by reading again, whereas a delayed beat
            // costs the connection.
            //
            // Fenced off this task rather than inline: answering waits on
            // acknowledgements from game clients, and parking the connection's
            // only sender on a client round-trip would stall liveness behind an
            // unrelated tenant's read. The spawned fence snapshots after its
            // probes resolve — still strictly after the request arrived, which is
            // the ordering the coordinator's claim rests on — and hands the
            // finished answer back through `answers` for this half to send, or
            // sheds the ask outright when this relay is already fencing as much as
            // it will at once.
            ask = load_state_rx.recv(), if load_state_open => {
                match ask {
                    Some(ask) => start_load_state_answer(&heartbeat.sources, ask, &answers_tx),
                    None => load_state_open = false,
                }
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

/// Sends a [`RelayToCoordinator::Draining`] up the control connection, asking the
/// coordinator to stop assigning this relay new sessions.
pub(super) async fn send_draining(
    socket: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
) -> Result<(), ControlError> {
    let frame =
        serde_json::to_string(&RelayToCoordinator::Draining).expect("a draining frame serializes");
    socket.send(Message::Text(frame.into())).await?;
    Ok(())
}

/// Sends one relay notice up the control connection as a tagged JSON frame,
/// wrapping it into the matching [`RelayToCoordinator`] variant by kind.
pub(super) async fn send_notice(
    socket: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    notice: &RelayNotice,
) -> Result<(), ControlError> {
    let frame = match notice {
        RelayNotice::Departure(notice) => RelayToCoordinator::Departure(notice.clone()),
        RelayNotice::Desync(notice) => RelayToCoordinator::Desync(notice.clone()),
        RelayNotice::Result(notice) => RelayToCoordinator::Result(notice.clone()),
        RelayNotice::SlotConnected(notice) => RelayToCoordinator::SlotConnected(notice.clone()),
        RelayNotice::SessionStarted(notice) => RelayToCoordinator::SessionStarted(notice.clone()),
        RelayNotice::SlotStarted(notice) => RelayToCoordinator::SlotStarted(notice.clone()),
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
