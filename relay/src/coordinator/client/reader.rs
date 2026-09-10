//! The read half of an enrolled control connection, and what applying a
//! coordinator push means.
//!
//! The frame loop that receives coordinator pushes and applies each in arrival
//! order, the per-message dispatch it delegates to, and the descriptor
//! reconciliation — full set and delta — that drives the Join source and the
//! applied-session set. Frames whose handling would be a *send* are routed to the
//! write half instead of answered here.

use futures_util::StreamExt;
use rally_point_proto::control::{CoordinatorToRelay, DescriptorKey, SessionDescriptor};
use rally_point_proto::ids::RelayId;
use tokio::sync::mpsc::{Sender, UnboundedSender};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;

use std::collections::HashSet;

use crate::mesh::control::MeshControl;
use crate::routing::SessionKey;

use super::connect::{ControlDisconnect, classify_control_close};
use super::heartbeat::LoadStateAsk;
use super::writer::FlightGrant;
use super::{AppliedSessions, ControlApplyTargets, ControlConnStats, ControlError};

/// The read half's routes to the write half: the frames it decodes but cannot act
/// on, because acting on each of them is a *send* and only the writer sends.
pub(super) struct ReaderRoutes {
    /// Where a mid-stream identity-challenge nonce goes to be answered.
    pub(super) challenge_tx: UnboundedSender<[u8; 32]>,
    /// Where a flight-upload grant or refusal goes, to the half that owns the
    /// parked shipment and its upload lifecycle.
    pub(super) flight_grant_tx: UnboundedSender<FlightGrant>,
    /// Where a load-state request goes to be fenced, snapshotted, and answered.
    /// Bounded ([`LOAD_STATE_ASK_CAPACITY`](super::LOAD_STATE_ASK_CAPACITY)): a full channel drops the question
    /// rather than parking the read half.
    pub(super) load_state_tx: Sender<LoadStateAsk>,
}

/// The read half of an enrolled control connection: receives coordinator frames
/// one at a time and applies each synchronously, in arrival order. A descriptor
/// push reconciles the Join source and the applied set (and records its apply lag
/// and set size into `stats`); `MeshPeers`/`TenantKeys`/`RegionBeacons` replace
/// their stores; a `DrainAck` flips the drain-acked signal. Because frames apply
/// strictly in arrival order, a descriptor push the coordinator sends just before a
/// `DrainAck` has already updated the applied set by the time the ack fires.
///
/// A frame whose handling is itself a *send* — a mid-stream `IdentityChallenge`, a
/// flight-upload grant, a `LoadStateRequest` — is routed to the write half through
/// `routes` rather than answered here. A `Close` (or the stream ending, or a
/// read/decode error) ends the connection with the same classification a close
/// carries anywhere.
///
/// The first successfully decoded application frame reports the control connection
/// established through `control_connected`: an accepted enroll always leads with a
/// connect-time push (tenant keys first), while every refusal — version, region,
/// identity, or ledger enrollment — closes without ever pushing one, so the first
/// inbound frame here is precisely the "this enroll was accepted" signal, and a
/// refusal loop never reads as connected.
pub(super) async fn read_control_frames(
    mut stream: impl futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
    + Unpin,
    apply_targets: &ControlApplyTargets,
    relay_id: RelayId,
    routes: ReaderRoutes,
    stats: ControlConnStats,
    control_connected: &watch::Sender<bool>,
) -> Result<ControlDisconnect, ControlError> {
    let ReaderRoutes {
        challenge_tx,
        flight_grant_tx,
        load_state_tx,
    } = routes;
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
                    CoordinatorToRelay::LoadStateRequest {
                        tenant,
                        session,
                        request_id,
                    } => {
                        // Answering is a send, so route the question to the write
                        // half, which snapshots the session's state at send time. The
                        // snapshot must be taken *after* this request arrived for the
                        // coordinator's completeness claim to hold, and routing an
                        // already-decoded question preserves that: nothing this relay
                        // learns from here on can be excluded from the answer, only
                        // included. Offered without blocking: a full queue (a writer
                        // behind on a burst of reads) or a dropped receiver (the write
                        // half gone, the connection ending) drops the question, which
                        // the coordinator reads as this relay not having attested.
                        if load_state_tx
                            .try_send(LoadStateAsk {
                                request_id,
                                key: SessionKey { tenant, session },
                            })
                            .is_err()
                        {
                            tracing::debug!(
                                request_id,
                                "dropping a load-state request: the writer is behind or gone",
                            );
                        }
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
pub(super) fn apply_message(
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
        // The connection loop intercepts LoadStateRequest (it routes the question to
        // the write half, which snapshots and answers) before delegating here, so
        // this arm is only a defensive no-op for a stray one.
        CoordinatorToRelay::LoadStateRequest { .. } => {
            tracing::debug!("ignoring a LoadStateRequest received outside the snapshot route");
        }
        CoordinatorToRelay::Unknown => {
            tracing::debug!("ignoring an unrecognized coordinator control message");
        }
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
pub(super) fn reconcile(
    control: &MeshControl,
    descriptors: &[SessionDescriptor],
    applied: &AppliedSessions,
) {
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
pub(super) fn reconcile_delta(
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
