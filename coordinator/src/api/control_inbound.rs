//! The reader half of a relay control connection: the liveness deadline and
//! every inbound frame's side effects.
//!
//! Holds the read loop, the per-frame dispatch, the wire-shape ceilings a
//! heartbeat's vectors are bounded against, the backbone-RTT ingest, and the
//! serving-set check that stops one relay reporting in another's name.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::ws::Message;
use futures_util::StreamExt;
use rally_point_proto::control::{
    CoordinatorToRelay, RegionId, RegionRttReport, RelayToCoordinator, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId};

use crate::ledger::RelayLedger;
use crate::notify;
use crate::pair_rtts::{self, PairRttStore};
use crate::presence;
use crate::regions::RegionsConfig;
use crate::registry;
use crate::session::{self, SessionSetup};

use super::control::{ControlInbound, ControlRead, DrainSend};
use super::control_flight::{
    FlightUploadState, handle_flight_upload_done, handle_flight_upload_request,
    handle_load_state_snapshot,
};
use super::control_writer::apply_drain_mark;

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

/// The inputs a relay control connection threads from enroll down to
/// [`note_inbound`], where each heartbeat's `region_rtts` fold into the coordinator's
/// backbone-RTT table.
///
/// `relay_region` is the reporting relay's own region — the origin of every direction
/// it measures — validated at enroll; a region-less relay reports nothing. `regions`
/// is the coordinator's configured set, so a report naming a region it does not list
/// (a stale target after a config change) is dropped. `store` is the shared pair table,
/// and `ledger` is the optional persistence a *changed* direction is written through to.
pub(super) struct RegionRttIngest<'a> {
    pub(super) relay_region: Option<&'a RegionId>,
    pub(super) regions: &'a RegionsConfig,
    pub(super) store: &'a PairRttStore,
    pub(super) ledger: Option<&'a RelayLedger>,
}

/// Folds a heartbeat's `region_rtts` into the backbone-RTT table: each report pairs
/// the reporting relay's own region (the direction's origin) with the region it
/// measured, recorded per-direction last-write-wins beyond a dead-band. A report naming
/// a region the coordinator does not configure is dropped (a stale target list after a
/// config change); a relay with no region contributes nothing. When a direction's value
/// actually changed and a ledger is present, that direction is persisted (keyed by pair
/// and origin) so last-known round-trips survive a restart — a steady-state re-report
/// (the same value every heartbeat) changes nothing and writes nothing.
///
/// `measured_at` is stamped with a plain Unix-seconds now, `0` on a pre-epoch clock
/// rather than failing: the value is informational (it exposes a pair's age), not
/// security-bearing like the ledger's token expiry.
pub(super) fn ingest_region_rtts(
    rtt: &RegionRttIngest<'_>,
    relay_id: RelayId,
    reports: &[RegionRttReport],
) {
    let Some(relay_region) = rtt.relay_region else {
        if !reports.is_empty() {
            tracing::debug!(
                relay_id = relay_id.0,
                "ignoring backbone RTT reports from a relay with no configured region",
            );
        }
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for report in reports {
        if !rtt.regions.contains(&report.region) {
            tracing::debug!(
                relay_id = relay_id.0,
                region = report.region.as_ref(),
                "dropping a backbone RTT report for a region not in the coordinator's config",
            );
            continue;
        }
        let changed = rtt
            .store
            .record(relay_region, &report.region, report.rtt_ms, now);
        if changed {
            let (a, b) = pair_rtts::canonical_pair(relay_region, &report.region);
            // A beyond-dead-band change is rare — a direction's first fill, or a real
            // backbone shift — so each one is worth a log line: the log stream is the
            // pair table's per-direction change history (the table itself keeps only the
            // latest value per direction).
            tracing::info!(
                relay_id = relay_id.0,
                pair_a = a.as_ref(),
                pair_b = b.as_ref(),
                origin = relay_region.as_ref(),
                rtt_ms = report.rtt_ms,
                "backbone RTT recorded",
            );
            if let Some(ledger) = rtt.ledger
                && let Err(error) =
                    ledger.record_direction_rtt(a, b, relay_region, report.rtt_ms, now)
            {
                tracing::warn!(
                    relay_id = relay_id.0,
                    %error,
                    "persisting a backbone RTT to the ledger failed; keeping the in-memory value",
                );
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

/// The most sessions a single heartbeat's roster may name — every session the
/// relay still holds, not only the occupied ones (a session whose local slots
/// have all left keeps restating its retained load state until it retires). No
/// relay's session count is tracked anywhere the coordinator could size this
/// exactly, so this is a generous ceiling rather than a tight one: bounding the
/// per-beat iteration cost against a roster a relay never legitimately grows
/// close to, while leaving enormous headroom over any real deployment.
pub(super) const MAX_HEARTBEAT_SESSIONS: usize = 4096;

/// The most slots a single relay-reported session entry may name in any one of its
/// three slot lists — [`session::MAX_SLOT`] plus one, the same ceiling a session's
/// own slots are validated against at creation. Such an entry (a heartbeat's roster
/// entry, or an attested load-state snapshot) carries no length validation on the
/// wire, so one naming more slots than a session could ever legitimately have is
/// definitely forged, not just generous. (An entry naming *no* connected slot is
/// ordinary: the relay holds the session but no live link into it.)
pub(super) const MAX_HEARTBEAT_SESSION_SLOTS: usize = session::MAX_SLOT as usize + 1;

/// The most backbone round-trip reports a single heartbeat may carry. A
/// legitimate report never exceeds the coordinator's own configured region
/// count (an unconfigured region's report is dropped in
/// [`ingest_region_rtts`]), so this is a large multiple of any realistic fleet
/// region catalog — bounding the per-beat iteration cost without ever
/// crowding out real headroom for the fleet to grow.
pub(super) const MAX_HEARTBEAT_REGION_RTTS: usize = 256;

/// Handles an inbound relay frame, returning what the connection loop should do
/// next. Any frame already counts as the liveness signal; a
/// [`RelayToCoordinator::Departure`], [`RelayToCoordinator::Desync`],
/// [`RelayToCoordinator::Result`], or [`RelayToCoordinator::SessionClosed`]
/// additionally drives its webhook and lifecycle paths here; a
/// [`RelayToCoordinator::Draining`] returns [`InboundAction::DrainRequested`] so the
/// loop can run the drain exchange (which needs the socket + generation it owns). A
/// heartbeat is just liveness plus a presence/RTT ingest — bounded against an
/// oversize roster and validated against the reporting relay's own serving
/// sessions, both below — anything undecodable is flagged.
///
/// The lifecycle accounting (result/departure account a slot; `SessionClosed`
/// closes a serving relay) is fed *before* the webhook path and independent of the
/// dedup and notify-config gates the webhook path applies — the reap and the
/// `sessionClosed` signal must track a session even for a tenant with no webhook
/// configured. Redundant notices from multiple relays are idempotent in the
/// accounting (a set insert), so feeding every copy is harmless.
pub(super) fn note_inbound(
    inbound: &ControlInbound<'_>,
    flight: &mut FlightUploadState,
    message: &Message,
) -> InboundAction {
    // `flight_store` is read through `inbound` by the flight-upload handlers below, not
    // bound here.
    let &ControlInbound {
        setup,
        notices,
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
            mut sessions,
            mut region_rtts,
        }) => {
            tracing::trace!(relay_id = relay_id.0, "relay heartbeat");
            // Shape-bound the wire data before any of it is applied: a beat's
            // vectors carry no length limit of their own, so a roster or report
            // list past the generous ceilings above is definitely forged (or a
            // relay bug), not a fleet this coordinator was ever going to see.
            // Truncated rather than the whole beat rejected — the beat still
            // carries the relay's own liveness signal and whatever legitimate
            // entries precede the excess.
            let mut complete_roster = roster_complete;
            if sessions.len() > MAX_HEARTBEAT_SESSIONS {
                tracing::warn!(
                    relay_id = relay_id.0,
                    reported = sessions.len(),
                    cap = MAX_HEARTBEAT_SESSIONS,
                    "heartbeat session roster exceeds the per-beat cap; truncating",
                );
                sessions.truncate(MAX_HEARTBEAT_SESSIONS);
                // Once the coordinator drops a suffix, omission is no longer an
                // authoritative statement even if the sender marked its original
                // snapshot complete. Positive entries remain useful below.
                complete_roster = false;
            }
            for session in &mut sessions {
                bound_session_slot_lists(relay_id, session);
            }
            if region_rtts.len() > MAX_HEARTBEAT_REGION_RTTS {
                tracing::warn!(
                    relay_id = relay_id.0,
                    reported = region_rtts.len(),
                    cap = MAX_HEARTBEAT_REGION_RTTS,
                    "heartbeat region-RTT report exceeds the per-beat cap; truncating",
                );
                region_rtts.truncate(MAX_HEARTBEAT_REGION_RTTS);
            }

            // The beat's roster feeds active-player presence — but only from the
            // relay's CURRENT connection. A stale connection's late beat (a
            // reconnect raced it) is dropped whole: its roster describes a
            // superseded view, and applying it would overwrite what the live
            // connection reports. (The store's own generation fences are the
            // second line of defense.)
            if registry::generation_is_current(setup.registry(), relay_id, generation) {
                // A relay may only beat presence for sessions it actually
                // serves — the same membership check the departure/desync/result
                // arms apply, applied per roster entry rather than to the whole
                // beat, since a heartbeat legitimately batches many sessions and
                // one forged entry must not cost the rest. Unchecked, any
                // enrolled relay could name a victim `(tenant, session, slot)`
                // and forge it present: blocking that slot from re-queueing, and
                // (via `on_presence_seen` below) cancelling a reap timer that was
                // never supposed to be cancelled. `relay_serves_session` itself
                // stays fail-open when the coordinator holds no serving-relay
                // record for a session (the post-restart tail), so a legitimate
                // pre-existing session's beat is unaffected.
                sessions.retain(|session| {
                    let allowed =
                        relay_serves_session(setup, relay_id, &session.tenant, session.session);
                    if !allowed {
                        tracing::warn!(
                            relay_id = relay_id.0,
                            tenant = session.tenant.as_ref(),
                            session = session.session.0,
                            "heartbeat presence for a session this relay does not serve; rejecting",
                        );
                    }
                    allowed
                });
                presence::apply_heartbeat(
                    setup.presence(),
                    relay_id,
                    generation,
                    &sessions,
                    std::time::Instant::now(),
                );
                lifecycle.on_relay_heartbeat(
                    relay_id,
                    generation,
                    &sessions,
                    complete_roster,
                    std::time::Instant::now(),
                );
                // The beat also restates each session's accumulated load state,
                // which is the durable record behind the droppable slot-connected
                // / session-started / slot-started notices: the notice is the fast
                // path to the tenant's webhook, this is what repairs the record
                // when one is lost or a restart forgets it. It fires no webhook of
                // its own — the facts here have already been notified, and
                // re-notifying them every beat would flood the feed. A beat says
                // nothing about *when* the relay observed any of it, which is why
                // the load-state read asks its own question rather than reading a
                // beat's arrival as a deadline.
                lifecycle.merge_load_state(&sessions);
                // Backbone RTTs fold in under the same generation fence as presence: a
                // stale connection's beat describes a superseded view, so its measured
                // pairs must not overwrite what the live connection reports. Unlike the
                // session roster, RTTs carry no per-relay ownership to check — a
                // report only ever names the relay's own measured pair.
                ingest_region_rtts(rtt, relay_id, &region_rtts);
            } else {
                tracing::debug!(
                    relay_id = relay_id.0,
                    "dropping a heartbeat roster from a stale control connection",
                );
            }
            InboundAction::None
        }
        Ok(RelayToCoordinator::Draining) => {
            // Presence is enough for liveness; the loop runs the set-before-ack drain
            // exchange, which needs the connection's socket and generation.
            InboundAction::DrainRequested
        }
        Ok(RelayToCoordinator::Departure(notice)) => {
            if !relay_serves_session(setup, relay_id, &notice.tenant, notice.session) {
                tracing::warn!(
                    relay_id = relay_id.0,
                    tenant = notice.tenant.as_ref(),
                    session = notice.session.0,
                    slot = notice.slot.0,
                    "departure notice from a relay not serving the session; rejecting",
                );
                return InboundAction::None;
            }
            lifecycle.on_departure(
                notice.tenant.clone(),
                notice.session,
                notice.slot,
                notice.kind,
                notice.final_turn_count,
                notice.finalized,
            );
            notify::handle_departure(setup, &notices.departures, lifecycle, notice);
            InboundAction::None
        }
        Ok(RelayToCoordinator::Desync(notice)) => {
            if !relay_serves_session(setup, relay_id, &notice.tenant, notice.session) {
                tracing::warn!(
                    relay_id = relay_id.0,
                    tenant = notice.tenant.as_ref(),
                    session = notice.session.0,
                    sync_ordinal = notice.sync_ordinal,
                    "desync notice from a relay not serving the session; rejecting",
                );
                return InboundAction::None;
            }
            notify::handle_desync(
                setup,
                &notices.desyncs,
                &notices.desync_marks,
                lifecycle,
                notice,
            );
            InboundAction::None
        }
        Ok(RelayToCoordinator::Result(notice)) => {
            if !relay_serves_session(setup, relay_id, &notice.tenant, notice.session) {
                tracing::warn!(
                    relay_id = relay_id.0,
                    tenant = notice.tenant.as_ref(),
                    session = notice.session.0,
                    slot = notice.slot.0,
                    "result notice from a relay not serving the session; rejecting",
                );
                return InboundAction::None;
            }
            lifecycle.on_result(notice.tenant.clone(), notice.session, notice.slot);
            notify::handle_result(setup, &notices.results, lifecycle, notice);
            InboundAction::None
        }
        Ok(RelayToCoordinator::SlotConnected(notice)) => {
            if !relay_serves_session(setup, relay_id, &notice.tenant, notice.session) {
                tracing::warn!(
                    relay_id = relay_id.0,
                    tenant = notice.tenant.as_ref(),
                    session = notice.session.0,
                    slot = notice.slot.0,
                    "slot-connected notice from a relay not serving the session; rejecting",
                );
                return InboundAction::None;
            }
            lifecycle.on_slot_connected(notice.tenant.clone(), notice.session, notice.slot);
            notify::handle_slot_connected(setup, &notices.slot_connects, lifecycle, notice);
            InboundAction::None
        }
        Ok(RelayToCoordinator::SessionStarted(notice)) => {
            if !relay_serves_session(setup, relay_id, &notice.tenant, notice.session) {
                tracing::warn!(
                    relay_id = relay_id.0,
                    tenant = notice.tenant.as_ref(),
                    session = notice.session.0,
                    "session-started notice from a relay not serving the session; rejecting",
                );
                return InboundAction::None;
            }
            lifecycle.on_session_started(
                notice.tenant.clone(),
                notice.session,
                notice.started_at_ms,
            );
            notify::handle_session_started(setup, &notices.session_starts, lifecycle, notice);
            InboundAction::None
        }
        Ok(RelayToCoordinator::SlotStarted(notice)) => {
            if !relay_serves_session(setup, relay_id, &notice.tenant, notice.session) {
                tracing::warn!(
                    relay_id = relay_id.0,
                    tenant = notice.tenant.as_ref(),
                    session = notice.session.0,
                    slot = notice.slot.0,
                    "slot-started notice from a relay not serving the session; rejecting",
                );
                return InboundAction::None;
            }
            lifecycle.on_slot_started(notice.tenant.clone(), notice.session, notice.slot);
            notify::handle_slot_started(setup, &notices.slot_starts, lifecycle, notice);
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

/// Truncates each of a session entry's three slot lists to
/// [`MAX_HEARTBEAT_SESSION_SLOTS`], logging what was cut.
///
/// A session cannot have more slots than that ceiling, so a longer list is forged
/// (or a relay bug) whether it names the connected slots or the
/// ever-connected/ever-started ones. Applied to every relay-supplied session entry
/// — a heartbeat's roster and an attested load-state snapshot alike — since both
/// arrive on the wire with no length limit of their own and both feed the same
/// accumulated sets. Truncated rather than rejected: the legitimate entries that
/// precede the excess are still worth folding in.
pub(super) fn bound_session_slot_lists(
    relay_id: RelayId,
    session: &mut rally_point_proto::control::SessionPresence,
) {
    for (label, slots) in [
        ("connected", &mut session.slots),
        ("ever-connected", &mut session.ever_connected),
        ("started", &mut session.started),
    ] {
        if slots.len() > MAX_HEARTBEAT_SESSION_SLOTS {
            tracing::warn!(
                relay_id = relay_id.0,
                tenant = session.tenant.as_ref(),
                session = session.session.0,
                list = label,
                reported = slots.len(),
                cap = MAX_HEARTBEAT_SESSION_SLOTS,
                "relay-reported session slot list exceeds the per-session cap; truncating",
            );
            slots.truncate(MAX_HEARTBEAT_SESSION_SLOTS);
        }
    }
}

/// Whether `relay_id` — the relay identity this control connection enrolled as —
/// is allowed to report a departure/desync/result for `(tenant, session)`. A
/// notice carries attacker-influenceable `tenant`/`session`/payload, and each one
/// drives a webhook signed with the tenant's own key; without this gate any
/// connected relay could name a victim tenant + session and have the coordinator
/// sign and deliver forged bytes to that tenant's webhook.
///
/// The rule: the reporting relay must be one of the session's serving relays.
/// When the coordinator holds **no** serving-relay record for the session, the
/// notice is allowed through — this is the routine post-restart tail case, where a
/// relay still holds a session created in a previous coordinator lifetime and
/// reports its closing events, but the in-memory serving set was wiped, so there
/// is nothing to check the reporter against. Enforcement therefore applies only
/// when serving-relay information exists this lifetime.
///
/// Residual gap: the unverifiable no-record path still trusts the reporter, and
/// the shared bootstrap secret authenticates "a relay," not a specific relay id,
/// so a secret holder could forge a tail notice for a session with no live serving
/// record. Fully closing that needs per-relay identity — the same work that binds
/// a control connection to its claimed relay id — and is out of scope here.
pub(super) fn relay_serves_session(
    setup: &SessionSetup,
    relay_id: RelayId,
    tenant: &TenantId,
    session: SessionId,
) -> bool {
    let serving = setup.serving_relays(tenant, session);
    serving.is_empty() || serving.contains(&relay_id)
}
