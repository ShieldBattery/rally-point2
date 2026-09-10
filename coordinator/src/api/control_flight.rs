//! The reader's out-of-band handlers: flight-recording upload grants and
//! attested load-state snapshots.
//!
//! Both arrive as ordinary inbound frames but do their work off the read loop —
//! a presign and a retention sweep are async store calls — so the grant
//! bookkeeping that ties a request to its later `done` lives here, per
//! connection, alongside the snapshot fold that resolves a pending read.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rally_point_proto::control::{CoordinatorToRelay, TenantId};
use rally_point_proto::ids::{RelayId, SessionId};

use crate::flight_store::{self, S3FlightStore};
use crate::notify;
use crate::tenant;

use super::control::ControlInbound;
use super::control_inbound::{bound_session_slot_lists, relay_serves_session};

/// The shortest gap between "a request arrived but no store is configured" warnings,
/// so a fleet asking a coordinator whose store config was forgotten to grant uploads
/// logs the misconfiguration without one log line per request.
const NO_STORE_WARN_INTERVAL_SECS: u64 = 60;

/// Unix seconds of the last no-store warning, so [`warn_no_flight_store`] can rate-limit
/// itself. `0` means it has never warned.
static LAST_NO_STORE_WARN_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Reader-local state for the flight-upload grant path on one control connection: the
/// channel that hands ready grant/refusal frames to the writer, and the grants minted
/// on this connection still awaiting their [`RelayToCoordinator::FlightUploadDone`].
pub(super) struct FlightUploadState {
    /// The ready [`CoordinatorToRelay::FlightUploadGrant`] / `FlightUploadRefused` frames
    /// the reader hands the writer to send. A presign runs off the read loop and pushes
    /// its result here.
    grants: tokio::sync::mpsc::UnboundedSender<CoordinatorToRelay>,
    /// Grants minted on this connection, keyed by the relay's request id, awaiting their
    /// `FlightUploadDone`. Swept opportunistically (on a new request or a done) at grant
    /// expiry, never with a timer.
    outstanding: std::collections::HashMap<u64, OutstandingGrant>,
}

impl FlightUploadState {
    pub(super) fn new(grants: tokio::sync::mpsc::UnboundedSender<CoordinatorToRelay>) -> Self {
        Self {
            grants,
            outstanding: std::collections::HashMap::new(),
        }
    }
}

/// One outstanding upload grant, recorded when the coordinator grants an upload and
/// removed by its `FlightUploadDone`. Carries what the done bookkeeping needs: the
/// tenant + session to run the pinned convergence sweep against, whether it was pinned,
/// and the byte count for the stored metric — plus the mint instant, so a grant whose
/// done never arrives (a refused presign, a relay that gave up uploading) expires rather
/// than lingering for the connection's life.
pub(super) struct OutstandingGrant {
    pub(super) tenant: TenantId,
    pub(super) session: SessionId,
    pub(super) pinned: bool,
    pub(super) bytes: u64,
    pub(super) minted_at: Instant,
}

/// Prunes every grant past its expiry — [`flight_store::PRESIGNED_PUT_EXPIRY`] from its
/// mint, the point its presigned URL is dead anyway. Opportunistic, run on each new
/// request and done rather than by a timer, so a grant whose done never arrives cannot
/// accumulate.
pub(super) fn prune_expired_grants(
    outstanding: &mut std::collections::HashMap<u64, OutstandingGrant>,
    now: Instant,
) {
    outstanding.retain(|_, grant| {
        now.saturating_duration_since(grant.minted_at) < flight_store::PRESIGNED_PUT_EXPIRY
    });
}

/// Removes and returns the outstanding grant for `request`, first pruning any grant past
/// its expiry — so an expired grant reads as absent. `None` for an unknown or expired
/// request: a done the coordinator ignores.
pub(super) fn take_outstanding_grant(
    outstanding: &mut std::collections::HashMap<u64, OutstandingGrant>,
    request: u64,
    now: Instant,
) -> Option<OutstandingGrant> {
    prune_expired_grants(outstanding, now);
    outstanding.remove(&request)
}

/// Handles one relay's flight-upload request: gate it (a configured store, a known and
/// key-safe tenant, a byte count within the cap), decide the retention class, record the
/// outstanding grant, and spawn the presign off the read loop — the SDK call is async
/// and must not run inline in the sync reader — which pushes the ready grant (or a
/// refusal on presign failure) to the writer. A gate failure pushes a refusal the same
/// way.
///
/// The object key is built from `relay_id` — the identity THIS connection enrolled as,
/// never a relay-supplied field — so a relay can only ever upload under its own id. The
/// retention class is pinned when the relay flagged a desync in its own recording OR the
/// coordinator has independently marked the session desynced: only the authority relay's
/// own recording carries the flag, but every relay's desync notice reaches the
/// coordinator, so the mark is what pins the non-authority relays' recordings.
///
/// Unlike its departure/desync/result siblings, this deliberately passes no
/// serving-set check: a recording flushes at the same moment the relay reports
/// `SessionClosed`, in no fixed order relative to it, so by the time the request arrives
/// the session's serving-set state may already be retired and a membership check would
/// wrongly refuse exactly the recordings the store exists to keep. The exposure is
/// proportionate: a forged request can only ever grant an upload under the requesting
/// relay's own key — pollution bounded to the identity that requested it.
pub(super) fn handle_flight_upload_request(
    inbound: &ControlInbound<'_>,
    flight: &mut FlightUploadState,
    request: u64,
    tenant: TenantId,
    session: SessionId,
    desynced: bool,
    bytes: u64,
) {
    let relay_id = inbound.relay_id;
    let tenant_known = tenant::tenant_state(inbound.setup.tenants(), &tenant).is_some();
    let pinned = desynced
        || notify::is_session_desynced(
            &inbound.notices.desync_marks,
            &tenant,
            session,
            Instant::now(),
        );

    match flight_store::plan_flight_upload(
        inbound.flight_store.is_some(),
        tenant_known,
        &tenant,
        session,
        relay_id,
        pinned,
        bytes,
    ) {
        Ok(plan) => {
            let store = inbound
                .flight_store
                .expect("a plan is only produced when a store is configured")
                .clone();
            // Record the grant before presigning; the presign pushes the URL (or a
            // refusal) to the writer off this loop. Prune expired grants opportunistically.
            prune_expired_grants(&mut flight.outstanding, Instant::now());
            flight.outstanding.insert(
                request,
                OutstandingGrant {
                    tenant,
                    session,
                    pinned: plan.pinned,
                    bytes,
                    minted_at: Instant::now(),
                },
            );
            spawn_presign(store, flight.grants.clone(), request, plan.key, bytes);
        }
        Err(drop) => {
            match drop {
                flight_store::FlightDrop::NoStore => {
                    // No store configured: the recording is unrecoverably lost, not a
                    // deliberate refusal.
                    crate::metrics::flight_recording_lost();
                    warn_no_flight_store(relay_id);
                }
                flight_store::FlightDrop::UnknownTenant => {
                    crate::metrics::flight_recording_refused();
                    tracing::warn!(
                        relay_id = relay_id.0,
                        tenant = tenant.as_ref(),
                        session = session.0,
                        "refusing a flight upload for a tenant not in the registry",
                    );
                }
                flight_store::FlightDrop::TenantIdNotKeySafe => {
                    crate::metrics::flight_recording_refused();
                    tracing::warn!(
                        relay_id = relay_id.0,
                        tenant = tenant.as_ref(),
                        session = session.0,
                        "refusing a flight upload: the tenant id cannot embed in an object key",
                    );
                }
                flight_store::FlightDrop::TooLarge => {
                    crate::metrics::flight_recording_refused();
                    tracing::warn!(
                        relay_id = relay_id.0,
                        tenant = tenant.as_ref(),
                        session = session.0,
                        bytes,
                        "refusing an oversize flight upload",
                    );
                }
            }
            let _ = flight
                .grants
                .send(CoordinatorToRelay::FlightUploadRefused { request });
        }
    }
}

/// Spawns the presign of one granted upload off the read loop (the SDK call is async and
/// must not run inline in the sync reader), pushing the ready
/// [`CoordinatorToRelay::FlightUploadGrant`] — or a `FlightUploadRefused` when presigning
/// fails — to the writer through `grants`. `content_length` is bound into the URL so it
/// cannot store a different-sized object.
fn spawn_presign(
    store: Arc<S3FlightStore>,
    grants: tokio::sync::mpsc::UnboundedSender<CoordinatorToRelay>,
    request: u64,
    key: String,
    content_length: u64,
) {
    tokio::spawn(async move {
        let frame = match store.presign_put(&key, content_length).await {
            Ok(url) => CoordinatorToRelay::FlightUploadGrant { request, url },
            Err(error) => {
                crate::metrics::flight_recording_lost();
                tracing::warn!(
                    request,
                    key,
                    %error,
                    "presigning a flight upload URL failed; refusing the request",
                );
                CoordinatorToRelay::FlightUploadRefused { request }
            }
        };
        let _ = grants.send(frame);
    });
}

/// Handles one relay's [`RelayToCoordinator::FlightUploadDone`]: the relay uploaded the
/// recording, so run the post-store bookkeeping — the stored (and, when pinned, pinned)
/// metric, and for a pinned grant the same unpinned→pinned convergence sweep the direct
/// store path used to trigger ([`flight_store::pin_session`]). A done for an unknown or
/// expired request is logged and ignored.
pub(super) fn handle_flight_upload_done(
    inbound: &ControlInbound<'_>,
    flight: &mut FlightUploadState,
    request: u64,
) {
    let relay_id = inbound.relay_id;
    let Some(grant) = take_outstanding_grant(&mut flight.outstanding, request, Instant::now())
    else {
        tracing::debug!(
            relay_id = relay_id.0,
            request,
            "flight upload done for an unknown or expired request; ignoring",
        );
        return;
    };
    crate::metrics::flight_recording_stored();
    if grant.pinned {
        crate::metrics::flight_recording_pinned();
    }
    tracing::info!(
        relay_id = relay_id.0,
        tenant = grant.tenant.as_ref(),
        session = grant.session.0,
        pinned = grant.pinned,
        bytes = grant.bytes,
        "flight recording uploaded",
    );
    // A pinned recording converges the session's already-stored unpinned blobs into the
    // pinned retention class — the same sweep the direct store path ran on a pinned
    // store. Off the read loop, since the sweep is a run of async store operations.
    if grant.pinned
        && let Some(store) = inbound.flight_store
    {
        let store = store.clone();
        tokio::spawn(async move {
            if let Err(error) =
                flight_store::pin_session(&*store, &grant.tenant, grant.session).await
            {
                tracing::warn!(
                    relay_id = relay_id.0,
                    tenant = grant.tenant.as_ref(),
                    session = grant.session.0,
                    %error,
                    "converging a desynced session's earlier recordings failed",
                );
            }
        });
    }
}

/// Handles one relay's [`RelayToCoordinator::LoadStateSnapshot`]: the attested
/// answer to a load-state question the coordinator put to this relay.
///
/// The snapshot is folded into the session's record through exactly the path a
/// heartbeat's restatement takes — positive facts only, no webhook — and then
/// delivered to the read still waiting on it, which is what lets that read conclude
/// this relay has now answered for itself.
///
/// Two gates precede both. A snapshot for a session this relay does not serve is
/// rejected, the same membership rule every other notice's arm applies: without it
/// an enrolled relay could name a victim `(tenant, session, slot)` and forge an
/// arrival into that session's record. And the broker accepts the correlation id
/// only when it names an outstanding request made to *this* relay for *this*
/// session, so one relay can never answer in another's name, and a late answer from
/// a read that already gave up finds nothing to resolve.
pub(super) fn handle_load_state_snapshot(
    inbound: &ControlInbound<'_>,
    request_id: u64,
    mut snapshot: rally_point_proto::control::SessionPresence,
    fenced: bool,
) {
    let relay_id = inbound.relay_id;
    bound_session_slot_lists(relay_id, &mut snapshot);
    if !relay_serves_session(inbound.setup, relay_id, &snapshot.tenant, snapshot.session) {
        tracing::warn!(
            relay_id = relay_id.0,
            tenant = snapshot.tenant.as_ref(),
            session = snapshot.session.0,
            "load-state snapshot from a relay not serving the session; rejecting",
        );
        return;
    }
    inbound
        .lifecycle
        .merge_load_state(std::slice::from_ref(&snapshot));
    if inbound
        .setup
        .attest()
        .resolve(
            request_id,
            relay_id,
            crate::attest::AttestedSnapshot {
                state: snapshot,
                fenced,
            },
        )
        .is_err()
    {
        tracing::debug!(
            relay_id = relay_id.0,
            request_id,
            "load-state snapshot for an unknown or already-answered request; ignoring",
        );
    }
}

/// Warns that a recording arrived with no store configured, at most once per
/// [`NO_STORE_WARN_INTERVAL_SECS`] — an operator who wired relays to ship but forgot the
/// store config should see it, without one log line per dropped recording. A racing pair
/// of warns is harmless (the store/load is best-effort, not a lock).
fn warn_no_flight_store(relay_id: RelayId) {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let last = LAST_NO_STORE_WARN_SECS.load(std::sync::atomic::Ordering::Relaxed);
    if now_secs.saturating_sub(last) < NO_STORE_WARN_INTERVAL_SECS {
        return;
    }
    LAST_NO_STORE_WARN_SECS.store(now_secs, std::sync::atomic::Ordering::Relaxed);
    tracing::warn!(
        relay_id = relay_id.0,
        "a relay shipped a flight recording but no --flight-store is configured; dropping it",
    );
}
