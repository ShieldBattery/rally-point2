//! Notice webhooks: the coordinator → tenant leg of the per-game facts relays
//! report — a player departure, a desync, a result, a slot's arrival, a
//! session's start, and a slot's game loop starting.
//!
//! A relay reports a mid-game departure up its control connection
//! ([`rally_point_proto::control::RelayToCoordinator::Departure`]); the api layer
//! hands each notice here. Every relay serving the session reports the same
//! departure independently (redundancy against any one relay's coordinator link
//! being down), so the first thing this module does is **dedup** by
//! `(tenant, session, slot)`. On the first sight it resolves the correlation
//! ids — preferring whatever the relay itself stamped into the notice (from the
//! coordinator descriptor it applied), falling back per-field to this
//! coordinator's own in-memory session-refs store — and the tenant's notify
//! config, then POSTs a webhook to the tenant, retrying with capped backoff.
//! Preferring the notice-carried refs is what makes a departure webhook survive
//! a coordinator restart: the in-memory session-refs store is wiped, but a
//! relay's already-applied descriptor is not.
//!
//! The webhook is an *optimization feed*, not a correctness signal: the consumer
//! (the app server) already holds a game's terminal result once it is decided and
//! ignores a departure for a game+player it has a result for, so a webhook that
//! is never delivered simply degrades to the consumer's result-based behavior.
//! That is why give-up-after-retries is acceptable, and why delivery is
//! at-least-once (a coordinator restart forgets the dedup set; the consumer is
//! idempotent).
//!
//! # Authentication — signed, not shared-secret
//!
//! Each POST carries `x-rp2-timestamp` (unix epoch milliseconds, decimal) and
//! `x-rp2-signature` (standard base64 of a 64-byte Ed25519 signature), signed
//! with the tenant's own signing key — the same key `tenant::mint_token`
//! already uses, not a second secret to provision and rotate. The signed
//! message is `rp2-webhook-v1:` + the timestamp string + `:` + the exact body
//! bytes; the `rp2-webhook-v1:` prefix domain-separates it from a player-token
//! signature made by the same key. Signing happens fresh on every delivery
//! attempt (not once, cached) because the timestamp must be current — the
//! consumer enforces a bounded replay window on it, so a retry with a stale
//! timestamp would be rejected before the consumer even reaches its own
//! dedup/idempotency check.
//!
//! # File map
//!
//! - `payloads` — the `*Webhook` JSON body shapes and the `sessionClosed`
//!   dispatch builder.
//! - `handlers` — one `handle_*` function per notice kind: dedup, correlation-id
//!   resolution, body construction, enqueue.
//! - `dispatch` — the signed-POST retry/backoff delivery loop shared by every
//!   notice kind.
//!
//! This file keeps what all three share: the dedup sets, the desync marks, the
//! process-wide webhook client + concurrency gate, and `resolve_notice_prefix`
//! (the tenant-config + gameId resolution every handler starts with).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use parking_lot::Mutex;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};

use crate::session::{self, SessionRefs, SessionSetup};
use crate::tenant::{self, NotifyConfig};

mod dispatch;
mod handlers;
mod payloads;

pub(crate) use dispatch::dispatch;
pub use handlers::{
    handle_departure, handle_desync, handle_result, handle_session_started, handle_slot_connected,
    handle_slot_started,
};
pub(crate) use payloads::session_closed_dispatch;

// Brought into this module's own namespace so `handlers` can build the
// `*Webhook` bodies via `use super::*;` without knowing they actually live in
// the `payloads` submodule (see `payloads` for why they're `pub(super)`
// rather than private there).
use payloads::{
    DepartureWebhook, DesyncWebhook, DivergedSlotWebhook, ResultEchoWebhook, ResultWebhook,
    SessionStartedWebhook, SlotConnectedWebhook, SlotStartedWebhook,
};
// Test-only: not needed by `handlers`/`dispatch` themselves (each already has
// direct access to its own module's items), only by `notify::tests`' `use
// super::*;` picking them up the same way it would if this were still one
// file — see `dispatch` for why each is `pub(super)` rather than private
// there.
#[cfg(test)]
use dispatch::{
    AttemptError, SIGNATURE_HEADER, TIMESTAMP_HEADER, WEBHOOK_SIG_DOMAIN, send_attempt,
};

/// Departures already handled, keyed by `(tenant, session, slot)`. Shared across
/// every relay control connection so the redundant reports of one leave collapse
/// to a single webhook. In-memory only: a coordinator restart forgets it, which
/// at worst re-fires a webhook the idempotent consumer discards.
pub type DepartureDedup = Arc<Mutex<HashSet<(TenantId, SessionId, SlotId)>>>;

/// Desyncs already handled, keyed by `(tenant, session, sync_ordinal)` — the
/// sibling of [`DepartureDedup`]. The sync ordinal is the event identity (a
/// re-detection after an authority promotion lands at a distinct later ordinal),
/// so it dedups the at-least-once redeliveries of one event without collapsing
/// two genuinely separate divergences.
pub type DesyncDedup = Arc<Mutex<HashSet<(TenantId, SessionId, u64)>>>;

/// Results already handled, keyed by `(tenant, session, slot)` — one report per
/// slot, the sibling of [`DepartureDedup`] with the same key shape (a slot
/// reports at most one result). Collapses the at-least-once redeliveries of one
/// report to a single webhook.
pub type ResultDedup = Arc<Mutex<HashSet<(TenantId, SessionId, SlotId)>>>;

/// Slot arrivals already notified, keyed by `(tenant, session, slot)` — the
/// sibling of [`DepartureDedup`] with the same key shape. A relay reports a slot
/// connected on *every* activation (reconnects included) so the coordinator's
/// ever-connected set follows the truth; this set is what keeps the tenant
/// notification to the first arrival per slot.
pub type SlotConnectedDedup = Arc<Mutex<HashSet<(TenantId, SessionId, SlotId)>>>;

/// Session starts already notified, keyed by `(tenant, session)` — one start per
/// session. Only the authority relay reports the latch, so this collapses
/// at-least-once redeliveries (and a second authority's report after a
/// promotion), not per-relay redundancy.
pub type SessionStartedDedup = Arc<Mutex<HashSet<(TenantId, SessionId)>>>;

/// Game-loop starts already notified, keyed by `(tenant, session, slot)` — one
/// report per slot, the same key shape as [`ResultDedup`].
pub type SlotStartedDedup = Arc<Mutex<HashSet<(TenantId, SessionId, SlotId)>>>;

/// Sessions the coordinator has seen a desync for, keyed by `(tenant, session)` and
/// stamped with when the mark was made. The flight-recorder sink reads this to pin a
/// recording's retention class even when the desync webhook was ultimately dropped
/// (no notify config, no gameId) or the shipping relay's own desync flag was lost to
/// a restart — the desync FACT is what selects the retention class, independent of
/// whether a webhook was delivered. Marks live beside the dedup sets, and
/// [`handle_desync`] inserts one on every desync it sees.
pub type DesyncMarks = Arc<Mutex<HashMap<(TenantId, SessionId), Instant>>>;

/// How long a desync mark is honored before it is pruned. Generous because a desync
/// is rare and a session's flight blobs arrive within minutes of its close, but the
/// window is deliberately **not** tied to session retirement: a blob's arrival and
/// the session-close bookkeeping travel two separate channels, so a blob can reach
/// the coordinator after the session's other state has already been retired, and the
/// mark must still be here to pin it.
pub const DESYNC_MARK_TTL: Duration = Duration::from_secs(60 * 60);

/// The notice dedup sets a coordinator holds, bundled so the api layer
/// threads one value rather than several through its control-connection handlers.
#[derive(Clone)]
pub struct NoticeDedup {
    /// Departure dedup by `(tenant, session, slot)`.
    pub departures: DepartureDedup,
    /// Desync dedup by `(tenant, session, sync_ordinal)`.
    pub desyncs: DesyncDedup,
    /// Result dedup by `(tenant, session, slot)`.
    pub results: ResultDedup,
    /// Slot-arrival dedup by `(tenant, session, slot)`.
    pub slot_connects: SlotConnectedDedup,
    /// Session-start dedup by `(tenant, session)`.
    pub session_starts: SessionStartedDedup,
    /// Game-loop-start dedup by `(tenant, session, slot)`.
    pub slot_starts: SlotStartedDedup,
    /// Desynced-session marks the flight-recorder sink reads to pin a recording's
    /// retention class. Not a dedup set — one mark per `(tenant, session)`, refreshed
    /// on every desync and pruned by [`DESYNC_MARK_TTL`], never by session retirement.
    pub desync_marks: DesyncMarks,
}

/// Creates an empty notice dedup set (departures + desyncs + results + slot
/// arrivals + session starts + game-loop starts + desync marks).
pub fn new_dedup() -> NoticeDedup {
    NoticeDedup {
        departures: Arc::new(Mutex::new(HashSet::new())),
        desyncs: Arc::new(Mutex::new(HashSet::new())),
        results: Arc::new(Mutex::new(HashSet::new())),
        slot_connects: Arc::new(Mutex::new(HashSet::new())),
        session_starts: Arc::new(Mutex::new(HashSet::new())),
        slot_starts: Arc::new(Mutex::new(HashSet::new())),
        desync_marks: Arc::new(Mutex::new(HashMap::new())),
    }
}

/// Records that `(tenant, session)` desynced, stamped `now`, opportunistically
/// pruning any mark older than [`DESYNC_MARK_TTL`] first. Idempotent: a repeated
/// desync for the same session simply refreshes its stamp.
pub fn mark_session_desynced(
    marks: &DesyncMarks,
    tenant: TenantId,
    session: SessionId,
    now: Instant,
) {
    let mut guard = marks.lock();
    guard.retain(|_, marked_at| now.saturating_duration_since(*marked_at) < DESYNC_MARK_TTL);
    guard.insert((tenant, session), now);
}

/// Whether `(tenant, session)` carries a live (un-expired) desync mark, pruning any
/// mark older than [`DESYNC_MARK_TTL`] as it checks — so an expired mark reads as
/// absent and is dropped in the same pass.
pub fn is_session_desynced(
    marks: &DesyncMarks,
    tenant: &TenantId,
    session: SessionId,
    now: Instant,
) -> bool {
    let mut guard = marks.lock();
    guard.retain(|_, marked_at| now.saturating_duration_since(*marked_at) < DESYNC_MARK_TTL);
    guard.contains_key(&(tenant.clone(), session))
}

impl NoticeDedup {
    /// Drops every dedup entry for one `(tenant, session)`, called when the
    /// session's lifecycle state is removed — the point the coordinator declares
    /// it is done with the session. Without this the sets are insert-only and
    /// grow for the process lifetime (a few tuples per session that ever ran).
    ///
    /// Pruning at removal means a late or replayed notice arriving *after* the
    /// session was reaped is no longer recognized as a duplicate, so it would
    /// re-deliver its webhook. That is acceptable: delivery is at-least-once by
    /// design and the consumer is idempotent, and removal only happens well after
    /// a session's activity has quiesced.
    pub fn prune_session(&self, tenant: &TenantId, session: SessionId) {
        let matches = |t: &TenantId, s: SessionId| t == tenant && s == session;
        self.departures.lock().retain(|(t, s, _)| !matches(t, *s));
        self.desyncs.lock().retain(|(t, s, _)| !matches(t, *s));
        self.results.lock().retain(|(t, s, _)| !matches(t, *s));
        self.slot_connects
            .lock()
            .retain(|(t, s, _)| !matches(t, *s));
        self.session_starts.lock().retain(|(t, s)| !matches(t, *s));
        self.slot_starts.lock().retain(|(t, s, _)| !matches(t, *s));
    }
}

/// How many webhook attempts before giving up. With [`BACKOFF_START`] doubling to
/// [`BACKOFF_CAP`], six attempts span roughly a minute of retries.
const MAX_ATTEMPTS: u32 = 6;
/// The first retry backoff; doubles each attempt up to [`BACKOFF_CAP`].
const BACKOFF_START: Duration = Duration::from_secs(2);
/// The retry-backoff ceiling.
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// How long one whole webhook attempt — connect through the full body read —
/// is allowed to run before it counts as failed. `drain_queue` delivers one
/// job at a time per `(tenant, session)` queue, so an endpoint that accepts
/// the connection but never finishes responding would otherwise hang the
/// attempt forever — parking that session's whole queue (every later notice,
/// including `sessionClosed`) behind it permanently, since neither
/// [`MAX_ATTEMPTS`] nor the backoff ever gets a chance to run. Spans the
/// entire attempt, not just the headers: a slow-body endpoint (headers arrive
/// promptly, then the response trickles or never finishes) is exactly as
/// capable of hanging the queue as one that never responds at all, so the
/// timeout has to cover both. A timeout here is treated exactly like a
/// transport error or a non-2xx response: it counts as one failed attempt and
/// feeds the same retry/backoff path.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest response body one webhook attempt will read before giving up on
/// it. The coordinator never looks at the response body — only the status
/// matters — so this exists purely to bound memory against an endpoint that
/// streams an unbounded (or just very large) body: [`http_body_util::Limited`]
/// stops accumulating past this many bytes rather than buffering an unbounded
/// stream to completion. A generous cap well past any sane webhook receiver's
/// real response (typically empty or a few bytes of JSON); hitting it is
/// treated exactly like a timeout — one failed attempt, retried.
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;

/// A hyper client built once and shared by every dispatch, rather than
/// constructed fresh per delivery. hyper/hyper-util clients pool connections
/// and are cheap to share (an internal `Arc`), so reusing one avoids a fresh
/// TCP+TLS handshake — and a re-parse of the webpki root store — for every
/// notice, including repeated ones to the same tenant endpoint.
///
/// The connector negotiates rustls (ring provider, webpki public-CA roots) for
/// an `https://` notify URL and falls through to plain HTTP for `http://` (the
/// dev/loopback flow). Webpki roots are sufficient because the prod app server
/// sits behind an HTTPS reverse proxy with a publicly-trusted certificate, not
/// a private/internal CA — no custom root store to provision.
static WEBHOOK_CLIENT: LazyLock<Client<HttpsConnector<HttpConnector>, Full<Bytes>>> =
    LazyLock::new(|| {
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        Client::builder(TokioExecutor::new()).build(https)
    });

/// The most webhook dispatch attempts allowed in flight across the whole
/// coordinator process at once. Each session's own queue already serializes
/// its own notices ([`crate::lifecycle`]'s `drain_queue`, one job at a time),
/// but nothing previously bounded how many *different* sessions' queues could
/// all be mid-attempt simultaneously — a fleet-wide burst of session churn
/// (or a fleet-wide slow tenant endpoint) could otherwise hold one open
/// connection per in-flight session with no ceiling, compounding exactly the
/// kind of unbounded-body and unbounded-hang risk [`MAX_RESPONSE_BODY_BYTES`]
/// and [`ATTEMPT_TIMEOUT`] bound per attempt. Fleet-wide, not per-tenant: a
/// slow or malicious tenant endpoint only ever occupies its own share of this
/// pool, and every other tenant's dispatches keep moving through the rest.
const MAX_CONCURRENT_DISPATCHES: usize = 32;

/// The process-wide gate [`MAX_CONCURRENT_DISPATCHES`] enforces. A `const`
/// initializer needs no lazy setup, unlike [`WEBHOOK_CLIENT`].
static DISPATCH_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_DISPATCHES);

/// The shared prefix behind every notice handler: tenant notify-config lookup,
/// then gameId resolution (notice-carried first, falling back to the stored
/// session). The dedup check is the caller's job, not this helper's — each
/// notice kind dedups on a differently-shaped key (a `(tenant, session, slot)`
/// triple for departures/results, `(tenant, session, sync_ordinal)` for
/// desyncs), so the caller inserts into its own dedup set and passes the
/// result in as `is_new` rather than this helper trying to generalize over
/// shapes it can't share.
///
/// The three ways a notice goes no further (a duplicate, no notify config, no
/// gameId from either source) are each a case the caller debug-logs with its
/// own event-specific fields (a departure/result logs `slot`, a desync logs
/// `sync_ordinal`) and message text — that logging stays with the caller so
/// the fields correlate on the id that actually applies to the event, rather
/// than this helper flattening them to a lowest common denominator.
enum NoticePrefix {
    /// The dedup key was already present.
    Duplicate,
    /// The tenant has no notify config — nothing to POST to.
    NoNotifyConfig,
    /// Neither the notice nor a stored session named a gameId — a webhook
    /// naming no game is useless to the consumer.
    NoExternalId,
    /// Resolved: the tenant's notify config, the gameId to embed, and the
    /// stored session (if any) for whatever further per-slot/ref resolution
    /// the caller's own notice kind still needs.
    Resolved {
        config: NotifyConfig,
        external_id: String,
        /// Boxed: `SessionRefs` grew a per-relay cert map alongside its other
        /// per-session state, which otherwise makes this the far larger of
        /// [`NoticePrefix`]'s variants and bloats every value of the enum to
        /// that size regardless of which variant it holds.
        stored: Box<Option<SessionRefs>>,
    },
}

fn resolve_notice_prefix(
    setup: &SessionSetup,
    tenant: &TenantId,
    session: SessionId,
    notice_external_id: Option<String>,
    is_new: bool,
) -> NoticePrefix {
    if !is_new {
        return NoticePrefix::Duplicate;
    }

    let Some(config) = tenant::notify_config(setup.tenants(), tenant) else {
        return NoticePrefix::NoNotifyConfig;
    };

    let stored = session::session_refs(setup, tenant, session);
    let external_id =
        notice_external_id.or_else(|| stored.as_ref().and_then(|refs| refs.external_id.clone()));

    let Some(external_id) = external_id else {
        return NoticePrefix::NoExternalId;
    };

    NoticePrefix::Resolved {
        config,
        external_id,
        stored: Box::new(stored),
    }
}

#[cfg(test)]
mod tests;
