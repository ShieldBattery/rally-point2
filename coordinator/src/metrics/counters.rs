//! The metric statics and the one-line recorders every event site increments
//! them through.
//!
//! The leaf of the metrics module: nothing here reads the coordinator's state,
//! so any module may call a recorder without acquiring a dependency on the
//! composed `CoordinatorState` the exposition is rendered from. The values live
//! in module-level statics precisely so a call site is one line and no handle
//! has to be threaded through the call graph.
//!
//! Label values are drawn only from bounded sets — region ids, tenant ids, and
//! fixed state/result/reason words — so a counter's cardinality stays bounded by
//! the fleet and tenant count rather than growing without limit.

use std::sync::atomic::{AtomicU64, Ordering};

use rally_point_proto::control::{RegionId, TenantId};

use super::instruments::{ColdStartHistogram, LabeledCounter, SendDurationHistogram};

/// The label value for an optional region: the region id, or `none` for an
/// untagged relay. Shared by the recorders here and by the scrape-time census,
/// so a relay with no region reads the same in both.
pub(super) fn region_label(region: Option<&RegionId>) -> String {
    region.map_or_else(|| "none".to_owned(), |r| r.as_ref().to_owned())
}

// ---------------------------------------------------------------------------
// The metric statics
// ---------------------------------------------------------------------------

pub(super) static RELAY_ENROLLS: LabeledCounter<String> = LabeledCounter::new();
pub(super) static RELAY_LAUNCHES: LabeledCounter<String> = LabeledCounter::new();
pub(super) static RELAY_LAUNCH_FAILURES: LabeledCounter<String> = LabeledCounter::new();
pub(super) static RELAY_REAPED: LabeledCounter<(String, String)> = LabeledCounter::new();
pub(super) static RELAY_DRAINS: LabeledCounter<String> = LabeledCounter::new();
pub(super) static SESSIONS_CREATED: LabeledCounter<String> = LabeledCounter::new();
pub(super) static SESSION_HOLDS: LabeledCounter<String> = LabeledCounter::new();
pub(super) static SESSIONS_CLOSED: LabeledCounter<String> = LabeledCounter::new();
pub(super) static SESSION_REAPS: LabeledCounter<(String, String)> = LabeledCounter::new();
pub(super) static DESYNCS: LabeledCounter<String> = LabeledCounter::new();
pub(super) static WEBHOOK_DELIVERIES: LabeledCounter<(String, String)> = LabeledCounter::new();
pub(super) static WEBHOOK_ATTEMPT_FAILURES: LabeledCounter<String> = LabeledCounter::new();
pub(super) static FLIGHT_RECORDINGS: LabeledCounter<String> = LabeledCounter::new();
pub(super) static FLIGHT_RECORDINGS_PINNED: AtomicU64 = AtomicU64::new(0);
pub(super) static RELAY_COLD_START: ColdStartHistogram = ColdStartHistogram::new();
pub(super) static REAP_DIRECTIVES_SENT: AtomicU64 = AtomicU64::new(0);
pub(super) static REAP_NUDGES_COALESCED: AtomicU64 = AtomicU64::new(0);
pub(super) static CONTROL_SEND_DURATION: SendDurationHistogram = SendDurationHistogram::new();
pub(super) static CONTROL_CONNECTION_ENDS: LabeledCounter<String> = LabeledCounter::new();
pub(super) static DESCRIPTOR_DELTAS_SENT: AtomicU64 = AtomicU64::new(0);
pub(super) static DESCRIPTOR_FULL_SETS_SENT: AtomicU64 = AtomicU64::new(0);
pub(super) static DESCRIPTOR_DELTA_ENTRIES_SENT: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Increment functions — one line at each event site
// ---------------------------------------------------------------------------

/// Records a relay control-connection enrollment (first enroll or reconnect).
pub(crate) fn relay_enrolled(region: Option<&RegionId>) {
    RELAY_ENROLLS.incr(region_label(region));
}

/// Records a relay launch task issued by the provisioning loop.
pub(crate) fn relay_launched(region: &RegionId) {
    RELAY_LAUNCHES.incr(region.as_ref().to_owned());
}

/// Records a relay launch that failed to mint an id or start a task.
pub(crate) fn relay_launch_failed(region: &RegionId) {
    RELAY_LAUNCH_FAILURES.incr(region.as_ref().to_owned());
}

/// Records a relay retired by a reconcile sweep. `reason` is one of the fixed
/// words `launch_deadline`, `vanished`, or `orphan`.
pub(crate) fn relay_reaped(region: Option<&RegionId>, reason: &str) {
    RELAY_REAPED.incr((region_label(region), reason.to_owned()));
}

/// Records a drain the coordinator honored. Counted where the relay's `Draining`
/// announcement is marked — the one point every drain passes through exactly
/// once, whether the relay initiated it or a scale-down task-stop prompted it.
pub(crate) fn relay_drained(region: Option<&RegionId>) {
    RELAY_DRAINS.incr(region_label(region));
}

/// Records a freshly minted session (not an idempotent replay).
pub(crate) fn session_created(tenant: &TenantId) {
    SESSIONS_CREATED.incr(tenant.as_ref().to_owned());
}

/// Records a session create answered with a `202` provisioning hold.
pub(crate) fn session_held(tenant: &TenantId) {
    SESSION_HOLDS.incr(tenant.as_ref().to_owned());
}

/// Records a session that has fully closed (every serving relay reported closed).
pub(crate) fn session_closed(tenant: &TenantId) {
    SESSIONS_CLOSED.incr(tenant.as_ref().to_owned());
}

/// Records a coordinator backstop that retired a session. `reason` is a fixed,
/// low-cardinality policy name such as `heartbeat_empty` or `never_started`.
pub(crate) fn session_reaped(tenant: &TenantId, reason: &str) {
    SESSION_REAPS.incr((tenant.as_ref().to_owned(), reason.to_owned()));
}

/// Records a distinct desync event (an at-least-once redelivery of the same
/// notice is not re-counted).
pub(crate) fn desync(tenant: &TenantId) {
    DESYNCS.incr(tenant.as_ref().to_owned());
}

/// Records a terminal webhook delivery outcome. `result` is `ok` or `gave_up`.
pub(crate) fn webhook_delivered(tenant: &TenantId, result: &str) {
    WEBHOOK_DELIVERIES.incr((tenant.as_ref().to_owned(), result.to_owned()));
}

/// Records a single failed webhook delivery attempt (retried or, if terminal,
/// followed by a `gave_up` delivery outcome).
pub(crate) fn webhook_attempt_failed(tenant: &TenantId) {
    WEBHOOK_ATTEMPT_FAILURES.incr(tenant.as_ref().to_owned());
}

/// Records a flight recording stored successfully.
pub(crate) fn flight_recording_stored() {
    FLIGHT_RECORDINGS.incr("stored".to_owned());
}

/// Records a flight recording deliberately refused before storage (bad tenant,
/// oversize payload, or the upload concurrency gate was saturated).
pub(crate) fn flight_recording_refused() {
    FLIGHT_RECORDINGS.incr("refused".to_owned());
}

/// Records a flight recording lost (no store configured, or a store write failed).
pub(crate) fn flight_recording_lost() {
    FLIGHT_RECORDINGS.incr("lost".to_owned());
}

/// Records a stored flight recording that landed under the desync-pinned prefix.
pub(crate) fn flight_recording_pinned() {
    FLIGHT_RECORDINGS_PINNED.fetch_add(1, Ordering::Relaxed);
}

/// Observes a relay's cold-start duration (launch to first enroll), in seconds.
pub(crate) fn observe_relay_cold_start(seconds: u64) {
    RELAY_COLD_START.observe(seconds);
}

/// Records `count` slot-close directives written down relay control connections.
pub(crate) fn reap_directives_sent(count: u64) {
    REAP_DIRECTIVES_SENT.fetch_add(count, Ordering::Relaxed);
}

/// Records `count` queued slot-close nudges that collapsed into an already-pending
/// directive for the same session before a single frame was written for it.
pub(crate) fn reap_nudges_coalesced(count: u64) {
    REAP_NUDGES_COALESCED.fetch_add(count, Ordering::Relaxed);
}

/// Observes one control-connection frame send's duration, in whole milliseconds.
pub(crate) fn observe_control_send(millis: u64) {
    CONTROL_SEND_DURATION.observe(millis);
}

/// Records a control connection ended by `cause` — `write_stall` (a send could not
/// complete within the liveness window) or `liveness_lapse` (the relay sent nothing
/// within the liveness window).
pub(crate) fn control_connection_ended(cause: &str) {
    CONTROL_CONNECTION_ENDS.incr(cause.to_owned());
}

/// Records one steady-state descriptor delta written down a relay control
/// connection: a single frame carrying `upserts` descriptors to apply and
/// `removals` sessions to leave. Bumps the delta-frame count by one and the
/// delta-entry count by their sum, so a pathological diff (a frame carrying nearly
/// the whole set) shows as a high entries-per-frame ratio.
pub(crate) fn descriptor_delta_sent(upserts: usize, removals: usize) {
    DESCRIPTOR_DELTAS_SENT.fetch_add(1, Ordering::Relaxed);
    DESCRIPTOR_DELTA_ENTRIES_SENT.fetch_add((upserts + removals) as u64, Ordering::Relaxed);
}

/// Records one steady-state full descriptor set written down a relay control
/// connection — the fallback for a relay whose negotiated version predates deltas.
/// Counted only on the steady-state change arm, never for the connect-time re-sync
/// or the drain exchange (both of which always send the full set regardless of
/// version), so the delta-vs-full ratio reflects steady-state pushes alone.
pub(crate) fn descriptor_full_set_sent() {
    DESCRIPTOR_FULL_SETS_SENT.fetch_add(1, Ordering::Relaxed);
}
