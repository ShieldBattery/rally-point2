//! Prometheus text-exposition metrics for the coordinator.
//!
//! A hand-rolled exporter: the coordinator already holds every value a scrape
//! wants as shared, `Arc`-backed state, so a scrape reads point-in-time
//! snapshots of that state and formats them directly, with no metrics-facade
//! crate and no background sampling tick. Two shapes of series live here:
//!
//! - **Gauges** are computed at scrape time from the coordinator's live state
//!   (the relay registry, the tenant store, the lifecycle map, warm demand, the
//!   backbone-RTT table). Nothing is stored between scrapes.
//! - **Counters and the cold-start histogram** are module-level statics that the
//!   event sites increment through the `pub(crate)` functions here, so a call
//!   site is one line and no handle has to be threaded through the call graph.
//!
//! The exposition is deterministic: every series family emits its `# HELP` and
//! `# TYPE` lines, series within a family are sorted, and label values are
//! escaped, so the output is stable enough to assert against in tests.
//!
//! # Label hygiene
//!
//! Label values are drawn only from bounded sets — region ids, tenant ids, and
//! fixed state/result/reason words. Per-relay, per-session, and per-task
//! identifiers are never labels, so a counter's cardinality stays bounded by the
//! fleet and tenant count rather than growing without limit.

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router, extract::State, http::header::CONTENT_TYPE, response::IntoResponse, routing::get,
};
use parking_lot::Mutex;
use rally_point_proto::control::{RegionId, TenantId};

use crate::api::CoordinatorState;
use crate::{lifecycle, registry, tenant};

/// The content type a Prometheus scrape expects for the version 0.0.4 text
/// exposition format.
const EXPOSITION_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Builds the plaintext metrics router: a single `GET /metrics` route over the
/// coordinator's shared state. Deliberately separate from the primary API router
/// so it can be bound on its own listener with no TLS and no peer-address
/// connect-info — it is reached only over the box's private sidecar, never
/// published.
pub fn router(state: CoordinatorState) -> Router {
    Router::new()
        .route("/metrics", get(serve_metrics))
        .with_state(state)
}

/// Renders the current metrics snapshot as the Prometheus text exposition.
async fn serve_metrics(State(state): State<CoordinatorState>) -> impl IntoResponse {
    ([(CONTENT_TYPE, EXPOSITION_CONTENT_TYPE)], render(&state))
}

// ---------------------------------------------------------------------------
// Counter primitives
// ---------------------------------------------------------------------------

/// A monotonic counter split by a small, bounded set of label-value tuples.
///
/// Every increment is a low-frequency control-plane event, so a single mutex
/// around a map keyed by the label tuple is ample — no need for a per-key
/// atomic. The map is created on first use behind a `OnceLock`, so the counter
/// itself is a `const`-constructible static.
struct LabeledCounter<K> {
    values: OnceLock<Mutex<HashMap<K, u64>>>,
}

impl<K> LabeledCounter<K>
where
    K: Eq + std::hash::Hash + Clone + Ord,
{
    const fn new() -> Self {
        Self {
            values: OnceLock::new(),
        }
    }

    fn map(&self) -> &Mutex<HashMap<K, u64>> {
        self.values.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn incr(&self, key: K) {
        *self.map().lock().entry(key).or_insert(0) += 1;
    }

    /// The counter's current values, sorted by label tuple so the exposition
    /// order is deterministic.
    fn sorted(&self) -> Vec<(K, u64)> {
        let mut rows: Vec<(K, u64)> = self
            .map()
            .lock()
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect();
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        rows
    }
}

/// The number of finite cold-start buckets; the exposition adds one more for
/// the `+Inf` overflow bucket.
const COLD_START_BUCKET_BOUNDS: [u64; 9] = [5, 10, 15, 20, 30, 45, 60, 90, 120];

/// A fixed-bucket histogram for relay cold-start durations. Bucket counts are
/// stored non-cumulatively and cumulated at render, so `observe` is a single
/// atomic add to one bucket plus the sum and count.
struct ColdStartHistogram {
    /// One non-cumulative count per finite bound, plus a trailing `+Inf` bucket.
    buckets: [AtomicU64; COLD_START_BUCKET_BOUNDS.len() + 1],
    /// The sum of all observed values, in whole seconds.
    sum: AtomicU64,
    /// The total number of observations.
    count: AtomicU64,
}

impl ColdStartHistogram {
    const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; COLD_START_BUCKET_BOUNDS.len() + 1],
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, seconds: u64) {
        let idx = COLD_START_BUCKET_BOUNDS
            .iter()
            .position(|&bound| seconds <= bound)
            .unwrap_or(COLD_START_BUCKET_BOUNDS.len());
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(seconds, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, name: &str) {
        write_meta(
            out,
            name,
            "Seconds from a provisioned relay's launch to its first enroll.",
            "histogram",
        );
        let bucket_name = format!("{name}_bucket");
        let mut cumulative = 0u64;
        for (idx, bound) in COLD_START_BUCKET_BOUNDS.iter().enumerate() {
            cumulative += self.buckets[idx].load(Ordering::Relaxed);
            let le = bound.to_string();
            write_series(out, &bucket_name, &[("le", le.as_str())], cumulative);
        }
        cumulative += self.buckets[COLD_START_BUCKET_BOUNDS.len()].load(Ordering::Relaxed);
        write_series(out, &bucket_name, &[("le", "+Inf")], cumulative);
        write_series(
            out,
            &format!("{name}_sum"),
            &[],
            self.sum.load(Ordering::Relaxed),
        );
        write_series(out, &format!("{name}_count"), &[], cumulative);
    }
}

// ---------------------------------------------------------------------------
// The metric statics
// ---------------------------------------------------------------------------

static RELAY_ENROLLS: LabeledCounter<String> = LabeledCounter::new();
static RELAY_LAUNCHES: LabeledCounter<String> = LabeledCounter::new();
static RELAY_LAUNCH_FAILURES: LabeledCounter<String> = LabeledCounter::new();
static RELAY_REAPED: LabeledCounter<(String, String)> = LabeledCounter::new();
static RELAY_DRAINS: LabeledCounter<String> = LabeledCounter::new();
static SESSIONS_CREATED: LabeledCounter<String> = LabeledCounter::new();
static SESSION_HOLDS: LabeledCounter<String> = LabeledCounter::new();
static SESSIONS_CLOSED: LabeledCounter<String> = LabeledCounter::new();
static DESYNCS: LabeledCounter<String> = LabeledCounter::new();
static WEBHOOK_DELIVERIES: LabeledCounter<(String, String)> = LabeledCounter::new();
static WEBHOOK_ATTEMPT_FAILURES: LabeledCounter<String> = LabeledCounter::new();
static FLIGHT_RECORDINGS: LabeledCounter<String> = LabeledCounter::new();
static FLIGHT_RECORDINGS_PINNED: AtomicU64 = AtomicU64::new(0);
static RELAY_COLD_START: ColdStartHistogram = ColdStartHistogram::new();

/// Whether the coverage bootstrap is currently backing off each region, published
/// by the reconcile loop as its coverage phase changes (the phase is otherwise
/// loop-local). A region absent from the map is not backing off.
static BEACON_BACKOFF: OnceLock<Mutex<HashMap<RegionId, bool>>> = OnceLock::new();

fn beacon_backoff_map() -> &'static Mutex<HashMap<RegionId, bool>> {
    BEACON_BACKOFF.get_or_init(|| Mutex::new(HashMap::new()))
}

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

/// Publishes whether the coverage bootstrap is backing off `region`, so the
/// `rp2_beacon_backoff` gauge can read the loop-local coverage phase.
pub(crate) fn set_beacon_backoff(region: &RegionId, backing_off: bool) {
    beacon_backoff_map()
        .lock()
        .insert(region.clone(), backing_off);
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Renders the full metrics exposition for `state`.
pub fn render(state: &CoordinatorState) -> String {
    let now = unix_now();
    let census = state.lifecycle.metrics_census();
    let mut out = String::new();

    write_meta(
        &mut out,
        "rp2_build_info",
        "Coordinator build information; the value is always 1.",
        "gauge",
    );
    write_series(
        &mut out,
        "rp2_build_info",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1,
    );

    render_relays(&mut out, state, now);
    render_sessions_active(&mut out, &census);
    render_warm_target(&mut out, state);
    render_backbone_rtt(&mut out, state);
    render_beacon_backoff(&mut out, state);
    render_notices_pending(&mut out, &census);

    write_meta(
        &mut out,
        "rp2_flight_store_configured",
        "Whether a flight-recording durable sink is configured (1) or not (0).",
        "gauge",
    );
    write_series(
        &mut out,
        "rp2_flight_store_configured",
        &[],
        u64::from(state.flight_store.is_some()),
    );

    render_tenants(&mut out, state);

    render_counter_1(
        &mut out,
        "rp2_relay_enrolls_total",
        "Relay control-connection enrollments accepted, by region.",
        &RELAY_ENROLLS,
        "region",
    );
    render_counter_1(
        &mut out,
        "rp2_relay_launches_total",
        "Relay launch tasks issued, by region.",
        &RELAY_LAUNCHES,
        "region",
    );
    render_counter_1(
        &mut out,
        "rp2_relay_launch_failures_total",
        "Relay launches that failed to mint an id or start a task, by region.",
        &RELAY_LAUNCH_FAILURES,
        "region",
    );
    render_counter_2(
        &mut out,
        "rp2_relay_reaped_total",
        "Relays retired by a reconcile sweep, by region and reason.",
        &RELAY_REAPED,
        "region",
        "reason",
    );
    render_counter_1(
        &mut out,
        "rp2_relay_drains_total",
        "Relay drains honored by the coordinator, by region.",
        &RELAY_DRAINS,
        "region",
    );
    render_counter_1(
        &mut out,
        "rp2_sessions_created_total",
        "Sessions freshly minted, by tenant.",
        &SESSIONS_CREATED,
        "tenant",
    );
    render_counter_1(
        &mut out,
        "rp2_session_holds_total",
        "Session creates answered with a provisioning hold, by tenant.",
        &SESSION_HOLDS,
        "tenant",
    );
    render_counter_1(
        &mut out,
        "rp2_sessions_closed_total",
        "Sessions fully closed, by tenant.",
        &SESSIONS_CLOSED,
        "tenant",
    );
    render_counter_1(
        &mut out,
        "rp2_desyncs_total",
        "Distinct desync events handled, by tenant.",
        &DESYNCS,
        "tenant",
    );
    render_counter_2(
        &mut out,
        "rp2_webhook_deliveries_total",
        "Terminal webhook delivery outcomes, by tenant and result.",
        &WEBHOOK_DELIVERIES,
        "tenant",
        "result",
    );
    render_counter_1(
        &mut out,
        "rp2_webhook_attempt_failures_total",
        "Individual webhook delivery attempts that failed, by tenant.",
        &WEBHOOK_ATTEMPT_FAILURES,
        "tenant",
    );

    write_meta(
        &mut out,
        "rp2_webhook_notices_dropped_total",
        "Non-terminal notices dropped from a full session dispatch queue.",
        "counter",
    );
    write_series(
        &mut out,
        "rp2_webhook_notices_dropped_total",
        &[],
        lifecycle::dropped_notice_count(),
    );

    render_counter_1(
        &mut out,
        "rp2_flight_recordings_total",
        "Flight recordings shipped by relays, by ingest result.",
        &FLIGHT_RECORDINGS,
        "result",
    );

    write_meta(
        &mut out,
        "rp2_flight_recordings_pinned_total",
        "Flight recordings stored under the desync-pinned prefix.",
        "counter",
    );
    write_series(
        &mut out,
        "rp2_flight_recordings_pinned_total",
        &[],
        FLIGHT_RECORDINGS_PINNED.load(Ordering::Relaxed),
    );

    RELAY_COLD_START.render(&mut out, "rp2_relay_cold_start_seconds");

    out
}

fn render_relays(out: &mut String, state: &CoordinatorState, now: u64) {
    let mut counts: BTreeMap<(String, String), u64> = BTreeMap::new();
    for relay in registry::enrolled_relays(state.setup.registry()) {
        let key = (
            region_label(relay.region.as_ref()),
            if relay.draining { "draining" } else { "live" }.to_owned(),
        );
        *counts.entry(key).or_default() += 1;
    }
    // Launching relays live only in the ledger (they have not enrolled yet), so
    // they are counted per configured region there. Skip on an unusable clock, the
    // same guard the ledger's own expiry comparisons use.
    if let Some(ledger) = &state.ledger
        && now != u64::MAX
    {
        for region in state.regions.regions() {
            if let Ok(count) = ledger.count_launching(Some(&region.id), now)
                && count > 0
            {
                counts.insert(
                    (region.id.as_ref().to_owned(), "launching".to_owned()),
                    count as u64,
                );
            }
        }
    }
    write_meta(
        out,
        "rp2_relays",
        "Relays known to the coordinator, by region and lifecycle state.",
        "gauge",
    );
    for ((region, relay_state), value) in &counts {
        write_series(
            out,
            "rp2_relays",
            &[("region", region.as_str()), ("state", relay_state.as_str())],
            *value,
        );
    }
}

fn render_sessions_active(out: &mut String, census: &lifecycle::LifecycleMetrics) {
    write_meta(
        out,
        "rp2_sessions_active",
        "Sessions with an assigned serving relay, by tenant and whether a client has been seen.",
        "gauge",
    );
    let mut rows: Vec<(&TenantId, &lifecycle::SessionCensus)> = census.sessions.iter().collect();
    rows.sort_by(|left, right| left.0.as_ref().cmp(right.0.as_ref()));
    for (tenant, counts) in rows {
        if counts.loading > 0 {
            write_series(
                out,
                "rp2_sessions_active",
                &[("tenant", tenant.as_ref()), ("state", "loading")],
                counts.loading,
            );
        }
        if counts.started > 0 {
            write_series(
                out,
                "rp2_sessions_active",
                &[("tenant", tenant.as_ref()), ("state", "started")],
                counts.started,
            );
        }
    }
}

fn render_warm_target(out: &mut String, state: &CoordinatorState) {
    write_meta(
        out,
        "rp2_warm_target",
        "The relay count each region is currently kept warm for.",
        "gauge",
    );
    let warm = state.setup.provision().warm();
    for region in state.regions.regions() {
        write_series(
            out,
            "rp2_warm_target",
            &[("region", region.id.as_ref())],
            u64::from(warm.target(&region.id)),
        );
    }
}

fn render_backbone_rtt(out: &mut String, state: &CoordinatorState) {
    let mut series: Vec<(String, String, u64)> = state
        .pair_rtts
        .direction_snapshot()
        .into_iter()
        .map(|row| {
            // The origin is one end of the canonical pair; the target is the other.
            let target = if row.origin == row.a { &row.b } else { &row.a };
            (
                row.origin.0.clone(),
                target.0.clone(),
                u64::from(row.rtt_ms),
            )
        })
        .collect();
    series.sort_by(|left, right| {
        (left.0.as_str(), left.1.as_str()).cmp(&(right.0.as_str(), right.1.as_str()))
    });
    write_meta(
        out,
        "rp2_backbone_rtt_ms",
        "Measured backbone round-trip per direction, in milliseconds.",
        "gauge",
    );
    for (origin, target, rtt) in &series {
        write_series(
            out,
            "rp2_backbone_rtt_ms",
            &[("origin", origin.as_str()), ("target", target.as_str())],
            *rtt,
        );
    }
}

fn render_beacon_backoff(out: &mut String, state: &CoordinatorState) {
    let map = beacon_backoff_map().lock();
    write_meta(
        out,
        "rp2_beacon_backoff",
        "1 while the coverage bootstrap is backing off a region, else 0.",
        "gauge",
    );
    for region in state.regions.regions() {
        let backing_off = map.get(&region.id).copied().unwrap_or(false);
        write_series(
            out,
            "rp2_beacon_backoff",
            &[("region", region.id.as_ref())],
            u64::from(backing_off),
        );
    }
}

fn render_notices_pending(out: &mut String, census: &lifecycle::LifecycleMetrics) {
    write_meta(
        out,
        "rp2_webhook_notices_pending",
        "Pending (unsent) webhook notices across a tenant's session dispatch queues.",
        "gauge",
    );
    let mut rows: Vec<(&TenantId, &u64)> = census.notices_pending.iter().collect();
    rows.sort_by(|left, right| left.0.as_ref().cmp(right.0.as_ref()));
    for (tenant, depth) in rows {
        write_series(
            out,
            "rp2_webhook_notices_pending",
            &[("tenant", tenant.as_ref())],
            *depth,
        );
    }
}

fn render_tenants(out: &mut String, state: &CoordinatorState) {
    let counts = tenant::state_counts(state.setup.tenants());
    write_meta(
        out,
        "rp2_tenants",
        "Enrolled tenants, by operational state.",
        "gauge",
    );
    // Alphabetical by state value, for a deterministic order.
    write_series(out, "rp2_tenants", &[("state", "active")], counts.active);
    write_series(out, "rp2_tenants", &[("state", "revoked")], counts.revoked);
    write_series(
        out,
        "rp2_tenants",
        &[("state", "suspended")],
        counts.suspended,
    );
}

fn render_counter_1(
    out: &mut String,
    name: &str,
    help: &str,
    counter: &LabeledCounter<String>,
    label: &str,
) {
    write_meta(out, name, help, "counter");
    for (key, value) in counter.sorted() {
        write_series(out, name, &[(label, key.as_str())], value);
    }
}

fn render_counter_2(
    out: &mut String,
    name: &str,
    help: &str,
    counter: &LabeledCounter<(String, String)>,
    label_a: &str,
    label_b: &str,
) {
    write_meta(out, name, help, "counter");
    for ((first, second), value) in counter.sorted() {
        write_series(
            out,
            name,
            &[(label_a, first.as_str()), (label_b, second.as_str())],
            value,
        );
    }
}

// ---------------------------------------------------------------------------
// Text-format helpers
// ---------------------------------------------------------------------------

/// The label value for an optional region: the region id, or `none` for an
/// untagged relay.
fn region_label(region: Option<&RegionId>) -> String {
    region.map_or_else(|| "none".to_owned(), |r| r.as_ref().to_owned())
}

/// Writes a metric family's `# HELP` and `# TYPE` header lines.
fn write_meta(out: &mut String, name: &str, help: &str, kind: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
}

/// Writes one sample line: `name{label="value",...} value`.
fn write_series(out: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
    out.push_str(name);
    for (index, (key, val)) in labels.iter().enumerate() {
        out.push(if index == 0 { '{' } else { ',' });
        out.push_str(key);
        out.push_str("=\"");
        escape_label_value_into(out, val);
        out.push('"');
    }
    if !labels.is_empty() {
        out.push('}');
    }
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

/// Appends a label value with the escaping the text format requires: backslash,
/// double-quote, and newline are the three characters that must be escaped inside
/// a quoted label value.
fn escape_label_value_into(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
}

/// The current Unix time in seconds, `u64::MAX` on a pre-epoch or errored clock —
/// the sentinel the launching-relay count is skipped on, matching the ledger's own
/// fail-closed clock convention.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use rally_point_proto::control::{BufferBounds, RelayHello, TenantId};
    use rally_point_proto::ids::RelayId;
    use rally_point_proto::token::KeyId;
    use rally_point_proto::version::ProtocolVersion;
    use tower::ServiceExt;

    use super::*;
    use crate::api::{ControlAuth, HELLO_TIMEOUT, LIVENESS_TIMEOUT};
    use crate::lifecycle::Lifecycle;
    use crate::regions::RegionsConfig;
    use crate::{notify, pair_rtts, session};

    /// A coordinator state with one enrolled (untagged) relay and one active
    /// tenant, with no ledger or flight store — enough for the gauges to render.
    fn test_state() -> CoordinatorState {
        let reg = registry::new_registry();
        registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(1),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                ProtocolVersion::CURRENT,
                vec![0xC1; 4],
            ),
        );
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("k1".to_owned()),
            TenantId("sb-metrics".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = session::SessionSetup::new(reg, tenants);
        let lifecycle = Lifecycle::new(setup.clone());
        CoordinatorState {
            setup,
            notices: notify::new_dedup(),
            lifecycle,
            control_auth: ControlAuth::Open,
            hello_timeout: HELLO_TIMEOUT,
            liveness_timeout: LIVENESS_TIMEOUT,
            regions: RegionsConfig::default(),
            player_token_lifetime: Duration::from_secs(3600),
            ledger: None,
            pair_rtts: pair_rtts::new_store(),
            flight_store: None,
        }
    }

    /// The trailing value of the first series line matching `name` and containing
    /// `needle` (a label-value substring), parsed as a `u64`.
    fn series_value(text: &str, name: &str, needle: &str) -> Option<u64> {
        text.lines()
            .find(|line| line.starts_with(name) && line.contains(needle))
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse().ok())
    }

    #[test]
    fn escapes_label_values() {
        let mut out = String::new();
        escape_label_value_into(&mut out, "a\\b\"c\nd");
        assert_eq!(out, "a\\\\b\\\"c\\nd");
    }

    #[test]
    fn histogram_buckets_are_cumulative() {
        let histogram = ColdStartHistogram::new();
        histogram.observe(3); // le=5
        histogram.observe(7); // le=10
        histogram.observe(1_000); // +Inf only
        let mut out = String::new();
        histogram.render(&mut out, "test_cold");

        assert!(out.contains("test_cold_bucket{le=\"5\"} 1"), "{out}");
        assert!(out.contains("test_cold_bucket{le=\"10\"} 2"), "{out}");
        // The 1000s observation falls only into +Inf, so every finite bucket at or
        // above 10 stays at 2.
        assert!(out.contains("test_cold_bucket{le=\"120\"} 2"), "{out}");
        assert!(out.contains("test_cold_bucket{le=\"+Inf\"} 3"), "{out}");
        assert!(out.contains("test_cold_sum 1010"), "{out}");
        assert!(out.contains("test_cold_count 3"), "{out}");
    }

    #[test]
    fn render_emits_help_type_and_sorted_series() {
        let text = render(&test_state());

        let help = text.find("# HELP rp2_tenants ").expect("HELP line");
        let type_line = text.find("# TYPE rp2_tenants gauge").expect("TYPE line");
        assert!(help < type_line, "HELP precedes TYPE");

        // State values render in a deterministic (alphabetical) order.
        let active = text.find("rp2_tenants{state=\"active\"}").expect("active");
        let revoked = text
            .find("rp2_tenants{state=\"revoked\"}")
            .expect("revoked");
        let suspended = text
            .find("rp2_tenants{state=\"suspended\"}")
            .expect("suspended");
        assert!(active < revoked && revoked < suspended, "sorted states");
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_prometheus_text() {
        let app = router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(
            content_type.contains("version=0.0.4"),
            "content type was {content_type}",
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();

        assert!(text.contains("# TYPE rp2_build_info gauge"), "{text}");
        assert!(text.contains("rp2_build_info{version=\""), "{text}");
        // The enrolled untagged relay renders as one live relay in region `none`.
        assert!(
            text.contains("rp2_relays{region=\"none\",state=\"live\"} 1"),
            "{text}",
        );
        assert!(text.contains("rp2_tenants{state=\"active\"} 1"), "{text}");
        assert!(text.contains("rp2_flight_store_configured 0"), "{text}");
    }

    #[test]
    fn labeled_counter_increments_by_a_delta() {
        // Counter statics are process-global, so assert the delta a single
        // increment produces rather than an absolute value. A tenant label unique
        // to this test isolates it from any other test's increments.
        let tenant = TenantId("metrics-delta-tenant".to_owned());
        let state = test_state();

        let before = series_value(
            &render(&state),
            "rp2_sessions_created_total",
            "metrics-delta-tenant",
        )
        .unwrap_or(0);
        session_created(&tenant);
        let after = series_value(
            &render(&state),
            "rp2_sessions_created_total",
            "metrics-delta-tenant",
        )
        .expect("the series exists after an increment");

        assert_eq!(after - before, 1);
    }
}
