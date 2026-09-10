//! Renders a full metrics snapshot as Prometheus text exposition: [`render`] walks
//! the coordinator's live state and the metric statics in [`super`], and every
//! `render_*`/`write_*`/`escape_*` helper below does one piece of that formatting.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rally_point_proto::control::{RegionId, TenantId};

use super::instruments::LabeledCounter;
use super::{
    CONTROL_CONNECTION_ENDS, CONTROL_SEND_DURATION, DESCRIPTOR_DELTA_ENTRIES_SENT,
    DESCRIPTOR_DELTAS_SENT, DESCRIPTOR_FULL_SETS_SENT, DESYNCS, FLIGHT_RECORDINGS,
    FLIGHT_RECORDINGS_PINNED, REAP_DIRECTIVES_SENT, REAP_NUDGES_COALESCED, RELAY_COLD_START,
    RELAY_DRAINS, RELAY_ENROLLS, RELAY_LAUNCH_FAILURES, RELAY_LAUNCHES, RELAY_REAPED,
    SESSION_HOLDS, SESSION_REAPS, SESSIONS_CLOSED, SESSIONS_CREATED, WEBHOOK_ATTEMPT_FAILURES,
    WEBHOOK_DELIVERIES, beacon_backoff_map,
};
use crate::api::CoordinatorState;
use crate::{lifecycle, registry, tenant};
use std::sync::atomic::Ordering;

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
    render_counter_2(
        &mut out,
        "rp2_session_reaps_total",
        "Sessions retired by coordinator lifecycle backstops, by tenant and reason.",
        &SESSION_REAPS,
        "tenant",
        "reason",
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

    write_meta(
        &mut out,
        "rp2_reap_directives_sent_total",
        "Slot-close directives written down relay control connections.",
        "counter",
    );
    write_series(
        &mut out,
        "rp2_reap_directives_sent_total",
        &[],
        REAP_DIRECTIVES_SENT.load(Ordering::Relaxed),
    );

    write_meta(
        &mut out,
        "rp2_reap_nudges_coalesced_total",
        "Queued slot-close nudges collapsed into a same-session directive before a frame was sent.",
        "counter",
    );
    write_series(
        &mut out,
        "rp2_reap_nudges_coalesced_total",
        &[],
        REAP_NUDGES_COALESCED.load(Ordering::Relaxed),
    );

    write_meta(
        &mut out,
        "rp2_descriptor_deltas_sent_total",
        "Steady-state descriptor delta frames written down relay control connections.",
        "counter",
    );
    write_series(
        &mut out,
        "rp2_descriptor_deltas_sent_total",
        &[],
        DESCRIPTOR_DELTAS_SENT.load(Ordering::Relaxed),
    );

    write_meta(
        &mut out,
        "rp2_descriptor_full_sets_sent_total",
        "Steady-state full descriptor sets written down relay control connections (a pre-delta relay's fallback).",
        "counter",
    );
    write_series(
        &mut out,
        "rp2_descriptor_full_sets_sent_total",
        &[],
        DESCRIPTOR_FULL_SETS_SENT.load(Ordering::Relaxed),
    );

    write_meta(
        &mut out,
        "rp2_descriptor_delta_entries_sent_total",
        "Descriptor delta entries (upserts plus removals) written down relay control connections.",
        "counter",
    );
    write_series(
        &mut out,
        "rp2_descriptor_delta_entries_sent_total",
        &[],
        DESCRIPTOR_DELTA_ENTRIES_SENT.load(Ordering::Relaxed),
    );

    render_counter_1(
        &mut out,
        "rp2_control_connection_ends_total",
        "Relay control connections ended by a send stall or a liveness lapse, by cause.",
        &CONTROL_CONNECTION_ENDS,
        "cause",
    );

    CONTROL_SEND_DURATION.render(&mut out, "rp2_control_send_duration_milliseconds");

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
        "Sessions with an assigned serving relay, by tenant and lifecycle state.",
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
        if counts.empty_grace > 0 {
            write_series(
                out,
                "rp2_sessions_active",
                &[("tenant", tenant.as_ref()), ("state", "empty_grace")],
                counts.empty_grace,
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

/// The label value for an optional region: the region id, or `none` for an
/// untagged relay.
///
/// `pub(super)`: the parent `metrics` module's increment functions (e.g.
/// `relay_enrolled`) also label by region and share this helper.
pub(super) fn region_label(region: Option<&RegionId>) -> String {
    region.map_or_else(|| "none".to_owned(), |r| r.as_ref().to_owned())
}

/// Writes a metric family's `# HELP` and `# TYPE` header lines.
///
/// `pub(super)`: the sibling `instruments` module's histograms render their own
/// families and share this helper.
pub(super) fn write_meta(out: &mut String, name: &str, help: &str, kind: &str) {
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
///
/// `pub(super)`: the sibling `instruments` module's histograms render their own
/// series and share this helper.
pub(super) fn write_series(out: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
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
///
/// `pub(super)`: the sibling `tests` module asserts on it directly.
pub(super) fn escape_label_value_into(out: &mut String, value: &str) {
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
