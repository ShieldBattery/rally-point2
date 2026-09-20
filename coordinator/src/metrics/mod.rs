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
//! # Module layout
//!
//! The module is layered, lowest first, and the layering is the point: a module
//! that merely counts something must not thereby depend on the composed state a
//! scrape renders.
//!
//! - `instruments` — the counting primitives: a labeled counter and two
//!   fixed-bucket histograms.
//! - `counters` — the metric statics and the one-line recorders event sites
//!   call. The leaf: it knows nothing about the coordinator's state.
//! - `census` — the only file that reads a [`CoordinatorState`], asking each
//!   subsystem for a census of itself.
//! - `render` — pure formatting: a census and the counters in, exposition text
//!   out.
//!
//! This file composes them: the `/metrics` router, and [`render`] as the entry
//! point that gathers a census and formats it.

use axum::{
    Router, extract::State, http::header::CONTENT_TYPE, response::IntoResponse, routing::get,
};

use crate::api::CoordinatorState;

mod census;
mod counters;
mod instruments;
mod render;
#[cfg(test)]
mod tests;

pub(crate) use counters::{
    control_connection_ended, descriptor_delta_sent, descriptor_full_set_sent, desync,
    flight_recording_lost, flight_recording_pinned, flight_recording_refused,
    flight_recording_stored, observe_control_send, observe_relay_cold_start, reap_directives_sent,
    reap_nudges_coalesced, relay_drained, relay_enrolled, relay_launch_failed, relay_launched,
    relay_reaped, session_closed, session_created, session_held, session_reaped,
    webhook_attempt_failed, webhook_delivered,
};

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

/// Renders the full metrics exposition for `state`: gather one census of every
/// subsystem, then format it alongside the counter statics.
pub fn render(state: &CoordinatorState) -> String {
    render::exposition(&census::CoordinatorCensus::gather(state))
}
