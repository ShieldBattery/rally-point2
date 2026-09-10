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
use crate::{notify, pair_rtts, registry, session, tenant};

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
    render::escape_label_value_into(&mut out, "a\\b\"c\nd");
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
fn send_duration_histogram_buckets_are_cumulative() {
    let histogram = SendDurationHistogram::new();
    histogram.observe(0); // le=1
    histogram.observe(7); // le=10
    histogram.observe(100_000); // +Inf only (past the top finite bound)
    let mut out = String::new();
    histogram.render(&mut out, "test_send");

    assert!(out.contains("test_send_bucket{le=\"1\"} 1"), "{out}");
    assert!(out.contains("test_send_bucket{le=\"10\"} 2"), "{out}");
    // The 100000ms observation falls only into +Inf, so every finite bucket at
    // or above 10 stays at 2.
    assert!(out.contains("test_send_bucket{le=\"30000\"} 2"), "{out}");
    assert!(out.contains("test_send_bucket{le=\"+Inf\"} 3"), "{out}");
    assert!(out.contains("test_send_sum 100007"), "{out}");
    assert!(out.contains("test_send_count 3"), "{out}");
}

#[test]
fn control_connection_end_causes_are_counted_by_label() {
    // Counter statics are process-global, so assert the delta a single increment
    // produces. A cause word unique to this test isolates it from any other.
    let state = test_state();
    let before = series_value(
        &render(&state),
        "rp2_control_connection_ends_total",
        "metrics-test-cause",
    )
    .unwrap_or(0);
    control_connection_ended("metrics-test-cause");
    let after = series_value(
        &render(&state),
        "rp2_control_connection_ends_total",
        "metrics-test-cause",
    )
    .expect("the series exists after an increment");
    assert_eq!(after - before, 1);
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
