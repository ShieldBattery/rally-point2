//! Shared fixtures for the notify tests: the signature-verification helper and
//! the tenant/session wiring every topic file below drives a handler with, via
//! `use super::*;`. Split by topic: `departures`, `desync_and_results`,
//! `dispatch_delivery`. The webhook receiver and the session builder are the
//! crate-wide test-support ones.

use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::http::StatusCode;
use axum::routing::post;
use base64::Engine as _;
use rally_point_proto::control::{BufferBounds, DepartureKind, DivergedSlot, TenantId};
use rally_point_proto::ids::SlotId;
use rally_point_proto::token::KeyId;
use ring::signature::{ED25519, UnparsedPublicKey};
use tokio::time::{Duration, Instant, timeout};

use super::*;
use crate::test_support::*;

/// The three load-progress bodies serialize to exactly the shapes the tenant
/// parses: camelCase keys, the `event` discriminator naming the kind, and
/// absent optionals omitted from the object rather than sent as `null` (the
/// consumer validates them as optional strings/numbers, and a literal `null`
/// fails that validation instead of reading as "absent").
#[test]
fn the_load_progress_webhook_bodies_serialize_to_their_documented_shapes() {
    let connected = SlotConnectedWebhook {
        event: "slotConnected",
        tenant: "sb-staging".to_owned(),
        session: 42,
        external_id: Some("game-99".to_owned()),
        slot: 1,
        external_ref: Some("sb-user-7".to_owned()),
        resumed: false,
        connected_at_ms: 1_700_000_000_000,
    };
    assert_eq!(
        serde_json::to_string(&connected).unwrap(),
        r#"{"event":"slotConnected","tenant":"sb-staging","session":42,"externalId":"game-99","slot":1,"externalRef":"sb-user-7","resumed":false,"connectedAtMs":1700000000000}"#,
    );

    let started = SessionStartedWebhook {
        event: "sessionStarted",
        tenant: "sb-staging".to_owned(),
        session: 42,
        external_id: Some("game-99".to_owned()),
        started_at_ms: 1_700_000_000_000,
        initial_buffer_turns: Some(6),
    };
    assert_eq!(
        serde_json::to_string(&started).unwrap(),
        r#"{"event":"sessionStarted","tenant":"sb-staging","session":42,"externalId":"game-99","startedAtMs":1700000000000,"initialBufferTurns":6}"#,
    );

    let slot_started = SlotStartedWebhook {
        event: "slotStarted",
        tenant: "sb-staging".to_owned(),
        session: 42,
        external_id: Some("game-99".to_owned()),
        slot: 1,
        external_ref: Some("sb-user-7".to_owned()),
        arrival_ms: 1_700_000_000_000,
        session_frame: Some(12),
        slot_frame: Some(14),
    };
    assert_eq!(
        serde_json::to_string(&slot_started).unwrap(),
        r#"{"event":"slotStarted","tenant":"sb-staging","session":42,"externalId":"game-99","slot":1,"externalRef":"sb-user-7","arrivalMs":1700000000000,"sessionFrame":12,"slotFrame":14}"#,
    );

    // The minimal shapes: every optional absent, so each key is omitted.
    let bare_started = SessionStartedWebhook {
        event: "sessionStarted",
        tenant: "sb-staging".to_owned(),
        session: 42,
        external_id: None,
        started_at_ms: 7,
        initial_buffer_turns: None,
    };
    assert_eq!(
        serde_json::to_string(&bare_started).unwrap(),
        r#"{"event":"sessionStarted","tenant":"sb-staging","session":42,"startedAtMs":7}"#,
    );

    let bare_slot_started = SlotStartedWebhook {
        event: "slotStarted",
        tenant: "sb-staging".to_owned(),
        session: 42,
        external_id: None,
        slot: 0,
        external_ref: None,
        arrival_ms: 7,
        session_frame: None,
        slot_frame: None,
    };
    assert_eq!(
        serde_json::to_string(&bare_slot_started).unwrap(),
        r#"{"event":"slotStarted","tenant":"sb-staging","session":42,"slot":0,"arrivalMs":7}"#,
    );
}

/// Asserts a received webhook is properly signed: the timestamp header
/// parses as a decimal unix-epoch-milliseconds value that is current-ish
/// (within a generous minute of "now" — a loose sanity check, not the
/// consumer's own ±5 minute replay window), and the signature verifies
/// against `tenant`'s enrolled public key over the exact domain-separated
/// message (`rp2-webhook-v1:<timestamp>:<raw body bytes>`). No
/// `Authorization` header is asserted anywhere: the bearer-secret scheme
/// it belonged to is gone.
pub(super) fn assert_signed(setup: &SessionSetup, tenant: &str, received: &Received) {
    let timestamp_str = received
        .timestamp
        .as_deref()
        .expect("x-rp2-timestamp header is present");
    let timestamp_ms: u128 = timestamp_str
        .parse()
        .expect("x-rp2-timestamp is a decimal integer");
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    assert!(
        now_ms.abs_diff(timestamp_ms) < 60_000,
        "timestamp {timestamp_ms} is not current-ish (now is {now_ms})",
    );

    let signature_b64 = received
        .signature
        .as_deref()
        .expect("x-rp2-signature header is present");
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .expect("x-rp2-signature is valid standard base64");

    let mut message = Vec::new();
    message.extend_from_slice(WEBHOOK_SIG_DOMAIN.as_bytes());
    message.extend_from_slice(timestamp_str.as_bytes());
    message.push(b':');
    message.extend_from_slice(&received.raw_body);

    let (_, pubkey) = tenant::verifying_key(setup.tenants(), &TenantId(tenant.to_owned())).unwrap();
    UnparsedPublicKey::new(&ED25519, pubkey)
        .verify(&message, &signature)
        .expect("the signature verifies against the tenant's enrolled public key");
}

/// A setup with one relay and the test tenant enrolled, plus a created session
/// carrying the given correlation ids. Returns the setup and session.
pub(super) fn setup_with_session(
    external_id: Option<&'static str>,
    slot0_ref: Option<&'static str>,
) -> (SessionSetup, SessionId) {
    SessionFixture {
        players: vec![PlayerSpec {
            slot: 0,
            external_ref: slot0_ref,
            region: None,
        }],
        external_id,
        ..Default::default()
    }
    .build()
}

/// A tenant enrolled for its signing key with **no** session created this
/// lifetime — the post-restart shape, where a notice must carry its own
/// correlation ids to deliver at all. `url` is the tenant's webhook.
pub(super) fn setup_without_session(url: String) -> SessionSetup {
    SessionFixture {
        relays: vec![],
        notify_url: Some(url),
        ..Default::default()
    }
    .setup_only()
}

mod departures;
mod desync_and_results;
mod dispatch_delivery;
