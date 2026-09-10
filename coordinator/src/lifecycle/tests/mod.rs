//! Shared fixtures for the lifecycle tests: tenant/session setup helpers, the
//! fake webhook receiver, and the relay/heartbeat staging used across the topic
//! modules below.

use std::net::Ipv4Addr;
use std::sync::Arc as StdArc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use rally_point_proto::control::{BufferBounds, SessionDescriptor};
use rally_point_proto::token::KeyId;
use tokio::sync::{Notify as TokioNotify, mpsc as tokio_mpsc};
use tokio::time::timeout;

use super::*;
use crate::registry;
use crate::tenant;

const TENANT: &str = "sb-test";
const HOUR: Duration = Duration::from_secs(3600);
const SHORT: Duration = Duration::from_millis(80);

fn tid() -> TenantId {
    TenantId(TENANT.to_owned())
}

/// Records a terminal notice in lifecycle-only tests, explicitly installing
/// authoritative membership and a stable synthetic connection epoch when the
/// test intentionally bypassed normal session creation and enrollment.
fn close(lifecycle: &Lifecycle, tenant: TenantId, session: SessionId, relay: RelayId) {
    if lifecycle
        .inner
        .setup
        .serving_relays(&tenant, session)
        .is_empty()
    {
        let cached = lifecycle
            .inner
            .sessions
            .lock()
            .get(&(tenant.clone(), session))
            .map(|state| state.serving_relays.clone())
            .unwrap_or_default();
        lifecycle
            .inner
            .setup
            .set_session_membership_for_test(&tenant, session, cached);
    }
    let existing = lifecycle
        .inner
        .relay_epochs
        .lock()
        .get(&relay)
        .map(|epoch| epoch.generation);
    let generation = existing.unwrap_or_else(|| {
        let generation = relay.0.max(1);
        lifecycle.on_relay_enrolled(relay, generation);
        generation
    });
    lifecycle.on_session_closed(tenant, session, relay, generation);
}

/// A bare setup with a tenant enrolled (its signing key), no notify config —
/// enough for reap tests, which never POST a webhook.
fn bare_setup() -> SessionSetup {
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("k1".to_owned()),
        tid(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    SessionSetup::new(registry::new_registry(), tenants)
}

/// One webhook the stand-in tenant received: its `event` discriminator.
#[derive(Clone, Debug)]
struct Received {
    event: String,
}

/// The stand-in receiver's axum state: the record channel, the optional
/// first-request gate, and the "have we seen the first request" flag.
type ReceiverState = (
    tokio_mpsc::UnboundedSender<Received>,
    Option<StdArc<TokioNotify>>,
    StdArc<std::sync::atomic::AtomicBool>,
);

/// A stand-in tenant receiver recording each POST's `event` in order. If
/// `gate` is set, the *first* request blocks on it until the test releases it —
/// so a test can prove a stuck notice blocks the queue behind it.
async fn spawn_receiver(
    gate: Option<StdArc<TokioNotify>>,
) -> (String, tokio_mpsc::UnboundedReceiver<Received>) {
    let (tx, rx) = tokio_mpsc::unbounded_channel::<Received>();
    let first = StdArc::new(std::sync::atomic::AtomicBool::new(true));
    let app =
        Router::new()
            .route(
                "/hook",
                post(
                    move |State((tx, gate, first)): State<ReceiverState>,
                          body: axum::body::Bytes| async move {
                        let is_first = first.swap(false, std::sync::atomic::Ordering::SeqCst);
                        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let event = value["event"].as_str().unwrap_or_default().to_owned();
                        let _ = tx.send(Received { event });
                        if is_first && let Some(gate) = gate {
                            gate.notified().await;
                        }
                        StatusCode::OK
                    },
                ),
            )
            .with_state((tx, gate, first));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/hook"), rx)
}

fn setup_with_notify(url: String) -> SessionSetup {
    let setup = bare_setup();
    tenant::set_notify(setup.tenants(), &tid(), Some(NotifyConfig { url }));
    setup
}

/// A setup with relay 1 enrolled and the test tenant, plus a real two-player
/// session created on it — so its `session_relays`/`session_refs` membership is
/// recorded, the way a lifecycle full-close later retires. Returns the setup and
/// the created session id.
fn setup_with_relay_and_session() -> (SessionSetup, SessionId) {
    use rally_point_proto::control::{PlayerHandoff, RelayHello, SessionRequest};
    use rally_point_proto::token::{ClientPublicKey, ExpiresAt};
    use rally_point_proto::version::ProtocolVersion;

    let reg = registry::new_registry();
    registry::enroll(
        &reg,
        RelayHello::new(
            RelayId(1),
            std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
            vec![1u8; 4],
        ),
    );
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("k1".to_owned()),
        tid(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let setup = SessionSetup::new(reg, tenants);
    let resp = crate::session::create_session(
        &setup,
        SessionRequest {
            tenant: tid(),
            players: vec![
                PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([0xAA; 32]),
                    external_ref: None,
                    observer: false,
                    region: None,
                },
                PlayerHandoff {
                    slot: SlotId(1),
                    client_pubkey: ClientPublicKey([0xBB; 32]),
                    external_ref: None,
                    observer: false,
                    region: None,
                },
            ],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    (setup, resp.session)
}

fn heartbeat_session(session: SessionId, slots: &[u8]) -> SessionPresence {
    SessionPresence {
        tenant: tid(),
        session,
        slots: slots.iter().copied().map(SlotId).collect(),
        ever_connected: vec![],
        started: vec![],
        started_at_ms: None,
    }
}

fn stage_assignments(setup: &SessionSetup, session: SessionId, relays: &[RelayId]) {
    for &relay in relays {
        setup.descriptors().record(
            relay,
            SessionDescriptor {
                finalized_drops: false,
                tenant: tid(),
                session,
                peers: vec![],
                bounds: BufferBounds::new(1, 6).unwrap(),
                authority_order: relays.to_vec(),
                external_id: None,
                slot_refs: vec![],
                observer_slots: vec![],
                expected_slots: vec![],
                homed_slots: vec![],
                resumed: false,
                departed_slots: vec![],
                latency_estimate_ms: None,
                relay_regions: Vec::new(),
            },
        );
    }
}

/// A roster entry carrying load state alongside the connected slots.
fn heartbeat_load(
    session: SessionId,
    connected: &[u8],
    ever_connected: &[u8],
    started: &[u8],
    started_at_ms: Option<u64>,
) -> SessionPresence {
    SessionPresence {
        ever_connected: ever_connected.iter().copied().map(SlotId).collect(),
        started: started.iter().copied().map(SlotId).collect(),
        started_at_ms,
        ..heartbeat_session(session, connected)
    }
}

mod close;
mod empty_reap;
mod notices;
mod reaps;
mod rehome;
mod sessions;
