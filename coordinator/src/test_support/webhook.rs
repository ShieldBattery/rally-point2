//! The webhook receiver (an in-process HTTP endpoint recording what the
//! coordinator posts) and the session builders the notify-driven tests share.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use rally_point_proto::control::{
    BufferBounds, PlayerHandoff, RegionId, RelayHello, SessionPresence, SessionRequest,
    SessionResponse, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};
use rally_point_proto::version::ProtocolVersion;
use tokio::sync::{Notify, mpsc};

use crate::registry;
use crate::session::{self, SessionSetup};
use crate::tenant::{self, NotifyConfig};

/// The tenant every area's fixtures enroll and sign as.
pub(crate) const TEST_TENANT: &str = "sb-test";

/// The loopback port each fixture relay enrolls on: `RELAY_PORT_BASE + id`, so
/// two relays never claim one address.
const RELAY_PORT_BASE: u16 = 14_900;

/// One webhook the stand-in tenant received: the two signature headers (raw
/// strings, unvalidated — verification is the test's job), the exact body bytes
/// (needed to reconstruct the signed message), and the body parsed as JSON.
#[derive(Clone, Debug)]
pub(crate) struct Received {
    pub(crate) timestamp: Option<String>,
    pub(crate) signature: Option<String>,
    pub(crate) raw_body: Vec<u8>,
    pub(crate) body: serde_json::Value,
}

impl Received {
    /// The body's `event` discriminator — what most tests assert on.
    pub(crate) fn event(&self) -> &str {
        self.body["event"].as_str().unwrap_or_default()
    }
}

/// A stand-in tenant webhook endpoint: an axum server recording each POST it
/// gets, in order, onto a channel.
///
/// The signature header names are spelled out rather than taken from the
/// dispatch module's constants: this stands in for a tenant's own server, which
/// knows them from the documented wire contract, so a rename on our side is a
/// contract break the recorded headers should show rather than follow.
///
/// `status` is what every response carries, so a test can drive the dispatch
/// retry path. `gate`, when set, makes the *first* request block until the test
/// releases it — which is how a test proves a stuck notice blocks the queue
/// behind it.
pub(crate) struct WebhookReceiver {
    pub(crate) status: StatusCode,
    pub(crate) gate: Option<Arc<Notify>>,
}

impl Default for WebhookReceiver {
    fn default() -> Self {
        Self {
            status: StatusCode::OK,
            gate: None,
        }
    }
}

/// The receiver's axum state: the record channel, the optional first-request
/// gate, the "still the first request" flag, and the status to answer with.
type ReceiverState = (
    mpsc::UnboundedSender<Received>,
    Option<Arc<Notify>>,
    Arc<AtomicBool>,
    StatusCode,
);

impl WebhookReceiver {
    /// Binds an ephemeral loopback port and serves the endpoint, returning its
    /// URL (to point a tenant's notify config at) and the receive end.
    pub(crate) async fn spawn(self) -> (String, mpsc::UnboundedReceiver<Received>) {
        let (tx, rx) = mpsc::unbounded_channel::<Received>();
        let first = Arc::new(AtomicBool::new(true));
        let app = Router::new()
            .route(
                "/hook",
                post(
                    move |State((tx, gate, first, status)): State<ReceiverState>,
                          headers: HeaderMap,
                          raw_body: axum::body::Bytes| async move {
                        let header = |name: &str| {
                            headers
                                .get(name)
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_owned)
                        };
                        let body =
                            serde_json::from_slice(&raw_body).unwrap_or(serde_json::Value::Null);
                        let _ = tx.send(Received {
                            timestamp: header("x-rp2-timestamp"),
                            signature: header("x-rp2-signature"),
                            raw_body: raw_body.to_vec(),
                            body,
                        });
                        let is_first = first.swap(false, Ordering::SeqCst);
                        if is_first && let Some(gate) = gate {
                            gate.notified().await;
                        }
                        status
                    },
                ),
            )
            .with_state((tx, self.gate, first, self.status));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/hook"), rx)
    }
}

/// A relay to enroll into a fixture's registry: its id and the region it
/// advertises, if any.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RelaySpec {
    pub(crate) id: u64,
    pub(crate) region: Option<&'static str>,
}

impl RelaySpec {
    /// The enroll `Hello` this relay presents: a loopback address derived from
    /// its id and a placeholder certificate.
    pub(crate) fn hello(self) -> RelayHello {
        let hello = RelayHello::new(
            RelayId(self.id),
            SocketAddr::from((Ipv4Addr::LOCALHOST, RELAY_PORT_BASE + self.id as u16)),
            ProtocolVersion::CURRENT,
            vec![0xC0 | self.id as u8; 4],
        );
        match self.region {
            Some(region) => hello.with_region(RegionId(region.to_owned())),
            None => hello,
        }
    }
}

/// Untagged relays with the given ids — the region-blind fixture fleet.
pub(crate) fn untagged_relays(ids: &[u64]) -> Vec<RelaySpec> {
    ids.iter()
        .map(|&id| RelaySpec { id, region: None })
        .collect()
}

/// One player in a fixture session: its slot, the tenant's per-slot
/// correlation ref, and the region it asks to be homed in.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PlayerSpec {
    pub(crate) slot: u8,
    pub(crate) external_ref: Option<&'static str>,
    pub(crate) region: Option<&'static str>,
}

/// Refless, region-blind players on the given slots.
pub(crate) fn plain_players(slots: &[u8]) -> Vec<PlayerSpec> {
    slots
        .iter()
        .map(|&slot| PlayerSpec {
            slot,
            external_ref: None,
            region: None,
        })
        .collect()
}

/// Builds a [`SessionSetup`] with relays and the test tenant enrolled and one
/// session created on it, so the session's real `session→relay` membership and
/// staged descriptors exist the way a full close later retires them.
///
/// Every area's setup differs only in the relay fleet, the player roster, the
/// correlation ids, and whether the tenant has a webhook configured — so a test
/// names the fields it cares about and leaves the rest at [`Default`]: one
/// untagged relay 1, one refless player on slot 0, no correlation ids, and no
/// notify config.
pub(crate) struct SessionFixture {
    pub(crate) relays: Vec<RelaySpec>,
    pub(crate) players: Vec<PlayerSpec>,
    pub(crate) external_id: Option<&'static str>,
    pub(crate) notify_url: Option<String>,
}

impl Default for SessionFixture {
    fn default() -> Self {
        Self {
            relays: untagged_relays(&[1]),
            players: plain_players(&[0]),
            external_id: None,
            notify_url: None,
        }
    }
}

impl SessionFixture {
    /// Enrolls the fleet and the tenant, then creates the session. Returns the
    /// setup and the created session's id.
    pub(crate) fn build(self) -> (SessionSetup, SessionId) {
        let (setup, response) = self.build_response();
        (setup, response.session)
    }

    /// [`build`](Self::build) keeping the whole create response, for the tests
    /// that assert on where the session was placed.
    pub(crate) fn build_response(self) -> (SessionSetup, SessionResponse) {
        let setup = self.setup_only();
        let response = create_fixture_session(&setup, &self.players, self.external_id);
        (setup, response)
    }

    /// The fleet and the tenant without a session — for the tests whose subject
    /// is what happens when the coordinator holds no session record at all.
    pub(crate) fn setup_only(&self) -> SessionSetup {
        let reg = registry::new_registry();
        for relay in &self.relays {
            registry::enroll(&reg, relay.hello());
        }
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId(TEST_TENANT.to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        if let Some(url) = &self.notify_url {
            tenant::set_notify(
                &tenants,
                &TenantId(TEST_TENANT.to_owned()),
                Some(NotifyConfig { url: url.clone() }),
            );
        }
        SessionSetup::new(reg, tenants)
    }
}

/// Creates the fixture session on `setup`, returning the create response.
fn create_fixture_session(
    setup: &SessionSetup,
    players: &[PlayerSpec],
    external_id: Option<&str>,
) -> SessionResponse {
    // Slot n's client key is 0xAA, 0xBB, … so two players never share one; it
    // wraps rather than overflowing once a roster runs past slot 5.
    let players = players
        .iter()
        .map(|player| PlayerHandoff {
            slot: SlotId(player.slot),
            client_pubkey: ClientPublicKey(
                [0xAAu8.wrapping_add(player.slot.wrapping_mul(0x11)); 32],
            ),
            external_ref: player.external_ref.map(str::to_owned),
            observer: false,
            region: player.region.map(|region| RegionId(region.to_owned())),
        })
        .collect();
    session::create_session(
        setup,
        SessionRequest {
            tenant: TenantId(TEST_TENANT.to_owned()),
            players,
            external_id: external_id.map(str::to_owned),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response
}

/// Slot ids from their raw numbers — the shape every roster field takes.
pub(crate) fn slots(ids: &[u8]) -> Vec<SlotId> {
    ids.iter().copied().map(SlotId).collect()
}

/// A heartbeat / attestation roster entry for `session` naming `connected` as
/// the slots whose clients are linked right now, carrying no retained load
/// state. A test that also cares about the load-state fields names them with
/// struct-update syntax over this.
pub(crate) fn presence_entry(
    tenant: &TenantId,
    session: SessionId,
    connected: &[u8],
) -> SessionPresence {
    SessionPresence {
        tenant: tenant.clone(),
        session,
        slots: slots(connected),
        ever_connected: vec![],
        started: vec![],
        started_at_ms: None,
    }
}
