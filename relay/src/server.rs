//! The relay's client-facing edge: accept QUIC connections, authorize them, and
//! route each one's turns to its session.
//!
//! This is the `C–S–C` path — clients to a single relay and back, no mesh. The
//! accept loop turns each incoming QUIC connection into its own task that runs the
//! authorization handshake, registers the authorized slot for routing, tells the
//! client it's in, and then serves the connection's turns until it closes. One
//! misbehaving or rejected connection only ends its own task; the loop keeps
//! accepting.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_transport::Link;
use rally_point_transport::quinn::{self, VarInt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::auth::{self, AuthError, HANDSHAKE_OK, Registry};
use crate::routing::{self, SessionKey, Sessions};

/// QUIC application close code for a connection whose authorized slot is already
/// connected by another client.
const SLOT_TAKEN_CLOSE: u32 = 0x02;

/// Maximum authorization handshakes in flight at once. A coarse admission backstop:
/// connections that stall mid-handshake can only tie up this many slots of pre-auth
/// state no matter how fast they arrive, so an unauthenticated flood can't grow
/// unbounded. The per-relay capacity model and full DDoS posture come later; this
/// is set generously so it never sheds legitimate load.
const MAX_PENDING_HANDSHAKES: usize = 4096;

/// QUIC application close code for a connection dropped because its authorization
/// handshake did not finish within [`AUTH_TIMEOUT`].
const AUTH_TIMEOUT_CLOSE: u32 = 0x03;

/// How long a client has to complete the authorization handshake once its QUIC
/// connection is accepted. The exchange is sub-second in practice; this bounds a
/// client that connects and then stalls — opening no stream, or sending only part
/// of the handshake — so unauthenticated connections cannot pin a relay task open.
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Why one connection ended. Logged per connection; never tears down the relay.
#[derive(Debug, thiserror::Error)]
enum ConnError {
    /// The QUIC handshake itself failed.
    #[error("QUIC connection failed: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// The client did not finish the authorization handshake within the deadline.
    #[error("authorization handshake timed out")]
    AuthTimeout,
    /// The client did not authorize.
    #[error("authorization failed: {0}")]
    Auth(#[from] AuthError),
    /// The authorized slot was already taken by another live connection.
    #[error("tenant {tenant:?} session {session:?} slot {slot:?} is already connected")]
    SlotTaken {
        tenant: TenantId,
        session: SessionId,
        slot: SlotId,
    },
}

/// Failure to stand up the relay's listening endpoint.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Binding the UDP socket / QUIC endpoint failed.
    #[error("binding the relay endpoint failed: {0}")]
    Bind(#[from] std::io::Error),
}

/// Binds a QUIC server endpoint on `listen` and serves the client edge on it.
///
/// Runs until the endpoint stops yielding connections. `registry` is the set of
/// tenant signing keys clients authorize against.
pub async fn run(
    listen: SocketAddr,
    server_config: quinn::ServerConfig,
    registry: Arc<Registry>,
) -> Result<(), ServerError> {
    let endpoint = quinn::Endpoint::server(server_config, listen)?;
    serve(endpoint, registry).await;
    Ok(())
}

/// Serves the client edge on an already-bound endpoint.
///
/// Split out from [`run`] so a caller that owns its endpoint — a test binding an
/// ephemeral port, or a process wiring its own socket — can drive the accept loop
/// directly. Uses the default in-flight handshake limit ([`MAX_PENDING_HANDSHAKES`]).
pub async fn serve(endpoint: quinn::Endpoint, registry: Arc<Registry>) {
    serve_with_max_pending(endpoint, registry, MAX_PENDING_HANDSHAKES).await;
}

/// Serves the client edge with an explicit cap on concurrent in-flight
/// authorization handshakes. Connections accepted past the cap are refused at once,
/// before any handshake work, so unauthenticated load stays bounded.
pub async fn serve_with_max_pending(
    endpoint: quinn::Endpoint,
    registry: Arc<Registry>,
    max_pending_handshakes: usize,
) {
    if let Ok(addr) = endpoint.local_addr() {
        tracing::info!(%addr, "relay client edge listening");
    }
    if registry.is_empty() {
        tracing::warn!("no tenant signing keys registered; all clients will be rejected");
    }

    let sessions: Sessions = Arc::default();
    let admission = Arc::new(Semaphore::new(max_pending_handshakes));
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = Arc::clone(&admission).try_acquire_owned() else {
            // Too many handshakes already in flight; shed this one without work.
            incoming.refuse();
            continue;
        };
        let registry = Arc::clone(&registry);
        let sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            if let Err(error) = serve_connection(incoming, &registry, sessions, permit).await {
                tracing::info!(%error, "client connection ended");
            }
        });
    }
}

/// Authorizes one incoming connection, wires it into routing, and serves its turns
/// until it closes.
async fn serve_connection(
    incoming: quinn::Incoming,
    registry: &Registry,
    sessions: Sessions,
    handshake_permit: OwnedSemaphorePermit,
) -> Result<(), ConnError> {
    let connection = incoming.await?;

    // Bound the whole authorization handshake: a client that connects but then
    // never opens its stream, or only half-sends, must not hold this task open.
    let handshake = auth::authenticate(&connection, registry, unix_now());
    let (authorized, mut handshake_send) = match tokio::time::timeout(AUTH_TIMEOUT, handshake).await
    {
        Ok(result) => result?,
        Err(_elapsed) => {
            connection.close(
                VarInt::from_u32(AUTH_TIMEOUT_CLOSE),
                b"authorization timed out",
            );
            return Err(ConnError::AuthTimeout);
        }
    };

    // Authorized: release the admission slot so the cap bounds only pre-auth work,
    // not the lifetime of established sessions. (Early returns above drop it too.)
    drop(handshake_permit);

    let key = SessionKey {
        tenant: authorized.tenant.clone(),
        session: authorized.session,
    };

    let Some((mut registration, inbox)) = routing::register(&sessions, &key, authorized.slot)
    else {
        connection.close(
            VarInt::from_u32(SLOT_TAKEN_CLOSE),
            b"slot already connected",
        );
        return Err(ConnError::SlotTaken {
            tenant: key.tenant,
            session: key.session,
            slot: authorized.slot,
        });
    };

    // Acknowledge only after the slot is routable, so a peer that sees this client
    // authorized can already have its turns delivered here. If the client has
    // already left, this write fails and `registration` frees the slot on drop.
    handshake_send
        .write_all(&[HANDSHAKE_OK])
        .await
        .map_err(AuthError::from)?;
    let _ = handshake_send.finish();

    // The link task owns the slot's lifetime from here and deregisters on exit.
    registration.disarm();

    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        slot = authorized.slot.0,
        "client authorized",
    );

    routing::run_slot_link(Link::new(connection), key, authorized.slot, inbox, sessions).await;
    Ok(())
}

/// Current Unix time in seconds, used to check token expiry. A clock before the
/// epoch yields 0, which simply expires every token rather than misbehaving.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
