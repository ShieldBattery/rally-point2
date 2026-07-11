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
use crate::consensus;
use crate::routing::{self, SessionKey, Sessions};

/// QUIC application close code for a connection whose authorized slot is already
/// connected by another client.
const SLOT_TAKEN_CLOSE: u32 = 0x02;

/// QUIC application close code for a re-register the relay refuses because the
/// slot's leave was already decided — a survivor's drop request was honored, or it
/// left cleanly — so the game has moved on without it. Distinct from every transport-error close
/// so a reconnecting client can tell "you were dropped, the session is over for
/// you" from a mere connection failure and stop retrying. Contrast
/// `SLOT_TAKEN_CLOSE`, which means the slot is *still connected* by a live
/// connection (a genuine double-connect), not gone.
pub const SLOT_DEPARTED_CLOSE: u32 = 0x06;

/// QUIC application close code for a connection the relay refuses because its
/// authorized slot is not among the session descriptor's [`homed_slots`]
/// (non-empty) for this relay. A token binds tenant/session/slot/key but not
/// the specific relay, so this is the home-relay-binding gate: without it, a
/// misrouted (or malicious) client presenting a token for a slot homed on a
/// *different* relay in a true multi-relay session could register here too,
/// feeding this relay's clients a competing view of that slot's turns —
/// exactly the split the mesh's topological dedup cannot detect or prevent
/// (it only suppresses the echo, on each side, of what looks like a duplicate
/// turn). Distinct from every other close so a misrouted client is
/// diagnosable rather than looking like a generic double-connect or refusal.
///
/// [`homed_slots`]: rally_point_proto::control::SessionDescriptor::homed_slots
pub const SLOT_NOT_HOMED_CLOSE: u32 = 0x08;

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
    /// The authorized slot re-registered after its leave was already decided (a
    /// drop request was honored, or it left cleanly) — too late to resume, so the
    /// re-register is refused terminally.
    #[error("tenant {tenant:?} session {session:?} slot {slot:?} already departed the game")]
    SlotDeparted {
        tenant: TenantId,
        session: SessionId,
        slot: SlotId,
    },
    /// The authorized slot is not among the session descriptor's homed set for
    /// this relay — a misrouted client (or a token replayed against the wrong
    /// relay in a multi-relay session).
    #[error("tenant {tenant:?} session {session:?} slot {slot:?} is not homed on this relay")]
    SlotNotHomed {
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
    sessions: Sessions,
    mesh: crate::mesh::MeshState,
    mesh_accept: Option<tokio::sync::mpsc::Sender<quinn::Connection>>,
) -> Result<(), ServerError> {
    let endpoint = quinn::Endpoint::server(server_config, listen)?;
    serve(endpoint, registry, sessions, mesh, mesh_accept).await;
    Ok(())
}

/// Serves the client edge on an already-bound endpoint.
///
/// `sessions` is the shared session roster the caller creates upfront and passes
/// to both the client edge and the mesh-link drivers, so a turn validated at the
/// client edge and a turn arriving from a mesh peer share one roster and fan out
/// to the same local slots. `mesh_accept` receives peer-relay connections
/// dispatched by the ALPN check; pass `None` if the relay isn't meshed.
pub async fn serve(
    endpoint: quinn::Endpoint,
    registry: Arc<Registry>,
    sessions: Sessions,
    mesh: crate::mesh::MeshState,
    mesh_accept: Option<tokio::sync::mpsc::Sender<quinn::Connection>>,
) {
    serve_with_max_pending(
        endpoint,
        registry,
        sessions,
        mesh,
        mesh_accept,
        MAX_PENDING_HANDSHAKES,
    )
    .await;
}

/// Serves the client edge with an explicit cap on concurrent in-flight
/// authorization handshakes, plus ALPN-based dispatch for mesh connections.
///
/// The admission semaphore is acquired **before** the TLS handshake (not after),
/// so the cap bounds in-flight handshakes including the TLS exchange itself —
/// the original "refused before any handshake work" DoS posture. Each handshake
/// runs in a spawned task so handshakes are concurrent, not serialized. After
/// the handshake, the negotiated ALPN dispatches:
///
/// - `MESH_ALPN`: a peer relay. The admission permit is dropped (mesh peers
///   skip the client-auth bound), and the connection is sent over
///   `mesh_accept` to the mesh-link establishment task (or the test harness).
///   If `mesh_accept` is `None`, the connection is closed — the relay isn't
///   configured for mesh.
pub async fn serve_with_max_pending(
    endpoint: quinn::Endpoint,
    registry: Arc<Registry>,
    sessions: Sessions,
    mesh: crate::mesh::MeshState,
    mesh_accept: Option<tokio::sync::mpsc::Sender<quinn::Connection>>,
    max_pending_handshakes: usize,
) {
    if let Ok(addr) = endpoint.local_addr() {
        tracing::info!(%addr, "relay client edge listening");
    }
    if registry.is_empty() {
        tracing::warn!("no tenant signing keys registered; all clients will be rejected");
    }

    let admission = Arc::new(Semaphore::new(max_pending_handshakes));
    while let Some(incoming) = endpoint.accept().await {
        // Acquire the admission slot BEFORE the handshake, so the cap bounds
        // in-flight handshakes (including TLS), not just app-level auth.
        let Ok(permit) = Arc::clone(&admission).try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let registry = Arc::clone(&registry);
        let sessions = Arc::clone(&sessions);
        let mesh = mesh.clone();
        let mesh_accept = mesh_accept.clone();
        tokio::spawn(async move {
            // Complete the TLS handshake in a spawned task so handshakes run
            // concurrently, not serialized in the accept loop.
            let connection = match incoming.await {
                Ok(conn) => conn,
                Err(error) => {
                    tracing::info!(%error, "incoming connection handshake failed");
                    return;
                }
            };

            let alpn = connection
                .handshake_data()
                .and_then(|data| {
                    data.downcast_ref::<quinn::crypto::rustls::HandshakeData>()
                        .and_then(|hd| hd.protocol.clone())
                })
                .unwrap_or_default();
            if alpn.as_slice() == rally_point_transport::quic::MESH_ALPN {
                // A peer relay. Mesh connections skip the auth bound — drop the
                // permit so the admission slot frees for the next client.
                drop(permit);
                if let Some(tx) = mesh_accept {
                    if tx.send(connection).await.is_err() {
                        tracing::info!("mesh accept channel closed; dropping connection");
                    }
                } else {
                    connection.close(VarInt::from_u32(0), b"mesh not configured");
                }
            } else {
                if let Err(error) =
                    serve_connection(connection, &registry, sessions, mesh, permit).await
                {
                    tracing::info!(%error, "client connection ended");
                }
            }
        });
    }
}
/// Authorizes one incoming client connection, wires it into routing, and serves
/// its turns until it closes. The TLS handshake is already complete (the accept
async fn serve_connection(
    connection: quinn::Connection,
    registry: &Registry,
    sessions: Sessions,
    mesh: crate::mesh::MeshState,
    handshake_permit: OwnedSemaphorePermit,
) -> Result<(), ConnError> {
    let handshake = auth::authenticate(&connection, registry, unix_now());
    let (authorized, resume_cursors, mut handshake_send) =
        match tokio::time::timeout(AUTH_TIMEOUT, handshake).await {
            Ok(result) => result?,
            Err(_elapsed) => {
                connection.close(
                    VarInt::from_u32(AUTH_TIMEOUT_CLOSE),
                    b"authorization timed out",
                );
                return Err(ConnError::AuthTimeout);
            }
        };

    drop(handshake_permit);

    let key = SessionKey {
        tenant: authorized.tenant.clone(),
        session: authorized.session,
    };

    // Home-relay binding gate: refuse a client whose authorized slot the
    // coordinator did not assign to this relay. A token binds
    // tenant/session/slot/key but not the relay itself, so without this a
    // misrouted (or malicious) client could register the same slot on two
    // relays in a true multi-relay session, feeding each a different turn at
    // the same (slot, seq) -- a split the mesh's topological dedup only
    // suppresses the symptom of, on each side, never detects or prevents.
    //
    // `slot_homed` admits (`true`) when no descriptor has arrived yet for
    // this session, or one arrived with an empty homed set (legacy, dev-mode,
    // a coordinator that predates the field) -- so this preserves today's
    // descriptor-arrival-race behavior exactly: a client dialing before any
    // descriptor exists for its session is admitted unconditionally, with no
    // new wait or window introduced here. Enforcement only ever refuses once
    // a non-empty homed set says this slot belongs to a different relay.
    if !consensus::slot_homed(&mesh.decision_makers, &key, authorized.slot) {
        connection.close(
            VarInt::from_u32(SLOT_NOT_HOMED_CLOSE),
            b"slot not homed on this relay",
        );
        return Err(ConnError::SlotNotHomed {
            tenant: key.tenant,
            session: key.session,
            slot: authorized.slot,
        });
    }

    // Cheap pre-register fast-fail against the slot's departure state, before
    // touching the roster at all: a departure recorded with no hold pending means
    // the leave was already decided (an honored drop request, or a clean leave),
    // so the re-register is hopeless and can be refused before spending a roster
    // slot on it. This is a snapshot — read before `register` below, and never
    // reused after it — which is sound only because decided-ness is monotonic (a
    // decided leave never becomes undecided again): if this snapshot is stale by
    // the time it's checked, it can only be stale in the direction of a hold that
    // has SINCE been claimed by a concurrent reconnect or decide, never the other
    // way, so a "departed" read here is never a false positive. The real
    // admission decision — the one this snapshot must never be reused for — is
    // below, keyed on current state after `register` succeeds.
    let departed = consensus::slot_departed(&mesh.decision_makers, &key, authorized.slot);
    let hold_pending = mesh.drop_holds.is_pending(&key, authorized.slot);
    if departed && !hold_pending {
        connection.close(
            VarInt::from_u32(SLOT_DEPARTED_CLOSE),
            b"slot already departed",
        );
        return Err(ConnError::SlotDeparted {
            tenant: key.tenant,
            session: key.session,
            slot: authorized.slot,
        });
    }

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

    // Write the handshake ack BEFORE touching any hold/departure state. A write
    // failure here returns via `?` with NOTHING mutated: `registration` is still
    // armed, so its guard frees the roster seat on drop (see `SlotRegistration`),
    // and neither a hold nor a departure record was ever claimed or cleared —
    // there is nothing to roll back, and nothing left inconsistent for a later
    // retry to trip over. The old ordering used to release the hold and reinstate
    // the slot first and write the ack after, so a write failure here would leave
    // the drop's hold gone and its departure record cleared with no client ever
    // actually connected — unrecoverable, since nothing was left to decide
    // against and no hold to admit a future retry's resume.
    handshake_send
        .write_all(&[HANDSHAKE_OK])
        .await
        .map_err(AuthError::from)?;
    let _ = handshake_send.finish();

    // Now decide this slot's admission against CURRENT state, not the
    // pre-register snapshot above — reusing that snapshot here is exactly the bug
    // this reorder fixes: a concurrent decide path (a survivor's `RequestDrop`
    // honored, or the abandoned-session timer's force-decide) can honor the
    // slot's drop in the gap between the snapshot and here, and a snapshot-keyed
    // release+reinstate would blindly resurrect a slot the session has already
    // moved on without — while a fresh hold, marked by this same slot's OLD link
    // finally dying in that same gap, would never be released as this connection
    // takes over. `take_if_pending` is the fix: it re-checks the hold and, if
    // still pending, reinstates the slot — atomically, under one lock
    // acquisition — so this reconnect and every decide path (an honored
    // `RequestDrop`, the abandoned-session force-decide, a superseding clean
    // leave) race the SAME linearization point, the hold's removal, and whichever
    // side wins is the one, and only one, side that acts.
    let reinstated = mesh.drop_holds.take_if_pending(&key, authorized.slot, || {
        consensus::reinstate_slot(&mesh.decision_makers, &key, authorized.slot)
    });
    if reinstated {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            slot = authorized.slot.0,
            "client re-registered while its drop was undecided; claimed the hold and reinstated",
        );
    } else if consensus::slot_departed(&mesh.decision_makers, &key, authorized.slot) {
        // Either there was no hold to claim (a clean leave already decided this
        // slot with no hold ever marked) or a concurrent decide path won the
        // claim moments ago (the hold was pending but `reinstate_slot` found the
        // leave already committed) — either way the leave is final. Refuse
        // without disarming `registration`: the guard frees the roster seat on
        // drop exactly as the pre-register fast-fail's refusal would have, and
        // the client sees the same terminal close either way.
        connection.close(
            VarInt::from_u32(SLOT_DEPARTED_CLOSE),
            b"slot already departed",
        );
        return Err(ConnError::SlotDeparted {
            tenant: key.tenant,
            session: key.session,
            slot: authorized.slot,
        });
    }
    // Neither a hold nor a departure record: a plain fresh admission (or a
    // resumed one whose hold and record another path already cleared) —
    // proceed exactly as a first-time dial would.

    registration.disarm();

    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        slot = authorized.slot.0,
        "client authorized",
    );
    routing::run_slot_link(
        // A single-ingress edge: every payload on this connection is authorized as
        // `authorized.slot`, so the link rebinds the untrusted wire slot to it
        // before dedup keys on it — keeping the receive-window anchor and dedup on
        // the same slot across a same-relay resume.
        Link::with_ingress_slot(connection, authorized.slot),
        key,
        authorized.slot,
        resume_cursors,
        inbox,
        sessions,
        mesh,
    )
    .await;
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
