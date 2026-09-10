//! Dialing, enrolling, and the reconnect loop for the coordinator control
//! connection.
//!
//! Everything that gets a connection up and decides what to do when one ends: the
//! never-returning subscriber loop and its backoff, the single connection's enroll
//! proof-of-possession handshake and read/write split, the signer that answers the
//! coordinator's challenge, and the close classification the next-dial delay keys on.

use futures_util::{SinkExt, StreamExt};
use rally_point_proto::control::{CoordinatorToRelay, ENROLL_POP_CONTEXT, RelayToCoordinator};
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::{
    CONTROL_CLOSE_DUPLICATE_RELAY_ID, CONTROL_CLOSE_ENROLL_UNAUTHORIZED,
    CONTROL_CLOSE_IDENTITY_UNPROVEN, CONTROL_CLOSE_PROTOCOL_MISMATCH, CONTROL_CLOSE_UNKNOWN_REGION,
};
use rally_point_transport::rustls::pki_types::PrivateKeyDer;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;

use super::reader::{ReaderRoutes, read_control_frames};
use super::writer::{WriterRoutes, send_draining, send_notice, write_control_frames};
use super::{
    ControlApplyTargets, ControlError, EnrollConfig, HEARTBEAT_INTERVAL, HeartbeatConfig,
    HeartbeatSources, LOAD_STATE_ASK_CAPACITY, OutboundQueues, RECONNECT_DELAY, ReconnectBackoff,
    VERSION_REFUSED_RECONNECT_DELAY,
};

/// How one control connection ended, when it ended without an error — what the
/// reconnect loop keys its next-dial delay on.
pub(super) enum ControlDisconnect {
    /// The connection closed ordinarily (a coordinator restart, a plain close, the
    /// stream ending). Redial after [`RECONNECT_DELAY`].
    Ordinary,
    /// The coordinator refused the connection over a protocol-version mismatch
    /// (close code [`CONTROL_CLOSE_PROTOCOL_MISMATCH`]). Redial only after the far
    /// longer [`VERSION_REFUSED_RECONNECT_DELAY`] — nothing changes until a deploy.
    VersionRefused,
    /// The coordinator refused the connection because this relay's `--region` is
    /// not in its configured region list (close code
    /// [`CONTROL_CLOSE_UNKNOWN_REGION`]). Like a version mismatch, hot-retrying
    /// changes nothing — the fix is a config/deploy correction — so it backs off
    /// the same [`VERSION_REFUSED_RECONNECT_DELAY`] rather than the ordinary delay.
    RegionRefused,
    /// The coordinator refused the connection because this relay's enroll
    /// proof-of-possession failed (close code
    /// [`CONTROL_CLOSE_IDENTITY_UNPROVEN`]). A bad signature (or none at all) is
    /// a config/implementation fault — a mismatched key, a broken signer — not a
    /// transient condition a redial fixes, so this backs off the same
    /// [`VERSION_REFUSED_RECONNECT_DELAY`] as a version or region refusal.
    IdentityUnproven,
    /// The coordinator refused the connection because its provisioned-relay
    /// ledger did not authorize this enroll (close code
    /// [`CONTROL_CLOSE_ENROLL_UNAUTHORIZED`]): the id was not minted, is retired,
    /// or the presented token/certificate is invalid. Redialing changes nothing —
    /// the provisioner must reissue an identity or token — so this backs off the
    /// same [`VERSION_REFUSED_RECONNECT_DELAY`] as a version, region, or identity
    /// refusal.
    EnrollUnauthorized,
}

/// Holds the coordinator control connection open and drives the Join source,
/// reconnecting whenever it drops. Spawned as a task on the relay when a
/// coordinator URL is configured; never returns.
///
/// The relay dials `enroll.coordinator_url`, enrolls with `enroll.relay_hello`, and
/// proves possession of `enroll.identity_key` when the coordinator challenges — a
/// challenge that always happens, since the relay's advertised protocol window
/// bottoms out at or above the proof-of-possession minimum, so any coordinator it
/// shares a version with reaches the challenge.
///
/// `apply_targets` are the shared handles inbound coordinator pushes are applied
/// into ([`ControlApplyTargets`]); `outbound` is the caller-owned notice and flight
/// queues the connection ships up ([`OutboundQueues`], which documents the
/// park-across-reconnect discipline); `heartbeat_sources` is what each heartbeat
/// reports on; `drain` (with `apply_targets.drain_acked`) is the
/// coordinated-drain seam; `control_connected` reports whether this relay is
/// enrolled and receiving coordinator pushes — set `true` on the first inbound
/// application frame (which an accepted enroll always sends and a refusal never
/// does), cleared on every disconnect — so the provisional-admission sweep
/// ([`crate::session::provisional::run_sweep`]) arms only while it is `true` rather than
/// reaping across a reconnect gap, and the idle self-exit
/// ([`crate::coordinator::idle_exit::run`]) reads it as the "not enrolled" half of its exit
/// condition.
///
/// This entry injects the production reconnect delays and heartbeat interval;
/// [`run_descriptor_subscriber_with`] takes them explicitly so a test need not wait
/// the production intervals.
pub async fn run_descriptor_subscriber(
    enroll: EnrollConfig,
    apply_targets: ControlApplyTargets,
    outbound: OutboundQueues,
    heartbeat_sources: HeartbeatSources,
    drain: watch::Receiver<bool>,
    control_connected: watch::Sender<bool>,
) {
    run_descriptor_subscriber_with(
        enroll,
        apply_targets,
        outbound,
        HeartbeatConfig {
            sources: heartbeat_sources,
            interval: HEARTBEAT_INTERVAL,
        },
        drain,
        control_connected,
        ReconnectBackoff {
            ordinary: RECONNECT_DELAY,
            version_refused: VERSION_REFUSED_RECONNECT_DELAY,
        },
    )
    .await
}

/// [`run_descriptor_subscriber`] with the reconnect delays and heartbeat interval
/// injected via `heartbeat` and `backoff`, so a test need not wait the production
/// intervals.
pub async fn run_descriptor_subscriber_with(
    enroll: EnrollConfig,
    apply_targets: ControlApplyTargets,
    // Caller-owned across reconnects: this loop owns the outbound queues and lends
    // `&mut` per connection, so a notice or shipment parked when a connection dies
    // rides the next connection's flush rather than being lost.
    mut outbound: OutboundQueues,
    heartbeat: HeartbeatConfig,
    mut drain: watch::Receiver<bool>,
    control_connected: watch::Sender<bool>,
    backoff: ReconnectBackoff,
) {
    let relay_id = enroll.relay_hello.relay_id;

    loop {
        let delay = match connect_and_stream(
            &enroll,
            &apply_targets,
            &mut outbound,
            &heartbeat,
            &mut drain,
            &control_connected,
        )
        .await
        {
            Ok(ControlDisconnect::Ordinary) => {
                tracing::info!(
                    relay_id = relay_id.0,
                    "coordinator control connection closed; reconnecting",
                );
                backoff.ordinary
            }
            // Already logged (with the coordinator's reason) where the close frame
            // was read; only the far longer backoff is decided here. A version
            // mismatch, an unknown region, an unproven identity, and a ledger
            // enrollment refusal are all operator/provisioner-fix-not-redial
            // refusals, so they share the long backoff. A duplicate-relay-id
            // refusal is deliberately absent from this list — it resolves on its
            // own as the stale entry ages out, so it takes the `Ordinary` path's
            // short delay instead.
            Ok(
                ControlDisconnect::VersionRefused
                | ControlDisconnect::RegionRefused
                | ControlDisconnect::IdentityUnproven
                | ControlDisconnect::EnrollUnauthorized,
            ) => backoff.version_refused,
            Err(error) => {
                tracing::warn!(
                    %error,
                    relay_id = relay_id.0,
                    "coordinator control connection failed; reconnecting",
                );
                backoff.ordinary
            }
        };
        // The connection just ended, however it ended -- report it down
        // uniformly here rather than at each of `connect_and_stream`'s several
        // exit points, so the provisional-admission sweep never observes a
        // stale "connected" reading across a reconnect gap.
        let _ = control_connected.send(false);
        tokio::time::sleep(delay).await;
    }
}

/// Dials the coordinator's control endpoint, enrolls by sending the relay's
/// `Hello` as the first frame, then applies every descriptor set the coordinator
/// pushes while sending a periodic heartbeat up the connection — until it closes
/// or errors. `applied` is updated in place across the connection's lifetime (and
/// persists into the next one). A clean ending reports *how* the connection ended
/// ([`ControlDisconnect`]), so the caller can back off a version refusal far
/// longer than an ordinary close.
///
/// Everything through the enroll handshake and its immediately-following flushes
/// runs sequentially on the whole socket. After that the socket is split into a
/// read half and a write half driven **concurrently**, so a large outbound frame
/// (a heartbeat, a close notice, or a multi-megabyte flight blob) can never stall
/// the reader while it is being sent: coordinator pushes keep applying while a blob
/// goes up. The two halves cooperate on one task — dropping either when the other
/// ends closes the connection with no task to leak — and every send is owned by the
/// write half, keeping the notice pipe strictly ordered and the caller-owned
/// `pending` slot and `pending_flights` table the single source of undelivered
/// state across a reconnect.
///
/// A heartbeat send that fails ends the connection so the caller redials: on a
/// half-open socket (a silently dead coordinator) the periodic send is what
/// eventually surfaces the failure, since no inbound frame arrives to reveal it.
async fn connect_and_stream(
    enroll: &EnrollConfig,
    apply_targets: &ControlApplyTargets,
    outbound: &mut OutboundQueues,
    heartbeat: &HeartbeatConfig,
    drain: &mut watch::Receiver<bool>,
    control_connected: &watch::Sender<bool>,
) -> Result<ControlDisconnect, ControlError> {
    let relay_id = enroll.relay_hello.relay_id;
    let request = build_request(&enroll.coordinator_url, enroll.bootstrap_secret.as_deref())?;
    let (mut socket, _response) = tokio_tungstenite::connect_async(request).await?;

    // Enroll: the first frame is this relay's Hello, registering it on the same
    // authenticated connection that then carries descriptor pushes back.
    let hello = serde_json::to_string(&RelayToCoordinator::Hello(enroll.relay_hello.clone()))
        .expect("a relay hello always serializes");
    socket.send(Message::Text(hello.into())).await?;
    tracing::info!(
        relay_id = relay_id.0,
        "coordinator control connection established",
    );

    // Complete the enroll proof-of-possession handshake before sending any
    // application frame. The coordinator sends an `IdentityChallenge` as the
    // first frame after the Hello and reads exactly one frame back expecting the
    // `IdentityProof`; if a pending notice or a drain re-assert reached the wire
    // first, the coordinator would read that instead and refuse the enroll — and
    // a pending notice persists across reconnects, locking the relay out of
    // re-enrolling indefinitely. Read frames until the challenge is answered.
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                match serde_json::from_str::<CoordinatorToRelay>(text.as_str())? {
                    CoordinatorToRelay::IdentityChallenge { nonce } => {
                        answer_identity_challenge(
                            &mut socket,
                            &enroll.identity_key,
                            &nonce,
                            relay_id,
                        )
                        .await?;
                        break;
                    }
                    // The coordinator always challenges first, so any other frame
                    // here is a protocol violation. End the connection rather than
                    // proceed un-enrolled; the caller redials.
                    _ => {
                        tracing::warn!(
                            relay_id = relay_id.0,
                            "coordinator sent a control frame before the enroll challenge; \
                             disconnecting",
                        );
                        return Ok(ControlDisconnect::Ordinary);
                    }
                }
            }
            // A refusal that arrives before the challenge: the coordinator
            // validates version and region before challenging and closes on
            // failure. Classify it with the same helper the steady-state loop uses.
            Some(Ok(Message::Close(frame))) => {
                return Ok(classify_control_close(frame, relay_id));
            }
            // Ping/pong (and any other non-text frame) carry no enrollment content;
            // keep reading for the challenge.
            Some(Ok(_)) => continue,
            // A read error ends the connection with that error.
            Some(Err(error)) => return Err(error.into()),
            // The stream ended before the challenge; let the caller redial.
            None => return Ok(ControlDisconnect::Ordinary),
        }
    }

    // The enroll handshake is complete, so application frames may now go out.
    // Flush a notice held over from a prior connection first: one decided while
    // the coordinator was down (or one a failed send left pending) must go out on
    // this fresh connection before anything else, so it is not lost to the
    // reconnect. On send failure it stays pending and rides the next reconnect.
    if let Some(notice) = outbound.pending.as_ref() {
        send_notice(&mut socket, notice).await?;
        outbound.pending = None;
    }

    // Re-assert a drain that is already in progress. A re-enroll clears the
    // coordinator-side draining flag, so if we are mid-drain this fresh connection
    // must re-send `Draining` (right after enrolling, ahead of the steady-state
    // loop) or the coordinator would treat us as available again.
    // `borrow_and_update` also marks the current value seen, so the loop's
    // `drain.changed()` below fires only on a *new* transition.
    if *drain.borrow_and_update() {
        send_draining(&mut socket).await?;
    }

    // Shipments held over from a prior connection are NOT flushed here: their bytes
    // never ride the socket. They stay parked in `pending_flights`, and the write half
    // re-sends each one's small `FlightUploadRequest` at its own entry (below), so a
    // shipment orphaned by a dead connection simply re-requests an upload URL on the
    // next one.

    // Split the enrolled socket into a read half and a write half, driven
    // concurrently. The write half owns every send, so a stalled send never stalls the
    // read half — coordinator pushes keep applying while the writer works its queues
    // and drives its uploads' request/grant/done handshakes.
    let (sink, stream) = socket.split();

    // The reader records the descriptor apply lag into the same stats handle the
    // writer refreshes the queue depths on; a clone points at the shared atomics, so
    // the reader can write it without contending with the writer's `&mut outbound`.
    let read_stats = outbound.stats.clone();

    // A mid-stream identity challenge's answer is a *send*, and only the write
    // half may send, so the read half routes the nonce here for the writer to
    // answer. The coordinator does not re-challenge after enroll, so this is a
    // rarely-if-ever-used defensive path.
    let (challenge_tx, challenge_rx) = tokio::sync::mpsc::unbounded_channel();

    // A flight-upload grant or refusal is read on the read half but acted on by the
    // write half (which owns the parked shipment and its upload lifecycle), so the read
    // half routes it here — the same shape as the challenge channel.
    let (flight_grant_tx, flight_grant_rx) = tokio::sync::mpsc::unbounded_channel();

    // A load-state request is read on the read half but answered by the write half,
    // which owns every send and the heartbeat sources the snapshot is built from.
    // Unlike the challenge and grant channels this one is bounded: a load-state read
    // is a tenant-driven fan-out, so a backed-up writer must shed questions rather
    // than queue them behind a caller that has already given up.
    let (load_state_tx, load_state_rx) = tokio::sync::mpsc::channel(LOAD_STATE_ASK_CAPACITY);

    // Run both halves until either ends; the first to finish is the connection's
    // outcome, and dropping the other closes its half of the socket. There is no
    // spawned task to leak, and the caller-owned `outbound` slots — mutated in place
    // by the writer through `&mut` — carry whatever stayed undelivered straight back
    // to the caller no matter which half ended the connection.
    tokio::select! {
        result = read_control_frames(
            stream,
            apply_targets,
            relay_id,
            ReaderRoutes {
                challenge_tx,
                flight_grant_tx,
                load_state_tx,
            },
            read_stats,
            control_connected,
        ) => result,
        result = write_control_frames(
            sink,
            outbound,
            drain,
            heartbeat,
            &enroll.identity_key,
            relay_id,
            WriterRoutes {
                challenge_rx,
                flight_grant_rx,
                load_state_rx,
            },
        ) => result,
    }
}

/// Answers the coordinator's enroll proof-of-possession challenge: signs
/// `ENROLL_POP_CONTEXT ++ nonce` with the relay's identity key (see
/// [`sign_enroll_proof`]) and sends the [`RelayToCoordinator::IdentityProof`] up
/// the connection, so the coordinator's verification against the certificate the
/// `Hello` presented succeeds.
///
/// A key this relay's own certificate loading could never have produced cannot
/// sign the challenge; that surfaces as [`ControlError::UnsupportedIdentityKey`],
/// ending the connection rather than proceeding un-enrolled. Both the enroll
/// handshake and the steady-state loop's defensive re-answer route through here,
/// so a challenge is answered identically wherever it arrives.
pub(super) async fn answer_identity_challenge(
    socket: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    identity_key: &PrivateKeyDer<'static>,
    nonce: &[u8; 32],
    relay_id: RelayId,
) -> Result<(), ControlError> {
    match sign_enroll_proof(identity_key, nonce) {
        Some(signature) => {
            let frame = serde_json::to_string(&RelayToCoordinator::IdentityProof { signature })
                .expect("an identity-proof frame always serializes");
            socket.send(Message::Text(frame.into())).await?;
            Ok(())
        }
        None => {
            tracing::error!(
                relay_id = relay_id.0,
                "cannot answer the coordinator's enroll proof-of-possession challenge: \
                 the loaded private key is not a supported algorithm",
            );
            Err(ControlError::UnsupportedIdentityKey)
        }
    }
}

/// Classifies a coordinator control-connection close into the
/// [`ControlDisconnect`] the reconnect loop backs its next-dial delay on, logging
/// the coordinator's stated reason at the level each code warrants. Shared by the
/// enroll handshake and the steady-state loop so a close is read identically
/// whether it lands before or after the identity challenge.
///
/// A version mismatch, an unknown region, and an unproven identity are
/// operator-fix-not-redial refusals — each maps to its own long-backoff variant.
/// A duplicate-relay-id refusal (a stale predecessor entry that ages out on its
/// own) is logged distinctly but takes the ordinary short delay, as does every
/// other close, so retrying is exactly what lets the enroll converge once the
/// stale entry expires.
pub(super) fn classify_control_close(
    frame: Option<CloseFrame>,
    relay_id: RelayId,
) -> ControlDisconnect {
    let Some(frame) = frame else {
        return ControlDisconnect::Ordinary;
    };
    match u16::from(frame.code) {
        CONTROL_CLOSE_PROTOCOL_MISMATCH => {
            tracing::error!(
                relay_id = relay_id.0,
                reason = %frame.reason,
                "coordinator refused our protocol version; backing off until a deploy resolves the skew",
            );
            ControlDisconnect::VersionRefused
        }
        CONTROL_CLOSE_UNKNOWN_REGION => {
            tracing::error!(
                relay_id = relay_id.0,
                reason = %frame.reason,
                "coordinator refused our region; backing off until the region config is fixed",
            );
            ControlDisconnect::RegionRefused
        }
        CONTROL_CLOSE_IDENTITY_UNPROVEN => {
            tracing::error!(
                relay_id = relay_id.0,
                reason = %frame.reason,
                "coordinator rejected our enroll proof of possession; backing off until the key/cert mismatch is fixed",
            );
            ControlDisconnect::IdentityUnproven
        }
        CONTROL_CLOSE_ENROLL_UNAUTHORIZED => {
            tracing::error!(
                relay_id = relay_id.0,
                reason = %frame.reason,
                "coordinator's ledger did not authorize our enrollment; backing off until the provisioner reissues our identity/token",
            );
            ControlDisconnect::EnrollUnauthorized
        }
        CONTROL_CLOSE_DUPLICATE_RELAY_ID => {
            tracing::warn!(
                relay_id = relay_id.0,
                reason = %frame.reason,
                "coordinator refused our relay id as already enrolled under a different certificate; retrying",
            );
            ControlDisconnect::Ordinary
        }
        _ => ControlDisconnect::Ordinary,
    }
}

/// Signs `nonce` for the enroll proof-of-possession exchange: the exact bytes
/// `ENROLL_POP_CONTEXT ++ nonce`, using the relay's TLS private key — the same
/// key backing the certificate its `Hello` presented, so the coordinator's
/// verification against that certificate's public key succeeds. `pub` so the
/// coordinator's own tests can cross-verify this signer against its verifier
/// without reimplementing signing there.
///
/// The key is always PKCS#8 in this codebase — `config::self_signed_cert`'s
/// `rcgen` key and `config::load_cert`'s PEM parser both only ever produce
/// [`PrivateKeyDer::Pkcs8`] — and its algorithm is either ECDSA P-256 (the
/// `rcgen` self-signed default) or Ed25519 (a PEM-supplied key), the same two
/// algorithms the coordinator's verifier accepts. A PKCS#8 blob doesn't
/// self-announce which one it encodes, so this tries ECDSA first, then
/// Ed25519. Returns `None` for a key this relay's own cert loading could never
/// have produced (not PKCS#8, or PKCS#8 bytes neither loader accepts) — there
/// is no proof to offer, so the caller leaves the challenge unanswered and the
/// coordinator's own timeout refuses the connection.
pub fn sign_enroll_proof(
    identity_key: &PrivateKeyDer<'static>,
    nonce: &[u8; 32],
) -> Option<Vec<u8>> {
    let PrivateKeyDer::Pkcs8(pkcs8) = identity_key else {
        return None;
    };
    let mut message = ENROLL_POP_CONTEXT.to_vec();
    message.extend_from_slice(nonce);

    let rng = ring::rand::SystemRandom::new();
    if let Ok(pair) = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8.secret_pkcs8_der(),
        &rng,
    ) {
        return pair
            .sign(&rng, &message)
            .ok()
            .map(|signature| signature.as_ref().to_vec());
    }
    if let Ok(pair) = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.secret_pkcs8_der()) {
        return Some(pair.sign(&message).as_ref().to_vec());
    }
    None
}

/// Draws this relay process's identity — the value its every
/// [`RelayHello`](rally_point_proto::control::RelayHello) carries as `boot_id`, telling the coordinator a redialing control
/// connection apart from a restarted process whose retained per-session state is
/// gone.
///
/// Call exactly once at startup and reuse the result for the process's whole life:
/// a value that changed mid-process would read as a restart, and one that survived
/// a restart would falsely claim the relay's memory did. `None` when the system RNG
/// refuses, which leaves the hello unstamped — the coordinator then assumes no
/// continuity, the same conservative reading it applies to a relay build that
/// predates the field.
pub fn new_boot_id() -> Option<u64> {
    let rng = ring::rand::SystemRandom::new();
    ring::rand::generate::<[u8; 8]>(&rng)
        .ok()
        .map(|bytes| u64::from_le_bytes(bytes.expose()))
}

/// Builds the WebSocket upgrade request: the control URL plus, when a secret is
/// configured, the `Authorization: Bearer <secret>` header the coordinator
/// checks before upgrading. The relay's identity rides the enroll `Hello`, not
/// the URL, so the path carries no relay id.
pub(super) fn build_request(
    coordinator_url: &str,
    secret: Option<&str>,
) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request, ControlError> {
    let base = to_ws_scheme(coordinator_url);
    let url = format!("{}/relay/control", base.trim_end_matches('/'));
    let mut request = url.into_client_request()?;
    if let Some(secret) = secret {
        let value = format!("Bearer {secret}").parse()?;
        request.headers_mut().insert(AUTHORIZATION, value);
    }
    Ok(request)
}

/// Rewrites an `http(s)://` coordinator base URL to its `ws(s)://` equivalent so
/// the same `--coordinator-url` works for both the JSON endpoints and the
/// WebSocket. A value already using a `ws` scheme passes through.
///
/// A `wss://` URL connects over rustls (this workspace's ring provider) and
/// validates the coordinator's certificate against the public web PKI roots —
/// fine for a publicly-trusted coordinator cert. Trusting an internal-CA or
/// self-signed coordinator cert (a custom root store, as the mesh edge takes via
/// `--mesh-roots`) is part of the deferred relay-trust / internal-CA work; until
/// then a `wss://` coordinator must present a publicly-trusted cert, or the
/// secret-bearing channel must run on trusted transport as `ws://`.
pub(super) fn to_ws_scheme(base: &str) -> String {
    if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_owned()
    }
}
