//! The relay's coordinator client: hold a control connection open and drive the
//! Join source from the descriptors the coordinator pushes down it.
//!
//! This is the relay side of the persistent coordinator↔relay control connection.
//! The relay dials the coordinator's control endpoint (a WebSocket), presents its
//! bootstrap secret, and **enrolls** by sending its `Hello` (id + reachable
//! address) as the first frame — registering itself over the same authenticated
//! connection rather than a separate phone-home. It then receives the
//! coordinator's pushes: the relay's current [`SessionDescriptor`] set, sent on
//! connect and again whenever it changes. Each set is fed to the [`MeshControl`]
//! Join source, which turns it into targeted mesh `Join`/`Leave`.
//!
//! # Why a held connection, not polling
//!
//! The relay reaches *out* to the coordinator (one connection, dialed by the
//! relay) rather than the coordinator reaching into a relay that churns under
//! scale-to-zero and may sit behind a firewall. Holding the connection open means
//! the coordinator pushes a change the instant it happens — no poll interval of
//! staleness — and the connection itself is a liveness signal: when it drops, each
//! side knows immediately. The relay also sends a periodic heartbeat up the
//! connection so the coordinator can tell a live relay from one whose connection
//! died silently (a half-open socket that never delivered a close). Heartbeats go
//! up, descriptors come down. One connection, authenticated once.
//!
//! # Declarative sets, reconnect, and removals
//!
//! Each pushed message is the relay's **whole current set**, not a delta. The set
//! is declarative — re-applying a descriptor already in effect is a no-op on the
//! Join source — so a reconnect (the coordinator re-sends the full set first
//! thing) converges rather than double-applies, and a dropped message is corrected
//! by the next one. The one thing a full set must do that a delta would carry
//! explicitly is detect *removals*: a session gone from the set is one to leave.
//! That is what `applied` tracks — the sessions delivered on the last set — and it
//! is kept **across reconnects** so a session removed while the relay was
//! disconnected is left when the next connection's full set arrives without it.

use std::collections::HashSet;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rally_point_proto::control::{
    CoordinatorToRelay, RelayHello, RelayToCoordinator, SessionDescriptor,
};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

use crate::consensus::RelayNotice;
use crate::mesh_control::MeshControl;
use crate::routing::SessionKey;

/// How long to wait before redialing after the control connection drops. The
/// control plane is not latency-critical and a running game does not depend on
/// the connection, so a couple of seconds avoids hammering a coordinator that is
/// restarting or briefly unreachable.
pub const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// How often the relay sends a heartbeat up its control connection, so the
/// coordinator can tell a live relay from one whose connection died silently. Well
/// under the coordinator's liveness deadline, so a single dropped beat or ordinary
/// jitter never trips it. The send doubles as the relay's own dead-coordinator
/// detector: a heartbeat on a half-open socket eventually errors, ending the
/// connection so the relay redials.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Why a control-connection attempt ended.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// Building the request, dialing, the handshake, or a read on the WebSocket
    /// failed — including a rejected auth handshake (a non-101 response). Boxed
    /// because `tungstenite::Error` is large and would bloat every `Result`.
    #[error("coordinator control connection failed: {0}")]
    WebSocket(Box<tokio_tungstenite::tungstenite::Error>),
    /// A pushed control message did not decode.
    #[error("decoding a coordinator control message failed: {0}")]
    Decode(#[from] serde_json::Error),
    /// The `Authorization` header value could not be built from the secret.
    #[error("building the control request authorization failed: {0}")]
    Authorization(#[from] tokio_tungstenite::tungstenite::http::header::InvalidHeaderValue),
}

impl From<tokio_tungstenite::tungstenite::Error> for ControlError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        ControlError::WebSocket(Box::new(error))
    }
}

/// Holds the coordinator control connection open and drives the Join source,
/// reconnecting whenever it drops. Spawned as a task on the relay when a
/// coordinator URL is configured; never returns.
///
/// `relay_hello` is the relay's identity + reachable address, sent as the first
/// frame on each connection to enroll into the coordinator's registry.
///
/// `notices` is the drain end of the decision-maker registry's notifier: the
/// leave sites push a departure and the desync comparator pushes a desync (both
/// as [`RelayNotice`]) onto it, and this loop forwards each up the control
/// connection. The channel is unbounded and held across reconnects, so a notice
/// decided while the coordinator is down goes out on the next successful
/// connection rather than being lost.
pub async fn run_descriptor_subscriber(
    coordinator_url: String,
    relay_hello: RelayHello,
    bootstrap_secret: Option<String>,
    control: MeshControl,
    notices: UnboundedReceiver<RelayNotice>,
) {
    run_descriptor_subscriber_with(
        coordinator_url,
        relay_hello,
        bootstrap_secret,
        control,
        notices,
        RECONNECT_DELAY,
        HEARTBEAT_INTERVAL,
    )
    .await
}

/// [`run_descriptor_subscriber`] with the reconnect delay and heartbeat interval
/// injected, so a test need not wait the production intervals.
pub async fn run_descriptor_subscriber_with(
    coordinator_url: String,
    relay_hello: RelayHello,
    bootstrap_secret: Option<String>,
    control: MeshControl,
    mut notices: UnboundedReceiver<RelayNotice>,
    reconnect_delay: Duration,
    heartbeat_interval: Duration,
) {
    // Kept across reconnects: a session removed while disconnected is left when
    // the next connection's full-set re-sync arrives without it.
    let mut applied: HashSet<SessionKey> = HashSet::new();
    // The one notice pulled from the channel but not yet confirmed sent. Held
    // across reconnects so a notice decided (or half-sent) while the coordinator
    // link was down is flushed first on the next connection rather than lost. The
    // rest stay queued in the unbounded channel behind it.
    let mut pending: Option<RelayNotice> = None;
    let relay_id = relay_hello.relay_id;

    loop {
        match connect_and_stream(
            &coordinator_url,
            &relay_hello,
            bootstrap_secret.as_deref(),
            &control,
            &mut applied,
            &mut notices,
            &mut pending,
            heartbeat_interval,
        )
        .await
        {
            Ok(()) => tracing::info!(
                relay_id = relay_id.0,
                "coordinator control connection closed; reconnecting",
            ),
            Err(error) => tracing::warn!(
                %error,
                relay_id = relay_id.0,
                "coordinator control connection failed; reconnecting",
            ),
        }
        tokio::time::sleep(reconnect_delay).await;
    }
}

/// Dials the coordinator's control endpoint, enrolls by sending the relay's
/// `Hello` as the first frame, then applies every descriptor set the coordinator
/// pushes while sending a periodic heartbeat up the connection — until it closes
/// or errors. `applied` is updated in place across the connection's lifetime (and
/// persists into the next one).
///
/// A heartbeat send that fails ends the connection so the caller redials: on a
/// half-open socket (a silently dead coordinator) the periodic send is what
/// eventually surfaces the failure, since no inbound frame arrives to reveal it.
#[allow(clippy::too_many_arguments)]
async fn connect_and_stream(
    coordinator_url: &str,
    relay_hello: &RelayHello,
    secret: Option<&str>,
    control: &MeshControl,
    applied: &mut HashSet<SessionKey>,
    notices: &mut UnboundedReceiver<RelayNotice>,
    pending: &mut Option<RelayNotice>,
    heartbeat_interval: Duration,
) -> Result<(), ControlError> {
    let relay_id = relay_hello.relay_id;
    let request = build_request(coordinator_url, secret)?;
    let (mut socket, _response) = tokio_tungstenite::connect_async(request).await?;

    // Enroll: the first frame is this relay's Hello, registering it on the same
    // authenticated connection that then carries descriptor pushes back.
    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello.clone()))
        .expect("a relay hello always serializes");
    socket.send(Message::Text(hello.into())).await?;
    tracing::info!(
        relay_id = relay_id.0,
        "coordinator control connection established",
    );

    // Flush a notice held over from a prior connection first: one decided while
    // the coordinator was down (or one a failed send left pending) must go out on
    // this fresh connection before anything else, so it is not lost to the
    // reconnect. On send failure it stays pending and rides the next reconnect.
    if let Some(notice) = pending.as_ref() {
        send_notice(&mut socket, notice).await?;
        *pending = None;
    }

    // The Hello already proved liveness at t=0, so skip the immediate first tick
    // and send the first heartbeat one interval later.
    let mut heartbeat = tokio::time::interval(heartbeat_interval);
    heartbeat.tick().await;

    // Once the notifier's senders are all dropped (relay shutdown) `recv` yields
    // `None` forever; stop selecting on it so the loop doesn't spin.
    let mut notifier_open = true;

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let frame = serde_json::to_string(&RelayToCoordinator::Heartbeat)
                    .expect("a heartbeat always serializes");
                socket.send(Message::Text(frame.into())).await?;
            }
            message = socket.next() => {
                let Some(message) = message else { break };
                match message? {
                    Message::Text(text) => {
                        apply_message(control, serde_json::from_str(text.as_str())?, applied);
                    }
                    Message::Close(_) => break,
                    // The coordinator sends no pings today and the relay reads only
                    // descriptor text frames; any other frame is ignored.
                    Message::Ping(_) | Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => {}
                }
            }
            // Drain one notice at a time: pull the next only once the current one
            // is confirmed sent (the `pending.is_none()` guard), so an undelivered
            // notice always sits in `pending` where the reconnect flush above
            // picks it up.
            notice = notices.recv(), if pending.is_none() && notifier_open => {
                match notice {
                    Some(notice) => {
                        *pending = Some(notice);
                        // A send error ends the connection (via `?`) with the
                        // notice still pending, so the next connection flushes it.
                        send_notice(&mut socket, pending.as_ref().expect("just set")).await?;
                        *pending = None;
                    }
                    None => notifier_open = false,
                }
            }
        }
    }
    Ok(())
}

/// Sends one relay notice up the control connection as a tagged JSON frame,
/// wrapping it into the matching [`RelayToCoordinator`] variant by kind.
async fn send_notice(
    socket: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    notice: &RelayNotice,
) -> Result<(), ControlError> {
    let frame = match notice {
        RelayNotice::Departure(notice) => RelayToCoordinator::Departure(notice.clone()),
        RelayNotice::Desync(notice) => RelayToCoordinator::Desync(notice.clone()),
        RelayNotice::Result(notice) => RelayToCoordinator::Result(notice.clone()),
        RelayNotice::SessionClosed { tenant, session } => RelayToCoordinator::SessionClosed {
            tenant: tenant.clone(),
            session: *session,
        },
    };
    let text = serde_json::to_string(&frame).expect("a relay notice always serializes");
    socket.send(Message::Text(text.into())).await?;
    Ok(())
}

/// Applies one decoded control message to the Join source.
///
/// A descriptor set reconciles membership; an unrecognized message kind (one a
/// newer coordinator sent that this build predates) is skipped, not an error —
/// the [`CoordinatorToRelay::Unknown`] catch-all already kept the decode from
/// failing, so the connection stays up and later descriptors keep flowing. A
/// *malformed* known message still surfaces as a decode error at the call site,
/// closing the connection so the next one re-syncs — that is a coordinator bug,
/// not a forward-compatible addition, and should not be silently swallowed.
fn apply_message(
    control: &MeshControl,
    message: CoordinatorToRelay,
    applied: &mut HashSet<SessionKey>,
) {
    match message {
        CoordinatorToRelay::Descriptors { descriptors } => {
            reconcile(control, &descriptors, applied);
        }
        CoordinatorToRelay::CloseSlot {
            tenant,
            session,
            slots,
        } => {
            let key = SessionKey { tenant, session };
            control.close_slots(&key, &slots);
        }
        CoordinatorToRelay::Unknown => {
            tracing::debug!("ignoring an unrecognized coordinator control message");
        }
    }
}

/// Builds the WebSocket upgrade request: the control URL plus, when a secret is
/// configured, the `Authorization: Bearer <secret>` header the coordinator
/// checks before upgrading. The relay's identity rides the enroll `Hello`, not
/// the URL, so the path carries no relay id.
fn build_request(
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
fn to_ws_scheme(base: &str) -> String {
    if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_owned()
    }
}

/// Drives the Join source to exactly the pushed descriptor set: applies each
/// descriptor, then leaves any session that was applied before but is no longer
/// present. Updates `applied` to the new set.
///
/// Apply-then-leave, both idempotent on the Join source: a descriptor already in
/// effect re-applies as a no-op, and a `Leave` for a session already gone is a
/// no-op. So a re-sync of an unchanged set issues no commands, and a shrunk set
/// issues only the leaves for what dropped.
fn reconcile(
    control: &MeshControl,
    descriptors: &[SessionDescriptor],
    applied: &mut HashSet<SessionKey>,
) {
    let present: HashSet<SessionKey> = descriptors
        .iter()
        .map(|d| SessionKey {
            tenant: d.tenant.clone(),
            session: d.session,
        })
        .collect();

    for descriptor in descriptors {
        control.apply_descriptor(descriptor);
    }
    for key in applied.difference(&present) {
        control.end_session(key);
    }

    *applied = present;
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use crate::mesh::MeshCommand;
    use rally_point_proto::control::{
        BufferBounds, DepartureNotice, DesyncNotice, DivergedSlot, RelayPeer, TenantId,
    };
    use rally_point_proto::ids::{RelayId, SessionId};
    use tokio::sync::mpsc;

    const TENANT: &str = "sb-test";

    fn key(session: u64) -> SessionKey {
        SessionKey {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(session),
        }
    }

    fn descriptor(session: u64, peers: &[u64]) -> SessionDescriptor {
        SessionDescriptor {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(session),
            peers: peers
                .iter()
                .map(|&id| RelayPeer {
                    relay_id: RelayId(id),
                    relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900 + id as u16)),
                    cert_der: vec![id as u8; 4],
                })
                .collect(),
            bounds: BufferBounds::new(1, 6).unwrap(),
            authority_order: vec![],
            external_id: None,
            slot_refs: vec![],
            observer_slots: vec![],
            expected_slots: vec![],
        }
    }

    #[test]
    fn reconcile_applies_descriptors_then_leaves_dropped_sessions() {
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        control.register_link(RelayId(2), tx2);
        let mut applied = HashSet::new();

        // First push: session 1 names peer 2 → Join.
        reconcile(&control, &[descriptor(1, &[2])], &mut applied);
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
        assert!(applied.contains(&key(1)));

        // Second push: the session has dropped out of the set → Leave.
        reconcile(&control, &[], &mut applied);
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
        assert!(applied.is_empty());
    }

    #[test]
    fn reconcile_is_idempotent_on_a_repeated_set() {
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        control.register_link(RelayId(2), tx2);
        let mut applied = HashSet::new();

        reconcile(&control, &[descriptor(1, &[2])], &mut applied);
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));

        // A re-sync of the same set (e.g. on reconnect) issues no further commands.
        reconcile(&control, &[descriptor(1, &[2])], &mut applied);
        assert!(rx2.try_recv().is_err(), "an unchanged set is a no-op");
    }

    #[test]
    fn reconcile_tracks_multiple_sessions_and_leaves_only_the_one_that_dropped() {
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        control.register_link(RelayId(2), tx2);
        let mut applied = HashSet::new();

        // Two sessions on the link to peer 2.
        reconcile(
            &control,
            &[descriptor(1, &[2]), descriptor(2, &[2])],
            &mut applied,
        );
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(2)));

        // Session 1 ends; session 2 remains. Only session 1 is left.
        reconcile(&control, &[descriptor(2, &[2])], &mut applied);
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
        assert!(rx2.try_recv().is_err(), "session 2 stays joined");
        assert_eq!(applied, HashSet::from([key(2)]));
    }

    #[tokio::test]
    async fn a_close_slot_message_signals_the_named_held_slot() {
        // A CloseSlot down-frame reaches the roster: the named slot's shutdown
        // signal fires (its link task would then close and deregister), and a slot
        // the relay does not hold is a harmless no-op.
        let sessions: crate::routing::Sessions = std::sync::Arc::default();
        let mesh_links = crate::mesh::new_mesh_links();
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        )
        .with_broadcast(sessions.clone(), mesh_links);

        let (mut guard, inbox) =
            crate::routing::register(&sessions, &key(1), rally_point_proto::ids::SlotId(0))
                .expect("slot 0 registers");
        guard.disarm();
        let shutdown = inbox.shutdown_handle();

        let mut applied = HashSet::new();
        apply_message(
            &control,
            CoordinatorToRelay::CloseSlot {
                tenant: TenantId(TENANT.to_owned()),
                session: SessionId(1),
                // Name a held slot and one the relay does not hold.
                slots: vec![
                    rally_point_proto::ids::SlotId(0),
                    rally_point_proto::ids::SlotId(7),
                ],
            },
            &mut applied,
        );

        tokio::time::timeout(Duration::from_millis(100), shutdown.notified())
            .await
            .expect("the held slot was signaled to close");
    }

    #[test]
    fn an_unknown_message_is_skipped_and_does_not_disturb_state_or_later_messages() {
        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        control.register_link(RelayId(2), tx2);
        let mut applied = HashSet::new();

        // A known message joins session 1.
        apply_message(
            &control,
            CoordinatorToRelay::Descriptors {
                descriptors: vec![descriptor(1, &[2])],
            },
            &mut applied,
        );
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));

        // An unknown message is a no-op: no commands, applied state untouched.
        apply_message(&control, CoordinatorToRelay::Unknown, &mut applied);
        assert!(rx2.try_recv().is_err(), "an unknown message issues nothing");
        assert_eq!(applied, HashSet::from([key(1)]));

        // A later known message still applies — the unknown one did not break the
        // stream's state.
        apply_message(
            &control,
            CoordinatorToRelay::Descriptors {
                descriptors: vec![],
            },
            &mut applied,
        );
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
    }

    #[test]
    fn an_unknown_frame_decodes_and_skips_rather_than_closing_the_stream() {
        // The exact rolling-deploy path: a frame a newer coordinator sent that
        // this build predates decodes to `Unknown` (not the serde error that
        // would propagate and close the connection), and applies as a no-op.
        let json = r#"{"type":"future_thing","whatever":true}"#;
        let message: CoordinatorToRelay =
            serde_json::from_str(json).expect("an unknown type must not be a decode error");
        assert_eq!(message, CoordinatorToRelay::Unknown);

        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        control.register_link(RelayId(2), tx2);
        let mut applied = HashSet::new();
        apply_message(&control, message, &mut applied);
        assert!(rx2.try_recv().is_err());
        assert!(applied.is_empty());
    }

    #[test]
    fn to_ws_scheme_rewrites_http_and_passes_ws_through() {
        assert_eq!(to_ws_scheme("http://host:14910"), "ws://host:14910");
        assert_eq!(to_ws_scheme("https://host:14910"), "wss://host:14910");
        assert_eq!(to_ws_scheme("ws://host:14910"), "ws://host:14910");
    }

    #[test]
    fn build_request_targets_the_control_path_and_sets_the_bearer() {
        let request = build_request("http://host:14910/", Some("s3cret")).unwrap();
        assert_eq!(request.uri().path(), "/relay/control");
        assert_eq!(request.uri().scheme_str(), Some("ws"));
        assert_eq!(
            request.headers().get(AUTHORIZATION).unwrap(),
            "Bearer s3cret",
        );
    }

    #[test]
    fn build_request_without_a_secret_sets_no_authorization() {
        let request = build_request("http://host:14910", None).unwrap();
        assert!(request.headers().get(AUTHORIZATION).is_none());
    }

    fn dropped_notice() -> DepartureNotice {
        DepartureNotice {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(42),
            slot: rally_point_proto::ids::SlotId(2),
            kind: rally_point_proto::control::DepartureKind::Dropped,
            reason: 0x4000_0006,
            leave_seq: 3,
            external_id: None,
            external_ref: None,
            result: None,
        }
    }

    fn desync_notice() -> DesyncNotice {
        DesyncNotice {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(42),
            sync_ordinal: 91,
            game_frame: Some(3000),
            detected_at_ms: 1_700_000_000_000,
            no_majority: false,
            diverged: vec![DivergedSlot {
                slot: rally_point_proto::ids::SlotId(1),
                external_ref: Some("sb-user-1".to_owned()),
            }],
            external_id: Some("game-42".to_owned()),
        }
    }

    /// Captures every frame a `send_notice` writes, so a test can assert exactly
    /// what went on the wire. The sink carries the WebSocket's error type, so the
    /// generic bound is satisfied exactly as the live socket satisfies it.
    async fn capture_sent(notice: &RelayNotice) -> Vec<Message> {
        use std::sync::{Arc, Mutex};

        let captured: Arc<Mutex<Vec<Message>>> = Arc::default();
        let for_sink = Arc::clone(&captured);
        let mut sink = Box::pin(futures_util::sink::unfold(
            (),
            move |(), message: Message| {
                let for_sink = Arc::clone(&for_sink);
                async move {
                    for_sink.lock().unwrap().push(message);
                    Ok::<(), tokio_tungstenite::tungstenite::Error>(())
                }
            },
        ));
        send_notice(&mut sink, notice).await.unwrap();
        let frames = captured.lock().unwrap();
        frames.clone()
    }

    #[tokio::test]
    async fn send_notice_emits_one_tagged_departure_frame() {
        let notice = RelayNotice::Departure(dropped_notice());
        let frames = capture_sent(&notice).await;
        assert_eq!(frames.len(), 1, "exactly one frame");
        let Message::Text(text) = &frames[0] else {
            panic!("a text frame");
        };
        let decoded: RelayToCoordinator = serde_json::from_str(text).unwrap();
        assert_eq!(decoded, RelayToCoordinator::Departure(dropped_notice()));
    }

    #[tokio::test]
    async fn send_notice_emits_one_tagged_desync_frame() {
        // The desync kind rides the same pipe and wraps into the matching frame.
        let notice = RelayNotice::Desync(desync_notice());
        let frames = capture_sent(&notice).await;
        assert_eq!(frames.len(), 1, "exactly one frame");
        let Message::Text(text) = &frames[0] else {
            panic!("a text frame");
        };
        assert!(text.contains("\"type\":\"desync\""));
        let decoded: RelayToCoordinator = serde_json::from_str(text).unwrap();
        assert_eq!(decoded, RelayToCoordinator::Desync(desync_notice()));
    }

    /// A notice queued while the coordinator is unreachable is delivered on the
    /// next successful connection, not lost. The first dial fails at the handshake
    /// (the server drops the socket), so the relay never touches the channel; the
    /// second dial completes, and the queued notice flushes right after the Hello.
    /// Run for both notice kinds, since they share the one buffered pipe.
    async fn a_queued_notice_is_delivered_after_a_reconnect(queued: RelayNotice) {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frame_tx, frame_rx) = tokio::sync::oneshot::channel();

        // The stand-in coordinator: fail the first dial, then accept the second
        // and capture the frame that follows the enroll Hello.
        tokio::spawn(async move {
            // First connection: drop it mid-handshake so the relay's connect
            // fails and it redials — without ever entering its send loop, so the
            // queued notice stays in the channel rather than being consumed here.
            let (first, _) = listener.accept().await.unwrap();
            drop(first);

            // Second connection: complete the WebSocket handshake, read the enroll
            // Hello, then the flushed notice.
            let (second, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(second).await.unwrap();
            let hello = ws.next().await.unwrap().unwrap();
            let Message::Text(hello) = hello else {
                panic!("first frame is the Hello");
            };
            assert!(hello.contains("\"type\":\"hello\""));
            let notice = ws.next().await.unwrap().unwrap();
            let _ = frame_tx.send(notice);
        });

        // Queue the notice before the subscriber starts: it sits in the unbounded
        // channel until a live connection can carry it.
        let (notices_tx, notices_rx) = mpsc::unbounded_channel();
        notices_tx.send(queued.clone()).unwrap();

        let control = MeshControl::new(
            RelayId(1),
            std::sync::Arc::default(),
            std::sync::Arc::default(),
        );
        tokio::spawn(run_descriptor_subscriber_with(
            format!("http://{addr}"),
            RelayHello::new(
                RelayId(1),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                rally_point_proto::version::ProtocolVersion::CURRENT,
                vec![0xAB; 4],
            ),
            None,
            control,
            notices_rx,
            Duration::from_millis(20), // redial fast after the failed first dial
            Duration::from_secs(3600), // no heartbeat during the test
        ));

        let received = tokio::time::timeout(Duration::from_secs(5), frame_rx)
            .await
            .expect("the queued notice is delivered after the reconnect")
            .unwrap();
        let Message::Text(text) = received else {
            panic!("a text frame");
        };
        let decoded: RelayToCoordinator = serde_json::from_str(&text).unwrap();
        let expected = match queued {
            RelayNotice::Departure(notice) => RelayToCoordinator::Departure(notice),
            RelayNotice::Desync(notice) => RelayToCoordinator::Desync(notice),
            RelayNotice::Result(notice) => RelayToCoordinator::Result(notice),
            RelayNotice::SessionClosed { tenant, session } => {
                RelayToCoordinator::SessionClosed { tenant, session }
            }
        };
        assert_eq!(decoded, expected);
    }

    #[tokio::test]
    async fn a_queued_departure_is_delivered_after_a_reconnect() {
        a_queued_notice_is_delivered_after_a_reconnect(RelayNotice::Departure(dropped_notice()))
            .await;
    }

    #[tokio::test]
    async fn a_queued_desync_is_delivered_after_a_reconnect() {
        a_queued_notice_is_delivered_after_a_reconnect(RelayNotice::Desync(desync_notice())).await;
    }
}
