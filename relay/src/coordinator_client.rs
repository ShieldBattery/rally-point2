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
//! side knows immediately, which is what the (coming) relay→coordinator presence
//! reporting wants. The same channel will carry that reporting up; descriptors
//! come down. One connection, authenticated once.
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
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

use crate::mesh_control::MeshControl;
use crate::routing::SessionKey;

/// How long to wait before redialing after the control connection drops. The
/// control plane is not latency-critical and a running game does not depend on
/// the connection, so a couple of seconds avoids hammering a coordinator that is
/// restarting or briefly unreachable.
pub const RECONNECT_DELAY: Duration = Duration::from_secs(2);

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
pub async fn run_descriptor_subscriber(
    coordinator_url: String,
    relay_hello: RelayHello,
    bootstrap_secret: Option<String>,
    control: MeshControl,
) {
    run_descriptor_subscriber_with(
        coordinator_url,
        relay_hello,
        bootstrap_secret,
        control,
        RECONNECT_DELAY,
    )
    .await
}

/// [`run_descriptor_subscriber`] with the reconnect delay injected, so a test
/// need not wait the production interval between attempts.
pub async fn run_descriptor_subscriber_with(
    coordinator_url: String,
    relay_hello: RelayHello,
    bootstrap_secret: Option<String>,
    control: MeshControl,
    reconnect_delay: Duration,
) {
    // Kept across reconnects: a session removed while disconnected is left when
    // the next connection's full-set re-sync arrives without it.
    let mut applied: HashSet<SessionKey> = HashSet::new();
    let relay_id = relay_hello.relay_id;

    loop {
        match connect_and_stream(
            &coordinator_url,
            &relay_hello,
            bootstrap_secret.as_deref(),
            &control,
            &mut applied,
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
/// pushes until the connection closes or errors. `applied` is updated in place
/// across the connection's lifetime (and persists into the next one).
async fn connect_and_stream(
    coordinator_url: &str,
    relay_hello: &RelayHello,
    secret: Option<&str>,
    control: &MeshControl,
    applied: &mut HashSet<SessionKey>,
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

    while let Some(message) = socket.next().await {
        match message? {
            Message::Text(text) => {
                apply_message(control, serde_json::from_str(text.as_str())?, applied);
            }
            Message::Close(_) => break,
            // No pings are sent on this channel today, and the relay sends
            // nothing yet; any other frame is ignored.
            Message::Ping(_) | Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => {}
        }
    }
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
    use rally_point_proto::control::{BufferBounds, RelayPeer, TenantId};
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
                })
                .collect(),
            bounds: BufferBounds::new(1, 6).unwrap(),
        }
    }

    #[test]
    fn reconcile_applies_descriptors_then_leaves_dropped_sessions() {
        let control = MeshControl::new(RelayId(1));
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
        let control = MeshControl::new(RelayId(1));
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
        let control = MeshControl::new(RelayId(1));
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

    #[test]
    fn an_unknown_message_is_skipped_and_does_not_disturb_state_or_later_messages() {
        let control = MeshControl::new(RelayId(1));
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

        let control = MeshControl::new(RelayId(1));
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
}
