//! Fixtures only the client-edge suite uses: starting a relay, dialing a slot
//! through the handshake, and the control/notice readers that skip the
//! informational frames every register fans.

pub use crate::common::*;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_relay::auth::Registry;
use rally_point_relay::server;
use rally_point_transport::quic::server_config;
use rally_point_transport::rustls::pki_types::CertificateDer;
use rally_point_transport::{Link, noq};

/// Binds an ephemeral relay endpoint serving `registry`, returning its address
/// and the CA a client trusts to reach it.
pub fn start_relay(registry: Registry) -> (SocketAddr, CertificateDer<'static>) {
    start_relay_with_mesh(registry, rally_point_relay::mesh::new_mesh_state())
}

/// [`start_relay`] with a caller-supplied [`MeshState`], so a test can hold its
/// decision-maker registry (to seed a pending buffer change) or its mesh links.
pub fn start_relay_with_mesh(
    registry: Registry,
    mesh: rally_point_relay::mesh::MeshState,
) -> (SocketAddr, CertificateDer<'static>) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let endpoint = noq::Endpoint::server(server_cfg, bind).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry),
        std::sync::Arc::default(),
        mesh,
        None,
    ));
    (addr, ca)
}

/// Connects a client for `slot`, completes the handshake as a fresh dial (no resume
/// cursors), and returns the connection wrapped as a transport link ready to carry
/// turns.
pub async fn connect_slot(
    endpoint: &noq::Endpoint,
    addr: SocketAddr,
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
) -> Link {
    connect_slot_resuming(endpoint, addr, tenant, session, slot, &[]).await
}

/// [`connect_slot`] presenting `resume_cursors`, so a reconnect test can ask the
/// relay to replay the turns it missed from each named peer slot.
pub async fn connect_slot_resuming(
    endpoint: &noq::Endpoint,
    addr: SocketAddr,
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
    resume_cursors: &[(SlotId, u64)],
) -> Link {
    let client_key = keypair();
    let token = mint_token(tenant, session, slot, client_key.public);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    handshake(&connection, &token, &client_key, resume_cursors)
        .await
        .unwrap();
    Link::new(connection)
}

/// Reads the next control frame that carries real meaning, skipping the
/// informational `SlotConnectivity` frames the relay now fans on every register
/// and disconnect. Panics on timeout or a closed stream. Tests asserting on a
/// leave or session-start frame use this so a connectivity frame that legitimately
/// precedes it does not fail the match.
pub async fn recv_meaningful(
    reader: &mut tokio::sync::mpsc::Receiver<rally_point_transport::control::ControlInbound>,
) -> rally_point_transport::control::ControlInbound {
    use rally_point_transport::control::ControlInbound;
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("a control frame arrives before the timeout")
            .expect("the control stream stays open");
        if !matches!(frame, ControlInbound::Connectivity(_)) {
            return frame;
        }
    }
}

/// Reads the next coordinator notice that reports a game *event*, skipping the
/// load-progress notices every slot activation fires. Panics on timeout or a
/// closed channel. Tests asserting on a result or departure use this so the
/// arrival notices that legitimately precede them do not fail the match.
pub async fn recv_event_notice(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<rally_point_relay::consensus::RelayNotice>,
) -> rally_point_relay::consensus::RelayNotice {
    use rally_point_relay::consensus::RelayNotice;
    loop {
        let notice = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a notice arrives before the timeout")
            .expect("the notice channel stays open");
        if !matches!(
            notice,
            RelayNotice::SlotConnected(_) | RelayNotice::SessionStarted(_)
        ) {
            return notice;
        }
    }
}

/// Asserts that no game-event notice arrives within `window`, tolerating the
/// load-progress notices a slot activation fires. The counterpart of
/// [`recv_event_notice`] for the tests that assert an inadmissible report is
/// dropped silently.
pub async fn assert_no_event_notice(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<rally_point_relay::consensus::RelayNotice>,
    window: Duration,
    message: &str,
) {
    use rally_point_relay::consensus::RelayNotice;
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Err(_) => return,
            Ok(None) => return,
            Ok(Some(RelayNotice::SlotConnected(_) | RelayNotice::SessionStarted(_))) => continue,
            Ok(Some(other)) => panic!("{message}, got {other:?}"),
        }
    }
}

/// Waits for the relay to close `link`'s connection, failing the test (rather
/// than hanging) if it never does.
pub async fn expect_closed(link: &mut Link) {
    let result = tokio::time::timeout(Duration::from_secs(5), link.recv()).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "expected the relay to have closed the link",
    );
}

/// Collects the next `n` oversize-turn payloads pushed down a control stream,
/// skipping the session-start and connectivity frames that a register also fans.
/// Panics on timeout. A reconnect test uses this to read the turns the relay replays
/// from the ring.
pub async fn collect_oversize_turns(
    reader: &mut tokio::sync::mpsc::Receiver<rally_point_transport::control::ControlInbound>,
    n: usize,
) -> Vec<Payload> {
    use rally_point_transport::control::ControlInbound;
    let mut turns = Vec::new();
    while turns.len() < n {
        let frame = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("a replayed turn arrives before the timeout")
            .expect("the control stream stays open");
        if let ControlInbound::OversizeTurn(payload) = frame {
            turns.push(payload);
        }
    }
    turns
}

/// Polls `condition` until it's true or `deadline` passes, sleeping briefly between
/// checks. Panics with `what` on timeout. Used to observe async server-side
/// teardown (a disconnect's `end_slot_link` running) that has no local peer to
/// signal it via a control frame.
pub async fn wait_until(
    deadline: tokio::time::Instant,
    what: &str,
    mut condition: impl FnMut() -> bool,
) {
    loop {
        if condition() {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("{what}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
