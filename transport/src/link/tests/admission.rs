//! Tests for which payloads may ride datagrams on a link: admission is judged
//! against the guaranteed floor rather than the live discovered budget, and
//! against a peer advertising a limit below that floor. Grouped because they
//! all need a connection brought up with a chosen datagram budget.

use super::*;

#[tokio::test]
async fn surfaces_a_turn_too_large_for_a_datagram() {
    let (mut client, _server, _client_ep, _server_ep) = connected_links().await;

    let budget = client
        .connection()
        .max_datagram_size()
        .expect("loopback supports datagrams");

    // A turn whose own bytes dwarf the datagram budget can ride no datagram, so
    // send surfaces it as an error rather than silently stalling. With the tiny
    // turns of a lockstep game this never happens. Admission is judged
    // against the guaranteed floor, so that is the budget the error names.
    let oversize = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0u8; budget + 1].into(),
        ..Default::default()
    };
    match client.send(Some(oversize)) {
        Err(LinkError::PayloadTooLarge {
            needed,
            budget: reported,
        }) => {
            assert_eq!(
                reported,
                crate::ack_manager::GUARANTEED_DATAGRAM_BUDGET.min(budget)
            );
            assert!(needed > reported);
        }
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }
}

/// Datagram admission is judged against the guaranteed floor, never the
/// live discovered budget: a payload sized between the two must be refused
/// (diverted by the caller), because path-MTU shrink — noq's black-hole
/// response to the loss weather redundancy exists for — could otherwise
/// leave it registered but too wide for every later packet, flushes
/// included, stranding it while its seq wedges the peer's prefix.
#[tokio::test]
async fn admission_uses_the_guaranteed_floor_not_the_discovered_budget() {
    let (client, _server, _client_ep, _server_ep) = connected_links().await;

    let live = client
        .connection()
        .max_datagram_size()
        .expect("loopback supports datagrams");
    assert!(
        live > crate::ack_manager::GUARANTEED_DATAGRAM_BUDGET,
        "premise: the live budget ({live}) must exceed the floor for the \
         gap this test covers to exist",
    );

    // Between the floor and the live budget: fits today's packets, but not
    // necessarily tomorrow's — refused.
    let between = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0u8; crate::ack_manager::GUARANTEED_DATAGRAM_BUDGET + 16].into(),
        ..Default::default()
    };
    assert!(!client.payload_fits(&between).unwrap());

    // Comfortably under the floor: admitted.
    let under = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0u8; crate::ack_manager::GUARANTEED_DATAGRAM_BUDGET - 64].into(),
        ..Default::default()
    };
    assert!(client.payload_fits(&under).unwrap());
}

/// A peer may advertise a datagram limit *below* the guaranteed floor —
/// noq permits an arbitrarily small handshake value — and admission
/// must then judge against that limit, exactly as `send` enforces it. A
/// `payload_fits` that ignored the peer limit would approve a payload
/// `send` refuses; the drivers treat that refusal as a recoverable bundle
/// race, so the fresh turn would be neither registered for re-carry nor
/// diverted — silently lost.
/// A client-side connection to a server that advertises `limit` as its
/// datagram receive size — the handshake constant that caps the client's
/// `max_datagram_size` toward it. The server connection and endpoints ride
/// along so they outlive the test body.
async fn connect_to_peer_with_datagram_limit(
    limit: usize,
) -> (
    noq::Connection,
    noq::Connection,
    noq::Endpoint,
    noq::Endpoint,
) {
    let (chain, key, ca) = self_signed();
    let mut server_cfg = server_config(chain, key).unwrap();
    let mut transport = noq::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(limit));
    server_cfg.transport_config(std::sync::Arc::new(transport));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let client_cfg = client_config(roots).unwrap();

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = noq::Endpoint::server(server_cfg, bind).unwrap();
    let server_addr = server.local_addr().unwrap();
    let client_ep = noq::Endpoint::client(bind).unwrap();
    client_ep.set_default_client_config(client_cfg);

    let accept = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
    };
    let client_conn = client_ep
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let server_conn = accept.await.unwrap();
    (client_conn, server_conn, client_ep, server)
}

#[tokio::test]
async fn admission_respects_a_peer_advertised_datagram_limit() {
    let (client_conn, _server_conn, _client_ep, _server_ep) =
        connect_to_peer_with_datagram_limit(800).await;
    let mut client = Link::new(client_conn);
    let live = client
        .connection()
        .max_datagram_size()
        .expect("datagrams supported");
    assert!(
        live < crate::ack_manager::GUARANTEED_DATAGRAM_BUDGET,
        "premise: the advertised limit ({live}) must undercut the floor",
    );

    // Between the peer's limit and the floor: payload_fits and send must
    // agree it cannot ride.
    let commands = 900usize;
    let wide = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0u8; commands].into(),
        ..Default::default()
    };
    assert!(!client.payload_fits(&wide).unwrap());
    match client.send(Some(wide)) {
        Err(LinkError::PayloadTooLarge { .. }) => {}
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }
    assert_eq!(client.payloads_in_flight(), 0);

    // Under the peer's limit: both admit it.
    let small = turn(0, 0, 0x11);
    assert!(client.payload_fits(&small).unwrap());
    client.send(Some(small)).unwrap();
}

/// The floor verification every establishment path runs: a peer whose
/// advertised datagram budget undercuts the guaranteed floor is an
/// unsupported configuration and must be refused whole — partially
/// serving it would let payloads admitted on one connection outgrow a
/// later one, stranding them.
#[tokio::test]
async fn establishment_verification_refuses_an_under_floor_peer() {
    let (small_conn, _server_conn, _client_ep, _server_ep) =
        connect_to_peer_with_datagram_limit(800).await;
    let refused = crate::quic::verify_datagram_budget(&small_conn);
    assert!(refused.is_err(), "an 800-byte peer sits under the floor");

    let (normal, _b, _ea, _eb) = connected_connections().await;
    crate::quic::verify_datagram_budget(&normal).expect("a default-config peer clears the floor");
}
