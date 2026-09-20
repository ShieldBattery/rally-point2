//! Tests for which payloads may ride datagrams on a link: admission is judged
//! against the guaranteed floor rather than the live discovered budget, and
//! against a peer advertising a limit below that floor. Grouped because they
//! all need a connection brought up with a chosen datagram budget.

use super::*;

/// Datagram admission is judged against the guaranteed floor, never the
/// live discovered budget: a payload sized between the two must be refused
/// (diverted by the caller), because path-MTU shrink — noq's black-hole
/// response to the loss weather redundancy exists for — could otherwise
/// leave it registered but too wide for every later packet, flushes
/// included, stranding it while its seq wedges the peer's prefix.
///
/// `payload_fits` and `send` are two spellings of one budget, so both are
/// asserted on every case: a preflight that approved what `send` refuses
/// would let the caller drop a turn it neither registered nor diverted.
#[tokio::test]
async fn admission_uses_the_guaranteed_floor_not_the_discovered_budget() {
    let (mut client, _server, _client_ep, _server_ep) = connected_links().await;

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
    // necessarily tomorrow's — refused by the preflight and by `send`, which
    // names the floor (not the live budget) as the budget it judged against.
    let between = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0u8; crate::ack_manager::GUARANTEED_DATAGRAM_BUDGET + 16].into(),
        ..Default::default()
    };
    assert!(!client.payload_fits(&between).unwrap());
    match client.send(Some(between)) {
        Err(LinkError::PayloadTooLarge {
            needed,
            budget: reported,
        }) => {
            assert_eq!(
                reported,
                crate::ack_manager::GUARANTEED_DATAGRAM_BUDGET.min(live)
            );
            assert!(needed > reported);
        }
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }
    assert_eq!(client.payloads_in_flight(), 0);

    // A turn whose own bytes dwarf even the live budget can ride no datagram
    // at all; with the tiny turns of a lockstep game this never happens, but
    // it must surface as an error rather than silently stalling.
    let oversize = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0u8; live + 1].into(),
        ..Default::default()
    };
    assert!(!client.payload_fits(&oversize).unwrap());
    assert!(matches!(
        client.send(Some(oversize)),
        Err(LinkError::PayloadTooLarge { .. })
    ));

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
#[tokio::test]
async fn admission_respects_a_peer_advertised_datagram_limit() {
    let (client_conn, _server_conn, _client_ep, _server_ep) =
        test_util::loopback_with_datagram_limit(Edge::Client, 800).await;
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
        test_util::loopback_with_datagram_limit(Edge::Client, 800).await;
    let refused = crate::quic::verify_datagram_budget(&small_conn);
    assert!(refused.is_err(), "an 800-byte peer sits under the floor");

    let (normal, _b, _ea, _eb) = test_util::loopback(Edge::Client).await;
    crate::quic::verify_datagram_budget(&normal).expect("a default-config peer clears the floor");
}
