//! Provisioned-relay ledger enrollment, exercised end to end over a real
//! WebSocket control connection: a ledger-backed coordinator mints a relay id
//! with a one-time token, admits the relay that presents that token (binding its
//! certificate), refuses a token-less or wrong-token enroll with a single generic
//! close code, admits the bound relay's reconnect on its certificate alone, and
//! refuses a different certificate claiming the bound id. It also proves the
//! coordinator-recorded advertise set overrides the hello's self-reported
//! addresses at enroll, and that the recorded expected-address gate is measured
//! against the connection's real transport peer.
//!
//! The tokenless dev / loopback path is proven unchanged by the sibling
//! `enroll_identity` suite, which runs against a coordinator with no ledger.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use rally_point_coordinator::registry;
use rally_point_proto::version::CONTROL_CLOSE_ENROLL_UNAUTHORIZED;

mod common;
use common::{
    ControlSocket, CoordinatorBuilder, connect_and_send_hello, expect_close, hello_at_current,
    in_memory_ledger, prove_identity, read_to_descriptors, self_signed, wait_for_deregistration,
    wait_for_enrollment,
};

/// The token lifetime tests mint with — comfortably longer than any test runs.
const TOKEN_TTL: Duration = Duration::from_secs(3600);

/// Reads down-frames until the descriptor re-sync every accepted enroll includes —
/// proof the connection enrolled rather than being closed. The enrolled path leads
/// with the tenant-key push before the first descriptor, so this reads past it.
async fn expect_enrolled(socket: &mut ControlSocket) {
    let _ = read_to_descriptors(socket).await;
}

#[tokio::test]
async fn a_recorded_advertise_set_overrides_the_hello_addresses() {
    // A relay behind NAT self-reports a useless address, so the addresses the
    // coordinator resolved for the task must win at enroll. With nothing
    // recorded there is nothing to override and the hello's own address stands.
    let ledger = in_memory_ledger();
    let served = CoordinatorBuilder::new()
        .with_ledger(ledger.clone())
        .serve()
        .await;

    // Nothing recorded: the hello's self-reported address is what enrolls.
    let self_reported = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");
    let (cert_der, key) = self_signed();
    let hello = hello_at_current(self_reported.relay_id.0, 14900, cert_der)
        .with_enroll_token(self_reported.token.clone());
    let mut socket = connect_and_send_hello(&served.base_url, hello).await;
    prove_identity(&mut socket, &key).await;

    assert!(
        wait_for_enrollment(served.registry(), self_reported.relay_id).await,
        "a minted relay presenting its token enrolls",
    );
    let entry = registry::entry(served.registry(), self_reported.relay_id).unwrap();
    assert_eq!(
        entry.relay_addr,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        "with no recorded advertise set, the hello's own address is used",
    );

    // A recorded advertise set: it replaces the hello's addresses entirely.
    let recorded = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");
    let v4: SocketAddr = "203.0.113.5:15000".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::5]:15000".parse().unwrap();
    ledger
        .record_task(recorded.relay_id, "arn:aws:ecs:task/abc", &[], &[v4, v6])
        .expect("record the task's advertise set");

    let (cert_der, key) = self_signed();
    let hello = hello_at_current(recorded.relay_id.0, 14901, cert_der)
        .with_enroll_token(recorded.token.clone());
    let mut socket = connect_and_send_hello(&served.base_url, hello).await;
    prove_identity(&mut socket, &key).await;

    assert!(wait_for_enrollment(served.registry(), recorded.relay_id).await);
    let entry = registry::entry(served.registry(), recorded.relay_id).unwrap();
    assert_eq!(
        entry.relay_addr, v4,
        "the ledger's primary address wins over the hello's self-report",
    );
    assert_eq!(
        entry.relay_addrs,
        vec![v4, v6],
        "the ledger's full advertise set is enrolled, not the hello's",
    );
}

#[tokio::test]
async fn a_tokenless_or_wrong_token_enroll_is_refused() {
    let ledger = in_memory_ledger();
    let served = CoordinatorBuilder::new()
        .with_ledger(ledger.clone())
        .serve()
        .await;
    let minted = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");
    let (cert_der, key) = self_signed();

    // No token at all: refused with the single generic close code.
    let hello = hello_at_current(minted.relay_id.0, 14900, cert_der.clone());
    let mut socket = connect_and_send_hello(&served.base_url, hello).await;
    prove_identity(&mut socket, &key).await;
    expect_close(&mut socket, CONTROL_CLOSE_ENROLL_UNAUTHORIZED).await;
    assert!(
        registry::peer(served.registry(), minted.relay_id).is_none(),
        "a token-less enroll never reaches the registry",
    );

    // A wrong token: the same generic refusal, indistinguishable on the wire.
    let hello = hello_at_current(minted.relay_id.0, 14900, cert_der)
        .with_enroll_token("not-the-real-token".to_owned());
    let mut socket = connect_and_send_hello(&served.base_url, hello).await;
    prove_identity(&mut socket, &key).await;
    expect_close(&mut socket, CONTROL_CLOSE_ENROLL_UNAUTHORIZED).await;
    assert!(registry::peer(served.registry(), minted.relay_id).is_none());
}

#[tokio::test]
async fn the_bound_cert_reconnects_tokenless_and_a_new_cert_is_refused() {
    let ledger = in_memory_ledger();
    let served = CoordinatorBuilder::new()
        .with_ledger(ledger.clone())
        .serve()
        .await;
    let minted = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");
    let (cert_der, key) = self_signed();

    // First enroll with the token binds this certificate to the id.
    let hello = hello_at_current(minted.relay_id.0, 14900, cert_der.clone())
        .with_enroll_token(minted.token.clone());
    let mut socket = connect_and_send_hello(&served.base_url, hello).await;
    prove_identity(&mut socket, &key).await;
    assert!(wait_for_enrollment(served.registry(), minted.relay_id).await);
    drop(socket);
    // Let the coordinator observe the drop and deregister before reconnecting.
    assert!(wait_for_deregistration(served.registry(), minted.relay_id).await);

    // Reconnect with the SAME certificate and NO token: the bound certificate
    // alone authorizes the reconnect.
    let hello = hello_at_current(minted.relay_id.0, 14901, cert_der.clone());
    let mut socket = connect_and_send_hello(&served.base_url, hello).await;
    prove_identity(&mut socket, &key).await;
    expect_enrolled(&mut socket).await;
    drop(socket);
    assert!(wait_for_deregistration(served.registry(), minted.relay_id).await);

    // Reconnect with a DIFFERENT certificate claiming the bound id — even with a
    // valid-looking token — is refused: the fingerprint does not match the bound
    // one, so the ledger closes before the registry is ever touched. A stolen
    // token cannot re-bind an id to a new certificate.
    let (other_cert, other_key) = self_signed();
    let hello = hello_at_current(minted.relay_id.0, 14902, other_cert)
        .with_enroll_token(minted.token.clone());
    let mut socket = connect_and_send_hello(&served.base_url, hello).await;
    prove_identity(&mut socket, &other_key).await;
    expect_close(&mut socket, CONTROL_CLOSE_ENROLL_UNAUTHORIZED).await;
}

#[tokio::test]
async fn a_retired_id_is_refused_even_with_its_token() {
    let ledger = in_memory_ledger();
    let served = CoordinatorBuilder::new()
        .with_ledger(ledger.clone())
        .serve()
        .await;
    let minted = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");
    ledger.retire(minted.relay_id).expect("retire the id");

    let (cert_der, key) = self_signed();
    let hello = hello_at_current(minted.relay_id.0, 14900, cert_der)
        .with_enroll_token(minted.token.clone());
    let mut socket = connect_and_send_hello(&served.base_url, hello).await;
    prove_identity(&mut socket, &key).await;
    expect_close(&mut socket, CONTROL_CLOSE_ENROLL_UNAUTHORIZED).await;
    assert!(
        registry::peer(served.registry(), minted.relay_id).is_none(),
        "a retired id can never enroll",
    );
}

#[tokio::test]
async fn the_expected_address_gate_is_measured_against_the_real_connection_peer() {
    // The gate compares the ledger's recorded expected addresses against the
    // connection's transport-level peer, which the handler only ever sees when
    // the server was built with connect-info the way the binary builds it. Every
    // arm below runs over a real socket from loopback, so the peer is known and
    // is 127.0.0.1.
    let ledger = in_memory_ledger();
    let served = CoordinatorBuilder::new()
        .with_ledger(ledger.clone())
        .with_connect_info()
        .serve()
        .await;

    // An id whose expected set contains the address this test connects from.
    let expected_here = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");
    ledger
        .record_task(
            expected_here.relay_id,
            "arn:aws:ecs:task/here",
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            &[],
        )
        .expect("record the expected address");
    let (cert_der, key) = self_signed();
    let hello = hello_at_current(expected_here.relay_id.0, 14900, cert_der)
        .with_enroll_token(expected_here.token.clone());
    let mut socket = connect_and_send_hello(&served.base_url, hello).await;
    prove_identity(&mut socket, &key).await;
    assert!(
        wait_for_enrollment(served.registry(), expected_here.relay_id).await,
        "a relay connecting from an address the ledger expects enrolls",
    );

    // An id expecting a different address: the same loopback connection is
    // refused with the one generic close code, and never reaches the registry.
    let expected_elsewhere = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");
    ledger
        .record_task(
            expected_elsewhere.relay_id,
            "arn:aws:ecs:task/elsewhere",
            &["203.0.113.7".parse().unwrap()],
            &[],
        )
        .expect("record the expected address");
    let (cert_der, key) = self_signed();
    let hello = hello_at_current(expected_elsewhere.relay_id.0, 14901, cert_der)
        .with_enroll_token(expected_elsewhere.token.clone());
    let mut socket = connect_and_send_hello(&served.base_url, hello).await;
    prove_identity(&mut socket, &key).await;
    expect_close(&mut socket, CONTROL_CLOSE_ENROLL_UNAUTHORIZED).await;
    assert!(
        registry::peer(served.registry(), expected_elsewhere.relay_id).is_none(),
        "a relay connecting from an address the ledger does not expect never enrolls",
    );
}

#[tokio::test]
async fn a_recorded_expected_address_refuses_a_server_that_cannot_see_its_peer() {
    // Served without connect-info — as a router-`oneshot` harness or a server
    // behind something that hides the peer would be — the handler reads the peer
    // as unknown. A non-empty expected set then refuses rather than waving the
    // enroll through, so losing the connect-info wiring fails closed.
    let ledger = in_memory_ledger();
    let served = CoordinatorBuilder::new()
        .with_ledger(ledger.clone())
        .serve()
        .await;

    let minted = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");
    ledger
        .record_task(
            minted.relay_id,
            "arn:aws:ecs:task/here",
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            &[],
        )
        .expect("record the expected address");

    let (cert_der, key) = self_signed();
    let hello = hello_at_current(minted.relay_id.0, 14900, cert_der)
        .with_enroll_token(minted.token.clone());
    let mut socket = connect_and_send_hello(&served.base_url, hello).await;
    prove_identity(&mut socket, &key).await;
    expect_close(&mut socket, CONTROL_CLOSE_ENROLL_UNAUTHORIZED).await;
    assert!(
        registry::peer(served.registry(), minted.relay_id).is_none(),
        "an enroll whose peer the server never recorded is refused, not trusted",
    );
}
