//! Relay process lineage, exercised end to end over a real WebSocket control
//! connection: whether a session's load record may still claim completeness turns
//! on whether the relays serving it have held it in one unbroken stretch of
//! process memory.
//!
//! A relay's retained load state lives in its process. A control connection
//! redialing keeps it; a restarted process comes back empty, and whatever the old
//! one observed and never restated is gone for good. The `boot_id` a hello carries
//! is what tells those apart, and this is where the coordinator's reading of it is
//! checked against real enrolls rather than a direct call.

use std::collections::HashSet;

use rally_point_coordinator::lifecycle::Lifecycle;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rustls_pki_types::PrivateKeyDer;

mod common;
use common::{
    ControlSocket, CoordinatorBuilder, TENANT, connect_and_send_hello, hello_at_current,
    prove_identity, read_to_descriptors, self_signed,
};

fn tenant_id() -> TenantId {
    TenantId(TENANT.to_owned())
}

/// Enrolls a relay: sends the hello, proves possession of `key`, and reads through
/// to the descriptor push that only an accepted enroll ever produces — so the
/// caller knows the enrollment has landed before it asserts on its effects.
async fn enroll(
    base_url: &str,
    id: u64,
    cert_der: Vec<u8>,
    key: &PrivateKeyDer<'static>,
    boot_id: Option<u64>,
) -> ControlSocket {
    let mut hello = hello_at_current(id, 14_900 + id as u16, cert_der);
    if let Some(boot_id) = boot_id {
        hello = hello.with_boot_id(boot_id);
    }
    let mut socket = connect_and_send_hello(base_url, hello).await;
    prove_identity(&mut socket, key).await;
    read_to_descriptors(&mut socket).await;
    socket
}

/// Whether the session's load record can still claim to cover its whole life.
fn attestable(lifecycle: &Lifecycle, session: SessionId) -> bool {
    lifecycle
        .load_state(&tenant_id(), session)
        .expect("the session was registered here")
        .attestable
}

#[tokio::test]
async fn the_completeness_claim_survives_a_reconnect_only_under_the_same_boot_id() {
    // Three reconnects, differing only in the boot id relay 1 comes back under,
    // and in each the claim for a session relay 1 does *not* serve is untouched —
    // the rule is about one relay's own sessions, not the fleet's.
    let cases = [
        (
            Some(0xAB),
            Some(0xAB),
            true,
            "the same process came back; nothing it held was lost",
        ),
        (
            Some(0xAB),
            Some(0xEF),
            false,
            "the relay restarted; no snapshot from the new process can speak for \
             what the old one saw and never restated",
        ),
        (
            None,
            None,
            false,
            "a build predating the field is indistinguishable from a restart, so \
             its reconnect is read as one",
        ),
    ];

    for (first_boot, again_boot, still_attestable, why) in cases {
        let served = CoordinatorBuilder::new().serve().await;
        let lifecycle = &served.lifecycle;
        let (cert_one, key_one) = self_signed();
        let (cert_two, key_two) = self_signed();
        let socket = enroll(&served.base_url, 1, cert_one.clone(), &key_one, first_boot).await;
        let _relay_two = enroll(&served.base_url, 2, cert_two, &key_two, Some(0xCD)).await;

        let shared = SessionId(5);
        let elsewhere = SessionId(6);
        lifecycle.register_session(
            tenant_id(),
            shared,
            vec![RelayId(1), RelayId(2)],
            HashSet::from([SlotId(0), SlotId(1)]),
            HashSet::new(),
        );
        lifecycle.register_session(
            tenant_id(),
            elsewhere,
            vec![RelayId(2)],
            HashSet::from([SlotId(0)]),
            HashSet::new(),
        );
        assert!(attestable(lifecycle, shared));

        drop(socket);
        let _reconnected = enroll(&served.base_url, 1, cert_one, &key_one, again_boot).await;

        assert_eq!(attestable(lifecycle, shared), still_attestable, "{why}");
        assert!(
            attestable(lifecycle, elsewhere),
            "a session relay 1 does not serve is untouched by its reconnect",
        );
    }
}
