//! Coordinator restart adoption, end to end over real control connections: a
//! session created in one coordinator lifetime survives into the next over the
//! same ledger, so the relay serving it — reconnecting to the new process — is
//! re-synced to a descriptor set that still holds its running game rather than an
//! empty one that would end it.
//!
//! Two coordinators served over one in-memory ledger stand in for the restart:
//! the first creates the session and flushes; the second restores at startup.

use std::time::Duration;

use rally_point_coordinator::session;
use rally_point_proto::control::{
    CoordinatorToRelay, PlayerHandoff, SessionDescriptor, SessionRequest, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt};

mod common;
use common::{
    CoordinatorBuilder, ServedCoordinator, TENANT, connect_and_send_hello, hello_at_current,
    in_memory_ledger, prove_identity, read_to_descriptors, self_signed, wait_for_enrollment,
};

/// The token lifetime tests mint with — comfortably longer than any test runs.
const TOKEN_TTL: Duration = Duration::from_secs(3600);

/// Creates a one-slot session on `served` the way the create handler does:
/// commit, register its lifecycle, and flush the store before "answering".
fn create_session(served: &ServedCoordinator) -> SessionId {
    let tenant = TenantId(TENANT.to_owned());
    let created = session::create_session(
        &served.setup,
        SessionRequest {
            lobby_policy: None,
            rollback: false,
            tenant: tenant.clone(),
            players: vec![PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xAA; 32]),
                external_ref: None,
                observer: false,
                region: None,
            }],
            external_id: Some("game-1".to_owned()),
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .expect("the enrolled relay takes the session");
    let session = created.response.session;
    served.lifecycle.register_session(
        tenant.clone(),
        session,
        served.setup.serving_relays(&tenant, session),
        [SlotId(0)].into_iter().collect(),
        Default::default(),
    );
    if let Some(store) = &served.session_store {
        store.flush().expect("flushing the session store");
    }
    session
}

/// Connects relay `id` (its token on a first enroll, its bound cert alone after)
/// and returns the full descriptor set the coordinator re-syncs it to.
async fn connect_and_read_set(
    served: &ServedCoordinator,
    id: RelayId,
    cert_der: &[u8],
    key: &rustls_pki_types::PrivateKeyDer<'static>,
    token: Option<&str>,
) -> (common::ControlSocket, Vec<SessionDescriptor>) {
    let mut hello = hello_at_current(id.0, 14900, cert_der.to_vec());
    if let Some(token) = token {
        hello = hello.with_enroll_token(token.to_owned());
    }
    let mut socket = connect_and_send_hello(&served.base_url, hello).await;
    prove_identity(&mut socket, key).await;
    let text = read_to_descriptors(&mut socket).await;
    let CoordinatorToRelay::Descriptors { descriptors, .. } =
        serde_json::from_str(&text).expect("a descriptors frame decodes")
    else {
        panic!("expected a full descriptor set, got {text}");
    };
    assert!(wait_for_enrollment(served.registry(), id).await);
    (socket, descriptors)
}

/// Runs a session through one coordinator lifetime and reconnects its relay to a
/// second over the same ledger, returning the second coordinator, the relay, the
/// session, and the set the second re-syncs the relay to.
async fn restart_with(
    persist: bool,
) -> (
    ServedCoordinator,
    RelayId,
    SessionId,
    Vec<SessionDescriptor>,
) {
    let ledger = in_memory_ledger();
    let minted = ledger.mint(None, TOKEN_TTL).expect("mint an id + token");
    let (cert_der, key) = self_signed();
    let builder = || {
        let builder = CoordinatorBuilder::new()
            .with_ledger(ledger.clone())
            .with_tenant();
        if persist {
            builder.with_session_store()
        } else {
            builder
        }
    };

    let first = builder().serve().await;
    let (socket, initial) = connect_and_read_set(
        &first,
        minted.relay_id,
        &cert_der,
        &key,
        Some(&minted.token),
    )
    .await;
    assert!(initial.is_empty(), "a fresh coordinator holds no sessions");
    let session = create_session(&first);
    assert!(
        first
            .setup
            .descriptors()
            .current_for(minted.relay_id)
            .iter()
            .any(|d| d.session == session),
        "the relay was assigned the session",
    );
    // The old process goes away; the relay redials the new one.
    drop(socket);

    let second = builder().serve().await;
    let (_socket, resynced) =
        connect_and_read_set(&second, minted.relay_id, &cert_der, &key, None).await;
    (second, minted.relay_id, session, resynced)
}

#[tokio::test]
async fn a_restarted_coordinator_resyncs_its_relay_to_the_running_session() {
    let (second, relay, session, resynced) = restart_with(true).await;
    let tenant = TenantId(TENANT.to_owned());

    assert_eq!(
        resynced.iter().map(|d| d.session).collect::<Vec<_>>(),
        vec![session],
        "the reconnecting relay is re-synced to the session it is still running",
    );
    assert_eq!(resynced[0].homed_slots, vec![SlotId(0)]);
    assert!(
        second.lifecycle.is_alive(&tenant, session),
        "the tenant's liveness probe still finds the session",
    );
    assert_eq!(
        second.setup.session_count_for_relay(relay),
        1,
        "scale-down sees the relay as busy, not idle",
    );
}

#[tokio::test]
async fn without_persistence_the_same_restart_ends_the_session() {
    // The failure the store exists to prevent: an amnesiac coordinator re-syncs
    // the relay to an empty set, which the relay applies by ending the game.
    let (second, _, session, resynced) = restart_with(false).await;
    assert!(resynced.is_empty());
    assert!(
        !second
            .lifecycle
            .is_alive(&TenantId(TENANT.to_owned()), session)
    );
}
