//! Shared fixtures for the session tests plus the topic modules that use them.
//!
//! Everything here is a fixture: relay/tenant enrollment helpers, the canned
//! rosters, and the response-shape readers. The tests themselves live in the
//! topic children, each of which glob-imports this module and therefore sees
//! both the fixtures and the private items of the code under test.

use std::net::{Ipv4Addr, SocketAddr};

use super::create::{
    MAX_EXTERNAL_STRING_LEN, candidate_session_id, create_session_inner, first_session_id,
};
use super::rehome::rehome_inner;
use super::*;
use crate::provision::WarmTargets;
use crate::registry::{self, RelayRegistry, SessionSetupError, cert_fingerprint};
use crate::tenant;
use rally_point_proto::control::{
    BufferBounds, DepartedSlot, DepartureKind, PlayerHandoff, RelayHello, RelayRegionLabel,
    SessionRequest, TenantId,
};
use rally_point_proto::ids::{RelayId, SlotId};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId, SignedToken};
use rally_point_proto::version::ProtocolVersion;
use rally_point_relay::auth::Registry;

mod cohorts;
mod create;
mod descriptors;
mod drain;
mod idempotency;
mod placement;
mod provisioning;
mod rehome;
mod rehome_close;

/// A fake per-relay cert DER, derived from the id so a test can check the
/// response carries the right relay's cert.
fn fake_cert(id: u64) -> Vec<u8> {
    vec![id as u8; 4]
}

fn enroll_relay(reg: &RelayRegistry, id: u64, port: u16) {
    enroll_relay_with_cert(reg, id, port, fake_cert(id));
}

/// Enrolls a relay advertising the finalized-drop capability.
fn enroll_capable_relay(reg: &RelayRegistry, id: u64, port: u16) {
    registry::enroll(
        reg,
        RelayHello::new(
            RelayId(id),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            ProtocolVersion::CURRENT,
            fake_cert(id),
        )
        .with_capabilities(vec![
            rally_point_proto::control::CAPABILITY_FINALIZED_DROP_V1.to_owned(),
        ]),
    );
}

/// Enrolls (or re-enrolls) a relay under an explicit cert, so a test can
/// simulate a same-id restart under a fresh one.
fn enroll_relay_with_cert(reg: &RelayRegistry, id: u64, port: u16, cert_der: Vec<u8>) {
    registry::enroll(
        reg,
        RelayHello::new(
            RelayId(id),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            ProtocolVersion::CURRENT,
            cert_der,
        ),
    );
}

fn setup_with_two_relays_and_tenant() -> SessionSetup {
    let reg = registry::new_registry();
    enroll_relay(&reg, 1, 14900);
    enroll_relay(&reg, 2, 14901);

    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();

    SessionSetup::new(reg, tenants)
}

fn two_players() -> Vec<PlayerHandoff> {
    vec![
        PlayerHandoff {
            slot: SlotId(0),
            client_pubkey: ClientPublicKey([0xAA; 32]),
            external_ref: None,
            observer: false,
            region: None,
        },
        PlayerHandoff {
            slot: SlotId(1),
            client_pubkey: ClientPublicKey([0xBB; 32]),
            external_ref: None,
            observer: false,
            region: None,
        },
    ]
}

/// Like `setup_with_two_relays_and_tenant`, but relay 2 is tagged `region-b`
/// so a player naming that region places there through the production region
/// path, producing a two-relay meshed session.
fn setup_with_two_relays_region_b_and_tenant() -> SessionSetup {
    let reg = registry::new_registry();
    enroll_relay(&reg, 1, 14900);
    enroll_relay_in_region(&reg, 2, 14901, Some("region-b"));

    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();

    SessionSetup::new(reg, tenants)
}

/// Like `two_players()`, but slot 1 requests `region-b` — landing it on relay
/// 2 in a `setup_with_two_relays_region_b_and_tenant` fleet while slot 0
/// falls back to relay 1, so both relays serve one meshed session.
fn two_players_slot_1_in_region_b() -> Vec<PlayerHandoff> {
    vec![
        PlayerHandoff {
            slot: SlotId(0),
            client_pubkey: ClientPublicKey([0xAA; 32]),
            external_ref: None,
            observer: false,
            region: None,
        },
        PlayerHandoff {
            slot: SlotId(1),
            client_pubkey: ClientPublicKey([0xBB; 32]),
            external_ref: None,
            observer: false,
            region: Some(RegionId("region-b".to_owned())),
        },
    ]
}

/// Resolves a slot's effective home from the response's primary-plus-overrides
/// representation.
fn response_home_for_slot(response: &SessionResponse, slot: SlotId) -> RelayId {
    response
        .slot_homes
        .iter()
        .find(|home| home.slot == slot)
        .map(|home| home.relay.relay_id)
        .unwrap_or(response.home_relay.relay_id)
}

/// Finds one serving relay's endpoint in the response's
/// primary-plus-overrides representation.
fn response_endpoint_for_relay(response: &SessionResponse, relay_id: RelayId) -> &RelayEndpoint {
    if response.home_relay.relay_id == relay_id {
        &response.home_relay
    } else {
        &response
            .slot_homes
            .iter()
            .find(|home| home.relay.relay_id == relay_id)
            .expect("every serving relay appears in the response topology")
            .relay
    }
}

/// A tenant-enrolled setup whose provisioning gate is on: relay 1 is untagged
/// (the region-blind fallback target) and `region-a` starts cold. The create
/// hold cap is `create_hold`; warms last a fixed 600s. Returns the setup and a
/// clone of its warm store so a test can assert on the demand a hold raised.
fn provisioning_setup(create_hold: Duration) -> (SessionSetup, WarmTargets) {
    let reg = registry::new_registry();
    enroll_relay(&reg, 1, 14900);
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        tid(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let warm = WarmTargets::new();
    let gate = ProvisionGate::provisioning(warm.clone(), Duration::from_secs(600), create_hold);
    (
        SessionSetup::new(reg, tenants).with_provision_gate(gate),
        warm,
    )
}

fn region_a() -> RegionId {
    RegionId("region-a".to_owned())
}

/// A create request whose single player names `region-a`, anchored on
/// `external_id` when one is given (so the hold cap has a key to track it by).
fn region_a_request(external_id: Option<&str>) -> SessionRequest {
    SessionRequest {
        tenant: tid(),
        players: vec![player_in_region(0, Some("region-a"))],
        external_id: external_id.map(|s| s.to_owned()),
        latency_estimate_ms: None,
    }
}

fn tid() -> TenantId {
    TenantId("sb-test".to_owned())
}

/// Creates a plain two-player session on `setup`, returning the response.
fn create_default_session(setup: &SessionSetup) -> SessionResponse {
    create_session(
        setup,
        SessionRequest {
            tenant: tid(),
            players: two_players(),
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// A one-relay setup returning the relay's enroll generation (needed to mark it
/// draining under the generation fence).
fn one_relay_setup() -> (SessionSetup, u64) {
    let reg = registry::new_registry();
    let generation = registry::enroll(
        &reg,
        RelayHello::new(
            RelayId(1),
            addr(14900),
            ProtocolVersion::CURRENT,
            fake_cert(1),
        ),
    );
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        tid(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    (SessionSetup::new(reg, tenants), generation)
}

/// A two-relay setup returning each relay's enroll generation.
fn two_relay_setup() -> (SessionSetup, u64, u64) {
    let reg = registry::new_registry();
    let g1 = registry::enroll(
        &reg,
        RelayHello::new(
            RelayId(1),
            addr(14900),
            ProtocolVersion::CURRENT,
            fake_cert(1),
        ),
    );
    let g2 = registry::enroll(
        &reg,
        RelayHello::new(
            RelayId(2),
            addr(14901),
            ProtocolVersion::CURRENT,
            fake_cert(2),
        ),
    );
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        tid(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    (SessionSetup::new(reg, tenants), g1, g2)
}

/// Enrolls a relay tagged with `region` (or untagged when `None`), under the
/// id-derived fake cert.
fn enroll_relay_in_region(reg: &RelayRegistry, id: u64, port: u16, region: Option<&str>) {
    let mut hello = RelayHello::new(
        RelayId(id),
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ProtocolVersion::CURRENT,
        fake_cert(id),
    );
    if let Some(region) = region {
        hello = hello.with_region(RegionId(region.to_owned()));
    }
    registry::enroll(reg, hello);
}

/// A player in `slot` requesting `region` (or none), with an id-derived pubkey.
fn player_in_region(slot: u8, region: Option<&str>) -> PlayerHandoff {
    PlayerHandoff {
        slot: SlotId(slot),
        client_pubkey: ClientPublicKey([slot; 32]),
        external_ref: None,
        observer: false,
        region: region.map(|r| RegionId(r.to_owned())),
    }
}

/// A tenant-enrolled setup with the given region-tagged relays.
fn setup_with_region_relays(relays: &[(u64, u16, Option<&str>)]) -> SessionSetup {
    let reg = registry::new_registry();
    for &(id, port, region) in relays {
        enroll_relay_in_region(&reg, id, port, region);
    }
    let tenants = tenant::new_store();
    tenant::enroll(
        &tenants,
        KeyId("test-key-1".to_owned()),
        tid(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    SessionSetup::new(reg, tenants)
}

/// Creates a session from `players` (region-tagged), returning the response.
fn create_region_session(setup: &SessionSetup, players: Vec<PlayerHandoff>) -> SessionResponse {
    create_session(
        setup,
        SessionRequest {
            tenant: tid(),
            players,
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response
}
