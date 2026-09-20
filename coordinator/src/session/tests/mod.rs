//! Shared fixtures for the session tests plus the topic modules that use them.
//!
//! Everything here is a fixture: relay/tenant enrollment helpers, the canned
//! rosters, and the response-shape readers, built on the crate-wide builders in
//! `crate::test_support`. The tests themselves live in the topic children, each
//! of which glob-imports this module and therefore sees both the fixtures and
//! the private items of the code under test.

use std::net::SocketAddr;

use super::create::{
    MAX_EXTERNAL_STRING_LEN, candidate_session_id, create_session_inner, first_session_id,
};
use super::rehome::rehome_inner;
use super::*;
use crate::provision::WarmTargets;
use crate::registry::{self, SessionSetupError, cert_fingerprint};
use crate::tenant;
use crate::test_support::*;
use rally_point_proto::control::{
    BufferBounds, DepartedSlot, DepartureKind, PlayerHandoff, RelayHello, RelayRegionLabel,
    SessionRequest, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
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

/// A fleet of two untagged, incapable relays (ids 1 and 2) and the tenant --
/// the shape most tests that don't care about regions or capabilities want.
fn two_relay_fleet() -> SessionSetup {
    fleet(&[(1, 14900, None, false), (2, 14901, None, false)]).0
}

/// [`two_relay_fleet`], also returning each relay's enroll generation (needed
/// to mark one draining under the generation fence).
fn two_relay_fleet_with_generations() -> (SessionSetup, u64, u64) {
    let (setup, generations) = fleet(&[(1, 14900, None, false), (2, 14901, None, false)]);
    (setup, generations[0], generations[1])
}

/// A single untagged, incapable relay (id 1) and the tenant, also returning
/// its enroll generation.
fn one_relay_fleet_with_generation() -> (SessionSetup, u64) {
    let (setup, generations) = fleet(&[(1, 14900, None, false)]);
    (setup, generations[0])
}

/// Like [`two_relay_fleet`], but relay 2 is tagged `region-b` so a player
/// naming that region places there through the production region path,
/// producing a two-relay meshed session.
fn region_b_fleet() -> SessionSetup {
    fleet(&[(1, 14900, None, false), (2, 14901, Some("region-b"), false)]).0
}

/// A tenant-enrolled fleet of incapable relays, each optionally region-tagged.
fn region_fleet(relays: &[(u64, u16, Option<&str>)]) -> SessionSetup {
    let relays: Vec<FleetRelay<'_>> = relays
        .iter()
        .map(|&(id, port, region)| (id, port, region, false))
        .collect();
    fleet(&relays).0
}

/// Like [`two_players`], but slot 1 requests `region-b` -- landing it on relay
/// 2 in a [`region_b_fleet`] while slot 0 falls back to relay 1, so both
/// relays serve one meshed session.
fn two_players_slot_1_in_region_b() -> Vec<PlayerHandoff> {
    let mut players = two_players();
    players[1].region = Some(region("region-b"));
    players
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
    let setup = fleet(&[(1, 14900, None, false)]).0;
    let warm = WarmTargets::new();
    let gate = ProvisionGate::provisioning(warm.clone(), Duration::from_secs(600), create_hold);
    (setup.with_provision_gate(gate), warm)
}

fn region_a() -> RegionId {
    region("region-a")
}

/// A create request whose single player names `region-a`, anchored on
/// `external_id` when one is given (so the hold cap has a key to track it by).
fn region_a_request(external_id: Option<&str>) -> SessionRequest {
    SessionRequest {
        external_id: external_id.map(|s| s.to_owned()),
        ..request(vec![player_in_region(0, Some("region-a"))])
    }
}

/// Creates a plain two-player session on `setup`, returning the response.
fn create_default_session(setup: &SessionSetup) -> SessionResponse {
    create_session(setup, request(two_players()), ExpiresAt(u64::MAX))
        .unwrap()
        .response
}

/// Creates a session from `players` (region-tagged), returning the response.
fn create_region_session(setup: &SessionSetup, players: Vec<PlayerHandoff>) -> SessionResponse {
    create_session(setup, request(players), ExpiresAt(u64::MAX))
        .unwrap()
        .response
}
