//! Value builders: tenant/region ids, session descriptors, relay hellos, a
//! fleet of enrolled relays, a session request.
//!
//! The types here are wire structs with many fields, most of which any one test
//! does not care about. Each builder returns a plain, valid value; a test that
//! cares about a field overrides it with struct-update syntax
//! (`SessionRequest { external_id: Some(..), ..request(players) }`) so the line
//! a reader sees is exactly the part that matters to the test.

use std::net::{Ipv4Addr, SocketAddr};

use rally_point_proto::control::{
    BufferBounds, PlayerHandoff, RegionId, RelayHello, SessionDescriptor, SessionRequest, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, KeyId};
use rally_point_proto::version::ProtocolVersion;

use crate::regions::RegionsConfig;
use crate::registry::{self, RelayRegistry};
use crate::session::SessionSetup;
use crate::tenant::{self, TenantStore};

/// The tenant every unit test enrolls and requests under.
pub(crate) fn tid() -> TenantId {
    TenantId("sb-test".to_owned())
}

/// The signing-key id `tid()`'s tenant enrolls under.
pub(crate) fn test_key_id() -> KeyId {
    KeyId("test-key-1".to_owned())
}

/// A region id from its name.
pub(crate) fn region(name: &str) -> RegionId {
    RegionId(name.to_owned())
}

/// A loopback address on `port`.
pub(crate) fn addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// A fake per-relay cert DER, derived from the id so a test can check that a
/// response, peer list, or pin carries the right relay's certificate.
pub(crate) fn fake_cert(id: u64) -> Vec<u8> {
    vec![id as u8; 4]
}

/// A relay phone-home for `id` on a loopback `port`, carrying the id-derived
/// fake cert. Chain [`RelayHello::with_region`] /
/// [`RelayHello::with_capabilities`] for the tagged and capable variants, or
/// use [`hello_with_cert`] to simulate a same-id restart under a fresh cert.
pub(crate) fn hello(id: u64, port: u16) -> RelayHello {
    RelayHello::new(
        RelayId(id),
        addr(port),
        ProtocolVersion::CURRENT,
        fake_cert(id),
    )
}

/// [`hello`] under an explicit certificate — a same-id relay that restarted
/// with a new leaf, which is the signal a re-home keys on.
pub(crate) fn hello_with_cert(id: u64, port: u16, cert_der: Vec<u8>) -> RelayHello {
    RelayHello::new(RelayId(id), addr(port), ProtocolVersion::CURRENT, cert_der)
}

/// A tenant store with `tid()` enrolled under bounds `1..=6`.
pub(crate) fn tenant_store() -> TenantStore {
    let tenants = tenant::TenantStore::new();
    tenant::enroll(
        &tenants,
        test_key_id(),
        tid(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    tenants
}

/// One relay in a [`fleet`]: its id, the loopback port it advertises, the
/// region it enrolled in (`None` for an untagged relay — the region-blind
/// fallback pick), and whether its build advertises finalized drops.
pub(crate) type FleetRelay<'a> = (u64, u16, Option<&'a str>, bool);

/// Enrolls `relays` into a fresh registry, enrolls `tid()` in a fresh tenant
/// store, and returns the [`SessionSetup`] over both plus each relay's enroll
/// generation in the order given (a drain mark or a fenced removal needs it).
pub(crate) fn fleet(relays: &[FleetRelay<'_>]) -> (SessionSetup, Vec<u64>) {
    let reg = registry::RelayRegistry::new();
    let generations = enroll_fleet(&reg, relays);
    (SessionSetup::new(reg, tenant_store()), generations)
}

/// Enrolls `relays` into `reg` the way [`fleet`] does, for a test that already
/// holds a registry (a relay arriving after setup, say).
pub(crate) fn enroll_fleet(reg: &RelayRegistry, relays: &[FleetRelay<'_>]) -> Vec<u64> {
    relays
        .iter()
        .map(|&(id, port, relay_region, capable)| {
            let mut relay_hello = hello(id, port);
            if let Some(name) = relay_region {
                relay_hello = relay_hello.with_region(region(name));
            }
            if capable {
                relay_hello = relay_hello.with_capabilities(vec![
                    rally_point_proto::control::CAPABILITY_FINALIZED_DROP_V1.to_owned(),
                ]);
            }
            registry::enroll(reg, relay_hello)
        })
        .collect()
}

/// A player in `slot` with an id-derived pubkey, requesting no region and
/// carrying no external ref. Override fields with struct-update syntax.
pub(crate) fn player(slot: u8) -> PlayerHandoff {
    PlayerHandoff {
        slot: SlotId(slot),
        client_pubkey: ClientPublicKey([slot; 32]),
        external_ref: None,
        observer: false,
        region: None,
    }
}

/// A player in `slot` requesting `in_region` (or none).
pub(crate) fn player_in_region(slot: u8, in_region: Option<&str>) -> PlayerHandoff {
    PlayerHandoff {
        region: in_region.map(region),
        ..player(slot)
    }
}

/// The canned two-player roster: slots 0 and 1, no regions, no refs.
pub(crate) fn two_players() -> Vec<PlayerHandoff> {
    vec![
        PlayerHandoff {
            client_pubkey: ClientPublicKey([0xAA; 32]),
            ..player(0)
        },
        PlayerHandoff {
            client_pubkey: ClientPublicKey([0xBB; 32]),
            ..player(1)
        },
    ]
}

/// A create request for `tid()` over `players`, with no external id and no
/// latency estimate. Override either with struct-update syntax.
pub(crate) fn request(players: Vec<PlayerHandoff>) -> SessionRequest {
    SessionRequest {
        tenant: tid(),
        players,
        external_id: None,
        latency_estimate_ms: None,
    }
}

/// An empty descriptor for `(tenant, session)`: no peers, no refs, no homed
/// slots, bounds `1..=6`. A test overrides the fields it asserts on with
/// struct-update syntax, so its body shows only what it is about.
pub(crate) fn descriptor(tenant: TenantId, session: u64) -> SessionDescriptor {
    SessionDescriptor {
        tenant,
        session: SessionId(session),
        peers: Vec::new(),
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: Vec::new(),
        external_id: None,
        slot_refs: Vec::new(),
        observer_slots: Vec::new(),
        expected_slots: Vec::new(),
        homed_slots: Vec::new(),
        resumed: false,
        finalized_drops: false,
        departed_slots: Vec::new(),
        latency_estimate_ms: None,
        relay_regions: Vec::new(),
    }
}

/// A region config listing each of `ids`, with placeholder display and beacon
/// fields — enough for the region-aware paths that only read the id list.
pub(crate) fn regions_config(ids: &[&str]) -> RegionsConfig {
    let entries: Vec<String> = ids
        .iter()
        .map(|id| {
            format!(r#"{{"id":"{id}","display_name":"{id}","beacon":"h:1","fallback":"h:2"}}"#)
        })
        .collect();
    RegionsConfig::from_json(&format!(r#"{{"regions":[{}]}}"#, entries.join(","))).unwrap()
}
