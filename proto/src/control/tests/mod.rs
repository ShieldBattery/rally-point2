//! Tests for `control`, split by the same topics as the non-test files.
//!
//! Shared fixtures/imports live here; each child does `use super::*;` to pick
//! them up along with everything `control`'s own top brought into scope,
//! private items included (a child is a descendant of this module).

use std::net::{Ipv4Addr, SocketAddr};

use super::*;
use crate::ids::{RelayId, SessionId, SlotId};
use crate::token::{ClientPublicKey, KeyId, PUBLIC_KEY_LEN};
use crate::version::ProtocolVersion;

mod messages_flight_load;
mod messages_frames;
mod messages_heartbeat;
mod notices;
mod relay;
mod session;

/// A fully populated descriptor: one peer, an authority order, a latency
/// estimate, and every optional list at its default. Tests that need a
/// different shape build on it with struct-update syntax.
fn a_descriptor() -> SessionDescriptor {
    SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId("sb-staging".to_owned()),
        session: SessionId(42),
        peers: vec![RelayPeer {
            relay_id: RelayId(2),
            relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
            cert_der: vec![0x30, 0x82, 0xCC, 0xDD],
            relay_addrs: vec![],
        }],
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![RelayId(1), RelayId(2)],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: Some(45),
        relay_regions: Vec::new(),
    }
}

/// A minimal enroll hello: one address, no additive field set. The fixture the
/// additive-field tests start from, since every one of them is about what this
/// hello does *not* put on the wire.
fn a_hello() -> RelayHello {
    RelayHello::new(
        RelayId(7),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        ProtocolVersion::CURRENT,
        vec![0xAA; 4],
    )
}
