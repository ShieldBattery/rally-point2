//! `mesh::control` unit tests: shared fixtures (a session-key builder, a
//! peer/descriptor builder, and a stand-in link sender) plus three topic
//! modules split by what they exercise: link/peer membership, authority and
//! resumed-descriptor sync, and end-of-life/observability behavior.

use std::net::{Ipv4Addr, SocketAddr};

use super::*;
use rally_point_proto::control::{
    BufferBounds, DepartedSlot, DepartureKind, RelayPeer, SessionDescriptor, SlotExternalRef,
    TenantId,
};
use rally_point_proto::ids::{SessionId, SlotId};

const TENANT: &str = "sb-test";

fn key(session: u64) -> SessionKey {
    SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(session),
    }
}

fn relay_peer(id: u64) -> RelayPeer {
    RelayPeer {
        relay_id: RelayId(id),
        relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900 + id as u16)),
        cert_der: vec![id as u8; 4],
        relay_addrs: vec![],
    }
}

fn descriptor(session: u64, peers: &[u64]) -> SessionDescriptor {
    SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(session),
        peers: peers.iter().map(|&id| relay_peer(id)).collect(),
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
        relay_regions: Vec::new(),
    }
}

/// A registered link plus the receiver standing in for its driver's command
/// stream, so a test can assert what the link was told.
fn link() -> (
    mpsc::UnboundedSender<MeshCommand>,
    mpsc::UnboundedReceiver<MeshCommand>,
) {
    mpsc::unbounded_channel()
}

/// A descriptor carrying an explicit authority order, as a coordinator
/// that assigns one sends.
fn descriptor_with_order(session: u64, peers: &[u64], order: &[u64]) -> SessionDescriptor {
    SessionDescriptor {
        authority_order: order.iter().map(|&id| RelayId(id)).collect(),
        ..descriptor(session, peers)
    }
}

mod authority;
mod lifecycle;
mod membership;
