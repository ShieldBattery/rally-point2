//! Shared fixtures for the mesh-link tests: a loopback QUIC connection wrapped
//! at both ends, plus the conditions builder several topics use.
//!
//! The tests themselves are split by subject into the submodules below; each
//! pulls these helpers in with `use super::*`.

use rally_point_proto::messages::Packet;

use super::*;
use crate::test_util::{self, Edge, turn};

mod conditions;
mod demux;
mod dial;
mod receive;
mod send_budget;

/// Brings up a loopback QUIC connection negotiated on the mesh ALPN and wraps
/// each end in a `MeshLink`. Both endpoints are returned so the caller keeps
/// them alive for the test.
async fn connected_mesh_links() -> (MeshLink, MeshLink, noq::Endpoint, noq::Endpoint) {
    let (client_conn, server_conn, client, server) = test_util::loopback(Edge::Mesh).await;
    (
        MeshLink::new(client_conn),
        MeshLink::new(server_conn),
        client,
        server,
    )
}

/// [`connected_mesh_links`] on a connection whose acceptor advertises `limit`
/// as its datagram receive size, capping the sender's `max_datagram_size`
/// toward it — a stand-in for any connection whose datagram budget sits near
/// the payloads riding it (a small peer limit, or a path fallen back to the
/// MTU floor).
async fn connected_mesh_links_with_datagram_limit(
    limit: usize,
) -> (MeshLink, MeshLink, noq::Endpoint, noq::Endpoint) {
    let (client_conn, server_conn, client, server) =
        test_util::loopback_with_datagram_limit(Edge::Mesh, limit).await;
    (
        MeshLink::new(client_conn),
        MeshLink::new(server_conn),
        client,
        server,
    )
}

/// The largest conditions sidecar a real game can produce, using the same
/// field values as the relay hot-path benchmark. Each slot has a distinct,
/// stable physical-connection generation, matching production rather than
/// the legacy epoch-less rolling-upgrade shape.
fn full_epoch_conditions() -> LinkConditions {
    LinkConditions {
        slots: (0..8u32)
            .map(|slot| rally_point_proto::messages::SlotConditions {
                slot,
                rtt_us: 25_000 + slot * 7_000,
                lost_packets: u64::from(slot) * 3,
                sent_packets: 10_024,
                connection_epoch: Some(0xC0DE_0000_0000_0000 | u64::from(slot)),
            })
            .collect(),
    }
}
