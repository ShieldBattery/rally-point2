//! Tests for the transport link, split by subject.
//!
//! This file holds only what the topic modules share: the `Link`-wrapped
//! loopback QUIC pair. Each topic module opens with `use super::*;`,
//! inheriting that fixture, the crate's shared test fixtures, and the link's
//! own items.

use super::*;
use crate::test_util::{self, Edge, turn};

mod admission;
mod dedup;
mod delivery;
mod ingress;
mod resume;

/// Brings up a client-edge loopback QUIC connection and wraps each end in a
/// plain [`Link`]. The endpoints are returned so the caller keeps them alive
/// for the test.
async fn connected_links() -> (Link, Link, noq::Endpoint, noq::Endpoint) {
    let (client_conn, server_conn, client, server) = test_util::loopback(Edge::Client).await;
    (
        Link::new(client_conn),
        Link::new(server_conn),
        client,
        server,
    )
}
