//! Integration coverage of the mesh-edge **connection half**
//! (`mesh::edge::run_mesh_accept` + `run_mesh_dial`): two real relays serve on
//! their own endpoints, the lower-id one dials the higher-id one through the
//! production dial path, the higher-id one accepts through the production
//! accept drain, and each established link comes back on the `links` channel as
//! `(peer id, MeshCommand sender)` — the dialer's id known from config, the
//! acceptor's learned from the identity hello. The first test sends `Join` on
//! both senders directly and proves a turn flows cross-relay; the second drives
//! the same turn through `MeshControl::apply_descriptor`, exactly as the
//! coordinator's session-descriptor push will once its control transport exists.
//!
//! This mirrors `mesh_edge`'s `cross_relay_turn_delivery_is_exactly_once` but
//! exercises the connection-establishment layer (`mesh::edge`) instead of
//! manually creating `MeshLink`s and spawning `run_mesh_link`. The per-link
//! driver, dedup, and fan-out are already proven by `mesh_edge`; these tests
//! prove the connection half wires them up correctly, labels each link with its
//! peer, and that Join drives cross-relay delivery end-to-end.

#[path = "../common/mod.rs"]
mod common;
mod helpers;

mod authority;
mod cross_relay;
mod dial;
mod dialer;
mod flight_recorder;
mod peer_auth;
