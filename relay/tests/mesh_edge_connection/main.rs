//! Integration coverage of the mesh-edge **connection half**
//! (`mesh::edge::run_mesh_accept` + `run_mesh_dial`): two real relays serve on
//! their own endpoints, the lower-id one dials the higher-id one through the
//! production dial path, the higher-id one accepts through the production
//! accept drain, and each established link comes back on the `links` channel as
//! `(peer id, MeshCommand sender)` — the dialer's id known from config, the
//! acceptor's learned from the identity hello.
//!
//! `mesh_edge` covers what flows over an established pair by wiring `MeshLink`s
//! by hand; these tests cover how that pair comes to exist and stays alive:
//! who dials, what a peer must present to be accepted, what makes a link
//! redial, and how the dialer supervisor reconciles the peers a coordinator
//! descriptor names.

#[path = "../common/mod.rs"]
mod common;
mod helpers;

mod authority;
mod dial;
mod dialer;
mod flight_recorder;
mod peer_auth;
