//! End-to-end coverage of the relay mesh: `C–S===S–C`.
//!
//! Two relays serve on one endpoint each (client + mesh ALPNs). A dials B on
//! the mesh ALPN; B's accept loop dispatches the connection to the mesh path
//! via `mesh_accept`. Both sides wrap as `MeshLink`, register a forward channel
//! for the session, and spawn the mesh-link driver. What these tests drive is
//! what flows once that pair is up: turns and leaves across the mesh, lobby and
//! mid-game control traffic, slot presence, several sessions sharing one link,
//! and when a link stands down.

#[path = "../common/mod.rs"]
mod common;
mod helpers;

mod delivery;
mod link_lifecycle;
mod lobby;
mod presence;
mod sessions;
