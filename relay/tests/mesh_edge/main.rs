//! End-to-end coverage of the relay mesh: `C–S===S–C`.
//!
//! Two relays serve on one endpoint each (client + mesh ALPNs). A dials B on
//! the mesh ALPN; B's accept loop dispatches the connection to the mesh path
//! via `mesh_accept`. Both sides wrap as `MeshLink`, register a forward channel
//! for the session, and spawn the mesh-link driver. A client on relay A sends
//! a turn; a client on relay B receives it across the mesh. Asserts the turn
//! arrives exactly once — proving the full cross-relay delivery path through
//! the real ALPN dispatch + mesh fan-out.

#[path = "../common/mod.rs"]
mod common;
mod helpers;

mod link_lifecycle;
mod lobby;
mod presence;
mod sessions;
mod turns;
