//! End-to-end coordinator→relay descriptor transport over the persistent control
//! connection: a relay holds a real WebSocket open to the coordinator, and the
//! descriptors the coordinator pushes drive that relay's Join source.
//!
//! This is the seam the two halves were built to meet at, exercised for real: a
//! bound coordinator WebSocket server and the relay's live `coordinator::client`.
//! It covers the behaviors that matter — the relay's Hello enrolls it, the initial
//! push on connect drives a `Join`, a session ending pushes a `Leave`, and a wrong
//! bootstrap secret drives nothing — none of which the per-side unit tests show.
//!
//! Split by topic across this directory: [`helpers`] holds every fixture shared
//! by more than one topic (coordinator/relay stand-ups, hello builders, frame
//! readers); each sibling module below holds one topic's tests.

#[path = "../common/mod.rs"]
mod common;
mod helpers;

mod descriptor_deltas;
mod drain;
mod enrollment;
mod liveness;
mod mesh_peers;
mod reader_writer_split;
mod regions;
mod tenant_keys;
