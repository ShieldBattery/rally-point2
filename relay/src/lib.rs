//! `rally-point-relay` — the validating netcode v2 relay (library half).
//!
//! The relay is the transport *below* the game's OUT/IN hooks and the
//! server-side vantage point for everything stateful in netcode v2:
//!
//! - **authorization** ([`auth`]) — verify each client's connection-bound,
//!   per-tenant token and prove key possession before any turn is trusted.
//! - **validation** ([`validation`]) — bind each turn to the token's slot,
//!   bounds-check every command, allowlist live ids, strip client-originated
//!   control commands.
//! - **routing** ([`routing`]) — group authorized connections by session and fan
//!   each validated turn out to that session's other slots.
//! - **server** ([`server`]) — the client-facing accept loop tying the three
//!   together: the single-relay `C–S–C` edge, no mesh.
//! - **mesh + dedup** — one QUIC connection per relay-pair, topological fan-out,
//!   topological dedup, degrade-to-single-relay (`C–S–C`).
//! - **mesh_edge** ([`mesh_edge`]) — the mesh-edge connection half: establish
//!   each relay↔relay QUIC connection (dial when lower-id, accept otherwise),
//!   exchange a peer-identity hello so each link is labeled with its peer's id,
//!   and spawn a `run_mesh_link` driver. The Join/Leave stream that drives
//!   session membership is pluggable — the test sends it today, the
//!   coordinator's session-descriptor push does in production (Phase 3).
//! - **mesh_control** ([`mesh_control`]) — the Join source: holds the per-peer
//!   `MeshCommand` senders the connection half surfaces and turns a coordinator
//!   `SessionDescriptor` into targeted `Join`/`Leave` on the links serving that
//!   session. Robust to whether a link or its descriptor arrives first.
//! - **coordinator_client** ([`coordinator_client`]) — the relay side of the
//!   coordinator→relay control transport: polls the coordinator for this relay's
//!   current session-descriptor set and feeds each descriptor to the
//!   `mesh_control` Join source, reconciling membership as sessions come and go.
//! - **consensus** ([`consensus`]) — the latency-buffer decision-maker: the
//!   relay-side core that turns game-wide network conditions into a buffer-size
//!   change, scheduled at an agreed future turn. Authority is an injected input
//!   (single-relay = `SelfRelay`) until multi-relay liveness lands with the mesh
//!   wiring + coordinator; the coordinator only sets *bounds*.
//! - **turn log** — persist + replicate the per-game turn log; the same
//!   "replay from cursor X" primitive serves failover and (future) observers.
//! - **flight recorder** — per-game turn stream + per-link health + events,
//!   flushed to a durable store *before* scale-to-zero teardown.
//!
//! The client edge — authorization, validation, single-relay routing, the
//! consensus decision core, and the mesh-edge connection half — is built; the
//! stateful layers above the decision core are not yet. The binary half
//! ([`main`](../main.rs)) wires up the process.

pub mod auth;
pub mod config;
pub mod coordinator_client;
pub mod mesh;
pub mod mesh_control;
pub mod mesh_dialer;
pub mod mesh_edge;
pub mod presence;
pub mod routing;
pub mod server;
pub mod validation;

pub mod consensus;
// TODO: pub mod turn_log;         // replicated, bounded + flushed
// TODO: pub mod flight_recorder;  // tenant/session/slot/turn

/// Default UDP port the relay listens on for client + mesh QUIC connections.
// TODO: reconcile with the Fargate task def + per-game IP rotation.
pub const DEFAULT_PORT: u16 = 14_900;
