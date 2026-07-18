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
//! - **lobby** ([`lobby`]) — fan pre-game lobby commands out to a session's local
//!   members and keep the per-session ordered replay log a late-joining member
//!   catches up from.
//! - **chat** ([`chat`]) — fan in-game chat messages out to a session's local
//!   members. The mid-game counterpart to `lobby`: no replay log (chat is
//!   ephemeral), plus a per-slot size and rate cap enforced at the relay.
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
//!   coordinator→relay control transport: a held WebSocket connection the relay
//!   dials out, over which the coordinator pushes this relay's current
//!   session-descriptor set (on connect and again on every change, no polling).
//!   Each set is fed to the `mesh_control` Join source, reconciling membership
//!   as sessions come and go.
//! - **region_ping** ([`region_ping`]) — relay-measured backbone round-trips:
//!   ping each region's always-up UDP echo beacon (the target set the coordinator
//!   pushes down the control connection), keep the latest measured medians, and let
//!   the heartbeat carry them back up so the coordinator can serve a measured
//!   region-pair backbone table instead of static config.
//! - **consensus** ([`consensus`]) — the latency-buffer decision-maker: the
//!   relay-side core that turns game-wide network conditions into a buffer-size
//!   change, scheduled at an agreed future turn. Authority is an injected input,
//!   computed by the caller from the coordinator descriptor's priority order and
//!   the live-player presence relays track among themselves — the first relay in
//!   that order still serving players is the authority, with handoff on presence
//!   change and no coordinator round-trip; the coordinator only sets *bounds*.
//!   The same layer also carries desync detection (a comparator across relays'
//!   independent views of the turn stream) and synced player-leaves (an agreed
//!   apply frame every survivor's client applies identically).
//! - **delivery** ([`delivery`]) — end-to-end turn-delivery tracking: the
//!   per-pair fold of client-claimed beacon cursors (origin turns reaching each
//!   destination client), hop inference, and the clamped cushion it feeds the
//!   latency-buffer decision.
//! - **turn_ring** ([`turn_ring`]) — a bounded, local, per-session record of
//!   the turns a relay has forwarded, kept only long enough to replay a
//!   reconnecting client's missed turns from its last-delivered cursor. Local
//!   and ephemeral, not persisted or replicated across relays.
//! - **flight recorder** ([`flight_recorder`]) — per-game observability:
//!   bounded per-session events + link-health samples + turn-stream counters
//!   (summaries only, never payload bytes), flushed as a self-describing JSON
//!   blob on session close and wholesale before a drain exits.
//! - **task_stats** ([`task_stats`]) — self-reported Fargate task resources:
//!   polls this relay's own ECS Task Metadata `/stats` endpoint and logs
//!   CPU/memory/network, independent of CloudWatch. A no-op outside Fargate.
//!
//! Beyond what the bullets above name directly, the relay also negotiates
//! protocol versions on connect, coordinates its own drain on shutdown (finish
//! in-flight sessions, refuse new ones, tell the coordinator it's going),
//! tracks per-slot presence across the mesh, dials peers over whichever of
//! IPv4/IPv6 the pair shares, and resumes a mesh link's turn stream from a
//! cursor after a peer reconnects — each living alongside the module it most
//! directly serves rather than as a bullet of its own. The binary half
//! ([`main`](../main.rs)) wires up the process.

pub mod auth;
pub mod chat;
pub mod config;
pub mod coordinator_client;
pub mod delivery;
pub mod drop_hold;
pub mod flight_recorder;
pub mod lobby;
pub mod mesh;
pub mod mesh_control;
pub mod mesh_dialer;
pub mod mesh_edge;
pub mod presence;
pub mod provisional;
pub mod region_ping;
pub mod routing;
pub mod server;
pub mod task_stats;
pub mod turn_ring;
pub mod validation;

pub mod consensus;

/// Default UDP port the relay listens on for client + mesh QUIC connections.
// TODO: reconcile with the Fargate task def + per-game IP rotation.
pub const DEFAULT_PORT: u16 = 14_900;
