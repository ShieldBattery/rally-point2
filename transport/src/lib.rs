//! `rally-point-transport` — per-link reliable delivery over unreliable QUIC datagrams.
//!
//! Every hop of the netcode v2 path is an independent unreliable link with its own
//! packet loss — client ↔ home relay (`C–S`) and relay ↔ relay across the mesh
//! (`S===S`). Both want the same machinery, so it lives here and is shared by
//! both the [`client`](../rally_point_client) and the [`relay`](../rally_point_relay)
//! rather than in either one. Each endpoint runs one instance per link.
//!
//! Recovery is **ours, not QUIC's**: payloads ride unreliable
//! QUIC datagrams, and this layer adds the redundancy + acknowledgement on top —
//! unacked payloads are repacked into later packets until a packet carrying them
//! is acked. QUIC supplies encryption, congestion control, MTU sizing, migration,
//! and loss detection, but its datagram API gives no per-datagram delivery
//! receipt (and would ack packets, not our redundantly-packed payloads), so the
//! payload-level ack/redundancy is genuinely ours to own.
//!
//! This is **not** a standard reliable-ordered protocol, and it is easy to misread
//! as one. A `Packet`'s seq is only an ack handle — it names which payloads a packet
//! carried so an ack can retire them — and orders nothing;
//! packets may arrive in any order. Loss is recovered by *redundancy*, never by
//! waiting a round-trip to notice a gap and retransmit: the next packet already
//! re-carries the unacked payloads. And nothing here reassembles a globally-ordered
//! stream — each [`recv`](link::Link::recv) returns one packet's new payloads,
//! dedup'd, in their own seq order, but successive calls follow arrival; putting
//! turns back in game order is the job of the layer above (the client, before the
//! game runs them). These are deliberate. The game is lockstep, where every player
//! advances only as fast as the slowest turn, so the head-of-line blocking and
//! retransmit-timeout latency a reliable-ordered stream would add are exactly what
//! must be avoided — and turns are tiny, so paying redundancy bandwidth to never pay
//! that latency is the trade.
//!
//! The redundancy/ack logic is ported from the proven implementation in
//! `shieldbattery/game/src/netcode/`: [`sequence_buffer`] carries over essentially
//! verbatim, while [`ack_manager`] is *re-derived* for our message shapes. It
//! keeps the original's independent per-payload `seq` as the dedup/ack key —
//! `game_frame_count` rides inside each payload as the consensus coordinate
//! (which turn a decision applies to), never as the transport key, and the
//! relay validates payload contents and preserves the frame verbatim.
//!
//! [`quic`] holds the shared QUIC/TLS setup the link runs on: the client and
//! relay build their endpoints from the same crypto config so they stay in
//! lockstep on protocol version, ALPN, and crypto provider.

pub mod ack_manager;
pub mod link;
pub mod mesh_link;
pub mod quic;
pub mod sequence_buffer;

pub use ack_manager::{AckError, AckManager};
pub use link::{Link, LinkError, Received};
pub use mesh_link::{MeshLink, MeshLinkError, SessionLink, should_dial_mesh};

/// Shared ack-beacon side-channel helpers (read-loop task + cursor push), used
/// by both the client and relay drivers.
pub mod beacon;

/// Re-exports of the QUIC stack and its TLS layer, so a consumer pins exactly
/// the versions this crate was built against rather than declaring its own.
pub use {quinn, rustls};
