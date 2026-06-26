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
//! The redundancy/ack logic is ported from the proven implementation in
//! `shieldbattery/game/src/netcode/`: [`sequence_buffer`] carries over essentially
//! verbatim, while [`ack_manager`] is *re-derived* for our message shapes. It
//! keeps the original's independent per-payload `seq` as the dedup/ack key —
//! `game_frame_count` rides inside payloads as the consensus coordinate, not
//! as the transport key — and the relay validates payload contents.
//!
//! [`quic`] holds the shared QUIC/TLS setup the link runs on: the client and
//! relay build their endpoints from the same crypto config so they stay in
//! lockstep on protocol version, ALPN, and crypto provider.

pub mod ack_manager;
pub mod link;
pub mod quic;
pub mod sequence_buffer;

pub use ack_manager::{AckError, AckManager};
pub use link::{Link, LinkError};

/// Re-exports of the QUIC stack and its TLS layer, so a consumer pins exactly
/// the versions this crate was built against rather than declaring its own.
pub use {quinn, rustls};
