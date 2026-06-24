//! `rally-point-transport` — per-leg reliable delivery over unreliable QUIC datagrams.
//!
//! Every hop of the netcode v2 path is an independent unreliable leg with its own
//! packet loss — client ↔ home relay (`C–S`) and relay ↔ relay across the mesh
//! (`S===S`). Both want the same machinery, so it lives here and is shared by
//! both the [`client`](../rally_point_client) and the [`relay`](../rally_point_relay)
//! rather than in either one. Each endpoint runs one instance per leg.
//!
//! Recovery is **ours, not QUIC's** (build plan §4): payloads ride unreliable
//! QUIC datagrams, and this layer adds the redundancy + acknowledgement on top —
//! unacked payloads are repacked into later packets until a packet carrying them
//! is acked. QUIC supplies encryption, congestion control, MTU sizing, migration,
//! and loss detection, but its datagram API gives no per-datagram delivery
//! receipt (and would ack packets, not our redundantly-packed payloads), so the
//! payload-level ack/redundancy is genuinely ours to own.
//!
//! The design is ported from the proven implementation in
//! `shieldbattery/game/src/netcode/`: [`sequence_buffer`] carries over essentially
//! verbatim, while the ack manager is *re-derived* for our message shapes. It
//! keeps the original's independent per-payload `seq` as the dedup/ack key —
//! `game_frame_count` rides inside payloads as the consensus coordinate (D9), not
//! as the transport key — and the relay validates payload contents (D10).

pub mod sequence_buffer;

// TODO(phase-1): pub mod ack_manager;
// Adapted from `shieldbattery/game/src/netcode/ack_manager.rs`: same
// repack-unacked-until-acked + transitive-`ack_bits` algorithm, keyed on the
// per-payload `seq`, sized to the live `max_datagram_size()` (turns at 24/sec).
