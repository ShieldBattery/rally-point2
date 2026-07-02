//! `rally-point-proto` — the shared contracts for ShieldBattery netcode v2.
//!
//! This crate is the single source of truth for every interface that crosses a
//! component boundary in netcode v2. Interfaces are *frozen here* before the
//! components that use them are built:
//!
//! - **game DLL ⇄ relay** and **relay ⇄ relay** — the datagram framing,
//!   generated from `proto/wire.proto` into [`messages`].
//! - **coordinator ⇄ relay** and **coordinator ⇄ app server** — the control
//!   plane ([`control`]). Note: consensus *decisions* are **not** here — those
//!   run on the relay/mesh keyed on [`ids::GameFrameCount`].
//! - **authorization** — connection-bound, per-tenant tokens ([`token`]) and the
//!   sans-I/O codec for the connection handshake that presents them ([`handshake`]).
//! - **relay ⇄ relay mesh establishment** — the post-connect identity hello a
//!   dialing relay sends so the accepting relay can label the link ([`mesh`]).
//! - **SC:R command parsing** — `command_lengths` + var-length rules ([`commands`]).
//! - **protocol versioning + negotiation** ([`version`]).
//! - **typed turn coordinates / ids** shared across the logic layers ([`ids`]).
//!
//! Protobuf is only the *envelope*: the SC:R command bytes inside each payload
//! are still hand-parsed and bounds-checked against [`commands`] on the relay.
//!
//! Everything here is `unsafe`-free and target-agnostic so this crate can be
//! consumed by the 32-bit game DLL (`i686-pc-windows-msvc`) as well as the
//! Linux relay / coordinator binaries.

pub mod commands;
pub mod control;
pub mod handshake;
pub mod ids;
pub mod mesh;
pub mod token;
pub mod version;

/// Sans-I/O codec for the ack-beacon side-channel.
pub mod beacon;
pub mod control_stream;

/// Generated protobuf wire messages — the turn-datagram framing.
///
/// Built from `proto/wire.proto` by this crate's `build.rs`. See
/// [`messages::Packet`] and [`messages::Payload`].
#[allow(clippy::all)]
pub mod messages {
    include!(concat!(env!("OUT_DIR"), "/rally_point.wire.rs"));
}
