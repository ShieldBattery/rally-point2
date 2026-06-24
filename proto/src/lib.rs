//! `rally-point-proto` — the shared contracts for ShieldBattery netcode v2.
//!
//! This crate is the single source of truth for every interface that crosses a
//! component boundary in netcode v2. Per Phase 0 of the build plan, interfaces
//! are *frozen here* before the components that use them are built:
//!
//! - **game DLL ⇄ relay** and **relay ⇄ relay** — the datagram framing,
//!   generated from `proto/wire.proto` into [`messages`].
//! - **coordinator ⇄ relay** and **coordinator ⇄ app server** — the control
//!   plane ([`control`]). Note: consensus *decisions* are **not** here — those
//!   run on the relay/mesh keyed on [`ids::GameFrameCount`] (decision **D9**).
//! - **authorization** — connection-bound, per-tenant tokens ([`token`]).
//! - **SC:R command parsing** — `command_lengths` + var-length rules ([`commands`]).
//! - **protocol versioning + negotiation** ([`version`]).
//! - **typed turn coordinates / ids** shared across the logic layers ([`ids`]).
//!
//! Protobuf is only the *envelope*: the SC:R command bytes inside each payload
//! are still hand-parsed and bounds-checked against [`commands`] on the relay
//! (D10).
//!
//! Everything here is `unsafe`-free and target-agnostic so this crate can be
//! consumed by the 32-bit game DLL (`i686-pc-windows-msvc`) as well as the
//! Linux relay / coordinator binaries.
//!
//! See `../shieldbattery/netcode-v2-build-plan.md` (Phase 0) for the full
//! rationale and the `D1`–`D11` decisions referenced throughout.

pub mod commands;
pub mod control;
pub mod ids;
pub mod token;
pub mod version;

/// Generated protobuf wire messages — the turn-datagram framing.
///
/// Built from `proto/wire.proto` by this crate's `build.rs`. See
/// [`messages::Packet`] and [`messages::Payload`].
#[allow(clippy::all)]
pub mod messages {
    include!(concat!(env!("OUT_DIR"), "/rally_point.wire.rs"));
}
