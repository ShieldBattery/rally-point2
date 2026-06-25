//! `rally-point-client` — the portable netcode v2 client transport.
//!
//! This crate owns the wire side of the game seam: a quinn QUIC client that
//! sends SC:R turns as datagrams and carries chat/control/resync over reliable
//! streams, with app-level forward recovery and a "home relay unreachable →
//! reconnect + resync from turn X" path.
//!
//! It is consumed by the ShieldBattery game DLL (`shieldbattery/game/`), which
//! owns the BW-thread ⇄ Tokio-thread handoff. This crate stays portable,
//! `unsafe`-free, and target-agnostic so it also builds for
//! `i686-pc-windows-msvc` inside the 32-bit DLL — CI enforces that target.
//!
//! TODO: quinn client; datagram turn I/O numbered on the `game_frame_count`
//! coordinate; reliable control streams; forward recovery that treats
//! `send_datagram` refusal as a loss event and sizes bundles to the live
//! `max_datagram_size()`; reconnect + resync-from-cursor.

/// Re-export of the shared protocol contracts, so consumers depend on a single
/// `rally_point_client` surface rather than pulling in `rally-point-proto`
/// separately.
pub use rally_point_proto as proto;

/// Re-export of the shared per-leg transport machinery (ack/redundancy +
/// sequence buffer) — the client runs one instance for its home-relay leg.
pub use rally_point_transport as transport;
