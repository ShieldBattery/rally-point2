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
//! What's here today: dial the home relay ([`ClientEndpoint`]), present
//! credentials and answer the connection-binding challenge ([`Identity`]), and
//! drive a transport [`Link`](transport::Link) over the established connection
//! with [`LinkDriver`] — turns out as datagrams, peers' turns in, with app-level
//! forward recovery. Redundancy bundles are sized to the live `max_datagram_size()`
//! by the link beneath the driver; a path-MTU shrink that refuses an already-built
//! bundle is a recoverable loss the next packet re-carries, while a turn too large
//! to fit any datagram is surfaced as a hard error rather than silently dropped.
//!
//! TODO: the reliable-stream ack-beacon that force-advances the unacked window
//! under sustained loss; reliable control streams for chat/control/resync;
//! reconnect + resync-from-cursor.

/// Re-export of the shared protocol contracts, so consumers depend on a single
/// `rally_point_client` surface rather than pulling in `rally-point-proto`
/// separately.
pub use rally_point_proto as proto;

/// Re-export of the shared per-link transport machinery (ack/redundancy +
/// sequence buffer) — the client runs one instance for its home-relay link.
pub use rally_point_transport as transport;

mod dial;
mod driver;
mod identity;

pub use dial::{ClientEndpoint, DialError, EndpointError};
pub use driver::{DriverError, LinkDriver, TurnChannels};
pub use identity::{Identity, IdentityError};
