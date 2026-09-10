//! Tests for `control`, split by the same topics as the non-test files.
//!
//! Shared fixtures/imports live here; each child does `use super::*;` to pick
//! them up along with everything `control`'s own top brought into scope,
//! private items included (a child is a descendant of this module).

use std::net::{Ipv4Addr, SocketAddr};

use super::*;
use crate::ids::{RelayId, SessionId, SlotId};
use crate::token::{ClientPublicKey, KeyId, PUBLIC_KEY_LEN};
use crate::version::ProtocolVersion;

mod messages_flight_load;
mod messages_frames;
mod messages_heartbeat;
mod notices;
mod relay;
mod session;
