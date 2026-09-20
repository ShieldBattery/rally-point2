#![allow(dead_code)]

//! Fixtures shared across the relay's unit tests, so the routing, session,
//! mesh and consensus suites stop re-declaring the same session key and the
//! same "make a decision-maker exist" prologue. Test-only; the integration
//! suites under `relay/tests/` keep their own `common` module because they see
//! only the public API.

use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::LeaveDirective;

use crate::consensus::{Authority, DecisionMakers, MakerSync, sync_maker};
use crate::key::SessionKey;

/// A session key under the shared test tenant.
pub(crate) fn session_key(session: u64) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("sb-test").unwrap(),
        session: SessionId(session),
    }
}

/// The bounds most tests run under: a wide-open latency buffer.
pub(crate) fn wide_bounds() -> BufferBounds {
    BufferBounds::new(0, 20).unwrap()
}

/// Makes a decision-maker exist for `key` with `authority`, expecting
/// `expected` slots and homing `homed` ones, the way a first descriptor push
/// would. Returns the leaves the push would broadcast (none for a fresh maker).
pub(crate) fn seed_maker(
    makers: &DecisionMakers,
    key: &SessionKey,
    authority: Authority,
    expected: &[u8],
    homed: &[u8],
) -> Vec<LeaveDirective> {
    sync_maker(
        makers,
        key,
        MakerSync {
            expected_slots: expected.iter().map(|&s| SlotId(s)).collect(),
            homed_slots: homed.iter().map(|&s| SlotId(s)).collect(),
            ..MakerSync::new(wide_bounds(), authority)
        },
    )
}

/// `seed_maker` for the common single-relay shape: self is the authority and
/// every expected slot is homed here.
pub(crate) fn seed_local_maker(makers: &DecisionMakers, key: &SessionKey, slots: &[u8]) {
    let _ = seed_maker(makers, key, Authority::SelfRelay, slots, slots);
}
