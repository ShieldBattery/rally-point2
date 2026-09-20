//! The identity of one game on this relay.
//!
//! Every per-session store in the relay — the routing roster, the mesh
//! registries, the side channels, the decision-makers — is keyed by this pair,
//! so it lives at the crate root rather than inside any one of them.

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::SessionId;

/// Identifies one game's routing group. Session ids are unique only *within* a
/// tenant, so two tenants can independently be assigned the same number; the
/// tenant is therefore part of the key. Slot occupancy and fan-out are scoped by
/// this whole key, never by the session number alone, so one tenant's game can
/// neither block nor receive another's.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    /// Tenant that owns the game — the registry's tenant, never a token claim.
    pub tenant: TenantId,
    /// Session id, unique only within `tenant`.
    pub session: SessionId,
}
