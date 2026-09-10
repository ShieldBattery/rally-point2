//! Building the per-relay [`SessionDescriptor`] the coordinator stages in a
//! relay's outbox, and the reads over a session's recorded correlation state
//! (`SessionRefs`) that both the descriptor build and the api handlers use.

use rally_point_proto::control::{
    DepartedSlot, RegionId, RelayPeer, RelayRegionLabel, SessionDescriptor, SlotExternalRef,
};
use rally_point_proto::ids::{RelayId, SessionId};

use crate::registry;
use crate::tenant;

use super::SessionRefs;
use super::setup::SessionSetup;

/// Builds the [`SessionDescriptor`] the coordinator pushes to a relay serving
/// `session`, so the relay can join the session on its mesh links.
///
/// `peers` is the list of *other* relays serving the same session — the
/// relay's mesh peers, read from the session→relay membership `create_session`
/// recorded. For a single-relay session (no mesh), this is empty. For a
/// multi-relay session, it's every relay in the session except the one the
/// descriptor is being built for.
///
/// Every descriptor also carries the tenant's stored correlation ids
/// ([`session_refs`]) — the session's `external_id` and each slot's
/// `external_ref` — so every relay serving the session can stamp them into a
/// departure notice itself, rather than the notification depending on the
/// coordinator's in-memory session-refs store surviving to notice time (it
/// doesn't survive a coordinator restart; the descriptor-carried copy is what
/// does, since a relay holds what it last received independently of the
/// coordinator's process lifetime). It carries the session's observer slots the
/// same way, so a relay's desync comparator can exclude them.
///
/// Returns `None` if the session has no recorded relay membership (the
/// session doesn't exist or wasn't created through `create_session`), or if
/// the tenant's bounds are no longer enrolled (the tenant was removed).
pub fn descriptor_for(
    setup: &SessionSetup,
    tenant: &rally_point_proto::control::TenantId,
    session: SessionId,
    relay_id: RelayId,
) -> Option<SessionDescriptor> {
    build_descriptor(setup, tenant, session, relay_id, false, Vec::new())
}

/// Builds the [`SessionDescriptor`] for a relay serving `session`, with the
/// rehome-specific fields controlled by the caller.
///
/// `resumed` marks a descriptor that re-homes an already-running session onto a
/// relay (the coordinator-mediated failover path), and `departed_slots` seeds the
/// slots the coordinator already knows departed so a fresh relay with no mesh peer
/// to replay them still treats their leaves as decided. `create_session` and the
/// public [`descriptor_for`] pass `false`/empty (the ordinary start-on-coverage
/// path); [`rehome`](fn@crate::session::rehome) passes `true` plus the session's departed accounting.
pub fn build_descriptor(
    setup: &SessionSetup,
    tenant: &rally_point_proto::control::TenantId,
    session: SessionId,
    relay_id: RelayId,
    resumed: bool,
    departed_slots: Vec<DepartedSlot>,
) -> Option<SessionDescriptor> {
    let bounds = tenant::bounds(&setup.tenants, tenant)?;

    let relay_ids = setup
        .session_relays
        .lock()
        .get(&(tenant.clone(), session))?
        .clone();

    // The peers are the session's relays except the one this descriptor is
    // for — each relay meshes with the others serving the same session.
    let peers: Vec<RelayPeer> = relay_ids
        .iter()
        .filter(|&&id| id != relay_id)
        .filter_map(|&id| registry::peer(&setup.registry, id))
        .collect();

    let refs = session_refs(setup, tenant, session).unwrap_or_default();

    Some(SessionDescriptor {
        finalized_drops: refs.finalized_drops,
        tenant: tenant.clone(),
        session,
        peers,
        bounds,
        // The recorded membership is already the authority priority order:
        // `create_session` lists the primary home relay first, then the other
        // homes. A unique plurality is primary; equal-population ties rotate by
        // session id so authority load spreads across balanced sessions. It
        // decides the buffer while its players are present, and authority falls
        // down this list as relays' players leave.
        authority_order: relay_ids,
        external_id: refs.external_id,
        slot_refs: refs
            .slots
            .into_iter()
            .map(|(slot, external_ref)| SlotExternalRef { slot, external_ref })
            .collect(),
        observer_slots: refs.observers,
        expected_slots: refs.expected,
        // Only the slots homed on THIS relay — `refs.homes` covers every slot
        // in the session, so filter to this descriptor's `relay_id`. Iterating
        // a `BTreeMap` yields ascending slot order, so this is deterministic
        // without an explicit sort.
        homed_slots: refs
            .homes
            .into_iter()
            .filter(|&(_, home_relay)| home_relay == relay_id)
            .map(|(slot, _)| slot)
            .collect(),
        resumed,
        departed_slots,
        // The tenant's latency hint, carried down so the authority relay folds it
        // into the initial buffer depth. Present on a rehome-rebuilt descriptor too
        // (harmless: a resumed relay never re-stamps a depth).
        latency_estimate_ms: refs.latency_estimate_ms,
        // Every serving relay's region — the whole session's map, not just this
        // descriptor's relay, since a relay releases the complete map to its
        // clients once its own release delay has elapsed in-game. Rebuilt on
        // every push, so a re-home's replacement relay and its region reach every
        // serving relay with the peer set.
        relay_regions: relay_region_labels(&refs.relay_regions),
    })
}

/// Reduces a relay→region map, as recorded per session in
/// [`SessionRefs::relay_regions`], to the wire label list a descriptor or session
/// response carries: one [`RelayRegionLabel`] per relay the coordinator tagged
/// with a region, in ascending relay-id order (a `BTreeMap`'s natural iteration
/// order). Untagged relays are dropped rather than carried with an empty label,
/// so an absent entry unambiguously means "no region recorded".
pub(super) fn relay_region_labels(
    relay_regions: &std::collections::BTreeMap<RelayId, Option<RegionId>>,
) -> Vec<RelayRegionLabel> {
    relay_regions
        .iter()
        .filter_map(|(&relay_id, region)| {
            region
                .clone()
                .map(|region| RelayRegionLabel { relay_id, region })
        })
        .collect()
}

/// The region `session` has recorded for `relay`, or `None` when the relay
/// carries no region, or the session (or this particular relay within it) has no
/// recorded region — an unknown session, a relay the session never served, or a
/// coordinator run without a region catalog. Backed by the same
/// [`SessionRefs::relay_regions`] a re-home itself consults to prefer the dead
/// relay's own region for its replacement pick, so a re-home response can label
/// its replacement relay the same way a session-create response labels its home
/// relay.
pub fn relay_region_for(
    setup: &SessionSetup,
    tenant: &rally_point_proto::control::TenantId,
    session: SessionId,
    relay: RelayId,
) -> Option<RegionId> {
    session_refs(setup, tenant, session)?
        .relay_regions
        .get(&relay)
        .cloned()
        .flatten()
}

/// The tenant's correlation ids for `session`, recorded at `create_session`, or
/// `None` if the session was never created here (or predates this coordinator
/// lifetime). Read when a departure notice is enriched into a webhook.
pub fn session_refs(
    setup: &SessionSetup,
    tenant: &rally_point_proto::control::TenantId,
    session: SessionId,
) -> Option<SessionRefs> {
    setup
        .session_refs
        .lock()
        .get(&(tenant.clone(), session))
        .cloned()
}
