//! Region-aware placement: which relay homes each slot, which relay is primary,
//! and the pending-create hold that keeps a create waiting while a cold region
//! is warmed. Grouped together because the hold decision and the placement it
//! defers to must read the same available-relay snapshot and region-match rule.

use std::collections::HashMap;
use std::time::Duration;

use parking_lot::Mutex;
use rally_point_proto::control::{
    RegionId, RelayEndpoint, RelayEntry, SessionRequest, SlotHome, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};

use crate::registry::{self, RelayRegistry, SessionSetupError, cert_fingerprint};

use super::PENDING_PRUNE_MIN_SLACK;

/// A session's relay placement, distilled into the response shape and the
/// coordinator-side records the descriptors and a later re-home read, built by
/// [`place_by_region`].
pub(super) struct Placement {
    /// The session's primary home relay — the response's `home_relay`, where the
    /// most slots home (ties rotate deterministically by session id).
    pub(super) home: RelayEndpoint,
    /// Per-slot overrides for the slots homing on a relay other than `home`.
    pub(super) slot_homes: Vec<SlotHome>,
    /// The session's serving relays in authority order — `home` first, then the
    /// rest by ascending id. The distinct assigned homes, so every serving relay
    /// homes at least one slot.
    pub(super) relay_ids: Vec<RelayId>,
    /// Every slot's assigned home relay id.
    pub(super) homes: std::collections::BTreeMap<SlotId, RelayId>,
    /// Whether the session runs the finalized-drop handshake: the placed
    /// cohort is capable AND the feature switch is on (see `place_by_region`).
    pub(super) finalized_drops: bool,
    /// Whether the placed cohort is finalized-drop capable — the session's
    /// build class, kept even when the feature switch is off so rehome and
    /// eviction never mix build classes.
    pub(super) capable_cohort: bool,
    /// Each serving relay's client-cert fingerprint, for a later re-home's
    /// restart-in-place detection.
    pub(super) relay_certs: std::collections::BTreeMap<RelayId, [u8; 32]>,
    /// Each serving relay's region at pick time, so a re-home can prefer the dead
    /// relay's region for the replacement.
    pub(super) relay_regions: std::collections::BTreeMap<RelayId, Option<RegionId>>,
}

/// The requested slot regions with no available relay to home them — the regions
/// [`place_by_region`] would fall back to the region-blind pick for. Reads the same
/// available-relay snapshot placement does and applies the same region-match rule,
/// so the hold decision and the eventual placement agree on which regions are lit.
/// Order-preserving and de-duplicated: each unlit region appears once, in
/// first-requested order. A request naming no regions yields an empty set.
pub(super) fn unlit_requested_regions(
    registry: &RelayRegistry,
    request: &SessionRequest,
) -> Vec<RegionId> {
    let entries = registry::available_entries(registry);
    let mut unlit: Vec<RegionId> = Vec::new();
    for player in &request.players {
        if let Some(region) = &player.region
            && !unlit.contains(region)
            && !entries.iter().any(|e| e.region.as_ref() == Some(region))
        {
            unlit.push(region.clone());
        }
    }
    unlit
}

/// Consults (and updates) the pending-create anchor for `key`, returning whether
/// the create should be held (answered [`CreateOutcome::Provisioning`]) rather than
/// placed now.
///
/// The first hold for a key stamps `now`; a retry within `create_hold` of that
/// stamp keeps holding; once `create_hold` has elapsed the anchor is dropped and the
/// create is released to placement. An unusable clock (`now == u64::MAX`) never holds
/// and clears any anchor it finds, so a broken clock releases the create to fallback
/// rather than wedging it. Every consult also prunes anchors older than the cap plus
/// generous slack, so a create that is started and never retried cannot leave its
/// anchor in the map for the process lifetime; a live create polling within the cap
/// is released by the cap before it could ever reach the prune horizon, so pruning
/// never drops the current key from under it.
pub(super) fn hold_pending_create(
    pending: &Mutex<HashMap<(TenantId, String), u64>>,
    key: &(TenantId, String),
    now: u64,
    create_hold: Duration,
) -> bool {
    // An unusable clock cannot measure the cap: do not hold, and drop any stale
    // anchor so a recovered clock starts a fresh, bounded hold.
    if now == u64::MAX {
        pending.lock().remove(key);
        return false;
    }
    let cap = create_hold.as_secs();
    let prune_horizon = cap
        .saturating_mul(10)
        .max(PENDING_PRUNE_MIN_SLACK.as_secs());
    let mut map = pending.lock();
    map.retain(|_, &mut first| now.saturating_sub(first) <= prune_horizon);
    match map.get(key).copied() {
        None => {
            map.insert(key.clone(), now);
            true
        }
        Some(first) if now.saturating_sub(first) < cap => true,
        Some(_) => {
            map.remove(key);
            false
        }
    }
}

/// The current Unix time in seconds, **failing closed**: a pre-epoch or errored
/// clock yields `u64::MAX`, which the hold logic treats as an unusable clock and
/// declines to hold on, so a broken clock releases a create to fallback instead of
/// wedging it.
pub(super) fn now_unix_secs_fail_closed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

/// Region-aware placement: home each slot on a live relay in the region it
/// requested, falling back to the region-blind pick (the lowest-id available
/// relay overall) for a slot that named no region, or whose region has no live
/// relay. Slots sharing a region share that region's relay, so a same-region
/// game stays single-relay while a cross-region game produces the meshed
/// `slot_homes` shape.
///
/// The response's `home_relay` is the relay assigned the most slots. When several
/// relays tie for that maximum, the would-be session id rotates the primary among
/// them; `slot_homes` still records the exact same per-slot assignment regardless
/// of which tied relay is primary. By construction the serving set is exactly the
/// distinct assigned homes and every serving relay homes at least one slot.
pub(super) fn place_by_region(
    registry: &RelayRegistry,
    request: &SessionRequest,
    session: SessionId,
    finalize_feature: bool,
) -> Result<Placement, SessionSetupError> {
    let mut entries = registry::available_entries(registry);
    if entries.is_empty() {
        return Err(SessionSetupError::NoRelaysAvailable);
    }

    // Capability-homogeneous placement: a session's relays must all sit on
    // the same side of the finalized-drop capability boundary. A relay
    // without the capability can still author the historical counted-drop
    // behavior that capability-bearing relays strip at ingress, so mixing the
    // two classes in one session would hand different clients different leave
    // schedules — the divergence the capability exists to rule out. Prefer
    // the capable cohort (the fleet's future); fall back to the incapable one
    // only when no capable relay is available at all. Within the chosen
    // cohort the region logic below runs unchanged — a slot whose region only
    // exists in the other cohort takes the in-cohort region-blind fallback
    // rather than mixing. Cohorting applies whether or not the FEATURE is
    // enabled — build classes must never mix in one session regardless — but
    // the handshake itself only turns on for a capable cohort when the
    // coordinator's feature switch says so.
    let capable_cohort = entries.iter().any(relay_finalize_capable);
    if capable_cohort {
        entries.retain(relay_finalize_capable);
    }
    let finalized_drops = capable_cohort && finalize_feature;

    // NOTE(version-aware placement): each entry carries the relay's advertised
    // `protocol` (negotiated against at enroll — an incompatible relay never gets
    // this far), so a placement policy that keeps one session's relays on a single
    // protocol version — needed once a wire bump rolls through a mixed fleet —
    // would filter the candidates here. Nothing consumes it yet; assignment stays
    // version-blind.

    // Ascending id, so "first in a region" and "first overall" are both the
    // deterministic lowest-id pick.
    entries.sort_by_key(|e| e.relay_id);
    let fallback = &entries[0];

    // Assign each slot: the lowest-id available relay in its requested region if
    // one exists, else the region-blind fallback.
    let slot_relay: Vec<(SlotId, &RelayEntry)> = request
        .players
        .iter()
        .map(|player| {
            let entry = player
                .region
                .as_ref()
                .and_then(|region| entries.iter().find(|e| e.region.as_ref() == Some(region)))
                .unwrap_or(fallback);
            (player.slot, entry)
        })
        .collect();

    // The home relay is the one assigned the most slots. A unique plurality or
    // majority always wins; among equal maxima, rotate deterministically by the
    // would-be session id so consecutive balanced sessions do not concentrate all
    // authority work on the same relay. The map orders candidates by relay id,
    // making the modulo selection stable across coordinator processes.
    let mut counts: std::collections::BTreeMap<RelayId, usize> = std::collections::BTreeMap::new();
    for (_, entry) in &slot_relay {
        *counts.entry(entry.relay_id).or_insert(0) += 1;
    }
    let max_count = counts
        .values()
        .copied()
        .max()
        .expect("a non-empty player list always assigns at least one slot");
    let home_candidates: Vec<RelayId> = counts
        .iter()
        .filter_map(|(&id, &count)| (count == max_count).then_some(id))
        .collect();
    let home_id = home_candidates[(session.0 % home_candidates.len() as u64) as usize];

    // Serving relays in authority order: home first, then the rest ascending
    // (`counts` keys are already ascending).
    let mut relay_ids = vec![home_id];
    relay_ids.extend(counts.keys().copied().filter(|&id| id != home_id));

    let entry_for = |id: RelayId| -> &RelayEntry {
        entries
            .iter()
            .find(|e| e.relay_id == id)
            .expect("a serving relay is always one of the assigned entries")
    };

    let home = RelayEndpoint::from(entry_for(home_id));
    let slot_homes: Vec<SlotHome> = slot_relay
        .iter()
        .filter(|(_, entry)| entry.relay_id != home_id)
        .map(|(slot, entry)| SlotHome {
            slot: *slot,
            relay: RelayEndpoint::from(*entry),
        })
        .collect();
    let homes = slot_relay
        .iter()
        .map(|(slot, entry)| (*slot, entry.relay_id))
        .collect();
    let relay_certs = relay_ids
        .iter()
        .map(|&id| (id, cert_fingerprint(&entry_for(id).cert_der)))
        .collect();
    let relay_regions = relay_ids
        .iter()
        .map(|&id| (id, entry_for(id).region.clone()))
        .collect();

    Ok(Placement {
        home,
        slot_homes,
        relay_ids,
        homes,
        relay_certs,
        relay_regions,
        finalized_drops,
        capable_cohort,
    })
}

/// Whether `entry` enrolled advertising the finalized-drop capability — the
/// cohort test placement and rehome both key on.
pub(super) fn relay_finalize_capable(entry: &RelayEntry) -> bool {
    entry
        .capabilities
        .iter()
        .any(|c| c == rally_point_proto::control::CAPABILITY_FINALIZED_DROP_V1)
}
