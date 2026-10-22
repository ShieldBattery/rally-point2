//! Region-aware placement: which relay homes each slot, which relay is primary,
//! and the pending-create hold that keeps a create waiting while a cold region
//! is warmed. Grouped together because the hold decision and the placement it
//! defers to must read the same available-relay snapshot and region-match rule.

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use parking_lot::Mutex;
use rally_point_proto::control::{
    RegionId, RelayEndpoint, RelayEntry, SessionRequest, SlotHome, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};

use crate::pair_rtts::PairRttStore;
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
    /// Whether the session rolls back: the request asked for it and every placed relay supports
    /// it (see `place_by_region`).
    pub(super) rollback: bool,
    /// Each serving relay's client-cert fingerprint, for a later re-home's
    /// restart-in-place detection.
    pub(super) relay_certs: std::collections::BTreeMap<RelayId, [u8; 32]>,
    /// Each serving relay's region at pick time, so a re-home can prefer the dead
    /// relay's region for the replacement.
    pub(super) relay_regions: std::collections::BTreeMap<RelayId, Option<RegionId>>,
}

/// How much farther (backbone round-trip, in milliseconds) a relay already serving
/// the session may sit from a slot's region than the nearest available relay and
/// still be chosen over it. Reusing a serving relay keeps the session's relay set
/// from growing: one fewer mesh link for turns to cross and one fewer relay whose
/// death disturbs the game. A gap this small is about what two independent
/// medians of the same long backbone path disagree by (the pair table's own
/// dead-band is 5% of the value, 15 ms on a 300 ms trans-oceanic link), and well
/// under one 42 ms game frame, so treating it as a tie costs the slot nothing it
/// would feel. A larger gap is a real geographic difference and the nearer relay
/// wins.
const SERVING_RELAY_MARGIN_MS: u32 = 15;

/// The relay in `entries` nearest to `requested`, for a slot or homed group whose
/// own region may have no available relay. `entries` is the already-filtered
/// candidate cohort; `serving` lists the relays already serving the session, in
/// preference order.
///
/// A relay in `requested` itself scores 0; any other relay scores the backbone
/// round-trip between its region and `requested` from `pair_rtts`. A relay with
/// no region, or whose region has no stored pair with `requested`, is not ranked
/// at all. A serving relay scoring within [`SERVING_RELAY_MARGIN_MS`] of the best
/// score wins (nearest first, then `serving` order); otherwise the best score
/// wins, ties broken by the lowest relay id, so the choice is deterministic for a
/// given registry and table.
///
/// `None` when no relay can be ranked — no relay in `requested` and no pair data
/// for any candidate's region — so the caller applies its own region-blind rule
/// rather than this guessing.
pub(super) fn nearest_relay<'a>(
    entries: &'a [RelayEntry],
    requested: &RegionId,
    serving: &[RelayId],
    pair_rtts: &PairRttStore,
) -> Option<&'a RelayEntry> {
    let rtts = pair_rtts.rtts_from(requested);
    let score = |entry: &RelayEntry| -> Option<u32> {
        let region = entry.region.as_ref()?;
        if region == requested {
            Some(0)
        } else {
            rtts.get(region).copied()
        }
    };
    let (best, best_entry) = entries
        .iter()
        .filter_map(|entry| score(entry).map(|rtt| (rtt, entry)))
        .min_by_key(|&(rtt, entry)| (rtt, entry.relay_id))?;
    let serving_pick = serving
        .iter()
        .enumerate()
        .filter_map(|(rank, &id)| {
            let entry = entries.iter().find(|e| e.relay_id == id)?;
            let rtt = score(entry)?;
            (rtt <= best.saturating_add(SERVING_RELAY_MARGIN_MS)).then_some((rtt, rank, entry))
        })
        .min_by_key(|&(rtt, rank, _)| (rtt, rank))
        .map(|(_, _, entry)| entry);
    Some(serving_pick.unwrap_or(best_entry))
}

/// The requested slot regions with no available relay to home them — the regions
/// [`place_by_region`] would send to a relay in another region. Reads the same
/// available-relay snapshot placement does and applies the same region-match rule.
/// Order-preserving and de-duplicated: each unlit region appears once, in
/// first-requested order. A request naming no regions yields an empty set.
///
/// Deliberately blind to the capability cohort placement narrows the snapshot to.
/// A region lit only by relays outside the cohort reads as lit here, so its create
/// places at once on the nearest in-cohort relay instead of holding: the warm
/// demand a hold raises is met by any relay in the region, whatever its build, so
/// such a region is already at its warm target, nothing launches, and a hold could
/// only wait out its whole cap before falling back to the same relay.
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

/// Region-aware placement: home each slot on a live relay in the region it
/// requested. A slot whose region has no live relay homes in the nearest region
/// that has one by backbone round-trip ([`nearest_relay`]), reusing a relay
/// another slot already homes on when it is nearly as close. A slot that named no
/// region, or whose region has no pair data to rank by, takes the region-blind
/// pick (the lowest-id available relay overall). Slots sharing a region share one
/// relay, so a same-region game stays single-relay while a cross-region game
/// produces the meshed `slot_homes` shape.
///
/// The response's `home_relay` is the relay assigned the most slots. When several
/// relays tie for that maximum, the would-be session id rotates the primary among
/// them; `slot_homes` still records the exact same per-slot assignment regardless
/// of which tied relay is primary. By construction the serving set is exactly the
/// distinct assigned homes and every serving relay homes at least one slot.
pub(super) fn place_by_region(
    registry: &RelayRegistry,
    pair_rtts: &PairRttStore,
    request: &SessionRequest,
    session: SessionId,
    finalize_feature: bool,
) -> Result<Placement, SessionSetupError> {
    let mut entries = registry::available_entries(registry);
    if request.players.iter().any(|p| p.require_evidence) {
        entries.retain(relay_evidence_capable);
    }
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
    // exists in the other cohort takes the in-cohort cross-region fallback
    // rather than mixing. Cohorting applies whether or not the FEATURE is
    // enabled — build classes must never mix in one session regardless — but
    // the handshake itself only turns on for a capable cohort when the
    // coordinator's feature switch says so.
    // A rollback session is granted only when every relay serving it compares state hash reports,
    // so the placement keeps to relays that do when any is available and otherwise creates a
    // lockstep session, which the response reports so the tenant launches its clients to match.
    // Those relays are all finalized-drop capable too, and a rollback session always runs the
    // handshake, whatever the feature switch says: its clients apply a leave at exactly the step
    // a finalized count names, and a drop without a count gives them no step they would agree on.
    let rollback = request.rollback && entries.iter().any(relay_rollback_capable);
    if rollback {
        entries.retain(relay_rollback_capable);
    }
    let capable_cohort = entries.iter().any(relay_finalize_capable);
    if capable_cohort {
        entries.retain(relay_finalize_capable);
    }
    let finalized_drops = capable_cohort && (finalize_feature || rollback);

    // NOTE(version-aware placement): each entry carries the relay's advertised
    // `protocol` (negotiated against at enroll — an incompatible relay never gets
    // this far), so a placement policy that keeps one session's relays on a single
    // protocol version — needed once a wire bump rolls through a mixed fleet —
    // would filter the candidates here. Nothing consumes it yet; assignment stays
    // version-blind.

    // Ascending id, so "first in a region" and "first overall" are both the
    // deterministic lowest-id pick.
    entries.sort_by_key(|e| e.relay_id);
    let region_blind = &entries[0];

    // Each requested region's relay. Lit regions resolve first — the lowest-id
    // available relay in the region — along with the region-blind pick for slots
    // naming no region, so every relay those settle on is known before any unlit
    // region is ranked and can be reused by it, whatever order the roster lists
    // its players in. Unlit regions then resolve in first-requested order, each
    // one's pick joining the reusable set for the next.
    let mut region_relay: HashMap<&RegionId, &RelayEntry> = HashMap::new();
    let mut unlit: Vec<&RegionId> = Vec::new();
    let mut chosen: BTreeSet<RelayId> = BTreeSet::new();
    for player in &request.players {
        let Some(region) = &player.region else {
            chosen.insert(region_blind.relay_id);
            continue;
        };
        if region_relay.contains_key(region) || unlit.contains(&region) {
            continue;
        }
        match entries.iter().find(|e| e.region.as_ref() == Some(region)) {
            Some(entry) => {
                region_relay.insert(region, entry);
                chosen.insert(entry.relay_id);
            }
            None => unlit.push(region),
        }
    }
    for region in unlit {
        let serving: Vec<RelayId> = chosen.iter().copied().collect();
        let entry = nearest_relay(&entries, region, &serving, pair_rtts).unwrap_or(region_blind);
        region_relay.insert(region, entry);
        chosen.insert(entry.relay_id);
    }

    let slot_relay: Vec<(SlotId, &RelayEntry)> = request
        .players
        .iter()
        .map(|player| {
            let entry = player
                .region
                .as_ref()
                .map_or(region_blind, |region| region_relay[region]);
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
        rollback,
    })
}

/// Whether `entry` enrolled advertising what a rollback session needs from every relay serving
/// it: comparing state hash reports, and the finalized-drop handshake.
pub(super) fn relay_rollback_capable(entry: &RelayEntry) -> bool {
    relay_finalize_capable(entry)
        && entry
            .capabilities
            .iter()
            .any(|c| c == rally_point_proto::control::CAPABILITY_ROLLBACK_V1)
}

/// Whether `entry` enrolled advertising the finalized-drop capability — the
/// cohort test placement and rehome both key on.
pub(super) fn relay_finalize_capable(entry: &RelayEntry) -> bool {
    entry
        .capabilities
        .iter()
        .any(|c| c == rally_point_proto::control::CAPABILITY_FINALIZED_DROP_V1)
}

/// Whether a relay supports connection evidence and its required-slot policy.
pub(super) fn relay_evidence_capable(entry: &RelayEntry) -> bool {
    entry
        .capabilities
        .iter()
        .any(|c| c == rally_point_proto::control::CAPABILITY_EVIDENCE_V1)
}
