//! The per-session, per-slot network conditions this relay's own home-client
//! links observe — published by the slot-link tasks, snapshotted by the
//! mesh-link driver as the sidecar it attaches to an outgoing datagram.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{LinkConditions, SlotConditions};

use crate::routing::SessionKey;

/// Per-session, per-slot network conditions a relay's home-client links
/// observe, gathered for the latency-buffer decision-maker. Each
/// `run_slot_link` task publishes its own client's noq path stats here;
/// `run_mesh_link` snapshots the session's slots to build the outgoing
/// [`LinkConditions`] sidecar on each forwarded datagram.
///
/// Outgoing-only: the relay reports its *own* home clients' conditions. It does
/// not store conditions received from peer relays — those ride the peer's own
/// origin datagrams to the decision-maker, and storing them here would add a
/// stale-conditions correctness surface for a consumer (the decision-maker) that
/// is not yet built. The mesh-link driver traces incoming conditions
/// for observability but does not persist them.
///
/// A plain (non-async) mutex mirrors [`MeshLinks`](super::MeshLinks) and [`crate::routing::Sessions`]:
/// every critical section is a short, await-free slot edit or a snapshot clone,
/// so the lock is never held across a turn's delivery.
pub type ConditionsRegistry = Arc<Mutex<HashMap<SessionKey, HashMap<SlotId, SlotConditions>>>>;

/// Creates an empty conditions registry for a relay with no sessions yet.
pub fn new_conditions_registry() -> ConditionsRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Activates `conditions` for `key`'s `slot`, replacing any prior connection
/// generation. Called by `run_slot_link` after sampling its client's noq path
/// stats. Idempotent in the sense that a re-publish overwrites the stale
/// sample — conditions are per-moment, and the latest is always what the
/// mesh attaches.
pub fn activate_conditions(
    registry: &ConditionsRegistry,
    key: &SessionKey,
    slot: SlotId,
    conditions: SlotConditions,
) {
    registry
        .lock()
        .entry(key.clone())
        .or_default()
        .insert(slot, conditions);
}

/// Publishes a later sample only for the epoch currently active at this slot.
/// Returns false when a superseded task tries to overwrite its replacement.
pub fn publish_conditions(
    registry: &ConditionsRegistry,
    key: &SessionKey,
    slot: SlotId,
    conditions: SlotConditions,
) -> bool {
    let mut roster = registry.lock();
    let Some(slots) = roster.get_mut(key) else {
        return false;
    };
    if !slots
        .get(&slot)
        .is_some_and(|current| current.connection_epoch == conditions.connection_epoch)
    {
        return false;
    }
    slots.insert(slot, conditions);
    true
}

/// Removes `slot` from `key`'s conditions (the client disconnected). Idempotent.
/// Called by `run_slot_link` on exit so a departing client's stale stats don't
/// outlive its connection.
pub fn unpublish_conditions(
    registry: &ConditionsRegistry,
    key: &SessionKey,
    slot: SlotId,
    connection_epoch: Option<u64>,
) -> bool {
    let mut roster = registry.lock();
    if let Some(slots) = roster.get_mut(key) {
        if !slots
            .get(&slot)
            .is_some_and(|current| current.connection_epoch == connection_epoch)
        {
            return false;
        }
        slots.remove(&slot);
        if slots.is_empty() {
            roster.remove(key);
        }
        return true;
    }
    // Nothing is published for the slot, so this teardown has no registry
    // state to clobber. Treat the idempotent removal as successful; a live
    // replacement would have activated its epoch-bearing first sample above.
    true
}

/// Snapshots all slot conditions published for `key`, as the [`LinkConditions`]
/// sidecar the mesh attaches to an outgoing datagram. Returns `None` when the
/// session has no published conditions (no local clients, or none have sampled
/// yet) — so an ack-only flush or a session with no local clients attaches no
/// sidecar, preserving the redundancy budget.
pub fn snapshot_conditions(
    registry: &ConditionsRegistry,
    key: &SessionKey,
) -> Option<LinkConditions> {
    let roster = registry.lock();
    roster.get(key).map(|slots| {
        let mut slots: Vec<SlotConditions> = slots.values().cloned().collect();
        // Stable order by slot so the sidecar is deterministic across samples
        // (the decision-maker diffs consecutive samples; a stable order makes
        // the diff unambiguous).
        slots.sort_by_key(|s| s.slot);
        LinkConditions { slots }
    })
}
