//! The relay-wide sweep that judges rollback sessions' state hash reports once their deadlines
//! pass, and acts on the evictions its verdicts name. Reports arriving on turns trigger most
//! judgements, but a slot that withholds its report produces nothing to trigger one, so a timer
//! has to.
//!
//! The verdicts and the eviction queue belong to consensus
//! (`DecisionMakers::judge_overdue_state_hashes`, `DecisionMakers::claim_desync_evictions`);
//! closing a link and telling the other relays belong here, behind a [`DesyncEvictor`] so the
//! acting half can be driven with a fake.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rally_point_proto::ids::SlotId;

use crate::consensus::{DecisionMakers, DesyncEviction};
use crate::key::SessionKey;
use crate::observability::events::{FlightEvent, FlightEvents};
use crate::routing::{Sessions, close_slots_for_desync, finalize_evicted_drop};

/// How often the sweep checks every rollback session for overdue reports, and hands on the
/// evictions any verdict since the last check named. Short next to the report deadline, so a
/// verdict follows within a second of the deadline passing, and a verdict that a report on the
/// turn path completed is acted on within a second of it.
pub const STATE_HASH_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// What the sweep does with a slot a verdict named. Production ([`MeshEvictor`]) closes the
/// routing group's entry and broadcasts over the mesh; a test stands in with a recording fake, so
/// the pass can be driven without a live slot task or mesh link.
pub trait DesyncEvictor {
    /// Ends `slot`'s link in `key`'s session on this relay, which strictly homes the slot and has
    /// already marked it evicted.
    fn close_desynced_slot(&self, key: &SessionKey, slot: SlotId);

    /// Tells every peer relay serving `key` that the verdict for `sync_ordinal` named `slot`, so
    /// the relay that homes it evicts it.
    fn announce_desync_eviction(&self, key: &SessionKey, slot: SlotId, sync_ordinal: u64);
}

/// The production [`DesyncEvictor`]: this relay's slot roster and its mesh.
#[derive(Clone)]
pub struct MeshEvictor {
    pub sessions: Sessions,
    pub mesh: crate::mesh::MeshState,
}

impl DesyncEvictor for MeshEvictor {
    fn close_desynced_slot(&self, key: &SessionKey, slot: SlotId) {
        end_desynced_slot_link(&self.sessions, &self.mesh, key, slot);
    }

    fn announce_desync_eviction(&self, key: &SessionKey, slot: SlotId, sync_ordinal: u64) {
        crate::mesh::fan_out_evict_slot(&self.mesh.links, key, slot, sync_ordinal);
    }
}

/// Every `interval`, judges each rollback session's steps whose report deadlines have passed and
/// publishes the verdicts, then evicts every slot a verdict named since the last tick. One task
/// per relay, spawned by the binary; never returns.
///
/// A rollback client runs no native sync, so its game never notices on its own that it diverged
/// from everyone else's; the relay's verdict is the only thing that can take the player out. A
/// verdict that names someone (the minority when the rest agree, or a slot that kept playing
/// without its report) ends that slot's game as a disconnect: its home closes the link and
/// refuses it every later dial, then finalizes the drop, and the survivors apply a leave at an
/// exact turn count and play on. A verdict with no majority names nobody and evicts nobody.
pub async fn run_state_hash_watch(
    makers: Arc<DecisionMakers>,
    evictor: impl DesyncEvictor,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    // The first tick fires immediately; nothing can be overdue yet.
    tick.tick().await;
    loop {
        tick.tick().await;
        makers.judge_overdue_state_hashes(Instant::now());
        evict_desynced_slots(
            makers.flight_recorder(),
            &evictor,
            makers.claim_desync_evictions(),
        );
    }
}

/// Acts on every slot the verdicts named: closes the link of each one this relay homes (the claim
/// already marked it), then tells every peer relay, whether or not this relay was the home.
/// Homing is the receiver's own question: a peer that homes the slot evicts it, the rest ignore
/// the frame. Split from the claim so it can be driven with a fake evictor.
pub(super) fn evict_desynced_slots(
    recorder: &impl FlightEvents,
    evictor: &impl DesyncEvictor,
    claimed: Vec<(SessionKey, DesyncEviction)>,
) {
    for (key, eviction) in claimed {
        if eviction.homed {
            record_desync_eviction(recorder, &key, eviction.slot, eviction.sync_ordinal);
            evictor.close_desynced_slot(&key, eviction.slot);
        }
        evictor.announce_desync_eviction(&key, eviction.slot, eviction.sync_ordinal);
    }
}

/// Logs and records that this relay, as `slot`'s home, is evicting it for the verdict on
/// `sync_ordinal`. Shared by the sweep and the mesh arm that carries another relay's verdict here.
pub(crate) fn record_desync_eviction(
    recorder: &impl FlightEvents,
    key: &SessionKey,
    slot: SlotId,
    sync_ordinal: u64,
) {
    tracing::warn!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        slot = slot.0,
        sync_ordinal,
        "rollback state hash verdict named this slot; closing its link and finalizing its drop",
    );
    recorder.record(
        key,
        FlightEvent::SlotEvictedDesync {
            slot: slot.0,
            sync_ordinal,
        },
    );
}

/// Ends a desync-evicted slot's link on its home, which must already have marked the slot evicted
/// so no dial can reinstate it. A live link is signalled to close, and its own teardown finalizes
/// the drop once the departure is recorded (see `end_slot_link`). A slot with no link here is
/// finalized now: it disconnected before the verdict, and nothing else would end its held drop.
///
/// A link caught between leaving the roster and recording its departure is finalized not here but
/// by its own teardown, which reads the eviction mark only after recording the departure; a slot
/// both paths reach is finalized twice, which is idempotent.
pub(crate) fn end_desynced_slot_link(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    slot: SlotId,
) {
    close_slots_for_desync(sessions, key, &[slot]);
    let linked = sessions
        .lock()
        .get(key)
        .is_some_and(|slots| slots.contains_key(&slot));
    if !linked {
        finalize_evicted_drop(sessions, mesh, key, slot);
    }
}
