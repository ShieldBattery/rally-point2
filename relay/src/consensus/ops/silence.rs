//! The silence watch's registry half — the per-tick verdict sweep — and the
//! retained load state read alongside it.

use super::*;

/// Every session this relay holds a decision-maker for, paired with the load
/// state that maker has retained — the heartbeat builder's session universe.
///
/// A maker lives from the descriptor apply that created it until the session
/// retires, which outlasts every local link: a session whose slots have all
/// disconnected still has its retained state restated on every beat while the
/// game runs on elsewhere, which is the only way the coordinator hears facts this
/// relay learned before its last slot left. A session run without a maker (no
/// descriptor) is absent here and carries no retained state at all, which is
/// exactly what "this relay knows of no arrivals" means on the wire.
pub fn retained_load_states(registry: &DecisionMakers) -> Vec<(SessionKey, RetainedLoadState)> {
    registry
        .lock()
        .iter()
        .map(|(key, maker)| (key.clone(), maker.load_state()))
        .collect()
}

/// The load state one session's decision-maker has retained, or the empty state
/// for a session this relay holds no maker for.
///
/// Empty is a real answer, not a missing one: a relay with no maker for the session
/// has learned nothing about who arrived there, which is exactly what empty sets
/// say. The distinction that matters to the coordinator is between this relay
/// answering and this relay not answering at all, never between an empty answer and
/// an absent maker.
pub fn retained_load_state(registry: &DecisionMakers, key: &SessionKey) -> RetainedLoadState {
    registry
        .lock()
        .get(key)
        .map(|maker| maker.load_state())
        .unwrap_or_default()
}

/// Records that `slot`'s gap-free forwarded prefix advanced for `key`'s
/// session, stamping the slot's stop clock (see
/// [`DecisionMaker::note_forward_advance`]). Called from the forward gate's
/// fan-out choke point, once per turn that genuinely extends the prefix.
pub fn note_forward_advance(registry: &DecisionMakers, key: &SessionKey, slot: SlotId) {
    let now = Instant::now();
    if let Some(maker) = registry.lock().get_mut(key) {
        maker.note_forward_advance(slot, now);
    }
}

/// Every session whose decision-maker names a slot that has gone silent, with
/// that verdict marked so the same slot is not named again on a later tick.
///
/// The verdict itself is [`DecisionMaker::silent_slot`]: complete knowledge of
/// the session or no verdict at all, and only ever the slot that stopped
/// strictly earliest. What a caller does with a named slot — closing its link,
/// so the ordinary link-death path resolves it — belongs to the layer that
/// owns the links, which is why this hands the names back rather than acting
/// on them.
///
/// The whole sweep runs under one acquisition of the registry lock, and the
/// mark is taken inside it: acting on a name takes other locks, and a slot
/// already marked is out of the comparison regardless of how long the acting
/// takes.
pub fn claim_silent_slots(
    registry: &DecisionMakers,
    now: Instant,
    window: Duration,
) -> Vec<(SessionKey, SilentSlot)> {
    let mut claimed = Vec::new();
    for (key, maker) in registry.lock().iter_mut() {
        if let Some(found) = maker.silent_slot(now, window) {
            maker.mark_silence_evicted(found.slot);
            claimed.push((key.clone(), found));
        }
    }
    claimed
}
