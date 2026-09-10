//! The relay-wide silence watch task and the retained load state it reads
//! alongside.

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

/// How often the silence watch re-examines every live session. Short relative to
/// any sensible silence window, so a stalled session is released within a couple
/// of seconds of the window closing, and cheap: one registry lock plus a walk of
/// each session's slots, with no per-slot work between ticks.
pub const SILENCE_CHECK_INTERVAL: Duration = Duration::from_secs(2);

/// The relay-wide silent-slot watch: every `interval`, closes the link of the
/// slot this relay homes whose turns stopped reaching local clients at least
/// `window` ago and strictly before every other participant its session still
/// requires (see [`DecisionMaker::silent_slot`]). One task per relay, spawned by
/// the binary; never returns.
///
/// A lockstep session cannot outrun its slowest slot, so a client whose game
/// thread hung — or whose process a player suspended — holds every other player
/// still for as long as its QUIC link keeps answering keepalives. Nothing else
/// resolves that: the survivors' drop machinery only ever fires for a slot the
/// relay saw *disconnect*. Closing the link here manufactures exactly that
/// disconnect, and the ordinary link-death path (departure record, drop hold,
/// survivors' countdown, synced leave) takes it from there.
///
/// A verdict needs complete knowledge of the session, so most ticks produce
/// none: the participants compared are the descriptor's expected roster, a
/// roster slot this relay holds no state for blocks every verdict rather than
/// counting for nothing, a decided leave stays in the comparison until every
/// live participant has forwarded something after the decision, a resumed
/// session stands the watch down outright, and a participant with no game-started
/// report is unknown too — a client's pre-loop seed payloads advance its
/// forwarded prefix before it has simulated anything, so that prefix is not
/// simulation progress. Only a slot's home receives that
/// report, so the home shares it across the mesh (`SlotStarted`) and every relay
/// serving the session answers from the same set.
pub async fn run_silence_watch(
    makers: std::sync::Arc<DecisionMakers>,
    sessions: crate::routing::Sessions,
    window: Duration,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    // The first tick fires immediately; skip it so no session is judged before
    // it has had a chance to run.
    tick.tick().await;
    loop {
        tick.tick().await;
        // Marked under one registry lock, acted on outside it: closing a link and
        // recording an event both take other locks, and the mark is what keeps a
        // slot from being reported again on the next tick regardless.
        let evicted: Vec<(SessionKey, SilentSlot)> = {
            let now = Instant::now();
            let mut evicted = Vec::new();
            let mut registry = makers.lock();
            for (key, maker) in registry.iter_mut() {
                if let Some(found) = maker.silent_slot(now, window) {
                    maker.mark_silence_evicted(found.slot);
                    evicted.push((key.clone(), found));
                }
            }
            evicted
        };
        for (key, found) in evicted {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = found.slot.0,
                silent_ms = found.silent_for.as_millis() as u64,
                lead_ms = found.lead.as_millis() as u64,
                "slot's turns stopped reaching its peers before any other slot's did; closing its link so the survivors can drop it",
            );
            makers.flight_recorder().record(
                &key,
                crate::observability::flight_recorder::FlightEvent::SlotEvictedSilent {
                    slot: found.slot.0,
                    silent_ms: found.silent_for.as_millis() as u64,
                    lead_ms: found.lead.as_millis() as u64,
                },
            );
            crate::routing::close_slots_for_silence(&sessions, &key, &[found.slot]);
        }
    }
}
