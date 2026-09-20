//! The relay-wide silent-slot watch: a timer that asks every session's
//! decision-maker whether one of its slots has gone quiet, and closes that
//! slot's link when one has.
//!
//! The verdict belongs to consensus (`DecisionMaker::silent_slot` — which slot
//! stopped first, and whether the session knows enough to say); the actuation
//! belongs here, where the links are.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rally_point_proto::ids::SlotId;

use crate::consensus::{DecisionMakers, SilentSlot};
use crate::key::SessionKey;
use crate::observability::events::{FlightEvent, FlightEvents};
use crate::routing::Sessions;

/// How often the silence watch re-examines every live session. Short relative to
/// any sensible silence window, so a stalled session is released within a couple
/// of seconds of the window closing, and cheap: one registry lock plus a walk of
/// each session's slots, with no per-slot work between ticks.
pub const SILENCE_CHECK_INTERVAL: Duration = Duration::from_secs(2);

/// What the watch does to a slot it has named: end that slot's link on this
/// relay. Production closes the routing group's entry; a test stands in with a
/// recording fake, so the loop can be driven without a live slot task.
pub trait SilenceCloser {
    /// Closes `slot`'s link in `key`'s session.
    fn close_silent_slot(&self, key: &SessionKey, slot: SlotId);
}

impl SilenceCloser for Sessions {
    fn close_silent_slot(&self, key: &SessionKey, slot: SlotId) {
        crate::routing::close_slots_for_silence(self, key, &[slot]);
    }
}

/// The relay-wide silent-slot watch: every `interval`, closes the link of the
/// slot this relay homes whose turns stopped reaching local clients at least
/// `window` ago and strictly before every other participant its session still
/// requires. One task per relay, spawned by the binary; never returns.
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
/// none — see `DecisionMakers::claim_silent_slots` for everything that blocks
/// one.
pub async fn run_silence_watch(
    makers: Arc<DecisionMakers>,
    closer: impl SilenceCloser,
    window: Duration,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    // The first tick fires immediately; skip it so no session is judged before
    // it has had a chance to run.
    tick.tick().await;
    loop {
        tick.tick().await;
        evict_silent_slots(&makers, &closer, window, Instant::now());
    }
}

/// One pass of the watch: take every session's verdict, then close what it
/// named. The verdicts are claimed under the registry's own lock and acted on
/// here, outside it — closing a link and recording an event both take other
/// locks, and the claim is what keeps a slot from being named again on the
/// next tick regardless.
fn evict_silent_slots(
    makers: &DecisionMakers,
    closer: &impl SilenceCloser,
    window: Duration,
    now: Instant,
) {
    close_silent_slots(
        makers.flight_recorder(),
        closer,
        makers.claim_silent_slots(now, window),
    );
}

/// Closes every slot the watch named, logging and recording each eviction.
/// Split from the claim so the acting half can be driven with a fake closer.
pub(super) fn close_silent_slots(
    recorder: &impl FlightEvents,
    closer: &impl SilenceCloser,
    evicted: Vec<(SessionKey, SilentSlot)>,
) {
    for (key, found) in evicted {
        tracing::warn!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            slot = found.slot.0,
            silent_ms = found.silent_for.as_millis() as u64,
            lead_ms = found.lead.as_millis() as u64,
            "slot's turns stopped reaching its peers before any other slot's did; closing its link so the survivors can drop it",
        );
        recorder.record(
            &key,
            FlightEvent::SlotEvictedSilent {
                slot: found.slot.0,
                silent_ms: found.silent_for.as_millis() as u64,
                lead_ms: found.lead.as_millis() as u64,
            },
        );
        closer.close_silent_slot(&key, found.slot);
    }
}
