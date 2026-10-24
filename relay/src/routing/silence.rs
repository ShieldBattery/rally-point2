//! The relay-wide silent-slot watch: a timer that asks every session's
//! decision-maker whether one of its slots has gone quiet, and evicts that
//! slot when its link proves the client is still there.
//!
//! The verdict belongs to consensus (`DecisionMaker::silent_slot` — which slot
//! stopped first, and whether the session knows enough to say); the actuation
//! belongs here, where the links are.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rally_point_proto::ids::SlotId;
use rally_point_transport::quic::MAX_IDLE_TIMEOUT;

use crate::consensus::{DecisionMakers, SilentSlot};
use crate::key::SessionKey;
use crate::observability::events::{FlightEvent, FlightEvents};
use crate::routing::{LinkReceipts, Sessions};

/// How often the silence watch re-examines every live session. Short relative to
/// any sensible silence window, so a stalled session is released within a couple
/// of seconds of the window closing, and cheap: one registry lock plus a walk of
/// each session's slots, with no per-slot work between ticks.
pub const SILENCE_CHECK_INTERVAL: Duration = Duration::from_secs(2);

/// How long the watch waits on a named slot whose link has received nothing
/// since it was named before ending that link itself, as an ordinary
/// disconnect.
///
/// A link that receives nothing is closed by QUIC once its idle timer runs out:
/// [`MAX_IDLE_TIMEOUT`], or three probe timeouts when that is longer, which a
/// long or erratic round trip — or a peer advertising a long ACK delay — can
/// make it. By the time a slot is named its turns have been stopped for a whole
/// window, so an ordinary dead path is closed within seconds of the naming. A
/// link still up past this grace holds the session on a client that is not
/// there, so the watch frees it, without marking anything: its client may
/// still resume from the drop hold, like any client whose path was lost.
pub const TRANSPORT_QUIET_GRACE: Duration = Duration::from_secs(MAX_IDLE_TIMEOUT.as_secs() + 5);

/// The links behind the slots the watch names: what it reads about them, and
/// how it ends one. Production is the roster; a test stands in with a fake, so
/// the loop can be driven without a live slot task. Both closes act only on
/// the `connection_epoch` generation the watch read, never on a connection
/// that replaced it.
pub trait SilenceLinks {
    /// What `slot`'s registered link in `key`'s session has received, or
    /// `None` with no live link to read.
    fn receipts(&self, key: &SessionKey, slot: SlotId) -> Option<LinkReceipts>;

    /// Evicts `slot`'s link: its task marks the eviction, refusing every later
    /// dial, unless the link already ended on its own.
    fn close_silent_slot(&self, key: &SessionKey, slot: SlotId, connection_epoch: u64);

    /// Ends `slot`'s link as an ordinary lost connection, marking nothing.
    fn close_quiet_slot(&self, key: &SessionKey, slot: SlotId, connection_epoch: u64);
}

impl SilenceLinks for Sessions {
    fn receipts(&self, key: &SessionKey, slot: SlotId) -> Option<LinkReceipts> {
        crate::routing::link_receipts(self, key, slot)
    }

    fn close_silent_slot(&self, key: &SessionKey, slot: SlotId, connection_epoch: u64) {
        crate::routing::close_silent_slot_link(self, key, slot, connection_epoch);
    }

    fn close_quiet_slot(&self, key: &SessionKey, slot: SlotId, connection_epoch: u64) {
        crate::routing::close_quiet_slot_link(self, key, slot, connection_epoch);
    }
}

/// The relay-wide silent-slot watch: every `interval`, evicts the slot this
/// relay homes whose turns stopped reaching local clients at least `window`
/// ago, strictly before every other participant its session still requires,
/// and whose link has carried frames since. One task per relay, spawned by
/// the binary; never returns.
///
/// A lockstep session cannot outrun its slowest slot, so a client whose game
/// thread hung — or whose game a player suspended — holds every other player
/// still for as long as its QUIC link keeps answering keepalives. Nothing else
/// resolves that: the survivors' drop machinery only ever fires for a slot the
/// relay saw *disconnect*. Closing the link here manufactures exactly that
/// disconnect, and the ordinary link-death path (departure record, drop hold,
/// survivors' countdown, synced leave) takes it from there.
///
/// A slot whose whole network path died stops its turns too, and is named the
/// same way, but it is not evicted: its client's simulation is fine, and if
/// its path comes back while the survivors still hold its drop, its re-dial
/// can resume the game. The transport's idle timeout closes such a link as an
/// ordinary disconnect, and the watch only waits for that (see `SilenceWatch`).
///
/// A verdict needs complete knowledge of the session, so most ticks produce
/// none — see `DecisionMakers::silent_slots` for everything that blocks one.
pub async fn run_silence_watch(
    makers: Arc<DecisionMakers>,
    links: impl SilenceLinks,
    window: Duration,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    // The first tick fires immediately; skip it so no session is judged before
    // it has had a chance to run.
    tick.tick().await;
    let mut watch = SilenceWatch::default();
    loop {
        tick.tick().await;
        watch.tick(&makers, &links, window, Instant::now());
    }
}

/// What the watch remembers between ticks: each slot it has named, with what
/// its link had received when it was named, and whether the watch has already
/// ordered that link closed.
///
/// Evicting refuses every later dial for the rest of the session, so it needs
/// evidence that reconnecting could not help: the client still sending on the
/// link after its turns stopped. QUIC sends a keepalive at least every few
/// seconds on a live connection even when the game sends nothing, so a client
/// whose game hung keeps moving its link's count of received frames, and is
/// evicted on the first tick that sees it move. A dead path moves nothing, and
/// is left to the transport, until it outlasts [`TRANSPORT_QUIET_GRACE`] and
/// is ended as the lost connection it is.
///
/// The count is the relay's own, of frames that decrypted under the link's
/// keys, so nobody but the client can move it, and the client cannot use it
/// to keep a slot it stalled from being dropped: going quiet only ever
/// produces the disconnect a lost network path already does.
///
/// The watch never marks an eviction itself. It signals the named connection
/// generation, and that link's own task marks the eviction as it ends the link
/// on the signal — before it frees the slot's seat, and only if the connection
/// was still open when the task closed it — so a link already tearing down as
/// a disconnect stays one. The task's open check and its close are not one
/// atomic step with the transport, so a close of the link's own landing in
/// between still evicts: very rarely, a client that could have resumed is
/// refused (see `handle_shutdown`).
#[derive(Default)]
pub(super) struct SilenceWatch {
    named: HashMap<(SessionKey, SlotId), NamedSlot>,
}

/// One named slot's link, as the watch last read it.
struct NamedSlot {
    /// What the link had received at the watch's previous tick, so a move is
    /// evidence of frames within the last tick rather than at any point since
    /// the naming: the closer the evidence is to the eviction, the less room a
    /// close of the link's own has to land in between.
    receipts: LinkReceipts,
    named_at: Instant,
    /// The watch has signalled this link's close and only waits for its
    /// teardown to retire the verdict.
    closing: bool,
}

impl SilenceWatch {
    /// One pass of the watch: take every session's verdict, then decide each
    /// named slot from its link.
    ///
    /// Verdicts are taken under the registry's own lock, and rendered again
    /// before acting, with links read in between: reading a link takes the
    /// roster's lock and the transport's, and neither nests inside the
    /// registry's. A slot that moved, disconnected, or reconnected in between
    /// is not acted on for a stale verdict.
    pub(super) fn tick(
        &mut self,
        makers: &DecisionMakers,
        links: &impl SilenceLinks,
        window: Duration,
        now: Instant,
    ) {
        let verdicts = makers.silent_slots(now, window);
        self.named.retain(|(key, slot), _| {
            verdicts
                .iter()
                .any(|(named_key, found)| named_key == key && found.slot == *slot)
        });
        for (key, found) in verdicts {
            // No live link to read is a link already on its way down, which the
            // ordinary path resolves.
            let Some(receipts) = links.receipts(&key, found.slot) else {
                continue;
            };
            let named_key = (key.clone(), found.slot);
            let named = match self.named.get_mut(&named_key) {
                Some(named) if named.receipts.connection_epoch == receipts.connection_epoch => {
                    named
                }
                _ => {
                    note_named(makers.flight_recorder(), &key, &found);
                    self.named.insert(
                        named_key,
                        NamedSlot {
                            receipts,
                            named_at: now,
                            closing: false,
                        },
                    );
                    continue;
                }
            };
            if named.closing {
                continue;
            }
            let carrying = receipts.frames > named.receipts.frames;
            named.receipts = receipts;
            let overdue = now.saturating_duration_since(named.named_at) >= TRANSPORT_QUIET_GRACE;
            if !carrying && !overdue {
                continue;
            }
            let Some(confirmed) = makers.still_silent(&key, found.slot, now, window) else {
                continue;
            };
            named.closing = true;
            if carrying {
                request_eviction(links, &key, confirmed, receipts.connection_epoch);
            } else {
                request_quiet_close(links, &key, confirmed, receipts.connection_epoch);
            }
        }
    }
}

/// Records that the watch named a slot and is now reading its link.
fn note_named(recorder: &impl FlightEvents, key: &SessionKey, found: &SilentSlot) {
    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        slot = found.slot.0,
        silent_ms = found.silent_for.as_millis() as u64,
        lead_ms = found.lead.as_millis() as u64,
        "slot's turns stopped reaching its peers before any other slot's did; \
         evicting it once its link shows the client is still sending",
    );
    recorder.record(
        key,
        FlightEvent::SlotSilent {
            slot: found.slot.0,
            silent_ms: found.silent_for.as_millis() as u64,
            lead_ms: found.lead.as_millis() as u64,
        },
    );
}

/// Asks a named slot's link task to evict it. Only the request is logged here:
/// the task records the eviction if it commits one, so a request that reaches
/// a replacement seat, or a link already closed, leaves no eviction behind in
/// the recording either.
fn request_eviction(
    links: &impl SilenceLinks,
    key: &SessionKey,
    found: SilentSlot,
    connection_epoch: u64,
) {
    tracing::warn!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        slot = found.slot.0,
        silent_ms = found.silent_for.as_millis() as u64,
        lead_ms = found.lead.as_millis() as u64,
        "silent slot's link is still carrying frames; asking its link to evict it",
    );
    links.close_silent_slot(key, found.slot, connection_epoch);
}

/// Asks a named slot's quiet link task to end its link as a lost connection,
/// which the task records as it does.
fn request_quiet_close(
    links: &impl SilenceLinks,
    key: &SessionKey,
    found: SilentSlot,
    connection_epoch: u64,
) {
    tracing::warn!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        slot = found.slot.0,
        silent_ms = found.silent_for.as_millis() as u64,
        "silent slot's link received nothing yet outlasted the transport idle timeout; \
         asking its link to close as a lost connection",
    );
    links.close_quiet_slot(key, found.slot, connection_epoch);
}
