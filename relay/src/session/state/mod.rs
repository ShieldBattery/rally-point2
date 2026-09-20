//! Everything this relay holds for a session, in one bundle.

use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::ids::SlotId;

use crate::consensus::{DecisionMakers, ReconnectAdmission};
use crate::coordinator::load_fence::LoadStateFence;
use crate::key::SessionKey;
use crate::session::drop_hold::DropHolds;
use crate::session::gate::SessionGates;
use crate::session::presence::PresenceRegistry;
use crate::session::provisional::ProvisionalSessions;
use crate::session::provisional_turns::ProvisionalTurnPen;
use crate::session::side_channel::SideChannels;
use crate::session::turn_ring::TurnRing;

/// The windows and ceilings a [`SessionState`] builds its registries with.
///
/// [`Default`] is the production relay: every field is the constant its own
/// module documents. A test shrinks the one window it needs to drive and
/// spreads the rest — `SessionState::with_tunables(Tunables { drop_unlock: ...,
/// ..Tunables::default() })` — so a production timing never has to be waited
/// out and no knob grows a constructor of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tunables {
    /// How long after a slot's drop a manual `RequestDrop` may be honored.
    pub drop_unlock: Duration,
    /// How long a fully abandoned session waits before its held drops are
    /// force-decided.
    pub abandon_timeout: Duration,
    /// How long a client-admitted session may go without an applied descriptor
    /// before the provisional sweep reaps it.
    pub provisional_window: Duration,
    /// How many sessions the pre-descriptor turn journal tracks before it
    /// refuses to create another.
    pub journal_max_sessions: usize,
    /// How long after a session starts its region-label map is released to the
    /// local clients.
    pub region_release_delay: Duration,
}

impl Default for Tunables {
    fn default() -> Self {
        Tunables {
            drop_unlock: crate::session::drop_hold::DROP_UNLOCK,
            abandon_timeout: crate::session::drop_hold::ABANDONED_SESSION_TIMEOUT,
            provisional_window: crate::session::provisional::PROVISIONAL_WINDOW,
            journal_max_sessions: crate::session::provisional_turns::MAX_JOURNALED_SESSIONS,
            region_release_delay: crate::consensus::REGION_LABEL_RELEASE_DELAY,
        }
    }
}

/// Every registry this relay keeps per session, in one bundle.
///
/// These stores share a lifecycle — each comes into being as its session is
/// first touched and they are swept together as it empties and retires — and
/// they are threaded through the same two tasks, `run_slot_link` and
/// `run_mesh_link`, which would otherwise each take a dozen more arguments.
/// Each field's own doc says what it holds.
///
/// Clone the struct cheaply (each field is an `Arc` or a handle around one) to
/// hand a copy to a spawned task.
#[derive(Clone)]
pub struct SessionState {
    /// Per-session latency-buffer decision-makers. The slot-link and mesh-link
    /// tasks feed conditions in (home-client stats directly, peer-relay stats
    /// off the mesh sidecar) and stamp the authority's buffer changes onto the
    /// turns they forward. `MeshControl` creates and destroys the makers as
    /// descriptors arrive and sessions end; sharing the registry here is what
    /// lets the turn path reach them.
    pub decision_makers: Arc<DecisionMakers>,
    /// Per-session presence (the authority order plus who still serves live
    /// players), driving the buffer-authority verdict. The slot-link tasks
    /// report the local roster into it, the mesh-link drivers deliver peers'
    /// reports, and `MeshControl` sets the order from each descriptor.
    pub presence: Arc<PresenceRegistry>,
    /// The per-session lobby, chat and skin fan-outs. The slot-link tasks
    /// register each member on all three as its control stream comes up and
    /// deliver their clients' messages into them; the mesh-link drivers deliver
    /// peers' messages into them. They differ only in what each replays to a
    /// member that joined late — nothing, an ordered log, or the latest message
    /// per slot. See [`crate::session::side_channel`].
    pub side_channels: SideChannels,
    /// Per-relay holds on dropped slots' synced-leave decisions, plus the
    /// per-requester rate cap on the manual drop requests that resolve them. A
    /// slot that dropped (its link died) has its departure recorded and
    /// announced immediately, but the decision to remove it from lockstep is
    /// held here indefinitely — made only when a surviving member's
    /// `RequestDrop` is honored past the unlock floor, never on a timer; a clean
    /// leave bypasses the hold. Local and ephemeral, not replicated. See
    /// [`crate::session::drop_hold`].
    pub drop_holds: DropHolds,
    /// Per-session bounded record of the turns this relay has forwarded, so a
    /// client that dropped and re-dialed while its drop was undecided can be
    /// replayed the turns it missed and catch its sim up. Local and ephemeral
    /// like `drop_holds`: the turn forward path records into it, a re-register
    /// reads from it. See [`crate::session::turn_ring`].
    pub turn_ring: TurnRing,
    /// Provisional-admission deadlines: a session a client admitted with no
    /// applied descriptor yet is marked here, and the relay's periodic sweep
    /// tears it down if no descriptor claims it in time. Local and ephemeral
    /// like `drop_holds`. See [`crate::session::provisional`].
    pub provisional: ProvisionalSessions,
    /// The per-session terminal ingress boundary: client admission, the turn
    /// funnel, and mesh dispatch all run their critical sections through it,
    /// and descriptor retirement marks a session retired under its write side
    /// before sweeping any state — so no ingress can resurrect what a
    /// retirement removed. Shared with `MeshControl` (which retires and
    /// reopens) and the flight recorder (whose create-on-first-touch consults
    /// it). See [`crate::session::gate`].
    pub gates: SessionGates,
    /// The holding pen for pre-descriptor client turns: while a session has no
    /// decision-maker, the turn funnel deposits turns here instead of fanning
    /// them out, and descriptor application drains them through the ordinary
    /// forward path — where freshly seeded decided leaves fence a departed
    /// slot's turns. Armed only on a coordinator-managed relay (`main.rs`);
    /// disarmed (every test constructor), the funnel behaves exactly as before.
    /// See [`crate::session::provisional_turns`].
    pub provisional_turns: ProvisionalTurnPen,
    /// The load-state fence broker: the outstanding stream-position probes this
    /// relay has sent its local slots while answering a coordinator load-state
    /// question. It has no per-session lifecycle of its own; it lives here
    /// because the slot-link tasks — where the clients' acks land — are the ones
    /// already carrying this bundle. See [`crate::coordinator::load_fence`].
    pub load_fence: LoadStateFence,
}

impl Default for SessionState {
    /// Empty registries with the production windows and ceilings.
    fn default() -> Self {
        Self::with_tunables(Tunables::default())
    }
}

impl SessionState {
    /// Empty registries built with `tunables`, for a relay serving no session
    /// yet. Production passes [`Tunables::default`]; a test overrides just the
    /// window it drives and spreads the rest.
    pub fn with_tunables(tunables: Tunables) -> Self {
        SessionState {
            decision_makers: Arc::new(crate::consensus::new_decision_makers_with_region_delay(
                tunables.region_release_delay,
            )),
            presence: Arc::new(crate::session::presence::new_presence_registry()),
            side_channels: SideChannels::default(),
            drop_holds: DropHolds::new(tunables.drop_unlock, tunables.abandon_timeout),
            turn_ring: TurnRing::new(),
            provisional: ProvisionalSessions::new(tunables.provisional_window),
            gates: SessionGates::default(),
            provisional_turns: ProvisionalTurnPen::with_session_ceiling(
                tunables.journal_max_sessions,
            ),
            load_fence: LoadStateFence::new(),
        }
    }
}

/// The operations that span two of these stores, which is what makes them this
/// bundle's rather than either store's.
impl SessionState {
    /// Atomically resolves a reliable connection-up event against both the drop
    /// hold and the decision-maker's departure/generation state.
    ///
    /// The hold map stays locked while the maker is acquired, and
    /// reinstatement plus activation happen under that single maker lock. Thus
    /// an old departure can linearize only wholly before this operation (and be
    /// claimed here) or wholly after the new epoch is active (and be rejected
    /// as stale). The lock order is holds → decision-makers, everywhere.
    pub(crate) fn admit_reconnect(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: Option<u64>,
    ) -> ReconnectAdmission {
        self.admit_reconnect_with(key, slot, epoch, || {})
    }

    /// [`admit_reconnect`](Self::admit_reconnect) with a hook that runs inside
    /// the maker lock, right after a departure is reinstated — the seam a test
    /// needs to park a thread mid-transition and prove a stale teardown cannot
    /// interleave.
    pub(crate) fn admit_reconnect_with(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: Option<u64>,
        after_reinstate: impl FnOnce(),
    ) -> ReconnectAdmission {
        self.drop_holds
            .resolve_reconnect(key, slot, |hold_pending| {
                let transition = crate::consensus::resolve_reconnect(
                    &self.decision_makers,
                    key,
                    slot,
                    epoch,
                    hold_pending,
                    after_reinstate,
                );
                (transition.admission, transition.consume_hold)
            })
    }
}

/// The three phases of a session's teardown on this relay, in the order they
/// can happen: one slot's link ended, the last local slot went, the descriptor
/// was retired. Each is the whole checklist for its phase — a new store added
/// to [`SessionState`] is swept by adding it here, not by finding three call
/// sites.
impl SessionState {
    /// One slot's link has ended: drop its membership in the side channels.
    ///
    /// Called *before* the roster deregister that frees the seat. The roster
    /// refuses a duplicate slot, so a reconnecting slot cannot register (and
    /// re-register its side-channel membership) until that deregister runs —
    /// doing these first keeps a fresh connection's `register_member` from
    /// being clobbered by this one's cleanup.
    ///
    /// The session-scoped state behind each channel stays: the lobby log, the
    /// skin blob map and the chat state belong to the session, not to this
    /// member, and a remaining or reconnecting member still replays them.
    pub(crate) fn remove_slot(&self, key: &SessionKey, slot: SlotId) {
        self.side_channels.deregister_member(key, slot);
    }

    /// This relay's last local slot for the session is gone and the close has
    /// been claimed: drop the per-session state, except what a promised
    /// reconnect would still need.
    ///
    /// `seen` is the forward-once gate — a mesh registry, but tied to the same
    /// promise as the replay ring, so the two are swept together or not at all
    /// (see below); the caller passes it in rather than sweeping it apart from
    /// the rest.
    pub(crate) fn close_emptied(&self, key: &SessionKey, seen: &crate::mesh::SeenRegistries) {
        // An abandoned-session timer running for this session must not re-run
        // the close when its window elapses: the close has been reported now,
        // and this teardown is what it would otherwise repeat. Its
        // force-decide is still owed, so the timer is marked rather than
        // cancelled.
        self.drop_holds.note_session_closed(key);
        // The relay's last local member for the session is gone, so the side
        // channels' retained state and (now-empty) member sets can be dropped:
        // no local member remains to replay the lobby log or the skin map to —
        // mirroring how the roster group is dropped when its last slot leaves.
        self.side_channels.end_session(key);
        // Same for request limiters, and for any hold whose slot's leave is
        // already decided — but NOT for an undecided hold: on a session that
        // never started (where a fresh undecided drop does not defer the
        // close) that hold is still the reconnect-admission token and unlock
        // clock for a drop nobody has decided yet. See
        // [`crate::session::drop_hold`] module docs.
        let decided = self.decision_makers.decided_slots(key);
        self.drop_holds.end_session(key, &decided);
        // The forwarded-turn replay ring and the forward-once seen state
        // (whose entry is created lazily on the first turn forwarded — there
        // is no explicit "join" counterpart to pair the teardown with) go down
        // on the same "last local slot gone" trigger as the registries above —
        // UNLESS a surviving hold still promises a reconnect this relay would
        // admit. That reconnect's resume seeds its fresh receive window from
        // the seen state's receipts (every transport-acked seq its sparse
        // anchor will not re-send), so destroying them here while honoring the
        // hold would admit a resume whose acked holes nothing can ever fill:
        // the prefix wedges, and the live stream eventually exits the receive
        // window. Receipt-state lifetime must match the reconnect-admission
        // token's, exactly as the provisional journal is retained while a
        // descriptor could still drain it — so both stores are kept until no
        // such token remains: a reconnect re-opens the close latch and this
        // teardown re-runs at the next emptying, and descriptor retirement
        // sweeps them terminally ([`retire`](Self::retire)) if the reconnect
        // never comes. (The retained ring is empty in practice — it records
        // only started sessions, and a started session's reconnectable
        // departure defers this close entirely — but tying both stores to the
        // same token keeps the rule whole rather than shape-dependent.)
        let surviving_holds = self.drop_holds.pending_slots(key);
        if !self
            .decision_makers
            .has_reconnectable_departure(key, &surviving_holds)
        {
            self.turn_ring.end_session(key);
            crate::mesh::deregister_seen(seen, key);
        }
        // A session no descriptor ever named has no coordinator lifecycle, so
        // the retirement that ordinarily cleans up its ingress gate will never
        // come — drop the gate (and the provisional mark: a later dial for the
        // same id is a genuinely fresh admission with its own new deadline)
        // here, at its retirement-equivalent, or the entries live for the
        // relay's lifetime. A descriptor-named session keeps its gate until
        // real retirement, and its mark was already cleared at descriptor
        // application.
        //
        // EXCEPT when the provisional journal still holds anything undrained:
        // journaled entries are transport-acknowledged (turns) or the only
        // record that a slot left at all (departures), and the journal is
        // retained until a descriptor drains it or retirement ends the session
        // — no local fact can prove it unneeded sooner (see the retention rule
        // in [`crate::session::provisional_turns`]) — so discarding it here
        // would silently hole an accepted sequence, or leave peer-homed
        // survivors waiting forever on an expected slot with neither presence
        // nor a departure. The empty-check and the removal are ONE atomic step
        // (`discard_if_empty`), so a departure deposited by a sibling
        // teardown's announce racing this close can never be classified away
        // and then deleted: it either refuses the discard or lands in a fresh,
        // retained journal.
        if crate::consensus::maker_exists(&self.decision_makers, key) {
            self.provisional.clear(key);
        } else if self.provisional_turns.discard_if_empty(key) {
            self.provisional.clear(key);
            self.gates.discard(key);
        }
    }

    /// The coordinator retired the session's descriptor: the terminal sweep.
    ///
    /// The ingress gate closes first, before any state is destroyed. The write
    /// acquisition drains every in-flight ingress critical section (mesh
    /// dispatch, the turn funnel, an admission), so their mutations land
    /// wholly before the sweeps below; every ingress that starts afterward
    /// observes the retirement and refuses. Without this boundary a buffered
    /// mesh frame — still passing its link driver's joined check until the
    /// queued Leave drains — would find no maker, read a `SlotDeparted` as an
    /// undecided drop, and recreate a drop hold (or report a second close, or
    /// re-create a flight recording) for a session that no longer exists.
    ///
    /// `seen` is the forward-once gate, swept here for the same reason the
    /// replay ring is (see [`close_emptied`](Self::close_emptied)).
    ///
    /// The side channels are swept here too, not only by the emptied close: a
    /// session retired while local slots are still connected never runs that
    /// close (each slot's later teardown is refused by the gate this just
    /// shut), so without this sweep its lobby log, chat state and skin map
    /// would outlive the session for the relay's lifetime. Nothing can still
    /// need them — a retired session admits no reconnect to replay them to.
    ///
    /// The flight recording's close seal is not released here either: the
    /// caller clears it last, after its own mesh `Leave` commands are queued,
    /// so the seal guards against straggling mesh events for as much of the
    /// teardown as possible.
    pub(crate) fn retire(&self, key: &SessionKey, seen: &crate::mesh::SeenRegistries) {
        self.gates.retire(key);
        self.decision_makers.deregister_maker(key);
        crate::session::presence::forget(&self.presence, key);
        // Discard any turns still penned for the session — with the maker gone
        // and the gate retired, no descriptor will ever drain them. The replay
        // ring and forward-once seen state fall with them: the session-emptied
        // close retains both while an undecided hold still promises a
        // reconnect (their receipts seed that resume's receive window), and
        // retirement is the terminal boundary that ends the promise — with the
        // descriptor gone there is no admission path left, so nothing else
        // would ever sweep a retained pair whose reconnect never came.
        // Idempotent when the emptied close already removed them.
        self.provisional_turns.discard(key);
        self.turn_ring.end_session(key);
        crate::mesh::deregister_seen(seen, key);
        // Retirement is terminal for the session's drop bookkeeping: with the
        // descriptor gone there is no admission path left for a held slot's
        // reconnect and no decide path for its leave, so any armed abandon
        // timer and every remaining hold would otherwise leak forever — the
        // timer's expiry stands down on the forgotten presence (never deciding
        // or releasing), and nothing else ever sweeps the entries.
        self.drop_holds.cancel_abandon(key);
        self.drop_holds.end_session_terminal(key);
        // The lobby log, chat state and skin map ordinarily fall with the
        // relay's last local member (the emptied close), but a session retired
        // while members are still connected never reaches that close — their
        // later teardowns are refused by the retired gate — so this is their
        // only remaining sweep. Idempotent when the emptied close already ran.
        self.side_channels.end_session(key);
    }
}

#[cfg(test)]
mod tests;
