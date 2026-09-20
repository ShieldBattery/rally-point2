//! Everything this relay holds for a session, in one bundle.

use std::sync::Arc;
use std::time::Duration;

use crate::consensus::DecisionMakers;
use crate::coordinator::load_fence::LoadStateFence;
use crate::session::chat::ChatRegistry;
use crate::session::drop_hold::DropHolds;
use crate::session::gate::SessionGates;
use crate::session::lobby::LobbyRegistry;
use crate::session::presence::PresenceRegistry;
use crate::session::provisional::ProvisionalSessions;
use crate::session::provisional_turns::ProvisionalTurnPen;
use crate::session::skin::SkinRegistry;
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
    /// Per-session lobby-command fan-out and its ordered replay log. The
    /// slot-link tasks deliver their clients' lobby commands into it (and
    /// register each member for replay), and the mesh-link drivers deliver
    /// peers' lobby commands into it. See [`crate::session::lobby`].
    pub lobby: LobbyRegistry,
    /// Per-session game-chat fan-out. The mid-game counterpart to `lobby`: the
    /// slot-link tasks deliver their clients' chat messages into it (and
    /// register each member to receive others'), and the mesh-link drivers
    /// deliver peers' messages into it. No replay log — chat is ephemeral. See
    /// [`crate::session::chat`].
    pub chat: ChatRegistry,
    /// Per-session cosmetic-skin fan-out and its latest-blob-per-slot replay
    /// map. The slot-link tasks deliver their clients' skin blobs into it (and
    /// register each member to receive others' and replay the stored map), and
    /// the mesh-link drivers deliver peers' blobs into it. See
    /// [`crate::session::skin`].
    pub skins: SkinRegistry,
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
            lobby: crate::session::lobby::new_lobby_registry(),
            chat: crate::session::chat::new_chat_registry(),
            skins: crate::session::skin::new_skin_registry(),
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
