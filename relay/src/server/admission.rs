//! The client edge's refusal pipeline: the gates a dial has to pass, the
//! close code each refusal sends, and the rollback each one owes.
//!
//! A dial arrives with nothing of the relay's attached to it and leaves either
//! serving turns or refused. In between it can create exactly two things: the
//! roster seat `routing::register` takes, and the session scaffolding that
//! seat's first touch brings into being (the ingress gate, a provisional
//! journal reservation, a provisional mark). **A refused admission must leave
//! neither** — so every refusal goes through [`Admission::refuse`], which owns
//! the rollback rule rather than leaving it to be re-derived at each gate.
//!
//! ## The rollback rule
//!
//! Which rollback a refusal runs is a property of *why* it refused, recorded
//! on the refusal itself as a [`Rollback`]:
//!
//! - [`Rollback::Untouched`] — the gate ran before the roster was touched, so
//!   there is nothing this dial created. The pre-register gates are all this.
//! - [`Rollback::Scaffolding`] — the roster seat is freed and then
//!   `abandon_refused_admission` drops the session scaffolding *if nothing
//!   else owns it*. The seat must go first: that check reads the roster, and a
//!   seat still held would (correctly) make it keep the scaffolding.
//! - [`Rollback::RetirementOwnsIt`] — the seat is freed and nothing else is
//!   touched, because the refusal *is* the session's retirement. Retirement's
//!   own sweep owns every store the scaffolding rollback would reach, and the
//!   gate's tombstone makes that rollback a no-op anyway (`discard_if` refuses
//!   a retired gate without running its ownership check). Running it would be
//!   harmless but would suggest this path has cleanup to do when it does not.
//!
//! ## The gate order is load-bearing
//!
//! The gates run in the order [`PRE_REGISTER_GATES`] lists them and then in
//! the order `serve_connection` writes them out. Two orderings in particular
//! are not free to move: the handshake ack is written *before* any hold or
//! departure state is touched, and the journal seal is re-checked *after*
//! registration succeeds. Each one's reasoning is on the step itself.

use rally_point_proto::close_codes;
use rally_point_proto::ids::SlotId;
use rally_point_transport::noq::{self, VarInt};

use crate::consensus;
use crate::key::SessionKey;
use crate::routing::{self, Sessions, SlotRegistration};
use crate::session::SessionState;

use super::ConnError;

#[cfg(test)]
mod tests;

/// What a refusal has to undo. See the rollback rule in the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rollback {
    /// Nothing: the refusal happened before this dial touched the roster, so
    /// it created no seat and no scaffolding.
    Untouched,
    /// Free the roster seat, then drop the session scaffolding the register
    /// attempt created on first touch — but only if nothing else owns it
    /// (a live occupant's seat, an existing maker, an undrained journal).
    Scaffolding,
    /// Free the roster seat and leave the session's state alone: this refusal
    /// is the session's retirement, whose own sweep owns that state.
    RetirementOwnsIt,
}

/// Which [`ConnError`] a refusal ends the connection with. The session and
/// slot are the admission's own, so a gate only has to name the cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RefusalKind {
    /// The authorized slot is not among the session descriptor's homed set for
    /// this relay.
    SlotNotHomed,
    /// The authorized slot's leave was already decided, or its clean-leave
    /// intent was already journaled.
    SlotDeparted,
    /// The session's descriptor was retired and its tombstone still stands.
    SessionRetired,
    /// The authorized slot was already taken by another live connection.
    SlotTaken,
    /// The provisional journal's session ceiling refused a pre-descriptor
    /// admission.
    ProvisionalCapacity,
}

impl RefusalKind {
    /// The connection-ending error for this cause in `key`'s session at
    /// `slot`.
    fn into_error(self, key: SessionKey, slot: SlotId) -> ConnError {
        let SessionKey { tenant, session } = key;
        match self {
            RefusalKind::SlotNotHomed => ConnError::SlotNotHomed {
                tenant,
                session,
                slot,
            },
            RefusalKind::SlotDeparted => ConnError::SlotDeparted {
                tenant,
                session,
                slot,
            },
            RefusalKind::SessionRetired => ConnError::SessionRetired {
                tenant,
                session,
                slot,
            },
            RefusalKind::SlotTaken => ConnError::SlotTaken {
                tenant,
                session,
                slot,
            },
            RefusalKind::ProvisionalCapacity => ConnError::ProvisionalCapacity {
                tenant,
                session,
                slot,
            },
        }
    }
}

/// One refusal at the client edge: the close code the client reads, the reason
/// phrase that rides with it, the cause the relay logs, and the rollback the
/// refusal owes. Declaring all four together is what keeps a new gate from
/// getting three of them right and the fourth wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Refusal {
    /// The QUIC application close code. These are the client's only diagnosis
    /// of why its link ended, so they come from the shared table in `proto`
    /// and never change meaning.
    pub(super) code: u32,
    /// The close frame's reason phrase.
    pub(super) reason: &'static [u8],
    /// What this connection's error says happened.
    pub(super) kind: RefusalKind,
    /// What refusing here has to undo.
    pub(super) rollback: Rollback,
}

/// The dial's authorized slot belongs to another relay. Refused before the
/// roster is touched, so there is nothing to undo.
pub(super) const NOT_HOMED: Refusal = Refusal {
    code: close_codes::SLOT_NOT_HOMED,
    reason: b"slot not homed on this relay",
    kind: RefusalKind::SlotNotHomed,
    rollback: Rollback::Untouched,
};

/// The dial's slot has already left the game, found before the roster is
/// touched — either by its decided departure or by its journaled clean-leave
/// seal. Nothing to undo.
pub(super) const ALREADY_DEPARTED: Refusal = Refusal {
    code: close_codes::SLOT_DEPARTED,
    reason: b"slot already departed",
    kind: RefusalKind::SlotDeparted,
    rollback: Rollback::Untouched,
};

/// The same refusal reached *after* registration succeeded — the post-register
/// seal re-check, or a reconnect the decision-maker rejected. The roster seat
/// and any scaffolding this dial created go with it.
pub(super) const DEPARTED_AT_ADMISSION: Refusal = Refusal {
    code: close_codes::SLOT_DEPARTED,
    reason: b"slot already departed",
    kind: RefusalKind::SlotDeparted,
    rollback: Rollback::Scaffolding,
};

/// The dial's slot is already connected by another live connection. The
/// register attempt created the session's gate on first touch; if this session
/// holds nothing else, don't leave that scaffolding behind (the live
/// occupant's seat makes this a no-op here).
pub(super) const SLOT_TAKEN: Refusal = Refusal {
    code: close_codes::SLOT_TAKEN,
    reason: b"slot already connected",
    kind: RefusalKind::SlotTaken,
    rollback: Rollback::Scaffolding,
};

/// The session's descriptor was retired while this dial was in flight.
/// Retirement's own sweep owns the session's state — see the rollback rule.
pub(super) const SESSION_RETIRED: Refusal = Refusal {
    code: close_codes::SESSION_RETIRED,
    reason: b"session retired",
    kind: RefusalKind::SessionRetired,
    rollback: Rollback::RetirementOwnsIt,
};

/// The provisional journal has no capacity for another pre-descriptor session.
/// The connection is closed before any turn could be accepted, so nothing is
/// acknowledged that cannot be retained — and the seat and the reservation
/// this dial took are both rolled back.
pub(super) const PROVISIONAL_CAPACITY: Refusal = Refusal {
    code: close_codes::PROVISIONAL_CAPACITY,
    reason: b"provisional capacity exhausted",
    kind: RefusalKind::ProvisionalCapacity,
    rollback: Rollback::Scaffolding,
};

/// One gate: a pure read of the session's state that either lets the dial past
/// or names the refusal.
pub(super) type Gate = fn(&SessionState, &SessionKey, SlotId) -> Option<Refusal>;

/// The gates a dial passes before it is allowed to touch the roster, **in the
/// order they run**. All three are pure reads, so nothing here has created
/// anything to roll back — which is exactly why they can be a list rather than
/// a sequence of hand-written refusal blocks.
pub(super) const PRE_REGISTER_GATES: &[Gate] =
    &[home_relay_binding, decided_departure, journaled_leave_seal];

/// Home-relay binding gate: refuse a client whose authorized slot the
/// coordinator did not assign to this relay. A token binds
/// tenant/session/slot/key but not the relay itself, so without this a
/// misrouted (or malicious) client could register the same slot on two relays
/// in a true multi-relay session, feeding each a different turn at the same
/// (slot, seq) -- a split the mesh's topological dedup only suppresses the
/// symptom of, on each side, never detects or prevents.
///
/// `slot_homed` admits (`true`) when no descriptor has arrived yet for this
/// session, or one arrived with an empty homed set (legacy, dev-mode, a
/// coordinator that predates the field) -- so this preserves the
/// descriptor-arrival-race behavior exactly: a client dialing before any
/// descriptor exists for its session is admitted unconditionally, with no wait
/// or window introduced here. Enforcement only ever refuses once a non-empty
/// homed set says this slot belongs to a different relay.
fn home_relay_binding(session: &SessionState, key: &SessionKey, slot: SlotId) -> Option<Refusal> {
    if !consensus::slot_homed(&session.decision_makers, key, slot) {
        return Some(NOT_HOMED);
    }
    None
}

/// Cheap pre-register fast-fail against the slot's departure state, before
/// touching the roster at all: a departure recorded with no hold pending means
/// the leave was already decided (an honored drop request, or a clean leave),
/// so the re-register is hopeless and can be refused before spending a roster
/// slot on it. This is a snapshot -- read before `register`, and never reused
/// after it -- which is sound only because decided-ness is monotonic (a decided
/// leave never becomes undecided again): if this snapshot is stale by the time
/// it's checked, it can only be stale in the direction of a hold that has SINCE
/// been claimed by a concurrent reconnect or decide, never the other way, so a
/// "departed" read here is never a false positive. The real admission decision
/// -- the one this snapshot must never be reused for -- runs after `register`
/// succeeds, keyed on current state.
fn decided_departure(session: &SessionState, key: &SessionKey, slot: SlotId) -> Option<Refusal> {
    let departed = consensus::slot_departed(&session.decision_makers, key, slot);
    let hold_pending = session.drop_holds.is_pending(key, slot);
    if departed && !hold_pending {
        return Some(ALREADY_DEPARTED);
    }
    None
}

/// A clean leave journaled before the session's descriptor is terminal from
/// the moment of the intent, exactly as a maker's decided leave is: without
/// this, the same valid token could redial into the pre-descriptor window
/// (where the permissive no-maker admission would wave it through), and its
/// fresh generation would race the journaled leave's drained count with
/// post-count turns. The seal outlives the journal's drain (the drained decided
/// leave then refuses through the maker), so this check is monotone-safe read
/// here before registration.
fn journaled_leave_seal(session: &SessionState, key: &SessionKey, slot: SlotId) -> Option<Refusal> {
    if session.provisional_turns.armed() && session.provisional_turns.slot_sealed(key, slot) {
        return Some(ALREADY_DEPARTED);
    }
    None
}

/// The post-register re-check of the journal seal, run inside the admission's
/// own ingress section.
///
/// The pre-register check can race the sealing link itself — the old link's
/// clean intent installs the seal and only then frees the roster seat, so a
/// dial that read "not sealed" while the seat was still occupied can find it
/// free moments later. Registration succeeding proves the old link
/// deregistered, which proves its seal (if any) was already installed — so this
/// post-register read is authoritative where the pre-register one was only a
/// fast-fail.
pub(super) fn journal_seal_still_clear(
    session: &SessionState,
    key: &SessionKey,
    slot: SlotId,
) -> bool {
    !(session.provisional_turns.armed() && session.provisional_turns.slot_sealed(key, slot))
}

/// One client dial between authorization and the moment it starts serving
/// turns, plus everything a refusal has to undo.
///
/// Built the moment the authorized session and slot are known, which is the
/// first point at which a refusal could leave something behind. It holds the
/// connection so a refusal is always announced on it, and takes custody of the
/// roster seat the moment there is one, so no refusal path can forget to free
/// it.
pub(super) struct Admission<'a> {
    connection: noq::Connection,
    key: SessionKey,
    slot: SlotId,
    sessions: &'a Sessions,
    mesh: &'a crate::mesh::MeshState,
    /// The roster seat this dial holds, from the moment `register` succeeded
    /// until a successful admission disarms it or a refusal drops it.
    registration: Option<SlotRegistration>,
}

impl<'a> Admission<'a> {
    /// A dial authorized for `slot` in `key`'s session, holding nothing yet.
    pub(super) fn new(
        connection: noq::Connection,
        key: SessionKey,
        slot: SlotId,
        sessions: &'a Sessions,
        mesh: &'a crate::mesh::MeshState,
    ) -> Self {
        Admission {
            connection,
            key,
            slot,
            sessions,
            mesh,
            registration: None,
        }
    }

    /// Takes custody of the roster seat `register` just handed out, so every
    /// refusal from here on frees it without having to remember to.
    pub(super) fn hold_seat(&mut self, registration: SlotRegistration) {
        self.registration = Some(registration);
    }

    /// Refuses the dial: close the connection with the refusal's code and
    /// reason, run the rollback that refusal owes, and return the error this
    /// connection ends with.
    ///
    /// This is the only way a refusal reaches the client, which is what makes
    /// the rollback rule (see the module docs) enforceable rather than
    /// repeated: a gate names its cause, and the rollback follows from it.
    pub(super) fn refuse(mut self, refusal: Refusal) -> ConnError {
        self.connection
            .close(VarInt::from_u32(refusal.code), refusal.reason);
        self.roll_back(refusal.rollback);
        refusal.kind.into_error(self.key, self.slot)
    }

    /// Refuses the dial without announcing it: the handshake stream write
    /// already failed, so there is no working channel left to tell the client
    /// anything on. The rollback is the full one — the seat and the
    /// scaffolding — because the write failed *before* any hold or departure
    /// state was touched, so nothing else is left inconsistent.
    pub(super) fn refuse_unannounced(mut self, error: ConnError) -> ConnError {
        self.roll_back(Rollback::Scaffolding);
        error
    }

    /// The connection and the roster seat, handed to the slot-link task. The
    /// dial passed every gate; nothing is rolled back from here on.
    pub(super) fn into_serving(self) -> (noq::Connection, SlotRegistration) {
        let registration = self
            .registration
            .expect("an admission only starts serving after it registered a roster seat");
        (self.connection, registration)
    }

    fn roll_back(&mut self, rollback: Rollback) {
        match rollback {
            // Nothing was created: the refusal ran before the roster was
            // touched.
            Rollback::Untouched => {}
            Rollback::Scaffolding => {
                // Free the seat FIRST. `abandon_refused_admission`'s ownership
                // check reads the roster, and a seat still held would make it
                // keep the scaffolding this refusal is here to drop.
                drop(self.registration.take());
                routing::abandon_refused_admission(self.sessions, self.mesh, &self.key);
            }
            // The session is retired; its own sweep owns everything the
            // scaffolding rollback would reach.
            Rollback::RetirementOwnsIt => drop(self.registration.take()),
        }
    }
}
