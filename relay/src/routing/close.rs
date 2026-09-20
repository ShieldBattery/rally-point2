//! The emptied-session close: what this relay tears down (and reports to the
//! coordinator) once its last local slot for a session is gone, and the
//! reconnect promise that defers it.

use super::*;

/// Closes out this relay's serving state for a session whose local roster is
/// empty — the coordinator `SessionClosed` notice plus the per-session
/// registries (lobby log, chat, skin map, forwarded-turn replay ring,
/// session-level dedup, decided drop holds) — unless a still-held, undecided
/// departure of a homed slot promises a reconnect.
///
/// While such a departure is undecided, its drop hold is the admission token a
/// re-dial claims on this relay (the client edge's `Admission`), and the retained registries are
/// what make the admitted resume whole: the replay ring catches the client's
/// sim up and the lobby log restores its setup state. Closing eagerly would
/// also retire the session coordinator-side — on a single-relay session this
/// relay's notice alone satisfies the all-relays-closed condition — cutting
/// off the very reconnect the hold promises. So the close is re-evaluated
/// instead, from every place the blocking state can change: the roster
/// emptying (`end_slot_link`), a held drop decided by an honored request or by
/// a peer authority's leave directive (`mesh.rs`), and the abandoned-session
/// force-decide. The force-decide is what bounds the deferral for a *started*
/// session: the same emptying that defers here also flips the session empty
/// session-wide (single-relay), or the peers' own eventual emptying does
/// (multi-relay), and `reconcile_abandon` then arms the timer that decides
/// every held drop. A session that never started has no such bound — nothing
/// ever force-decides its holds — so its emptying closes immediately; the
/// undecided hold itself still survives the sweep and admits a quick re-dial,
/// whose link re-opens the close latch when it starts serving.
///
/// Safe to call whenever the session *might* be closeable: a non-empty roster,
/// a deferral, or an already-claimed close all make it a no-op. The claim
/// latch (`DecisionMakers::claim_close_report`) keeps two concurrent evaluations
/// from both running the close; the roster lock, held from the emptiness
/// check through the last registry erase, keeps a concurrent re-dial's
/// `register` (which inserts under the same lock) from landing mid-teardown —
/// without it, a quick re-dial into a never-started session (whose emptying
/// closes immediately, with no deferral to hide the window) could be admitted
/// and then have its lobby log and replay state erased underneath it while a
/// premature `SessionClosed` retires the session coordinator-side. Every call
/// inside the held section — the whole of `SessionState::close_emptied`
/// included — touches only its own module's lock (consensus, lobby, chat,
/// skin, turn ring, seen, drop holds, provisional), never this roster's, so
/// holding it across them cannot deadlock or reenter — the same discipline
/// `announce_departure` documents for its own roster-lock hold.
pub(crate) fn maybe_close_emptied_session(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
) {
    maybe_close_emptied_session_inner(sessions, mesh, key, false)
}

/// [`maybe_close_emptied_session`] for the abandon timer's expiry, which reads a
/// missing decision-maker the opposite way: the timer only ever arms while a
/// maker exists, so a missing one at expiry proves the descriptor was retired
/// mid-window and the close already ran. It must not report a second one.
pub(super) fn maybe_close_emptied_session_for_abandon_expiry(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
) {
    maybe_close_emptied_session_inner(sessions, mesh, key, true)
}

fn maybe_close_emptied_session_inner(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    close_claim_requires_maker: bool,
) {
    // The whole evaluation is one ingress critical section: an emptied-close
    // racing the session's retirement must land wholly before the sweeps (and
    // be swept) or observe the retirement and do nothing — without this, a
    // retired session's close evaluation would find no maker, claim the
    // no-maker close default, and report a second SessionClosed. Recursive
    // for the dispatch arms that already hold the gate.
    let _ = mesh.session.gates.with_ingress(key, || {
        maybe_close_emptied_session_gated(sessions, mesh, key, close_claim_requires_maker)
    });
}

fn maybe_close_emptied_session_gated(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
    close_claim_requires_maker: bool,
) {
    let roster = sessions.lock();
    if roster.contains_key(key) {
        // A slot is locally connected (or a reconnect already reclaimed one);
        // that link's own teardown re-evaluates when it ends.
        return;
    }
    let held = mesh.session.drop_holds.pending_slots(key);
    if mesh.session.decision_makers.is_started(key)
        && mesh
            .session
            .decision_makers
            .has_reconnectable_departure(key, &held)
    {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            "deferring emptied-session close; a homed slot's drop is held undecided",
        );
        return;
    }
    // A session with no decision-maker has nowhere to latch a claim, and the two
    // entry points read that opposite ways — so the default is chosen here, not
    // inside the claim. An ordinary emptying reports: a session no descriptor
    // ever named has no decide paths, so its emptying is the only close it can
    // ever reach. The abandon timer's expiry does not: that timer arms only
    // while a maker exists, so a missing one proves the descriptor was retired
    // mid-window and the close already ran and reached the coordinator.
    let claimed = mesh
        .session
        .decision_makers
        .claim_close_report(key)
        .unwrap_or(!close_claim_requires_maker);
    if !claimed {
        return;
    }
    mesh.session.decision_makers.session_closed(key);
    mesh.session.close_emptied(key, &mesh.seen);
}
