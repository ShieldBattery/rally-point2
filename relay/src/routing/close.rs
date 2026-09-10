//! The emptied-session close: what this relay tears down (and reports to the
//! coordinator) once its last local slot for a session is gone, and the
//! reconnect promise that defers it.

use super::*;

use crate::consensus;

/// Closes out this relay's serving state for a session whose local roster is
/// empty — the coordinator `SessionClosed` notice plus the per-session
/// registries (lobby log, chat, skin map, forwarded-turn replay ring,
/// session-level dedup, decided drop holds) — unless a still-held, undecided
/// departure of a homed slot promises a reconnect.
///
/// While such a departure is undecided, its drop hold is the admission token a
/// re-dial claims on this relay (`server.rs`), and the retained registries are
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
/// undecided hold itself still survives the sweep below and admits a quick
/// re-dial, whose link re-opens the close latch when it starts serving.
///
/// Safe to call whenever the session *might* be closeable: a non-empty roster,
/// a deferral, or an already-claimed close all make it a no-op. The claim
/// latch (`consensus::claim_close_report`) keeps two concurrent evaluations
/// from both running the close; the roster lock, held from the emptiness
/// check through the last registry erase, keeps a concurrent re-dial's
/// `register` (which inserts under the same lock) from landing mid-teardown —
/// without it, a quick re-dial into a never-started session (whose emptying
/// closes immediately, with no deferral to hide the window) could be admitted
/// and then have its lobby log and replay state erased underneath it while a
/// premature `SessionClosed` retires the session coordinator-side. Every call
/// inside the held section touches only its own module's lock (consensus,
/// lobby, chat, skin, turn ring, seen, drop holds, provisional), never this
/// roster's, so holding it across them cannot deadlock or reenter — the same
/// discipline `announce_departure` documents for its own roster-lock hold.
pub(crate) fn maybe_close_emptied_session(
    sessions: &Sessions,
    mesh: &crate::mesh::MeshState,
    key: &SessionKey,
) {
    maybe_close_emptied_session_inner(sessions, mesh, key, false)
}

/// [`maybe_close_emptied_session`] for the abandon timer's expiry: the close
/// claim additionally requires a decision-maker to still exist, in one atomic
/// registry acquisition (see [`consensus::claim_close_report_with_maker`]). The
/// timer only ever arms while a maker exists, so a missing one at expiry proves
/// the descriptor was retired mid-window and the close already ran — and a
/// separate exists-then-claim pair would leave a gap for that retirement to
/// land in, restoring `claim_close_report`'s no-maker default and duplicating
/// the close.
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
    let _ = mesh.gates.with_ingress(key, || {
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
    let held = mesh.drop_holds.pending_slots(key);
    if consensus::session_started(&mesh.decision_makers, key)
        && consensus::has_reconnectable_departure(&mesh.decision_makers, key, &held)
    {
        tracing::info!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            "deferring emptied-session close; a homed slot's drop is held undecided",
        );
        return;
    }
    let claimed = if close_claim_requires_maker {
        consensus::claim_close_report_with_maker(&mesh.decision_makers, key)
    } else {
        consensus::claim_close_report(&mesh.decision_makers, key)
    };
    if !claimed {
        return;
    }
    consensus::session_closed(&mesh.decision_makers, key);
    // An abandoned-session timer running for this session must not re-run the
    // close when its window elapses: the close has been reported now, and the
    // teardown below is what it would otherwise repeat. Its force-decide is still
    // owed, so the timer is marked rather than cancelled.
    mesh.drop_holds.note_session_closed(key);
    // The relay's last local member for the session is gone, so its lobby log
    // and (now-empty) member set can be dropped — mirroring how the roster
    // group is dropped when its last slot leaves.
    crate::session::lobby::end_session(&mesh.lobby, key);
    // Same for chat's (log-free) per-session state.
    crate::session::chat::end_session(&mesh.chat, key);
    // Same for the skin blob map and member set: no local member remains to
    // replay it to, so the whole per-session state can be dropped.
    crate::session::skin::end_session(&mesh.skins, key);
    // Same for request limiters, and for any hold whose slot's leave is already
    // decided — but NOT for an undecided hold: on a session that never started
    // (where a fresh undecided drop does not defer the close) that hold is
    // still the reconnect-admission token and unlock clock for a drop nobody
    // has decided yet. See `crate::session::drop_hold` module docs.
    let decided = consensus::decided_slots(&mesh.decision_makers, key);
    mesh.drop_holds.end_session(key, &decided);
    // The forwarded-turn replay ring and the forward-once seen state (whose
    // entry is created lazily on the first turn forwarded — there is no
    // explicit "join" counterpart to pair the teardown with) go down on the
    // same "last local slot gone" trigger as the registries above — UNLESS a
    // surviving hold still promises a reconnect this relay would admit. That
    // reconnect's resume seeds its fresh receive window from the seen state's
    // receipts (every transport-acked seq its sparse anchor will not re-send),
    // so destroying them here while honoring the hold would admit a resume
    // whose acked holes nothing can ever fill: the prefix wedges, and the
    // live stream eventually exits the receive window. Receipt-state lifetime
    // must match the reconnect-admission token's, exactly as the provisional
    // journal is retained while a descriptor could still drain it — so both
    // stores are kept until no such token remains: a reconnect re-opens the
    // close latch and this teardown re-runs at the next emptying, and
    // descriptor retirement sweeps them terminally (`MeshControl::end_session`)
    // if the reconnect never comes. (The retained ring is empty in practice —
    // it records only started sessions, and a started session's reconnectable
    // departure defers this close entirely above — but tying both stores to
    // the same token keeps the rule whole rather than shape-dependent.)
    let surviving_holds = mesh.drop_holds.pending_slots(key);
    if !consensus::has_reconnectable_departure(&mesh.decision_makers, key, &surviving_holds) {
        mesh.turn_ring.end_session(key);
        crate::mesh::deregister_seen(&mesh.seen, key);
    }
    // A session no descriptor ever named has no coordinator lifecycle, so the
    // retirement that ordinarily cleans up its ingress gate will never come —
    // drop the gate (and the provisional mark: a later dial for the same id
    // is a genuinely fresh admission with its own new deadline) here, at its
    // retirement-equivalent, or the entries live for the relay's lifetime. A
    // descriptor-named session keeps its gate until real retirement, and its
    // mark was already cleared at descriptor application.
    //
    // EXCEPT when the provisional journal still holds anything undrained:
    // journaled entries are transport-acknowledged (turns) or the only
    // record that a slot left at all (departures), and the journal is
    // retained until a descriptor drains it or retirement ends the session
    // — no local fact can prove it unneeded sooner (see the retention rule
    // in `crate::session::provisional_turns`) — so discarding it here would silently
    // hole an accepted sequence, or leave peer-homed survivors waiting
    // forever on an expected slot with neither presence nor a departure.
    // The empty-check and the removal are ONE atomic step
    // (`discard_if_empty`), so a departure deposited by a sibling
    // teardown's announce racing this close can never be classified away
    // and then deleted: it either refuses the discard or lands in a fresh,
    // retained journal.
    if consensus::maker_exists(&mesh.decision_makers, key) {
        mesh.provisional.clear(key);
    } else if mesh.provisional_turns.discard_if_empty(key) {
        mesh.provisional.clear(key);
        mesh.gates.discard(key);
    }
}
