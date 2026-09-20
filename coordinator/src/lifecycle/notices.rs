//! Notice ingest: the single owner of "a relay reported X".
//!
//! Six per-session facts arrive on a relay's control connection — a slot
//! connected, the session started, a client's game loop began, a player
//! departed, the game desynced, a client reported its result. Every one of them
//! runs the same three steps in the same order, and [`Lifecycle::ingest_notice`]
//! is where they run:
//!
//! 1. **Authorize the reporter.** A notice carries attacker-influenceable
//!    `tenant`/`session`/payload and drives a webhook signed with the tenant's own
//!    key, so the reporting relay must be one of the session's serving relays.
//! 2. **Record the fact** on the session's lifecycle state, independent of the
//!    dedup and notify-config gates the webhook path applies — the reaps, the
//!    `sessionClosed` signal, and the load-state read must track a session even
//!    for a tenant with no webhook configured.
//! 3. **Enqueue the webhook**, which dedups the redundant reports of one event
//!    and resolves the tenant's notify config and correlation ids.
//!
//! The caller decodes a frame and calls this once; it never picks the dedup set,
//! the ordering, or the authorization rule itself.

use rally_point_proto::control::{
    DepartureNotice, DesyncNotice, ResultNotice, SessionStartedNotice, SlotConnectedNotice,
    SlotStartedNotice, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};

use super::Lifecycle;
use crate::notify;

/// One per-session fact a relay reports up its control connection, as the union
/// of the six kinds that share the ingest path above. The relay's terminal
/// `SessionClosed` is deliberately not a member: it is fenced on the control
/// connection's generation rather than on session membership, and it drives no
/// webhook of its own.
#[derive(Debug, Clone)]
pub enum SessionNotice {
    /// A player permanently departed a running game (left vs. dropped).
    Departure(DepartureNotice),
    /// The game's sims diverged — a relay-observed desync.
    Desync(DesyncNotice),
    /// A client's end-of-game result, forwarded opaque.
    Result(ResultNotice),
    /// A slot's link activated on the reporting relay.
    SlotConnected(SlotConnectedNotice),
    /// The authority relay's coverage latch fired: the session started.
    SessionStarted(SessionStartedNotice),
    /// A client reported that its game loop began running.
    SlotStarted(SlotStartedNotice),
}

/// What identifies one notice *within* its session, for the logs a refused or
/// dropped notice leaves behind. A departure, result, or slot notice is
/// identified by its slot; a desync by the sync ordinal at which the mismatch
/// was observed; a session start by the session alone. Every such log therefore
/// correlates on the id that actually applies to the event, rather than
/// flattening the kinds to a lowest common denominator.
pub(crate) enum NoticeKey {
    /// A per-slot notice: logs `slot`.
    Slot(SlotId),
    /// A desync: logs `sync_ordinal`.
    SyncOrdinal(u64),
    /// A whole-session notice: logs neither.
    Session,
}

impl SessionNotice {
    /// The tenant whose session this notice claims to describe.
    fn tenant(&self) -> &TenantId {
        match self {
            Self::Departure(n) => &n.tenant,
            Self::Desync(n) => &n.tenant,
            Self::Result(n) => &n.tenant,
            Self::SlotConnected(n) => &n.tenant,
            Self::SessionStarted(n) => &n.tenant,
            Self::SlotStarted(n) => &n.tenant,
        }
    }

    /// The session this notice claims to describe.
    fn session(&self) -> SessionId {
        match self {
            Self::Departure(n) => n.session,
            Self::Desync(n) => n.session,
            Self::Result(n) => n.session,
            Self::SlotConnected(n) => n.session,
            Self::SessionStarted(n) => n.session,
            Self::SlotStarted(n) => n.session,
        }
    }

    /// What identifies this notice within its session, for a log.
    fn key(&self) -> NoticeKey {
        match self {
            Self::Departure(n) => NoticeKey::Slot(n.slot),
            Self::Desync(n) => NoticeKey::SyncOrdinal(n.sync_ordinal),
            Self::Result(n) => NoticeKey::Slot(n.slot),
            Self::SlotConnected(n) => NoticeKey::Slot(n.slot),
            Self::SessionStarted(_) => NoticeKey::Session,
            Self::SlotStarted(n) => NoticeKey::Slot(n.slot),
        }
    }

    /// The name this kind goes by in a log line.
    fn log_kind(&self) -> &'static str {
        match self {
            Self::Departure(_) => "departure",
            Self::Desync(_) => "desync",
            Self::Result(_) => "result",
            Self::SlotConnected(_) => "slot-connected",
            Self::SessionStarted(_) => "session-started",
            Self::SlotStarted(_) => "slot-started",
        }
    }
}

impl NoticeKey {
    /// Debug-logs `message` about a notice for `(tenant, session)`, carrying
    /// whichever within-session field identifies it.
    pub(crate) fn debug(&self, tenant: &TenantId, session: SessionId, message: &str) {
        match self {
            Self::Slot(slot) => tracing::debug!(
                tenant = tenant.as_ref(),
                session = session.0,
                slot = slot.0,
                "{message}",
            ),
            Self::SyncOrdinal(sync_ordinal) => tracing::debug!(
                tenant = tenant.as_ref(),
                session = session.0,
                sync_ordinal,
                "{message}",
            ),
            Self::Session => {
                tracing::debug!(tenant = tenant.as_ref(), session = session.0, "{message}",)
            }
        }
    }

    /// Warns that `relay` reported a notice it is not allowed to report,
    /// carrying the reporter alongside the fields [`debug`](Self::debug) logs.
    fn warn_refused(&self, relay: RelayId, tenant: &TenantId, session: SessionId, message: &str) {
        match self {
            Self::Slot(slot) => tracing::warn!(
                relay_id = relay.0,
                tenant = tenant.as_ref(),
                session = session.0,
                slot = slot.0,
                "{message}",
            ),
            Self::SyncOrdinal(sync_ordinal) => tracing::warn!(
                relay_id = relay.0,
                tenant = tenant.as_ref(),
                session = session.0,
                sync_ordinal,
                "{message}",
            ),
            Self::Session => tracing::warn!(
                relay_id = relay.0,
                tenant = tenant.as_ref(),
                session = session.0,
                "{message}",
            ),
        }
    }
}

impl Lifecycle {
    /// Ingests one notice `relay` reported: authorize the reporter, record the
    /// fact, enqueue the webhook. See this module's docs for why that order.
    ///
    /// A notice from a relay outside the session's serving set is refused here
    /// and has no effect at all — it claims no dedup entry, lands no fact, and
    /// signs nothing with the tenant's key. Adding a notice kind means adding a
    /// [`SessionNotice`] variant and an arm below; there is no second path that
    /// could quietly bypass the check.
    pub fn ingest_notice(&self, relay: RelayId, notice: SessionNotice) {
        let (tenant, session) = (notice.tenant(), notice.session());
        if !self
            .inner
            .setup
            .relay_serves_session(relay, tenant, session)
        {
            notice.key().warn_refused(
                relay,
                tenant,
                session,
                &format!(
                    "{} notice from a relay not serving the session; rejecting",
                    notice.log_kind()
                ),
            );
            return;
        }

        let setup = &self.inner.setup;
        let dedup = &self.inner.notices;
        match notice {
            SessionNotice::Departure(notice) => {
                self.on_departure(
                    notice.tenant.clone(),
                    notice.session,
                    notice.slot,
                    notice.kind,
                    notice.final_turn_count,
                    notice.finalized,
                );
                notify::handle_departure(setup, &dedup.departures, self, notice);
            }
            SessionNotice::Desync(notice) => {
                // No separate accounting step: the desync handler records the
                // session's desync mark and its orphan-tracking state itself,
                // because the mark must land even for a notice the webhook path
                // then drops.
                notify::handle_desync(setup, &dedup.desyncs, &dedup.desync_marks, self, notice);
            }
            SessionNotice::Result(notice) => {
                self.on_result(notice.tenant.clone(), notice.session, notice.slot);
                notify::handle_result(setup, &dedup.results, self, notice);
            }
            SessionNotice::SlotConnected(notice) => {
                self.on_slot_connected(notice.tenant.clone(), notice.session, notice.slot);
                notify::handle_slot_connected(setup, &dedup.slot_connects, self, notice);
            }
            SessionNotice::SessionStarted(notice) => {
                self.on_session_started(
                    notice.tenant.clone(),
                    notice.session,
                    notice.started_at_ms,
                );
                notify::handle_session_started(setup, &dedup.session_starts, self, notice);
            }
            SessionNotice::SlotStarted(notice) => {
                self.on_slot_started(notice.tenant.clone(), notice.session, notice.slot);
                notify::handle_slot_started(setup, &dedup.slot_starts, self, notice);
            }
        }
    }

    /// The desynced-session marks this lifetime has recorded, so the
    /// flight-recorder sink can pin a session's recordings on the desync fact
    /// even when the desync webhook was ultimately dropped.
    pub fn desync_marks(&self) -> &notify::DesyncMarks {
        &self.inner.notices.desync_marks
    }

    /// The notice dedup sets, so a test can read the gate's verdict off them —
    /// an accepted notice claims its entry synchronously, before any webhook is
    /// enqueued.
    #[cfg(test)]
    pub(crate) fn notice_dedup(&self) -> &notify::NoticeDedup {
        &self.inner.notices
    }
}
