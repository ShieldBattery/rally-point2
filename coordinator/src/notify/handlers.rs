//! The notice handlers: one `handle_*` function per relay-reported notice
//! kind, each following the same shape — claim the dedup entry, resolve the
//! tenant's notify config and correlation ids via
//! [`super::resolve_notice_prefix`], build the notice's `*Webhook` body, and
//! hand it to [`enqueue_dispatch`] for ordered delivery. Grouped separately
//! from `payloads` and `dispatch` because this is the one piece of logic that
//! actually varies per notice kind.

use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::Bytes;
use rally_point_proto::control::{
    DepartureNotice, DesyncNotice, ResultNotice, SessionStartedNotice, SlotConnectedNotice,
    SlotStartedNotice, TenantId,
};
use rally_point_proto::ids::SessionId;
use serde::Serialize;

use super::*;
use crate::lifecycle::Lifecycle;
use crate::session::SessionSetup;
use crate::tenant::NotifyConfig;

/// Handles one relay's departure notice.
///
/// First sight of a `(tenant, session, slot)` resolves its correlation ids and
/// the tenant's notify config and spawns a webhook dispatch. A duplicate
/// (another relay reporting the same leave), a tenant with no notify config, or
/// a departure with no gameId ref from any source are each a debug-logged drop
/// — the notification is best-effort, so silence there is correct, not an error.
///
/// **Correlation ids: notice-carried first, the stored session as fallback.**
/// The relay stamps `external_id`/`external_ref` into the notice itself (from
/// the coordinator descriptor it applied), so those survive a coordinator
/// restart that wipes the in-memory session-refs store — this is the case the
/// fallback exists to fix: a restarted coordinator with an empty session store
/// still delivers a correct webhook as long as the notice carries its own refs.
/// Each field falls back independently to the stored session (for a notice
/// from a relay that predates the fields, or one whose descriptor never carried
/// them) rather than requiring the whole pair from one source. Unlike the
/// previous behavior, an unresolved *session* is no longer a hard drop on its
/// own — only the absence of a `gameId` (`external_id`) from *both* sources is,
/// since a webhook naming no game is useless to the consumer regardless of
/// whether a player ref is available.
///
/// The dedup entry is claimed before the later lookups, so those terminal
/// drops are not re-processed by a later duplicate either.
pub fn handle_departure(
    setup: &SessionSetup,
    dedup: &DepartureDedup,
    lifecycle: &Lifecycle,
    notice: DepartureNotice,
) {
    let is_new = dedup
        .lock()
        .insert((notice.tenant.clone(), notice.session, notice.slot));

    let (config, external_id, stored) = match resolve_notice_prefix(
        setup,
        &notice.tenant,
        notice.session,
        notice.external_id.clone(),
        is_new,
    ) {
        NoticePrefix::Duplicate => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                slot = notice.slot.0,
                "duplicate departure notice; already handled",
            );
            return;
        }
        NoticePrefix::NoNotifyConfig => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                slot = notice.slot.0,
                "no notify config for tenant; dropping departure",
            );
            return;
        }
        NoticePrefix::NoExternalId => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                slot = notice.slot.0,
                "no gameId ref from the notice or a stored session; dropping departure",
            );
            return;
        }
        NoticePrefix::Resolved {
            config,
            external_id,
            stored,
        } => (config, external_id, stored),
    };

    let external_ref = notice.external_ref.clone().or_else(|| {
        (*stored)
            .as_ref()
            .and_then(|refs| refs.slots.get(&notice.slot).cloned())
    });

    let payload = DepartureWebhook {
        event: "departure",
        tenant: notice.tenant.as_ref().to_owned(),
        session: notice.session.0,
        external_id: Some(external_id),
        slot: notice.slot.0,
        external_ref,
        kind: notice.kind,
        reason: notice.reason,
        leave_seq: notice.leave_seq,
        result: notice.result.map(ResultEchoWebhook::from),
    };

    enqueue_dispatch(
        lifecycle,
        notice.tenant,
        notice.session,
        config,
        &payload,
        "departure",
    );
}

/// Handles one relay's desync notice.
///
/// A sibling of [`handle_departure`]: first sight of a
/// `(tenant, session, sync_ordinal)` resolves the session's `external_id` and the
/// tenant's notify config, then spawns a signed webhook. A duplicate (an
/// at-least-once redelivery of the same event), a tenant with no notify config,
/// or a desync with no `gameId` ref from any source are each a debug-logged drop.
///
/// Correlation ids come notice-first, stored-session as fallback — the same rule
/// as departures, so a coordinator restart that wiped the session store still
/// delivers a correct webhook from the notice's self-stamped refs. Each diverged
/// slot's `externalRef` resolves independently (notice ref, else the stored
/// per-slot ref), so a partially-ref'd notice still names whom it can.
///
/// A desynced-session mark is recorded first of all, before the dedup and
/// notify-config/gameId gates that can drop the webhook: the flight-recorder sink
/// pins a session's recordings on the desync FACT, which holds regardless of whether
/// a webhook is ever delivered for it.
pub fn handle_desync(
    setup: &SessionSetup,
    dedup: &DesyncDedup,
    marks: &DesyncMarks,
    lifecycle: &Lifecycle,
    notice: DesyncNotice,
) {
    mark_session_desynced(marks, notice.tenant.clone(), notice.session, Instant::now());

    let is_new = dedup
        .lock()
        .insert((notice.tenant.clone(), notice.session, notice.sync_ordinal));
    if is_new {
        // Counted behind the dedup so an at-least-once redelivery of the same
        // event (a relay resending an unacked notice across a reconnect) can't
        // inflate the desync count.
        crate::metrics::desync(&notice.tenant);
        // Every dedup entry inserted above must correspond to a lifecycle
        // state that will eventually retire it -- otherwise a notice this
        // coordinator can never resolve (dropped below as `NoNotifyConfig`
        // or `NoExternalId`, which never reaches `enqueue_dispatch`, the
        // path that would normally supply that state) leaks the entry for
        // the life of the process. See `Lifecycle::ensure_orphan_tracked`.
        lifecycle.ensure_orphan_tracked(notice.tenant.clone(), notice.session);
    }

    let (config, external_id, stored) = match resolve_notice_prefix(
        setup,
        &notice.tenant,
        notice.session,
        notice.external_id.clone(),
        is_new,
    ) {
        NoticePrefix::Duplicate => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                sync_ordinal = notice.sync_ordinal,
                "duplicate desync notice; already handled",
            );
            return;
        }
        NoticePrefix::NoNotifyConfig => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                sync_ordinal = notice.sync_ordinal,
                "no notify config for tenant; dropping desync",
            );
            return;
        }
        NoticePrefix::NoExternalId => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                sync_ordinal = notice.sync_ordinal,
                "no gameId ref from the notice or a stored session; dropping desync",
            );
            return;
        }
        NoticePrefix::Resolved {
            config,
            external_id,
            stored,
        } => (config, external_id, stored),
    };

    let diverged = notice
        .diverged
        .iter()
        .map(|d| DivergedSlotWebhook {
            slot: d.slot.0,
            external_ref: d.external_ref.clone().or_else(|| {
                (*stored)
                    .as_ref()
                    .and_then(|refs| refs.slots.get(&d.slot).cloned())
            }),
        })
        .collect();

    let payload = DesyncWebhook {
        event: "desync",
        tenant: notice.tenant.as_ref().to_owned(),
        session: notice.session.0,
        external_id: Some(external_id),
        sync_ordinal: notice.sync_ordinal,
        game_frame: notice.game_frame,
        detected_at_ms: notice.detected_at_ms,
        no_majority: notice.no_majority,
        diverged,
    };

    enqueue_dispatch(
        lifecycle,
        notice.tenant,
        notice.session,
        config,
        &payload,
        "desync",
    );
}

/// Handles one relay's result notice.
///
/// A sibling of [`handle_departure`]: first sight of a `(tenant, session, slot)`
/// resolves the reporting slot's correlation ids and the tenant's notify config,
/// base64-encodes the opaque payload, then spawns a signed webhook. A duplicate
/// (an at-least-once redelivery, or a second relay that somehow saw the report),
/// a tenant with no notify config, or a result with no `gameId` ref from any
/// source are each a debug-logged drop — the notification is best-effort.
///
/// Correlation ids come notice-first, stored-session as fallback — the same rule
/// as departures, so a coordinator restart that wiped the session store still
/// delivers a correct webhook from the notice's self-stamped refs. The payload
/// bytes are never parsed here; they are relayed straight through as base64.
pub fn handle_result(
    setup: &SessionSetup,
    dedup: &ResultDedup,
    lifecycle: &Lifecycle,
    notice: ResultNotice,
) {
    let is_new = dedup
        .lock()
        .insert((notice.tenant.clone(), notice.session, notice.slot));

    let (config, external_id, stored) = match resolve_notice_prefix(
        setup,
        &notice.tenant,
        notice.session,
        notice.external_id.clone(),
        is_new,
    ) {
        NoticePrefix::Duplicate => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                slot = notice.slot.0,
                "duplicate result notice; already handled",
            );
            return;
        }
        NoticePrefix::NoNotifyConfig => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                slot = notice.slot.0,
                "no notify config for tenant; dropping result",
            );
            return;
        }
        NoticePrefix::NoExternalId => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                slot = notice.slot.0,
                "no gameId ref from the notice or a stored session; dropping result",
            );
            return;
        }
        NoticePrefix::Resolved {
            config,
            external_id,
            stored,
        } => (config, external_id, stored),
    };

    let external_ref = notice.external_ref.clone().or_else(|| {
        (*stored)
            .as_ref()
            .and_then(|refs| refs.slots.get(&notice.slot).cloned())
    });

    let payload = ResultWebhook {
        event: "result",
        tenant: notice.tenant.as_ref().to_owned(),
        session: notice.session.0,
        external_id: Some(external_id),
        slot: notice.slot.0,
        external_ref,
        payload: BASE64_STANDARD.encode(&notice.payload),
        arrival_ms: notice.arrival_ms,
        session_frame: notice.session_frame,
        slot_frame: notice.slot_frame,
    };

    enqueue_dispatch(
        lifecycle,
        notice.tenant,
        notice.session,
        config,
        &payload,
        "result",
    );
}

/// Handles one relay's slot-connected notice.
///
/// A sibling of [`handle_departure`]: first sight of a `(tenant, session, slot)`
/// resolves the arriving slot's correlation ids and the tenant's notify config,
/// then spawns a signed webhook. Later activations of the same slot (reconnects,
/// re-home re-dials) are duplicates here and fire nothing — the lifecycle
/// accounting the api layer feeds first still records them, so the load-state
/// pull stays current either way.
///
/// Correlation ids come notice-first, stored-session as fallback — the same rule
/// as departures.
pub fn handle_slot_connected(
    setup: &SessionSetup,
    dedup: &SlotConnectedDedup,
    lifecycle: &Lifecycle,
    notice: SlotConnectedNotice,
) {
    let is_new = dedup
        .lock()
        .insert((notice.tenant.clone(), notice.session, notice.slot));

    let (config, external_id, stored) = match resolve_notice_prefix(
        setup,
        &notice.tenant,
        notice.session,
        notice.external_id.clone(),
        is_new,
    ) {
        NoticePrefix::Duplicate => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                slot = notice.slot.0,
                "duplicate slot-connected notice; already handled",
            );
            return;
        }
        NoticePrefix::NoNotifyConfig => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                slot = notice.slot.0,
                "no notify config for tenant; dropping slot-connected",
            );
            return;
        }
        NoticePrefix::NoExternalId => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                slot = notice.slot.0,
                "no gameId ref from the notice or a stored session; dropping slot-connected",
            );
            return;
        }
        NoticePrefix::Resolved {
            config,
            external_id,
            stored,
        } => (config, external_id, stored),
    };

    let external_ref = notice.external_ref.clone().or_else(|| {
        (*stored)
            .as_ref()
            .and_then(|refs| refs.slots.get(&notice.slot).cloned())
    });

    let payload = SlotConnectedWebhook {
        event: "slotConnected",
        tenant: notice.tenant.as_ref().to_owned(),
        session: notice.session.0,
        external_id: Some(external_id),
        slot: notice.slot.0,
        external_ref,
        resumed: notice.resumed,
        connected_at_ms: notice.connected_at_ms,
    };

    enqueue_dispatch(
        lifecycle,
        notice.tenant,
        notice.session,
        config,
        &payload,
        "slotConnected",
    );
}

/// Handles the authority relay's session-started notice.
///
/// A sibling of [`handle_departure`] keyed on `(tenant, session)` alone — a
/// session starts once. Only the authority reports the latch, so a duplicate here
/// is an at-least-once redelivery or a second authority's report after a
/// promotion, both of which describe the same start.
///
/// The `external_id` comes notice-first, stored-session as fallback — the same
/// rule as departures.
pub fn handle_session_started(
    setup: &SessionSetup,
    dedup: &SessionStartedDedup,
    lifecycle: &Lifecycle,
    notice: SessionStartedNotice,
) {
    let is_new = dedup.lock().insert((notice.tenant.clone(), notice.session));

    let (config, external_id) = match resolve_notice_prefix(
        setup,
        &notice.tenant,
        notice.session,
        notice.external_id.clone(),
        is_new,
    ) {
        NoticePrefix::Duplicate => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                "duplicate session-started notice; already handled",
            );
            return;
        }
        NoticePrefix::NoNotifyConfig => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                "no notify config for tenant; dropping session-started",
            );
            return;
        }
        NoticePrefix::NoExternalId => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                "no gameId ref from the notice or a stored session; dropping session-started",
            );
            return;
        }
        NoticePrefix::Resolved {
            config,
            external_id,
            ..
        } => (config, external_id),
    };

    let payload = SessionStartedWebhook {
        event: "sessionStarted",
        tenant: notice.tenant.as_ref().to_owned(),
        session: notice.session.0,
        external_id: Some(external_id),
        started_at_ms: notice.started_at_ms,
        initial_buffer_turns: notice.initial_buffer_turns,
    };

    enqueue_dispatch(
        lifecycle,
        notice.tenant,
        notice.session,
        config,
        &payload,
        "sessionStarted",
    );
}

/// Handles one relay's slot-started notice — a client's report that its game loop
/// is running.
///
/// A sibling of [`handle_result`] with the same `(tenant, session, slot)` dedup
/// key (a slot reports one game-loop start), the same notice-first correlation-id
/// resolution, and the same best-effort drops.
pub fn handle_slot_started(
    setup: &SessionSetup,
    dedup: &SlotStartedDedup,
    lifecycle: &Lifecycle,
    notice: SlotStartedNotice,
) {
    let is_new = dedup
        .lock()
        .insert((notice.tenant.clone(), notice.session, notice.slot));

    let (config, external_id, stored) = match resolve_notice_prefix(
        setup,
        &notice.tenant,
        notice.session,
        notice.external_id.clone(),
        is_new,
    ) {
        NoticePrefix::Duplicate => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                slot = notice.slot.0,
                "duplicate slot-started notice; already handled",
            );
            return;
        }
        NoticePrefix::NoNotifyConfig => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                slot = notice.slot.0,
                "no notify config for tenant; dropping slot-started",
            );
            return;
        }
        NoticePrefix::NoExternalId => {
            tracing::debug!(
                tenant = notice.tenant.as_ref(),
                session = notice.session.0,
                slot = notice.slot.0,
                "no gameId ref from the notice or a stored session; dropping slot-started",
            );
            return;
        }
        NoticePrefix::Resolved {
            config,
            external_id,
            stored,
        } => (config, external_id, stored),
    };

    let external_ref = notice.external_ref.clone().or_else(|| {
        (*stored)
            .as_ref()
            .and_then(|refs| refs.slots.get(&notice.slot).cloned())
    });

    let payload = SlotStartedWebhook {
        event: "slotStarted",
        tenant: notice.tenant.as_ref().to_owned(),
        session: notice.session.0,
        external_id: Some(external_id),
        slot: notice.slot.0,
        external_ref,
        arrival_ms: notice.arrival_ms,
        session_frame: notice.session_frame,
        slot_frame: notice.slot_frame,
    };

    enqueue_dispatch(
        lifecycle,
        notice.tenant,
        notice.session,
        config,
        &payload,
        "slotStarted",
    );
}

/// Serializes `payload` and enqueues its webhook onto the session's ordered
/// dispatch queue ([`Lifecycle`]), so every notice for one `(tenant, session)` is
/// delivered in the order it was enqueued — a notice's retry loop blocks the ones
/// behind it. This is what lets a delivered `sessionClosed` guarantee no earlier
/// notice for the session is still in flight. `kind` labels the delivery in logs.
fn enqueue_dispatch(
    lifecycle: &Lifecycle,
    tenant: TenantId,
    session: SessionId,
    config: NotifyConfig,
    payload: &impl Serialize,
    kind: &'static str,
) {
    let body = match serde_json::to_vec(payload) {
        Ok(bytes) => Bytes::from(bytes),
        Err(error) => {
            tracing::error!(%error, kind, "serializing a webhook body failed; dropping");
            return;
        }
    };
    lifecycle.enqueue_webhook(tenant, session, config, body, kind);
}
