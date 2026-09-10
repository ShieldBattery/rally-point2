//! The webhook JSON bodies: one `*Webhook` struct per notice kind, all
//! camelCase to match the tenant-facing convention, plus the `sessionClosed`
//! dispatch builder (the one webhook the [`crate::lifecycle::Lifecycle`]
//! builds itself rather than a `handlers` function). Grouped separately from
//! `handlers` because these are pure data shapes with no dedup/resolution
//! logic of their own.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::Bytes;
use rally_point_proto::control::{DepartureKind, TenantId};
use rally_point_proto::ids::SessionId;
use serde::Serialize;

use crate::session::{self, SessionSetup};
use crate::tenant::{self, NotifyConfig};

/// The JSON body POSTed to the tenant for a departure. camelCase, matching the
/// *consumer's* API conventions rather than the relay control plane's snake_case
/// — the webhook lands on the tenant's own HTTP surface, so its style wins.
/// `kind` serializes `"left"` / `"dropped"`. The `event` discriminator lets the
/// consumer's one webhook endpoint fan the body out by kind (a desync body
/// carries `"event":"desync"`). The correlation ids are **omitted** (not sent as
/// `null`) when the session carried none: the consumer validates them as optional
/// strings, and a literal JSON `null` fails that validation rather than reading
/// as "absent".
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DepartureWebhook {
    pub(super) event: &'static str,
    pub(super) tenant: String,
    pub(super) session: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) external_id: Option<String>,
    pub(super) slot: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) external_ref: Option<String>,
    pub(super) kind: DepartureKind,
    pub(super) reason: u32,
    pub(super) leave_seq: u32,
    /// The result this slot reported before departing, embedded so the departure
    /// webhook is atomic terminal truth. Omitted (not `null`) when the slot
    /// departed without ever reporting — the consumer reads its absence as "there
    /// provably never was one".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) result: Option<ResultEchoWebhook>,
}

/// The embedded result in a departure webhook body: the opaque payload as a
/// standard-base64 string (the coordinator never parses it), plus the relay's
/// arrival stamp and frame view. camelCase like the rest of the body; the frame
/// stamps are omitted when absent.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ResultEchoWebhook {
    pub(super) payload: String,
    pub(super) arrival_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) session_frame: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) slot_frame: Option<u32>,
}

impl From<rally_point_proto::control::ResultEcho> for ResultEchoWebhook {
    fn from(echo: rally_point_proto::control::ResultEcho) -> Self {
        ResultEchoWebhook {
            payload: BASE64_STANDARD.encode(&echo.payload),
            arrival_ms: echo.arrival_ms,
            session_frame: echo.session_frame,
            slot_frame: echo.slot_frame,
        }
    }
}

/// One diverged slot in a desync webhook body: the slot plus its optional tenant
/// ref, camelCase like the rest of the body. The `externalRef` is omitted when
/// absent, never `null`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DivergedSlotWebhook {
    pub(super) slot: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) external_ref: Option<String>,
}

/// The JSON body POSTed to the tenant for a desync. Same camelCase convention and
/// same `event` discriminator as the departure body. Optional fields
/// (`externalId`, `gameFrame`) are omitted when absent, never `null`. `diverged`
/// is always present (possibly empty, when `noMajority`).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DesyncWebhook {
    pub(super) event: &'static str,
    pub(super) tenant: String,
    pub(super) session: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) external_id: Option<String>,
    pub(super) sync_ordinal: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) game_frame: Option<u32>,
    pub(super) detected_at_ms: u64,
    pub(super) no_majority: bool,
    pub(super) diverged: Vec<DivergedSlotWebhook>,
}

/// The JSON body POSTed to the tenant for a result report. Same camelCase
/// convention and `event` discriminator as the other bodies. `payload` is the
/// tenant's opaque result bytes as a standard-base64 string (the relay and
/// coordinator never parse them). Optional fields (`externalId`, `externalRef`,
/// `sessionFrame`, `slotFrame`) are omitted when absent, never `null`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ResultWebhook {
    pub(super) event: &'static str,
    pub(super) tenant: String,
    pub(super) session: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) external_id: Option<String>,
    pub(super) slot: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) external_ref: Option<String>,
    pub(super) payload: String,
    pub(super) arrival_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) session_frame: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) slot_frame: Option<u32>,
}

/// The JSON body POSTed to the tenant when a slot's client first arrives on a
/// relay. Same camelCase convention and `event` discriminator as the other
/// bodies. `resumed` reports whether *that* arrival was a re-dial rather than a
/// first connect; since the webhook fires only on first sight per slot it is
/// normally `false`, and `true` means the coordinator's first sight of the slot
/// was itself a reconnect (a relay's coordinator link having been down over the
/// original arrival). Optional fields are omitted when absent, never `null`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SlotConnectedWebhook {
    pub(super) event: &'static str,
    pub(super) tenant: String,
    pub(super) session: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) external_id: Option<String>,
    pub(super) slot: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) external_ref: Option<String>,
    pub(super) resumed: bool,
    pub(super) connected_at_ms: u64,
}

/// The JSON body POSTed to the tenant when a session starts — the authority
/// relay observed every expected slot present. Same camelCase convention and
/// `event` discriminator as the other bodies. `initialBufferTurns` is omitted
/// when the authority sized no depth.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SessionStartedWebhook {
    pub(super) event: &'static str,
    pub(super) tenant: String,
    pub(super) session: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) external_id: Option<String>,
    pub(super) started_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) initial_buffer_turns: Option<u32>,
}

/// The JSON body POSTed to the tenant when a slot reports its game loop running.
/// Same camelCase convention and `event` discriminator as the other bodies. The
/// frame stamps are normally absent (a game announcing its loop has usually not
/// produced a framed turn yet) and are omitted rather than sent as `null`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SlotStartedWebhook {
    pub(super) event: &'static str,
    pub(super) tenant: String,
    pub(super) session: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) external_id: Option<String>,
    pub(super) slot: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) external_ref: Option<String>,
    pub(super) arrival_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) session_frame: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) slot_frame: Option<u32>,
}

/// The JSON body POSTed to the tenant when a session fully closes — every serving
/// relay tore down its state for it. Same camelCase convention and `event`
/// discriminator as the other bodies. `externalId` (the tenant's gameId) is
/// omitted when the session carried none — unlike the per-player webhooks, a
/// sessionClosed with no gameId is still useful (it names the rp2 session id the
/// tenant persisted), so it is delivered regardless.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionClosedWebhook {
    event: &'static str,
    tenant: String,
    session: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
}

/// Builds the `sessionClosed` webhook dispatch for a fully-closed session: the
/// tenant's notify config plus the serialized body (with the stored `externalId`
/// if any). `None` when the tenant has no notify config — nothing to POST to. The
/// [`crate::lifecycle::Lifecycle`] calls this once, when the last serving relay
/// reports closed, and enqueues the returned job onto the session's ordered queue
/// behind every prior notice.
pub(crate) fn session_closed_dispatch(
    setup: &SessionSetup,
    tenant: &TenantId,
    session: SessionId,
) -> Option<(NotifyConfig, Bytes)> {
    let config = tenant::notify_config(setup.tenants(), tenant)?;
    let external_id =
        session::session_refs(setup, tenant, session).and_then(|refs| refs.external_id);
    let payload = SessionClosedWebhook {
        event: "sessionClosed",
        tenant: tenant.as_ref().to_owned(),
        session: session.0,
        external_id,
    };
    let body = match serde_json::to_vec(&payload) {
        Ok(bytes) => Bytes::from(bytes),
        Err(error) => {
            tracing::error!(%error, "serializing a sessionClosed body failed; dropping");
            return None;
        }
    };
    Some((config, body))
}
