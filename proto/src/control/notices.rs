//! Relay-authored notices: what a relay reports up its control connection
//! about one session's player-visible events (departures, desyncs, results,
//! connects, and start/load progress).
//!
//! Every notice here carries its own `tenant`/`session` (and usually `slot`)
//! because one control connection serves many sessions, and stamps its own
//! tenant-facing correlation ids from the relay's stored `SessionDescriptor`
//! so a notice is self-describing across a coordinator restart.

use serde::{Deserialize, Serialize};

use crate::ids::{SessionId, SlotId};

use super::TenantId;

/// Whether a departing player left cleanly or was dropped, classified by the
/// relay from the synced leave's native reason. Rides the departure webhook as
/// `"left"` / `"dropped"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepartureKind {
    /// A clean departure — the player quit (native `strPLAYER_LEFT`).
    Left,
    /// An unclean drop — the player's link died (native `strPLAYER_WAS_DROPPED`).
    Dropped,
}

/// The end-of-game result a departing slot reported before it left, echoed into
/// a [`DepartureNotice`] so a departure webhook is atomic terminal truth: the
/// player left/dropped, and here is the result — or there provably never was one
/// (`None`). The relay's home for the departing slot authors it from the result
/// it retained; the standalone [`ResultNotice`] still fires early at dialog time,
/// so this embedded copy is a redundant delivery, not the only one.
///
/// The stamps mirror [`ResultNotice`]'s: `arrival_ms` is relay wall-clock at
/// receipt, `session_frame` the session's consensus coordinate then, `slot_frame`
/// the reporting slot's own newest frame. `payload` is the tenant's opaque bytes,
/// forwarded byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultEcho {
    /// The tenant's opaque serialized result, forwarded byte-for-byte.
    pub payload: Vec<u8>,
    /// Relay wall-clock at receipt, unix epoch milliseconds.
    pub arrival_ms: u64,
    /// The session's consensus frame when the report arrived. `None` before any
    /// slot produced a framed turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_frame: Option<u32>,
    /// The reporting slot's own newest observed frame when the report arrived.
    /// `None` before that slot produced a framed turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_frame: Option<u32>,
}

/// A relay's report that a player permanently departed a running game, sent up
/// the relay control connection ([`super::RelayToCoordinator::Departure`]).
///
/// It carries its own `tenant`/`session`/`slot` because one relay control
/// connection serves many sessions, so the frame must name which one. `kind` is
/// the relay's left-vs-dropped classification; `reason` is the raw native leave
/// reason it was classified from (kept for debugging); `leave_seq` is the
/// deciding relay's own ordering number for the leave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepartureNotice {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session the player departed from.
    pub session: SessionId,
    /// The slot that departed.
    pub slot: SlotId,
    /// The left-vs-dropped classification the relay derived from `reason`.
    pub kind: DepartureKind,
    /// The raw native `pending_leave_reason` value the relay decided
    /// (`0x40000006` dropped, else left), carried alongside `kind` for
    /// debugging.
    pub reason: u32,
    /// The deciding relay's ordering number for this leave. Not a dedup key on
    /// its own (the coordinator dedups by slot); useful telemetry.
    pub leave_seq: u32,
    /// The tenant's own id for the session, stamped by the relay from its
    /// stored [`super::SessionDescriptor`] if it has one. `None` when the relay never
    /// received the correlation ids — a standalone relay, a descriptor from a
    /// coordinator that predates them, or a departure decided before any
    /// descriptor carrying them arrived. The coordinator falls back to its own
    /// stored session refs when this is absent (which a coordinator restart may
    /// have forgotten — the descriptor-carried copy is what survives that).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The tenant's own id for the departed player's slot. Same source and
    /// fallback as `external_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    /// The result this slot reported before departing, if any — embedded so the
    /// departure webhook carries terminal truth in one delivery. `None` when the
    /// slot departed without ever reporting; a result can never arrive after the
    /// departure (reports ride only the live link, which the departure closes),
    /// so an embedded result is final. The standalone [`ResultNotice`] still
    /// fires separately, so this is a redundant copy. Optional so a relay that
    /// predates the field still interops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultEcho>,
    /// The exact number of the slot's turns clients consume before applying its
    /// leave, copied from the decided directive (the wire's
    /// `LeaveDirective.final_turn_count`). Retained by the coordinator so a
    /// rehome-rebuilt descriptor's [`super::DepartedSlot`] can hand a fresh relay the
    /// same count the original directive carried — a survivor that never
    /// received that directive must still apply the leave at the same
    /// simulation step as the survivors that did. `None` when the directive
    /// carried no count (the home relay had no delivery knowledge, or the
    /// deciding relay predates counted leaves).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_turn_count: Option<u64>,
    /// Whether `final_turn_count` on a dropped departure was derived through
    /// home-side finalization (the wire's `LeaveDirective.finalized`) — the
    /// proof that lets the coordinator retain a dropped count for rehome
    /// seeding instead of stripping it as legacy-unsound. Defaults `false`
    /// for a relay that predates the field.
    #[serde(default)]
    pub finalized: bool,
}

/// One slot the relay's desync comparator found on the losing side of a checksum
/// mismatch — a diverged member of the minority. Mirrors [`super::SlotExternalRef`]'s
/// shape (a slot plus its optional tenant ref) rather than a bare slot, so the
/// desync webhook can name the diverged player in the tenant's own terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergedSlot {
    /// The slot whose checksum diverged from the agreeing majority.
    pub slot: SlotId,
    /// The tenant's own id for the player in this slot, stamped by the relay from
    /// its stored [`super::SessionDescriptor`]. Same source and fallback as
    /// [`DepartureNotice::external_ref`]; `None` when the relay never received the
    /// correlation ids for the slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
}

/// A relay's report that a game desynced — two live slots' per-turn sync
/// checksums disagreed at the same sync ordinal, so their simulations diverged.
/// Sent up the relay control connection ([`super::RelayToCoordinator::Desync`]).
///
/// Like [`DepartureNotice`], it carries its own `tenant`/`session` because one
/// control connection serves many sessions, and stamps its own correlation ids
/// from the relay's stored [`super::SessionDescriptor`] so the notification is
/// self-describing across a coordinator restart.
///
/// The event is identified by `sync_ordinal` (the count of sync commands the
/// diverging slots had each emitted), not a relay-assigned sequence number:
/// authority promotion restarts the comparator from scratch, and keying the
/// event on the ordinal means a re-detection after a promotion lands at a
/// distinct, later ordinal rather than colliding with an earlier report. The
/// coordinator dedups on `(tenant, session, sync_ordinal)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesyncNotice {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session that desynced.
    pub session: SessionId,
    /// The per-slot sync ordinal at which the mismatch was observed — the number
    /// of sync commands each diverging slot had emitted. The event identity; the
    /// coordinator's dedup key alongside tenant + session.
    pub sync_ordinal: u64,
    /// The `game_frame_count` of the turn whose sync command confirmed the
    /// mismatch — a human-meaningful interval to correlate against replays and
    /// results. `None` when that turn carried no frame (it shouldn't in practice —
    /// sync commands flow only in-game — but the field is honest about it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub game_frame: Option<u32>,
    /// Relay wall-clock at detection, unix epoch milliseconds. Records when the
    /// relay observed the divergence, independent of when the webhook is delivered
    /// (which retries may delay).
    pub detected_at_ms: u64,
    /// Set when no strict majority of compared slots shared one checksum value (a
    /// 1v1 disagreement, or an even split), so which side is authoritative cannot
    /// be determined from the relay's view alone. `diverged` is then empty — the
    /// tenant must not infer the minority from topology. When `false`, `diverged`
    /// names exactly the minority slots.
    pub no_majority: bool,
    /// The slots that diverged from the agreeing majority (the minority). Empty
    /// when `no_majority` is set.
    pub diverged: Vec<DivergedSlot>,
    /// The tenant's own id for the session, stamped by the relay from its stored
    /// [`super::SessionDescriptor`]. Same source and fallback as
    /// [`DepartureNotice::external_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

/// A relay's forward of a client's end-of-game result report, sent up the relay
/// control connection ([`super::RelayToCoordinator::Result`]).
///
/// Like [`DepartureNotice`], it carries its own `tenant`/`session`/`slot` because
/// one control connection serves many sessions. `payload` is the tenant's opaque
/// serialized result, forwarded byte-for-byte — the relay never parses it, the
/// same boundary that keeps `external_ref` an opaque correlation string. `slot`
/// is the authenticated connection's slot the report arrived on, never a value
/// from the bytes. It stamps its own correlation ids from the relay's stored
/// [`super::SessionDescriptor`] so the notice is self-describing across a coordinator
/// restart, exactly as the departure and desync notices do.
///
/// The frame stamps are the relay's own view of *when* the report landed in the
/// game's timeline: `arrival_ms` is relay wall-clock at receipt, `session_frame`
/// the session's consensus coordinate (the slowest slot's progress) then, and
/// `slot_frame` the reporting slot's own newest observed frame. Each is `None`
/// when the relay had no such value yet (a report before any framed turn).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultNotice {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session the result is for.
    pub session: SessionId,
    /// The slot that reported — the authenticated connection's slot, never a
    /// value carried in the payload.
    pub slot: SlotId,
    /// The tenant's own id for the session, stamped by the relay from its stored
    /// [`super::SessionDescriptor`]. Same source and fallback as
    /// [`DepartureNotice::external_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The tenant's own id for the reporting slot's player. Same source and
    /// fallback as `external_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    /// The tenant's opaque serialized result, forwarded byte-for-byte.
    pub payload: Vec<u8>,
    /// Relay wall-clock at receipt, unix epoch milliseconds. Records when the
    /// relay observed the report, independent of when the webhook is delivered.
    pub arrival_ms: u64,
    /// The session's consensus coordinate (the slowest slot's observed frame)
    /// when the report arrived. `None` before any slot produced a framed turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_frame: Option<u32>,
    /// The reporting slot's own newest observed frame when the report arrived.
    /// `None` before that slot produced a framed turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_frame: Option<u32>,
}

/// A relay's report that a slot's link became active — the client connected (or
/// reconnected) and its slot link is serving — sent up the relay control
/// connection ([`super::RelayToCoordinator::SlotConnected`]).
///
/// Only the relay that homes the slot sends it, at the moment the slot link
/// activates, and it fires on *every* activation, reconnects included:
/// `resumed` distinguishes a re-dial that presented resume cursors from a fresh
/// first connect. The coordinator keeps the ever-connected set and fires the
/// webhook only on first sight per slot, so the repeats cost nothing beyond the
/// frame.
///
/// Like [`DepartureNotice`] it carries its own `tenant`/`session`/`slot` because
/// one control connection serves many sessions, and it stamps its own
/// correlation ids from the relay's stored [`super::SessionDescriptor`] so the notice is
/// self-describing across a coordinator restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotConnectedNotice {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session the slot connected to.
    pub session: SessionId,
    /// The slot whose link activated — the authenticated connection's slot.
    pub slot: SlotId,
    /// The tenant's own id for the session, stamped by the relay from its stored
    /// [`super::SessionDescriptor`]. Same source and fallback as
    /// [`DepartureNotice::external_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The tenant's own id for the connecting slot's player. Same source and
    /// fallback as `external_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    /// Whether the dial presented resume cursors — a reconnect or a re-home
    /// re-dial — rather than being this slot's first connect to this relay.
    pub resumed: bool,
    /// Relay wall-clock at activation, unix epoch milliseconds. Records when the
    /// relay observed the link come up, independent of when the webhook is
    /// delivered.
    pub connected_at_ms: u64,
}

/// A relay's report that a session started — every slot the descriptor listed as
/// expected is present somewhere in the session's mesh, so the game may begin —
/// sent up the relay control connection ([`super::RelayToCoordinator::SessionStarted`]).
///
/// Exactly one relay reports it: the session's authority, whose coverage latch
/// fires the `SessionStart` directive. A peer relay that merely adopts the
/// directive off the mesh reports nothing, so unlike a departure there is no
/// per-relay redundancy here — the coordinator still dedups by
/// `(tenant, session)` because at-least-once delivery can re-send one.
///
/// `initial_buffer_turns` is the latency-buffer depth the authority sized at the
/// latch and stamped onto the directive, or `None` when it sized none (nothing
/// observed and no hint supplied).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStartedNotice {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session that started.
    pub session: SessionId,
    /// The tenant's own id for the session, stamped by the relay from its stored
    /// [`super::SessionDescriptor`]. Same source and fallback as
    /// [`DepartureNotice::external_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Relay wall-clock at the coverage latch, unix epoch milliseconds.
    pub started_at_ms: u64,
    /// The initial latency-buffer depth the authority sized and stamped onto the
    /// start directive. `None` when it sized none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_buffer_turns: Option<u32>,
}

/// A relay's forward of a client's report that its game loop has started, sent up
/// the relay control connection ([`super::RelayToCoordinator::SlotStarted`]).
///
/// The client's own statement that it finished loading and is stepping the
/// simulation, so the tenant can attribute a stalled load to the slots that never
/// reported instead of guessing from a deadline. `slot` is the authenticated
/// connection's slot the frame arrived on, never a client-asserted value. Only
/// the reporting slot's home relay sends it (the fact never crosses the mesh),
/// and the relay accepts one per slot per link lifetime; the coordinator dedups
/// again by `(tenant, session, slot)`.
///
/// The stamps are the relay's own view of *when* the report landed in the game's
/// timeline, mirroring [`ResultNotice`]'s: `arrival_ms` is relay wall-clock at
/// receipt, `session_frame` the session's consensus coordinate then, and
/// `slot_frame` the reporting slot's own newest observed frame. Both frames are
/// normally absent here — a game announcing its loop has begun has usually not
/// produced a framed turn yet — which is exactly why they are optional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotStartedNotice {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session the report is for.
    pub session: SessionId,
    /// The slot that reported — the authenticated connection's slot.
    pub slot: SlotId,
    /// The tenant's own id for the session, stamped by the relay from its stored
    /// [`super::SessionDescriptor`]. Same source and fallback as
    /// [`DepartureNotice::external_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The tenant's own id for the reporting slot's player. Same source and
    /// fallback as `external_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    /// Relay wall-clock at receipt, unix epoch milliseconds.
    pub arrival_ms: u64,
    /// The session's consensus coordinate (the slowest slot's observed frame)
    /// when the report arrived. `None` before any slot produced a framed turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_frame: Option<u32>,
    /// The reporting slot's own newest observed frame when the report arrived.
    /// `None` before that slot produced a framed turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_frame: Option<u32>,
}
