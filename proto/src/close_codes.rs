//! QUIC application close codes for the client↔relay connection.
//!
//! A close code is the only thing that survives a connection's death, so these
//! are the diagnosis a client (or a log reader) gets for why its link ended.
//! Each cause has its own number precisely so the causes stay distinguishable:
//! never collapse two of them onto one code, and never reuse a retired number
//! for a new meaning — an old build in the field would read it as the old
//! cause.
//!
//! The two directions have independent code spaces. Everything named here
//! without a prefix is sent **by the relay to a client**; the `CLIENT_` codes
//! are sent the other way, by a client abandoning its own dial. A number may
//! therefore appear in both groups and mean two unrelated things.
//!
//! Only one of these gets special client-side handling: [`SLOT_DEPARTED`] is
//! terminal for a reconnecting client (no later dial can bring the slot back),
//! so it must stop retrying. Every other relay close is treated as an ordinary
//! transport failure and retried.

/// The client sent a turn that failed validation. Closing the link routes the
/// offender through the ordinary departure machinery, so survivors get a synced
/// leave and play on.
pub const INVALID_TURN: u32 = 0x01;

/// The dial's authorized slot is already connected by another live connection —
/// a genuine double-connect. Contrast [`SLOT_DEPARTED`], where the slot is gone
/// rather than occupied.
pub const SLOT_TAKEN: u32 = 0x02;

/// The connection's authorization handshake did not finish in time. Bounds a
/// client that connects and then stalls, so unauthenticated connections cannot
/// pin a relay task open.
pub const AUTH_TIMEOUT: u32 = 0x03;

/// The link fell hopelessly behind — its forward queue hit the payload-count or
/// resident-byte bound, or its unacked window crossed the relay's cap — so the
/// relay isolates it rather than let it back-pressure healthy peers.
pub const ISOLATED: u32 = 0x04;

/// The relay processed the client's leave-intent and closed the link itself.
/// Not an error: the announcement is never acked on its own terms, so this
/// close *is* the confirmation the departing client waits for.
pub const LEAVE_PROCESSED: u32 = 0x05;

/// A re-dial refused because the slot's leave was already decided — a
/// survivor's drop request was honored, or it left cleanly — so the game has
/// moved on without it. The one terminal close: a client that sees it must stop
/// retrying, since no later dial can bring the slot back.
pub const SLOT_DEPARTED: u32 = 0x06;

/// The client's control-stream reader ended while the connection was otherwise
/// alive (a one-sided reset, an over-cap frame, a decode failure, or a clean
/// EOF). That stream is the only channel a drop request and a clean leave
/// arrive on, so losing it is a link failure rather than a degradation to limp
/// on through — the close pushes the client into its ordinary reconnect, which
/// reopens every stream fresh.
pub const CONTROL_STREAM_LOST: u32 = 0x07;

/// The dial's authorized slot is not one this relay homes for the session. A
/// token binds tenant/session/slot/key but not a specific relay, so this is the
/// home-relay gate: without it a misrouted or malicious client could feed this
/// relay's clients a competing view of a slot homed elsewhere.
pub const SLOT_NOT_HOMED: u32 = 0x08;

/// The dial presented a resume-cursor anchor beyond any sane value. An anchor
/// is an unvalidated client number about to become authoritative window state,
/// so an absurd one is refused outright. Distinct from [`INVALID_TURN`], which
/// means a live turn failed validation rather than a resume-time value.
pub const RESUME_ANCHOR_INVALID: u32 = 0x09;

/// The session was admitted provisionally — the client dialed before any
/// descriptor named it — and no descriptor claimed it within the provisional
/// window. Only ever a delay, never terminal: a fresh dial re-admits with its
/// own new window.
pub const PROVISIONAL_EXPIRED: u32 = 0x0A;

/// The session's descriptor was retired — the coordinator ended the session —
/// and the dial arrived while the retirement still stands. A genuine re-serve
/// is preceded by a fresh descriptor, which lifts the gate before clients dial.
pub const SESSION_RETIRED: u32 = 0x0B;

/// The relay's provisional-journal session ceiling is full, so a
/// pre-descriptor connection cannot be admitted: every turn it sent would need
/// journaling, and a turn acknowledged but retained nowhere is a permanent
/// sequence hole. Retryable — capacity frees as descriptors drain journals and
/// sessions retire, and a described session is never refused this way.
pub const PROVISIONAL_CAPACITY: u32 = 0x0C;

/// The client stopped producing turns while its session advanced past it — its
/// game thread hung, or its process was suspended — and lockstep cannot proceed
/// until the slot is out. Nothing was wrong with the link.
pub const SILENT_SLOT: u32 = 0x0D;

/// Sent **by a client** abandoning a dial because the authorization exchange
/// did not finish within its deadline. Client-space, so it shares a number with
/// the relay's [`INVALID_TURN`] and means nothing like it.
pub const CLIENT_CONNECT_TIMEOUT: u32 = 0x01;
