//! Per-session state the relay keeps alongside the turn stream.
//!
//! Everything here is scoped to one game session rather than to a link or to
//! the relay as a whole: who is present in which slot, the lobby/chat/skin side
//! channels that carry non-turn traffic between members, the gate that decides
//! which connections may join, the short-lived provisional records that let a
//! member be admitted before the coordinator has confirmed it, the drop-vote
//! bookkeeping, and the bounded ring of recently forwarded turns a reconnecting
//! client replays from.

pub mod chat;
pub mod drop_hold;
/// The test bodies `chat`, `lobby` and `skin` share — they are one registry
/// with three replay policies, so everything that is not the replay policy is
/// asserted once, generically, rather than three times.
#[cfg(test)]
pub(crate) mod fanout_tests;
pub mod gate;
pub mod lobby;
pub mod presence;
pub mod provisional;
pub mod provisional_turns;
pub mod skin;
mod state;
pub mod turn_ring;

pub use state::{SessionState, Tunables};

/// What one payload costs wherever the relay bounds the turns it is holding:
/// the length of its command stream, and nothing else. Only the commands vary
/// materially in size — the rest of a payload is a handful of fixed scalar
/// fields — so a slot's resident forward queue, the replay ring and the
/// provisional journal all measure a turn the same way and cannot drift apart
/// on what one costs. A holder that charges for the envelope as well adds its
/// own named allowance on top of this, so that difference is visible right
/// where it is made.
pub(crate) fn payload_command_bytes(payload: &rally_point_proto::messages::Payload) -> usize {
    payload.commands.len()
}
