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
pub mod gate;
pub mod lobby;
pub mod presence;
pub mod provisional;
pub mod provisional_turns;
pub mod skin;
pub mod turn_ring;
