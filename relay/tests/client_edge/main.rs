//! End-to-end coverage of the relay's client-facing edge over loopback QUIC.
//!
//! Each test stands up a real relay endpoint and drives the client side of the
//! authorization handshake by hand — there is no client crate doing it yet, so
//! these tests are also the executable spec for the handshake's wire shape: a
//! `u16`-LE-prefixed token, a 32-byte challenge, a 64-byte response, then the
//! relay's one acknowledgement byte. Past that the connection carries turns as
//! transport `Link` datagrams exactly as the client will.

#[path = "../common/mod.rs"]
mod common;
mod helpers;

mod auth;
mod connectivity;
mod desync_eviction;
mod drop_holds;
mod lead_reports;
mod leaves;
mod lobby_policy;
mod lobby_policy_descriptor;
mod provisional;
mod reconnect;
mod region_labels;
mod restart_resume;
mod results;
mod session_start;
mod turns;
