//! Closes the `C–S–C` loop with real code on both ends: real clients (this
//! crate) authorize against a real relay (`rally-point-relay`) over loopback
//! QUIC, and a turn from one client is validated and fanned out to the other.
//!
//! Where `relay/tests/client_edge.rs` drove the client side of the handshake by
//! hand, these exercise the actual client transport — the same handshake codec on
//! both ends — so a drift in the wire framing would fail here.
//!
//! Split by topic: `helpers` holds the shared tenant/relay/client fixtures;
//! `connect_and_turns` covers dialing (success, failure, timeout) and the basic
//! turn/session-start path; `directives` covers the lobby/chat/skin
//! control-stream broadcasts; `reconnect_and_leaves` covers a dropped link's
//! reconnect-and-replay and a survivor's manual drop of a disconnected peer;
//! `rehome` covers failover to a replacement relay.

mod helpers;

mod connect_and_turns;
mod directives;
mod reconnect_and_leaves;
mod rehome;
