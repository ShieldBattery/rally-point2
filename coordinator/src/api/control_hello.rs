//! The pre-enroll socket reads: the opening `Hello`, and every later frame the
//! enroll sequence waits for.
//!
//! Both are deliberately unforgiving — the first frame is a `Hello` or the
//! connection ends — and neither waits on the socket itself: the caller's hello
//! deadline bounds how long a silent connection may sit. What a decoded frame
//! then *means* is [`super::control_enroll`]'s; these only turn bytes into a
//! frame.

use axum::extract::ws::{Message, WebSocket};
use rally_point_proto::control::{RelayHello, RelayToCoordinator};

/// Reads the relay's opening [`RelayToCoordinator::Hello`] from a freshly
/// upgraded connection, returning the [`RelayHello`] it carries.
///
/// The first *application* frame must be a Hello: the protocol puts enrollment
/// first, so anything else (a non-Hello message, an undecodable frame, binary)
/// is a violation and closes the connection (`None`) rather than waiting — a
/// later-protocol relay still works because its Hello decodes as one (unknown
/// fields are ignored). Only WebSocket ping/pong control frames are skipped; the
/// caller's deadline bounds how long a silent connection may sit before the Hello.
pub(super) async fn read_hello(socket: &mut WebSocket) -> Option<RelayHello> {
    loop {
        match socket.recv().await {
            Some(Ok(Message::Text(text))) => {
                return match serde_json::from_str::<RelayToCoordinator>(&text) {
                    Ok(RelayToCoordinator::Hello(hello)) => Some(hello),
                    // A heartbeat, a departure, a desync, a result, a flight-upload
                    // request or done, an identity proof, or any future up-frame before
                    // the enroll Hello is a protocol violation: enrollment comes
                    // first.
                    Ok(
                        RelayToCoordinator::Heartbeat { .. }
                        | RelayToCoordinator::Draining
                        | RelayToCoordinator::Departure(_)
                        | RelayToCoordinator::Desync(_)
                        | RelayToCoordinator::Result(_)
                        | RelayToCoordinator::SlotConnected(_)
                        | RelayToCoordinator::SessionStarted(_)
                        | RelayToCoordinator::SlotStarted(_)
                        | RelayToCoordinator::SessionClosed { .. }
                        | RelayToCoordinator::FlightUploadRequest { .. }
                        | RelayToCoordinator::FlightUploadDone { .. }
                        | RelayToCoordinator::LoadStateSnapshot { .. }
                        | RelayToCoordinator::IdentityProof { .. }
                        | RelayToCoordinator::Unknown,
                    ) => {
                        tracing::warn!("first control frame was not a Hello; closing");
                        None
                    }
                    Err(error) => {
                        tracing::warn!(%error, "bad first control frame; closing");
                        None
                    }
                };
            }
            // Ping/pong control frames may precede the Hello; keep waiting (the
            // caller's timeout bounds the wait).
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            // A close, a stream end, a binary frame, or a read error before any
            // Hello ends the handshake.
            Some(Ok(_)) | None => return None,
            Some(Err(error)) => {
                tracing::debug!(%error, "control connection error before hello");
                return None;
            }
        }
    }
}

/// Reads the relay's next frame once the opening `Hello` has been read — the
/// answer to the enroll sequence's identity challenge, in practice.
///
/// Any outcome that is not a decodable frame — an undecodable one, a close, a
/// stream end, a binary frame, or a read error — is `None`, and so is a frame
/// the sequence has no step for: the handshake treats all of them as "the relay
/// answered nothing", since none is the thing the step needed. Ping/pong control
/// frames are skipped, exactly like [`read_hello`]; the caller's own timeout
/// bounds how long a silent connection may sit before answering.
pub(super) async fn read_relay_frame(socket: &mut WebSocket) -> Option<RelayToCoordinator> {
    loop {
        match socket.recv().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str::<RelayToCoordinator>(&text).ok();
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(_)) | None => return None,
            Some(Err(error)) => {
                tracing::debug!(%error, "control connection error awaiting the next enroll frame");
                return None;
            }
        }
    }
}
