//! The pre-enroll handshake reads: the opening `Hello` and the identity
//! challenge/proof exchange that binds a claimed relay id to possession of its
//! certificate's private key.
//!
//! Both reads are deliberately unforgiving — anything other than the exact frame
//! the protocol expects ends the connection — and both are bounded by the
//! caller's hello deadline rather than waiting on the socket.

use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use rally_point_proto::control::{CoordinatorToRelay, RelayHello, RelayToCoordinator};
use rally_point_proto::version::CONTROL_CLOSE_IDENTITY_UNPROVEN;
use ring::rand::{SecureRandom, SystemRandom};

use crate::identity;

/// Challenges a freshly-negotiated control connection to prove possession of the
/// private key matching its `Hello`'s certificate, returning whether it proved
/// it. A fresh random nonce goes down as an
/// [`CoordinatorToRelay::IdentityChallenge`]; the relay must answer within
/// `hello_timeout` with a [`RelayToCoordinator::IdentityProof`] whose signature
/// verifies against `hello.cert_der` (see [`crate::identity`]).
///
/// On a failed or absent proof this sends the [`CONTROL_CLOSE_IDENTITY_UNPROVEN`]
/// close itself and returns `false`; it also returns `false` (closing the socket
/// implicitly) when the nonce cannot be generated or the challenge cannot be
/// sent. A `false` return means the caller must stop serving the connection
/// without enrolling. Called unconditionally: negotiation already refused any
/// relay advertising a version below
/// [`ProtocolVersion::ENROLL_POP_MIN`](rally_point_proto::version::ProtocolVersion::ENROLL_POP_MIN),
/// so there is no un-challenged enroll path.
pub(super) async fn challenge_and_verify(
    socket: &mut WebSocket,
    hello: &RelayHello,
    hello_timeout: Duration,
) -> bool {
    let relay_id = hello.relay_id;
    let mut nonce = [0u8; 32];
    if let Err(error) = SystemRandom::new().fill(&mut nonce) {
        tracing::error!(
            relay_id = relay_id.0,
            %error,
            "generating the enroll challenge nonce failed; closing",
        );
        return false;
    }
    let challenge_json = serde_json::to_string(&CoordinatorToRelay::IdentityChallenge { nonce })
        .expect("an identity-challenge frame always serializes");
    if socket
        .send(Message::Text(challenge_json.into()))
        .await
        .is_err()
    {
        return false;
    }

    // Bounded by the same hello_timeout pattern as the initial enroll frame: a
    // relay silent past it, or one that answers with anything other than an
    // IdentityProof, is exactly as unwelcome here as one that never sent a Hello.
    let proof = tokio::time::timeout(hello_timeout, read_identity_proof(socket))
        .await
        .ok()
        .flatten();
    let proven = proof.is_some_and(|signature| {
        identity::verify_enroll_proof(&hello.cert_der, &nonce, &signature)
    });
    if !proven {
        tracing::warn!(
            relay_id = relay_id.0,
            "refusing relay control connection: enroll proof-of-possession failed",
        );
        let _ = socket
            .send(Message::Close(Some(CloseFrame {
                code: CONTROL_CLOSE_IDENTITY_UNPROVEN,
                reason: "enroll proof-of-possession failed".into(),
            })))
            .await;
    }
    proven
}

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

/// Reads the relay's answer to an [`CoordinatorToRelay::IdentityChallenge`],
/// returning the raw signature bytes from a
/// [`RelayToCoordinator::IdentityProof`]. Any other outcome — a different
/// frame kind, an undecodable frame, a close, a stream end, or a read error —
/// is `None`: the caller treats all of them as an unanswered challenge
/// uniformly, since none proves possession of the claimed key. Ping/pong
/// control frames are skipped, exactly like [`read_hello`]; the caller's own
/// timeout bounds how long a silent connection may sit before answering.
async fn read_identity_proof(socket: &mut WebSocket) -> Option<Vec<u8>> {
    loop {
        match socket.recv().await {
            Some(Ok(Message::Text(text))) => {
                return match serde_json::from_str::<RelayToCoordinator>(&text) {
                    Ok(RelayToCoordinator::IdentityProof { signature }) => Some(signature),
                    _ => None,
                };
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(_)) | None => return None,
            Some(Err(error)) => {
                tracing::debug!(%error, "control connection error awaiting identity proof");
                return None;
            }
        }
    }
}
