//! How far one connection's authorization handshake got.
//!
//! The authorization deadline drops the handshake future, so the record of its
//! progress is owned by the caller and lent to [`super::authenticate`] for the
//! duration. Whatever the deadline interrupts, the caller can still say which
//! step the client never completed and, once the token has verified, which slot
//! the connection was for.

use std::fmt;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};

/// The step of the authorization exchange a connection is waiting on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthStage {
    /// The QUIC connection is up, but the client has not opened the handshake
    /// stream (or has opened it without sending anything on it yet).
    #[default]
    AwaitingStream,
    /// The handshake stream is open; the token frame has not fully arrived.
    AwaitingToken,
    /// The token verified; the challenge is not yet written to the handshake
    /// stream. The write waits on the stream's flow control, which the client
    /// grants, so a stall here is the client not taking the challenge rather
    /// than not answering it.
    SendingChallenge,
    /// The challenge was written; the signed response has not fully arrived.
    AwaitingChallengeResponse,
    /// The challenge proof passed; the resume-cursor frame has not fully arrived.
    AwaitingResumeCursors,
    /// The resume cursors arrived; the evidence frame, sent only on connections
    /// that support evidence, has not fully arrived.
    AwaitingEvidence,
    /// The client's side of the exchange is complete; a managed relay is waiting
    /// for the coordinator to install the session's descriptor.
    AwaitingSessionDescriptor,
}

impl fmt::Display for AuthStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AwaitingStream => "the client to open the handshake stream",
            Self::AwaitingToken => "the token",
            Self::SendingChallenge => "the challenge to be written to the handshake stream",
            Self::AwaitingChallengeResponse => "the challenge response",
            Self::AwaitingResumeCursors => "the resume cursors",
            Self::AwaitingEvidence => "the evidence frame",
            Self::AwaitingSessionDescriptor => "the session descriptor",
        })
    }
}

/// The slot a connection's verified token names.
///
/// Known as soon as the token's signature verifies against a registered tenant
/// key, so these claims are authentic. The presenter has not necessarily proven
/// it holds the token's client key yet, so this identifies which slot a
/// connection was dialing for, not that the slot's owner was the one dialing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenIdentity {
    /// Tenant that owns the token's signing key, from the registry.
    pub tenant: TenantId,
    /// Session the token names.
    pub session: SessionId,
    /// Slot the token names.
    pub slot: SlotId,
}

/// How far one connection's authorization handshake has advanced: the step it
/// is waiting on, plus the slot its token names once that token has verified.
///
/// Displays as `waiting for <step>`, followed by the token's tenant, session and
/// slot when they are known.
#[derive(Debug, Default)]
pub struct AuthProgress {
    stage: AuthStage,
    identity: Option<TokenIdentity>,
}

impl AuthProgress {
    /// A handshake that has not started: waiting for the client to open the
    /// handshake stream, with no identity known.
    pub fn new() -> Self {
        Self::default()
    }

    /// The step the handshake is waiting on.
    pub fn stage(&self) -> AuthStage {
        self.stage
    }

    /// The slot the connection's token names, once that token has verified.
    pub fn identity(&self) -> Option<&TokenIdentity> {
        self.identity.as_ref()
    }

    /// Records that the handshake is now waiting on `stage`.
    pub(crate) fn advance(&mut self, stage: AuthStage) {
        self.stage = stage;
    }

    /// Records the slot a just-verified token names.
    pub(super) fn record_identity(&mut self, identity: TokenIdentity) {
        self.identity = Some(identity);
    }
}

impl fmt::Display for AuthProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "waiting for {}", self.stage)?;
        if let Some(TokenIdentity {
            tenant,
            session,
            slot,
        }) = &self.identity
        {
            write!(
                f,
                " (token for tenant {tenant:?} session {session:?} slot {slot:?})"
            )?;
        }
        Ok(())
    }
}
