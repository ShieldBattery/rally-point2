//! How far one dial's authorization exchange got, and the log line a failed
//! dial leaves behind.
//!
//! The dial deadline drops the authorization future, so the record of its
//! progress is owned by the dialing function and lent to `authorize` for the
//! duration. A failed or timed-out dial reports from it which step was
//! outstanding and how long each completed step took to finish, measured from
//! the end of the QUIC handshake, so a stall can be pinned on a missing relay
//! message, a slow local step, or a slow path.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use rally_point_proto::token::TokenClaims;
use tokio::time::Instant;

/// One step of the client's side of the authorization exchange, in wire order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthorizeStep {
    OpenStream,
    SendToken,
    AwaitChallenge,
    SendChallengeResponse,
    SendResumeCursors,
    CollectEvidence,
    SendEvidence,
    AwaitAck,
}

impl AuthorizeStep {
    const COUNT: usize = 8;

    /// The step as it reads while outstanding.
    fn outstanding(self) -> &'static str {
        match self {
            Self::OpenStream => "opening the handshake stream",
            Self::SendToken => "sending the token",
            Self::AwaitChallenge => "waiting for the challenge",
            Self::SendChallengeResponse => "sending the challenge response",
            Self::SendResumeCursors => "sending the resume cursors",
            Self::CollectEvidence => "collecting evidence",
            Self::SendEvidence => "sending the evidence",
            Self::AwaitAck => "waiting for the acknowledgement",
        }
    }

    /// The step as it reads once finished. `evidence_supplied` is whether
    /// collection produced evidence: with no provider, a provider that returned
    /// nothing, or one that ran out of time, the frame sent is an empty one, and
    /// the two evidence steps say so.
    fn completed(self, evidence_supplied: bool) -> &'static str {
        match self {
            Self::OpenStream => "stream opened",
            Self::SendToken => "token sent",
            Self::AwaitChallenge => "challenge received",
            Self::SendChallengeResponse => "challenge response sent",
            Self::SendResumeCursors => "resume cursors sent",
            Self::CollectEvidence if evidence_supplied => "evidence collected",
            Self::CollectEvidence => "no evidence collected",
            Self::SendEvidence if evidence_supplied => "evidence sent",
            Self::SendEvidence => "empty evidence frame sent",
            Self::AwaitAck => "acknowledged",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// Where one dial's authorization exchange stands: how long its QUIC handshake
/// took, the step now outstanding, and when each finished step finished.
#[derive(Debug)]
pub(super) struct AuthorizeProgress {
    quic_handshake: Duration,
    handshake_done: Instant,
    outstanding: AuthorizeStep,
    /// When each step finished, as time since the QUIC handshake completed;
    /// indexed by [`AuthorizeStep::index`], `None` for a step not (yet) finished.
    finished: [Option<Duration>; AuthorizeStep::COUNT],
    /// Whether evidence collection produced evidence. False until collection
    /// finishes, and afterwards when it had nothing to supply.
    evidence_supplied: bool,
}

impl AuthorizeProgress {
    /// Starts the record the moment the QUIC handshake of a dial begun at
    /// `dial_started` completes.
    pub(super) fn new(dial_started: Instant) -> Self {
        Self::new_at(dial_started, Instant::now())
    }

    fn new_at(dial_started: Instant, handshake_done: Instant) -> Self {
        Self {
            quic_handshake: handshake_done.saturating_duration_since(dial_started),
            handshake_done,
            outstanding: AuthorizeStep::OpenStream,
            finished: [None; AuthorizeStep::COUNT],
            evidence_supplied: false,
        }
    }

    /// Records whether evidence collection produced anything to send.
    pub(super) fn record_evidence(&mut self, supplied: bool) {
        self.evidence_supplied = supplied;
    }

    /// Marks the outstanding step finished now, and `next` as outstanding.
    pub(super) fn advance(&mut self, next: AuthorizeStep) {
        self.advance_at(next, Instant::now());
    }

    fn advance_at(&mut self, next: AuthorizeStep, now: Instant) {
        self.finished[self.outstanding.index()] =
            Some(now.saturating_duration_since(self.handshake_done));
        self.outstanding = next;
    }

    /// Logs a dial to `relay_addr` whose authorization ended in `outcome`
    /// instead of an acknowledgement: the relay, the token's tenant, session and
    /// slot, the outstanding step, and the timeline up to it.
    pub(super) fn log_failure(
        &self,
        relay_addr: SocketAddr,
        claims: &TokenClaims,
        outcome: &dyn fmt::Display,
    ) {
        tracing::info!(
            relay = %relay_addr,
            tenant = claims.tenant.as_ref(),
            session = claims.session.0,
            slot = claims.slot.0,
            error = %outcome,
            outstanding = self.outstanding.outstanding(),
            quic_handshake_ms = millis(self.quic_handshake),
            completed = %self.completed(),
            "relay authorization failed",
        );
    }

    /// The finished steps in wire order, each with when it finished.
    fn completed(&self) -> CompletedSteps<'_> {
        CompletedSteps(self)
    }
}

/// Formats an [`AuthorizeProgress`]'s finished steps without allocating, as
/// `token sent +0ms, challenge received +41ms`, or `none` before any step has
/// finished.
struct CompletedSteps<'a>(&'a AuthorizeProgress);

impl fmt::Display for CompletedSteps<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut any = false;
        for step in ALL_STEPS {
            let Some(at) = self.0.finished[step.index()] else {
                continue;
            };
            if any {
                f.write_str(", ")?;
            }
            write!(
                f,
                "{} +{}ms",
                step.completed(self.0.evidence_supplied),
                millis(at)
            )?;
            any = true;
        }
        if !any {
            f.write_str("none")?;
        }
        Ok(())
    }
}

/// Every step, in wire order (and in [`AuthorizeStep::index`] order).
const ALL_STEPS: [AuthorizeStep; AuthorizeStep::COUNT] = [
    AuthorizeStep::OpenStream,
    AuthorizeStep::SendToken,
    AuthorizeStep::AwaitChallenge,
    AuthorizeStep::SendChallengeResponse,
    AuthorizeStep::SendResumeCursors,
    AuthorizeStep::CollectEvidence,
    AuthorizeStep::SendEvidence,
    AuthorizeStep::AwaitAck,
];

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
