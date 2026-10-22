//! Connection-bound evidence verification.

use super::*;
use crate::consensus::EvidenceConfig;
use rally_point_proto::control::EvidenceVerdict;
use rally_point_proto::handshake::{Evidence, EvidenceRequest};

/// Authenticated handshake inputs awaiting the descriptor admission gates.
pub struct Authenticated {
    pub authorized: AuthorizedClient,
    pub resume_cursors: HashMap<SlotId, u64>,
    pub connection_epoch: u64,
    pub send: noq::SendStream,
    pub evidence: Option<Evidence>,
    pub evidence_request: EvidenceRequest,
}

/// The result of checking a frame, carried unchanged into the connection report.
#[derive(Debug, Clone)]
pub struct CheckedEvidence {
    pub connection_id: [u8; CHALLENGE_LEN],
    pub assignment_revision: u64,
    pub verdict: EvidenceVerdict,
    pub key_id: Option<u32>,
    pub body: Vec<u8>,
}

/// Verifies a bounded frame against only the descriptor's session keys.
pub fn verify_evidence(
    request: &EvidenceRequest,
    evidence: Option<Evidence>,
    config: &EvidenceConfig,
) -> CheckedEvidence {
    let mut checked = CheckedEvidence {
        connection_id: request.challenge,
        assignment_revision: config
            .assignments
            .get(&request.slot)
            .copied()
            .unwrap_or_default(),
        verdict: EvidenceVerdict::Missing,
        key_id: None,
        body: Vec::new(),
    };
    if let Some(evidence) = evidence {
        checked.key_id = Some(evidence.key_id);
        checked.verdict = match config.keys.iter().find(|key| key.key_id == evidence.key_id) {
            None => EvidenceVerdict::UnknownKey,
            Some(key) => {
                let message = request.signed_message(evidence.key_id, &evidence.body);
                if verify_ed25519(
                    key.public_key.as_bytes(),
                    &message,
                    evidence.signature.as_bytes(),
                )
                .is_ok()
                {
                    EvidenceVerdict::Valid
                } else {
                    EvidenceVerdict::Invalid
                }
            }
        };
        if checked.verdict == EvidenceVerdict::Valid {
            checked.body = evidence.body;
        }
    }
    checked
}

#[cfg(test)]
mod tests;
