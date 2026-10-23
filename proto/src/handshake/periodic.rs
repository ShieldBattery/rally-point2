//! Bounded framing on the authenticated stream after admission completes.

use super::{
    Evidence, HandshakeError, decode_evidence, decode_evidence_len, encode_evidence_frame,
};

/// The only supported check measures the complete image selected by the provider.
/// The wire never supplies memory addresses or read lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EvidenceCheck {
    FullImage = 1,
}

/// A relay-issued challenge scoped to one authenticated connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeriodicEvidenceContext {
    pub challenge_id: u64,
    pub nonce: [u8; 32],
    pub assignment_revision: u64,
    pub check: EvidenceCheck,
}

/// Fixed challenge width: id, nonce, assignment revision, and check discriminant.
pub const PERIODIC_CHALLENGE_LEN: usize = 8 + 32 + 8 + 1;
/// Response header width: challenge id and the existing evidence length prefix.
pub const PERIODIC_RESPONSE_HEADER_LEN: usize = 8 + super::EVIDENCE_LEN_PREFIX_LEN;

/// Invalid periodic framing. Lengths are checked before payload allocation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeriodicEvidenceError {
    #[error("periodic challenge id must be nonzero")]
    ZeroChallengeId,
    #[error("unsupported evidence check {0}")]
    UnknownCheck(u8),
    #[error("periodic evidence payload length {actual} differs from header length {expected}")]
    PayloadLength { expected: usize, actual: usize },
    #[error(transparent)]
    Evidence(#[from] HandshakeError),
}

/// Encodes one fixed-size challenge. Zero is reserved for admission observations.
pub fn encode_periodic_challenge(
    challenge: &PeriodicEvidenceContext,
) -> Result<[u8; PERIODIC_CHALLENGE_LEN], PeriodicEvidenceError> {
    nonzero(challenge.challenge_id)?;
    let mut bytes = [0; PERIODIC_CHALLENGE_LEN];
    bytes[..8].copy_from_slice(&challenge.challenge_id.to_le_bytes());
    bytes[8..40].copy_from_slice(&challenge.nonce);
    bytes[40..48].copy_from_slice(&challenge.assignment_revision.to_le_bytes());
    bytes[48] = challenge.check as u8;
    Ok(bytes)
}

/// Decodes an exactly sized challenge, rejecting unknown checks rather than guessing.
pub fn decode_periodic_challenge(
    bytes: &[u8; PERIODIC_CHALLENGE_LEN],
) -> Result<PeriodicEvidenceContext, PeriodicEvidenceError> {
    let challenge_id = u64::from_le_bytes(bytes[..8].try_into().expect("fixed id width"));
    nonzero(challenge_id)?;
    let check = match bytes[48] {
        1 => EvidenceCheck::FullImage,
        value => return Err(PeriodicEvidenceError::UnknownCheck(value)),
    };
    Ok(PeriodicEvidenceContext {
        challenge_id,
        nonce: bytes[8..40].try_into().expect("fixed nonce width"),
        assignment_revision: u64::from_le_bytes(
            bytes[40..48].try_into().expect("fixed revision width"),
        ),
        check,
    })
}

/// Encodes an optional response with its challenge id and bounded payload length.
pub fn encode_periodic_response(
    challenge_id: u64,
    evidence: Option<&Evidence>,
) -> Result<Vec<u8>, PeriodicEvidenceError> {
    nonzero(challenge_id)?;
    let payload = encode_evidence_frame(evidence)?;
    let mut bytes = Vec::with_capacity(8 + payload.len());
    bytes.extend_from_slice(&challenge_id.to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

/// Validates the fixed header before a caller allocates or reads its payload.
/// The caller must also match the returned id against its outstanding challenge.
pub fn decode_periodic_response_header(
    bytes: &[u8; PERIODIC_RESPONSE_HEADER_LEN],
) -> Result<(u64, usize), PeriodicEvidenceError> {
    let challenge_id = u64::from_le_bytes(bytes[..8].try_into().expect("fixed id width"));
    nonzero(challenge_id)?;
    let len = decode_evidence_len(bytes[8..].try_into().expect("fixed length prefix width"))?;
    Ok((challenge_id, len))
}

/// Decodes a response only when its payload exactly matches the validated header.
pub fn decode_periodic_response(
    header: &[u8; PERIODIC_RESPONSE_HEADER_LEN],
    payload: &[u8],
) -> Result<(u64, Option<Evidence>), PeriodicEvidenceError> {
    let (challenge_id, expected) = decode_periodic_response_header(header)?;
    if payload.len() != expected {
        return Err(PeriodicEvidenceError::PayloadLength {
            expected,
            actual: payload.len(),
        });
    }
    Ok((challenge_id, decode_evidence(payload)?))
}

fn nonzero(challenge_id: u64) -> Result<(), PeriodicEvidenceError> {
    if challenge_id == 0 {
        Err(PeriodicEvidenceError::ZeroChallengeId)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
