//! Connection-bound evidence carried when the negotiated protocol supports it.

use crate::control::TenantId;
use crate::ids::{SessionId, SlotId};
use crate::token::{ClientPublicKey, SIGNATURE_LEN, Signature};

use super::HandshakeError;

/// Width of the little-endian evidence payload length prefix.
pub const EVIDENCE_LEN_PREFIX_LEN: usize = 2;
/// Maximum evidence payload length, including the key id and signature.
pub const MAX_EVIDENCE_LEN: usize = 4096;
const EVIDENCE_HEADER_LEN: usize = 4 + SIGNATURE_LEN;
/// Maximum length of the opaque evidence body.
pub const MAX_EVIDENCE_BODY_LEN: usize = MAX_EVIDENCE_LEN - EVIDENCE_HEADER_LEN;
const EVIDENCE_DOMAIN_TAG: u8 = 0x02;

/// The connection context supplied to an evidence provider.
#[derive(Clone, Debug)]
pub struct EvidenceRequest {
    pub challenge: [u8; 32],
    pub channel_binding: [u8; 32],
    pub tenant: TenantId,
    pub session: SessionId,
    pub slot: SlotId,
    pub client_pubkey: ClientPublicKey,
}

impl EvidenceRequest {
    /// Canonical bytes signed by the provider and verified by the relay.
    ///
    /// A distinct domain tag precedes the challenge, channel binding, u64-LE
    /// tenant byte length and UTF-8 bytes, u64-LE session, slot, client key,
    /// u32-LE evidence key id, and the opaque body.
    pub fn signed_message(&self, key_id: u32, body: &[u8]) -> Vec<u8> {
        let tenant = self.tenant.0.as_bytes();
        let mut message = Vec::new();
        message.push(EVIDENCE_DOMAIN_TAG);
        message.extend_from_slice(&self.challenge);
        message.extend_from_slice(&self.channel_binding);
        message.extend_from_slice(&(tenant.len() as u64).to_le_bytes());
        message.extend_from_slice(tenant);
        message.extend_from_slice(&self.session.0.to_le_bytes());
        message.push(self.slot.0);
        message.extend_from_slice(&self.client_pubkey.0);
        message.extend_from_slice(&key_id.to_le_bytes());
        message.extend_from_slice(body);
        message
    }
}

/// A provider's opaque body and its signature over the connection context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub key_id: u32,
    pub body: Vec<u8>,
    pub signature: Signature,
}

/// Encodes an optional evidence payload with its length prefix.
pub fn encode_evidence_frame(evidence: Option<&Evidence>) -> Result<Vec<u8>, HandshakeError> {
    let Some(evidence) = evidence else {
        return Ok(vec![0; EVIDENCE_LEN_PREFIX_LEN]);
    };
    // Bound the body before adding the header or allocating the encoded frame.
    if evidence.body.len() > MAX_EVIDENCE_BODY_LEN {
        return Err(HandshakeError::EvidenceTooLong {
            len: evidence.body.len().saturating_add(EVIDENCE_HEADER_LEN),
        });
    }
    let len = EVIDENCE_HEADER_LEN + evidence.body.len();
    let mut frame = Vec::with_capacity(EVIDENCE_LEN_PREFIX_LEN + len);
    frame.extend_from_slice(&(len as u16).to_le_bytes());
    frame.extend_from_slice(&evidence.key_id.to_le_bytes());
    frame.extend_from_slice(&evidence.signature.0);
    frame.extend_from_slice(&evidence.body);
    Ok(frame)
}

/// Validates the payload length before the caller allocates or reads it.
pub fn decode_evidence_len(prefix: [u8; EVIDENCE_LEN_PREFIX_LEN]) -> Result<usize, HandshakeError> {
    let len = usize::from(u16::from_le_bytes(prefix));
    validate_len(len)?;
    Ok(len)
}

/// Decodes the payload after its length prefix has been consumed.
pub fn decode_evidence(payload: &[u8]) -> Result<Option<Evidence>, HandshakeError> {
    validate_len(payload.len())?;
    if payload.is_empty() {
        return Ok(None);
    }
    let key_id = u32::from_le_bytes(payload[..4].try_into().expect("validated header length"));
    let signature = Signature(
        payload[4..EVIDENCE_HEADER_LEN]
            .try_into()
            .expect("validated signature length"),
    );
    Ok(Some(Evidence {
        key_id,
        body: payload[EVIDENCE_HEADER_LEN..].to_vec(),
        signature,
    }))
}

fn validate_len(len: usize) -> Result<(), HandshakeError> {
    if len > MAX_EVIDENCE_LEN {
        Err(HandshakeError::EvidenceTooLong { len })
    } else if len != 0 && len < EVIDENCE_HEADER_LEN {
        Err(HandshakeError::MalformedEvidence { len })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
