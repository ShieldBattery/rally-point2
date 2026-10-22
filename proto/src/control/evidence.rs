//! Session evidence configuration and connection observations.

use serde::{Deserialize, Serialize};

use crate::ids::SlotId;
use crate::token::ClientPublicKey;

/// Maximum number of evidence verification keys in a session.
pub const MAX_EVIDENCE_KEYS: usize = 16;

/// One session-scoped evidence verification key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceKey {
    pub key_id: u32,
    pub public_key: ClientPublicKey,
}

/// Outcome of checking a connection's evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVerdict {
    Missing,
    UnknownKey,
    Invalid,
    Valid,
}

/// A relay's observation of one connection attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceObservation {
    pub connection_id: [u8; 32],
    pub sequence: u64,
    pub assignment_revision: u64,
    pub verdict: EvidenceVerdict,
    pub key_id: Option<u32>,
    #[serde(with = "body_encoding")]
    pub body: Vec<u8>,
}

mod body_encoding {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::handshake::MAX_EVIDENCE_BODY_LEN;

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        if bytes.len() > MAX_EVIDENCE_BODY_LEN {
            return Err(serde::ser::Error::custom(
                "evidence body exceeds maximum length",
            ));
        }
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() > MAX_EVIDENCE_BODY_LEN.div_ceil(3) * 4 {
            return Err(serde::de::Error::custom(
                "evidence body exceeds maximum length",
            ));
        }
        let bytes = STANDARD.decode(encoded).map_err(serde::de::Error::custom)?;
        if bytes.len() > MAX_EVIDENCE_BODY_LEN {
            return Err(serde::de::Error::custom(
                "evidence body exceeds maximum length",
            ));
        }
        Ok(bytes)
    }
}

/// The latest evidence observation for a slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotEvidence {
    pub slot: SlotId,
    pub observation: EvidenceObservation,
}

/// A slot's coordinator-assigned home revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotEvidenceAssignment {
    pub slot: SlotId,
    pub revision: u64,
}
