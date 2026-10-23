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

/// A relay's observation of one admission or periodic sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceObservation {
    /// Zero for admission; otherwise the connection-local periodic challenge id.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub sample_id: u64,
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

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Maximum periodic observations in one session presence snapshot.
pub const MAX_PERIODIC_EVIDENCE_SLOTS: usize = 16;

pub(super) mod periodic_samples {
    use super::{MAX_PERIODIC_EVIDENCE_SLOTS, SlotEvidence};
    use serde::de::{Error, IgnoredAny, SeqAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        values: &[SlotEvidence],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if values.len() > MAX_PERIODIC_EVIDENCE_SLOTS {
            return Err(serde::ser::Error::custom("too many periodic observations"));
        }
        values.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<SlotEvidence>, D::Error> {
        struct Samples;
        impl<'de> Visitor<'de> for Samples {
            type Value = Vec<SlotEvidence>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("at most 16 periodic observations")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while values.len() < MAX_PERIODIC_EVIDENCE_SLOTS {
                    let Some(value) = seq.next_element()? else {
                        return Ok(values);
                    };
                    values.push(value);
                }
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("too many periodic observations"));
                }
                Ok(values)
            }
        }
        deserializer.deserialize_seq(Samples)
    }
}
