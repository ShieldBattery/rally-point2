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

/// Why an outstanding periodic observation ended without evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceInterruption {
    NoAnswer,
    Timeout,
    ConnectionClosed,
    ConnectionReplaced,
    StreamClosed,
    SilentSlot,
    DesyncEvicted,
    LaggingSlot,
    LobbyViolation,
    SlotDeparted,
    Revoked,
    SessionRetired,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interruption: Option<EvidenceInterruption>,
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
    /// Relay observation time, absent when an older producer did not retain it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at_ms: Option<u64>,
    pub slot: SlotId,
    pub observation: EvidenceObservation,
    #[serde(default, skip_serializing_if = "is_false")]
    pub historical: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_count: Option<u32>,
}

/// A slot's coordinator-assigned home revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotEvidenceAssignment {
    pub slot: SlotId,
    pub revision: u64,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn one() -> u32 {
    1
}
fn is_one(value: &u32) -> bool {
    *value == 1
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

/// Cumulative failures for one relay process and assignment: immutable first
/// failure, optional latest failure, and a saturating count. Each sample carries
/// its own admission; none establishes the currently active connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceHistory {
    pub admission: EvidenceObservation,
    pub sample: EvidenceObservation,
    pub observed_at_ms: u64,
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub failures: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest: Option<Box<EvidenceFailure>>,
}

/// A failure and the admission on the connection that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFailure {
    pub admission: EvidenceObservation,
    pub sample: EvidenceObservation,
    pub observed_at_ms: u64,
}

impl EvidenceHistory {
    pub fn latest_sample(&self) -> &EvidenceObservation {
        self.latest
            .as_ref()
            .map_or(&self.sample, |latest| &latest.sample)
    }
    pub fn latest_admission(&self) -> &EvidenceObservation {
        self.latest
            .as_ref()
            .map_or(&self.admission, |latest| &latest.admission)
    }
    pub fn latest_observed_at_ms(&self) -> u64 {
        self.latest
            .as_ref()
            .map_or(self.observed_at_ms, |latest| latest.observed_at_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotEvidenceHistory {
    pub slot: SlotId,
    pub history: EvidenceHistory,
}
pub(super) mod history_samples {
    use super::{MAX_PERIODIC_EVIDENCE_SLOTS, SlotEvidenceHistory};
    use serde::de::{Error, IgnoredAny, SeqAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        values: &[SlotEvidenceHistory],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if values.len() > MAX_PERIODIC_EVIDENCE_SLOTS {
            return Err(serde::ser::Error::custom("too many periodic observations"));
        }
        values.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<SlotEvidenceHistory>, D::Error> {
        struct Samples;
        impl<'de> Visitor<'de> for Samples {
            type Value = Vec<SlotEvidenceHistory>;
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

/// A retained historical observation, delivered independently of live descriptors.
/// Receivers validate the source relay and assignment before acknowledging it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReport {
    pub tenant: super::TenantId,
    pub session: crate::ids::SessionId,
    pub slot: SlotId,
    pub history: EvidenceHistory,
}

/// Terminal handling of one exact report snapshot. The disposition distinguishes
/// memory acceptance from redundant or declined reports; it never promises
/// durability across coordinator process loss.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceReceipt {
    pub tenant: super::TenantId,
    pub session: crate::ids::SessionId,
    pub slot: SlotId,
    pub assignment_revision: u64,
    pub connection_id: [u8; 32],
    pub sample_id: u64,
    pub sequence: u64,
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub failures: u32,
    #[serde(
        default,
        skip_serializing_if = "EvidenceReceiptDisposition::is_accepted"
    )]
    pub disposition: EvidenceReceiptDisposition,
}

/// Terminal handling of an authenticated report; none promises durable storage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceReceiptDisposition {
    #[default]
    Accepted,
    Superseded,
    SessionClosed,
    Capacity,
}

impl EvidenceReceiptDisposition {
    fn is_accepted(&self) -> bool {
        *self == Self::Accepted
    }
}

impl EvidenceReport {
    pub fn receipt(&self) -> EvidenceReceipt {
        let sample = self.history.latest_sample();
        EvidenceReceipt {
            tenant: self.tenant.clone(),
            session: self.session,
            slot: self.slot,
            assignment_revision: sample.assignment_revision,
            connection_id: sample.connection_id,
            sample_id: sample.sample_id,
            sequence: sample.sequence,
            failures: self.history.failures,
            disposition: EvidenceReceiptDisposition::Accepted,
        }
    }
}
