//! The setup half of a session's restart-surviving record: everything
//! [`SessionSetup`] holds for one session, captured as one value and restored
//! from it. `crate::persist` pairs it with the lifecycle's facts and decides when
//! to write; this file only knows how to read the maps out and put them back.
//!
//! The record is a persisted format. A field added here must deserialize from a
//! record written before it existed, so new fields carry `#[serde(default)]`.

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use parking_lot::MutexGuard;
use rally_point_proto::control::{SessionDescriptor, SessionResponse, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use serde::{Deserialize, Serialize};

use crate::descriptors::SlotClose;

use super::SessionRefs;
use super::gate::{CachedCreate, CreateFingerprint};
use super::setup::SessionSetup;

/// One session's setup state, as [`SessionSetup::export_records`] captures it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SetupRecord {
    /// The session's serving relays — its authoritative membership.
    pub(crate) serving: Vec<RelayId>,
    /// The tenant's correlation ids and the session's placement facts.
    pub(crate) refs: Option<SessionRefs>,
    /// The create-idempotency entry still pointing at this session, so a create
    /// retried across a restart replays rather than minting a second session.
    #[serde(default)]
    pub(crate) create: Option<PersistedCreate>,
    /// Each relay's staged descriptor for the session — exactly what a
    /// reconnecting relay is re-synced to.
    #[serde(default)]
    pub(crate) descriptors: Vec<(RelayId, SessionDescriptor)>,
    /// Each relay's pending slot-close directives for the session.
    #[serde(default)]
    pub(crate) reaps: Vec<(RelayId, Vec<SlotId>)>,
    /// Recorded re-home decisions, as `(dead, replacement)` pairs.
    #[serde(default)]
    pub(crate) rehomes: Vec<(RelayId, RelayId)>,
}

/// A create-idempotency entry: the `external_id` it is keyed on plus the cached
/// fingerprint and response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct PersistedCreate {
    external_id: String,
    fingerprint: CreateFingerprint,
    response: SessionResponse,
}

impl SetupRecord {
    /// The session's player (non-observer) and observer slot sets — the
    /// lifecycle's accounting split, re-derived from the recorded roster exactly
    /// as the create handler derives it from the request. `None` without refs.
    pub(crate) fn slot_split(&self) -> Option<(Vec<SlotId>, Vec<SlotId>)> {
        let refs = self.refs.as_ref()?;
        let players = refs
            .expected
            .iter()
            .filter(|slot| !refs.observers.contains(slot))
            .copied()
            .collect();
        Some((players, refs.observers.clone()))
    }
}

impl SessionSetup {
    /// Captures every live session's setup state. A session is live here while it
    /// has a non-empty serving set: a create records that membership first and a
    /// close takes it first, so a session mid-create or mid-close is either wholly
    /// absent or carries its full membership.
    ///
    /// The caller holds the assignment lock (the guard is the proof), so no
    /// create, re-home, lobby settle, enrollment, or terminal close is half-applied
    /// in what it reads — and the caller can read other state under the same hold.
    pub(crate) fn export_records(
        &self,
        _assignment: &MutexGuard<'_, ()>,
    ) -> HashMap<(TenantId, SessionId), SetupRecord> {
        let mut records: HashMap<(TenantId, SessionId), SetupRecord> = self
            .session_relays
            .lock()
            .iter()
            .filter(|(_, serving)| !serving.is_empty())
            .map(|(key, serving)| {
                (
                    key.clone(),
                    SetupRecord {
                        serving: serving.clone(),
                        refs: None,
                        create: None,
                        descriptors: Vec::new(),
                        reaps: Vec::new(),
                        rehomes: Vec::new(),
                    },
                )
            })
            .collect();
        for (key, refs) in self.session_refs.lock().iter() {
            if let Some(record) = records.get_mut(key) {
                record.refs = Some(refs.clone());
            }
        }
        for ((tenant, external_id), cached) in self.create_idempotency.lock().iter() {
            if let Some(record) = records.get_mut(&(tenant.clone(), cached.response.session)) {
                record.create = Some(PersistedCreate {
                    external_id: external_id.clone(),
                    fingerprint: cached.fingerprint.clone(),
                    response: cached.response.clone(),
                });
            }
        }
        for (relay, set) in self.descriptors.export_all() {
            for descriptor in set {
                let key = (descriptor.tenant.clone(), descriptor.session);
                if let Some(record) = records.get_mut(&key) {
                    record.descriptors.push((relay, descriptor));
                }
            }
        }
        for (relay, close) in self.reaps().export_pending() {
            if let Some(record) = records.get_mut(&(close.tenant, close.session)) {
                record.reaps.push((relay, close.slots));
            }
        }
        for ((tenant, session, dead), replacement) in self.rehomes.lock().iter() {
            if let Some(record) = records.get_mut(&(tenant.clone(), *session)) {
                record.rehomes.push((*dead, *replacement));
            }
        }
        // Map iteration order is arbitrary; sort so two captures of unchanged state
        // compare equal and the diffing writer skips them.
        for record in records.values_mut() {
            record.descriptors.sort_by_key(|(relay, _)| relay.0);
            record.reaps.sort_by_key(|(relay, _)| relay.0);
            record.rehomes.sort_by_key(|(dead, _)| dead.0);
        }
        records
    }

    /// Restores sessions captured by [`export_records`](Self::export_records) in a
    /// previous coordinator lifetime. Called once at startup, before the API
    /// serves and before any relay enrolls, so every reconnecting relay is
    /// re-synced to the descriptor set it already holds. Also advances the
    /// session-id counter past every restored id, so a clock that stepped back
    /// across the restart cannot mint a colliding id.
    pub(crate) fn restore_records(&self, records: Vec<((TenantId, SessionId), SetupRecord)>) {
        let _assignment = self.lock_assignment();
        for ((tenant, session), record) in records {
            if record.serving.is_empty() {
                continue;
            }
            let key = (tenant.clone(), session);
            self.next_session
                .fetch_max(session.0.saturating_add(1), Ordering::Relaxed);
            self.session_relays
                .lock()
                .insert(key.clone(), record.serving);
            if let Some(mut refs) = record.refs {
                refs.prune_retired_evidence_assignments(
                    rally_point_proto::time::unix_secs_fail_closed(),
                );
                self.session_refs.lock().insert(key.clone(), refs);
            }
            if let Some(create) = record.create {
                self.create_idempotency.lock().insert(
                    (tenant.clone(), create.external_id),
                    CachedCreate {
                        fingerprint: create.fingerprint,
                        response: create.response,
                    },
                );
            }
            for (relay, descriptor) in record.descriptors {
                self.descriptors.record(relay, descriptor);
            }
            for (relay, slots) in record.reaps {
                self.reaps().send(
                    relay,
                    SlotClose {
                        tenant: tenant.clone(),
                        session,
                        slots,
                    },
                );
            }
            let mut rehomes = self.rehomes.lock();
            for (dead, replacement) in record.rehomes {
                rehomes.insert((tenant.clone(), session, dead), replacement);
            }
        }
    }
}
