//! Restart survival: the coordinator's live-session state, flushed to the ledger
//! and restored at startup, so a restarted (or crashed) coordinator adopts the
//! relays it was managing instead of tearing their games down.
//!
//! # Why a restart would otherwise kill games
//!
//! A relay's descriptor set is declarative: every (re)connect re-syncs the full
//! set, and the relay ends any session absent from it. A coordinator that came up
//! with no memory would re-sync every reconnecting relay to an empty set, ending
//! every running game; the now-idle relays would then drain away. And the tenant
//! asks the coordinator which of its games are still alive, force-reconciling any
//! it does not know. So surviving a restart means the coordinator must come back
//! knowing every live session, not merely that relays keep running.
//!
//! # What is kept
//!
//! One record per live session ([`PersistedSession`]): the setup half
//! ([`SetupRecord`] — membership, correlation ids, the create-idempotency entry,
//! each relay's staged descriptor and pending slot-closes, recorded re-homes) and
//! the lifecycle half ([`LifecycleFacts`] — accounting, departures, load-state
//! sets, started). Plus each relay's last boot id, so a relay that restarted while
//! the coordinator was down is still told apart from one that merely redialed.
//! Timers and heartbeat evidence are not kept; restore re-arms them from the
//! facts and the relays' next beats.
//!
//! A session is persisted only while both halves exist. A create registers the
//! lifecycle inside its own commit, under the assignment lock and before its
//! response becomes replayable, and a close removes the lifecycle state before it
//! retires membership, so the intersection never holds a half-created or
//! half-closed session — a restart can neither resurrect a session that was
//! closing nor restore one without its accounting. And because registration
//! precedes replayability under the same lock, every answer a create hands out
//! (fresh or replayed) names a session the next capture includes.
//!
//! # When it is written
//!
//! [`SessionStore::flush`] captures the current state, diffs it against what the
//! last flush wrote, and applies only the changes in one ledger transaction. It
//! runs on a short interval ([`FLUSH_INTERVAL`]), synchronously before a create or
//! re-home answers — which refuses with a retryable `503` if the write fails, so
//! no client ever holds a token or a replacement relay a crash would forget — and
//! once more at shutdown after the control connections close. What a crash can
//! lose is therefore at most one interval of accumulated facts, most of which the
//! relays restate on their next heartbeat anyway.
//!
//! # Refusing to restore
//!
//! A restore is all or nothing. Any stored record that does not decode refuses
//! startup and is left in place ([`RestoreError::Unreadable`]): restoring the
//! others would re-sync that game's relays to a set without it and end it — the
//! very restart this module exists to prevent — while a coordinator that stays
//! down leaves every running game alone until an operator (or a build that reads
//! the record) intervenes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId};
use serde::{Deserialize, Serialize};

use crate::ledger::{LedgerError, RelayLedger, SessionStateWrite, StoredSession};
use crate::lifecycle::{Lifecycle, LifecycleFacts};
use crate::registry;
use crate::session::{SessionSetup, SetupRecord};

/// How often the background flush runs. Short, because a crash loses whatever
/// changed since the last one; cheap, because an unchanged session writes nothing.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

type SessionKey = (TenantId, SessionId);

/// One live session's persisted record. A persisted format: fields added later
/// must deserialize from a record written before them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PersistedSession {
    setup: SetupRecord,
    #[serde(default)]
    lifecycle: LifecycleFacts,
}

/// What the last successful flush wrote, which the next one diffs against.
#[derive(Default)]
struct Written {
    sessions: HashMap<SessionKey, PersistedSession>,
    boot_ids: Vec<(RelayId, Option<u64>)>,
}

/// One consistent capture of everything a flush writes.
struct Capture {
    sessions: HashMap<SessionKey, PersistedSession>,
    boot_ids: Vec<(RelayId, Option<u64>)>,
}

/// The outcome of [`SessionStore::restore`], for the startup log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreSummary {
    /// Sessions restored into the setup and lifecycle.
    pub restored: usize,
}

/// Why [`SessionStore::restore`] refused to restore.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    /// Reading the stored state failed.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// A stored record did not decode — corrupt, or written by a build whose
    /// format this one cannot read. Restoring without it would end that session's
    /// running game the moment its relays reconnect, so nothing is restored and
    /// the record is left in place for an operator (or a build that reads it).
    #[error("the persisted record for tenant {tenant:?} session {session:?} is unreadable")]
    Unreadable {
        /// The record's tenant.
        tenant: TenantId,
        /// The record's session.
        session: SessionId,
        /// The decode failure.
        #[source]
        source: serde_json::Error,
    },
}

/// The coordinator's session persistence over its ledger.
pub struct SessionStore {
    ledger: Arc<RelayLedger>,
    setup: SessionSetup,
    lifecycle: Lifecycle,
    /// Serializes flushes and holds what the last one wrote. Never held across an
    /// await: a flush is synchronous capture + diff + one short ledger write.
    written: Mutex<Written>,
    /// Test seam: run inside a capture, between reading the lifecycle facts and
    /// the boot ids, so a test can land an enrollment exactly there.
    #[cfg(test)]
    capture_seam: Mutex<Option<Box<dyn FnMut() + Send>>>,
}

impl SessionStore {
    /// Restores every stored session into `setup` and `lifecycle` — which must be
    /// fresh, with nothing served yet and no relay enrolled — and returns the
    /// store that keeps them flushed from here on. Refuses outright, restoring
    /// nothing, if any stored record is unreadable (see
    /// [`RestoreError::Unreadable`]).
    pub fn restore(
        ledger: Arc<RelayLedger>,
        setup: SessionSetup,
        lifecycle: Lifecycle,
    ) -> Result<(Self, RestoreSummary), RestoreError> {
        let stored = ledger.session_records()?;
        let mut boot_ids = ledger.relay_boot_ids()?;
        boot_ids.sort_by_key(|(id, _)| id.0);

        // Decode everything before touching the setup, so a refusal leaves the
        // process exactly as fresh as it was handed in.
        let records = stored
            .into_iter()
            .map(|row| {
                let record =
                    serde_json::from_str::<PersistedSession>(&row.record).map_err(|source| {
                        RestoreError::Unreadable {
                            tenant: row.tenant.clone(),
                            session: row.session,
                            source,
                        }
                    })?;
                Ok(((row.tenant, row.session), record))
            })
            .collect::<Result<Vec<_>, RestoreError>>()?;

        registry::seed_boot_ids(setup.registry(), boot_ids.clone());
        setup.restore_records(
            records
                .iter()
                .map(|(key, record)| (key.clone(), record.setup.clone()))
                .collect(),
        );
        for ((tenant, session), record) in &records {
            let (players, observers) = record.setup.slot_split().unwrap_or_default();
            lifecycle.restore_session(
                tenant.clone(),
                *session,
                record.setup.serving.clone(),
                players.into_iter().collect(),
                observers.into_iter().collect(),
                record.lifecycle.clone(),
            );
        }

        let summary = RestoreSummary {
            restored: records.len(),
        };
        let written = Written {
            sessions: records.into_iter().collect(),
            boot_ids,
        };
        Ok((
            Self {
                ledger,
                setup,
                lifecycle,
                written: Mutex::new(written),
                #[cfg(test)]
                capture_seam: Mutex::new(None),
            },
            summary,
        ))
    }

    /// Captures the current live-session state and writes whatever changed since
    /// the last successful flush. A failed write leaves the last-written view
    /// untouched, so the next flush retries the same changes.
    pub fn flush(&self) -> Result<(), LedgerError> {
        let mut written = self.written.lock();
        let current = self.capture();

        let mut write = SessionStateWrite::default();
        for (key, session) in &current.sessions {
            if written.sessions.get(key) != Some(session) {
                write.upserts.push(StoredSession {
                    tenant: key.0.clone(),
                    session: key.1,
                    record: serde_json::to_string(session)?,
                });
            }
        }
        write.deletes = written
            .sessions
            .keys()
            .filter(|key| !current.sessions.contains_key(*key))
            .cloned()
            .collect();
        if current.boot_ids != written.boot_ids {
            write.boot_ids = Some(current.boot_ids.clone());
        }
        if write.is_empty() {
            return Ok(());
        }

        self.ledger.write_session_state(&write)?;
        written.sessions = current.sessions;
        written.boot_ids = current.boot_ids;
        Ok(())
    }

    /// Flushes every [`FLUSH_INTERVAL`] forever. Logs on the transition into and
    /// out of failure rather than on every failed tick.
    pub async fn run(self: Arc<Self>) {
        let mut interval = tokio::time::interval(FLUSH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut failing = false;
        loop {
            interval.tick().await;
            match self.flush() {
                Ok(()) if failing => {
                    failing = false;
                    tracing::info!("persisting session state recovered");
                }
                Ok(()) => {}
                Err(error) if !failing => {
                    failing = true;
                    tracing::error!(
                        %error,
                        "persisting session state failed; a restart now would forget \
                         changes since the last successful flush, and creates and \
                         re-homes are refused until it recovers",
                    );
                }
                Err(_) => {}
            }
        }
    }

    /// Captures the sessions live in both halves — see the module docs for why the
    /// intersection, and only it, is safe to restore — plus the relay boot ids.
    ///
    /// All three reads happen under one hold of the assignment lock, which every
    /// enrollment also holds while it records a relay's new boot id and clears the
    /// completeness claim of the sessions that relay serves. Reading them apart
    /// could pair a session's pre-restart `attestable` with the relay's
    /// post-restart boot id; restored, that boot id would then match on
    /// re-enrollment and the stale claim would never be cleared.
    fn capture(&self) -> Capture {
        let assignment = self.setup.lock_assignment();
        let setup = self.setup.export_records(&assignment);
        let mut facts = self.lifecycle.export_facts();
        #[cfg(test)]
        if let Some(seam) = self.capture_seam.lock().as_mut() {
            seam();
        }
        let boot_ids = registry::export_boot_ids(self.setup.registry());
        drop(assignment);
        let sessions = setup
            .into_iter()
            .filter_map(|(key, setup)| {
                let lifecycle = facts.remove(&key)?;
                Some((key, PersistedSession { setup, lifecycle }))
            })
            .collect();
        Capture { sessions, boot_ids }
    }
}

#[cfg(test)]
mod tests;
