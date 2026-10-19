//! Storage for the coordinator's restart-surviving session state: one opaque JSON
//! record per live session, and the process identity each relay id last enrolled
//! with. The ledger only stores and returns the bytes — what a record holds, and
//! when one is written, belongs to `crate::persist`.

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId};
use rusqlite::params;

use super::schema::{as_i64, as_u64};
use super::{LedgerError, RelayLedger};

/// One stored session record: the session's key and its serialized state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredSession {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session id, unique within the tenant.
    pub session: SessionId,
    /// The serialized record, as `crate::persist` wrote it.
    pub record: String,
}

/// One flush's worth of changes, applied atomically by
/// [`RelayLedger::write_session_state`].
#[derive(Debug, Default)]
pub(crate) struct SessionStateWrite {
    /// Records to insert or replace.
    pub upserts: Vec<StoredSession>,
    /// Sessions whose records to delete (they closed since the last flush).
    pub deletes: Vec<(TenantId, SessionId)>,
    /// The full relay boot-id table to store in place of the current one, or
    /// `None` to leave it untouched.
    pub boot_ids: Option<Vec<(RelayId, Option<u64>)>>,
}

impl SessionStateWrite {
    /// Whether the write would change nothing.
    pub(crate) fn is_empty(&self) -> bool {
        self.upserts.is_empty() && self.deletes.is_empty() && self.boot_ids.is_none()
    }
}

impl RelayLedger {
    /// Every stored session record, in no particular order — the startup load a
    /// restarted coordinator restores its live sessions from.
    pub(crate) fn session_records(&self) -> Result<Vec<StoredSession>, LedgerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT tenant, session, record FROM session_records")?;
        let rows = stmt
            .query_map([], |row| {
                Ok(StoredSession {
                    tenant: TenantId(row.get(0)?),
                    session: SessionId(as_u64(row.get(1)?)),
                    record: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Every stored relay boot id, in no particular order.
    pub(crate) fn relay_boot_ids(&self) -> Result<Vec<(RelayId, Option<u64>)>, LedgerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT relay_id, boot_id FROM relay_boot_ids")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    RelayId(as_u64(row.get(0)?)),
                    row.get::<_, Option<i64>>(1)?.map(as_u64),
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Applies one flush's changes in a single transaction, so a crash mid-write
    /// leaves the previous flush's state intact rather than half of each.
    pub(crate) fn write_session_state(&self, write: &SessionStateWrite) -> Result<(), LedgerError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        {
            let mut upsert = tx.prepare(
                "INSERT INTO session_records (tenant, session, record) VALUES (?1, ?2, ?3)
                 ON CONFLICT(tenant, session) DO UPDATE SET record = excluded.record",
            )?;
            for stored in &write.upserts {
                upsert.execute(params![
                    stored.tenant.as_ref(),
                    as_i64(stored.session.0),
                    stored.record
                ])?;
            }
            let mut delete =
                tx.prepare("DELETE FROM session_records WHERE tenant = ?1 AND session = ?2")?;
            for (tenant, session) in &write.deletes {
                delete.execute(params![tenant.as_ref(), as_i64(session.0)])?;
            }
            if let Some(boot_ids) = &write.boot_ids {
                tx.execute("DELETE FROM relay_boot_ids", [])?;
                let mut insert =
                    tx.prepare("INSERT INTO relay_boot_ids (relay_id, boot_id) VALUES (?1, ?2)")?;
                for (relay, boot_id) in boot_ids {
                    insert.execute(params![as_i64(relay.0), boot_id.map(as_i64)])?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Makes every later session-state write fail (`true`, by dropping the records
    /// table) or work again (`false`, recreating it empty) — the injected storage
    /// fault the persistence-refusal tests drive.
    #[cfg(test)]
    pub(crate) fn set_session_writes_failing(&self, failing: bool) {
        let conn = self.conn.lock();
        if failing {
            conn.execute_batch("DROP TABLE session_records;").unwrap();
        } else {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS session_records (
                   tenant TEXT NOT NULL, session INTEGER NOT NULL, record TEXT NOT NULL,
                   PRIMARY KEY (tenant, session));",
            )
            .unwrap();
        }
    }
}
