//! Process-local historical reports. Retention is independent of live sessions.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rally_point_proto::control::{EvidenceReceipt, EvidenceReceiptDisposition, EvidenceReport};

const MAX_REPORTS: usize = 1024;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const RETENTION: Duration = Duration::from_secs(10 * 60);
const RETRY: Duration = Duration::from_secs(10);

#[derive(Default)]
pub(super) struct EvidenceOutbox {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    entries: VecDeque<Entry>,
    bytes: usize,
    lost_capacity: u64,
    lost_expired: u64,
    last_loss_log: Option<Instant>,
    logged_losses: (u64, u64),
}

struct Entry {
    report: EvidenceReport,
    expires: Instant,
    next_attempt: Instant,
    bytes: usize,
}

impl EvidenceOutbox {
    pub(super) fn insert(&self, report: EvidenceReport, now: Instant) {
        // Charge encoded bytes as well as the fixed entry so JSON expansion and
        // retained report metadata cannot defeat the aggregate byte limit.
        let Ok(encoded) = serde_json::to_vec(&report) else {
            let mut inner = self.inner.lock();
            inner.lost_capacity = inner.lost_capacity.saturating_add(1);
            inner.log_loss(now);
            return;
        };
        let bytes = encoded.len() + std::mem::size_of::<Entry>();
        let mut inner = self.inner.lock();
        inner.expire(now);
        if let Some(index) = inner.entries.iter().position(|entry| {
            entry.report.tenant == report.tenant
                && entry.report.session == report.session
                && entry.report.slot == report.slot
                && entry.report.history.sample.assignment_revision
                    == report.history.sample.assignment_revision
        }) {
            let previous = &inner.entries[index];
            if report.history.failures < previous.report.history.failures
                || report.history.latest_sample().sequence
                    <= previous.report.history.latest_sample().sequence
            {
                return;
            }
            let previous_bytes = previous.bytes;
            if bytes > MAX_BYTES.saturating_sub(inner.bytes - previous_bytes) {
                inner.lost_capacity = inner.lost_capacity.saturating_add(1);
                inner.log_loss(now);
                return;
            }
            inner.bytes = inner.bytes - previous_bytes + bytes;
            let entry = &mut inner.entries[index];
            entry.report = report;
            entry.bytes = bytes;
            entry.expires = now + RETENTION;
            // A newly settled failure refreshes retention, never the retry pace.
            return;
        }
        if inner.entries.len() >= MAX_REPORTS || bytes > MAX_BYTES.saturating_sub(inner.bytes) {
            inner.lost_capacity = inner.lost_capacity.saturating_add(1);
            inner.log_loss(now);
            return;
        }
        inner.bytes += bytes;
        inner.entries.push_back(Entry {
            report,
            expires: now + RETENTION,
            next_attempt: now,
            bytes,
        });
    }

    pub(super) fn reports(&self, now: Instant, limit: usize) -> Vec<EvidenceReport> {
        let mut inner = self.inner.lock();
        inner.expire(now);
        let mut reports = Vec::new();
        // Rotating selected entries makes rejected reports yield their place to
        // unsent ones. Retry eligibility survives control connection replacement.
        for _ in 0..inner.entries.len() {
            if reports.len() >= limit {
                break;
            }
            let mut entry = inner.entries.pop_front().expect("bounded by entry count");
            if entry.next_attempt <= now {
                entry.next_attempt = now + RETRY;
                reports.push(entry.report.clone());
            }
            inner.entries.push_back(entry);
        }
        reports
    }

    pub(super) fn contains(&self, receipt: &EvidenceReceipt, now: Instant) -> bool {
        let mut inner = self.inner.lock();
        inner.expire(now);
        inner.entries.iter().any(|entry| entry.matches(receipt))
    }

    pub(super) fn acknowledge(&self, receipt: &EvidenceReceipt) {
        // Only a disposition whose terminal meaning we know can retire a report.
        if receipt.disposition == EvidenceReceiptDisposition::Unrecognized {
            return;
        }
        let mut inner = self.inner.lock();
        let Some(index) = inner
            .entries
            .iter()
            .position(|entry| entry.matches(receipt))
        else {
            return;
        };
        let entry = inner.entries.remove(index).expect("found entry");
        inner.bytes -= entry.bytes;
    }
}

impl Entry {
    fn matches(&self, receipt: &EvidenceReceipt) -> bool {
        let report = &self.report;
        let sample = report.history.latest_sample();
        report.tenant == receipt.tenant
            && report.session == receipt.session
            && report.slot == receipt.slot
            && sample.assignment_revision == receipt.assignment_revision
            && sample.connection_id == receipt.connection_id
            && sample.sample_id == receipt.sample_id
            && sample.sequence == receipt.sequence
            && report.history.failures == receipt.failures
    }
}

impl Inner {
    fn expire(&mut self, now: Instant) {
        self.entries.retain(|entry| {
            if entry.expires > now {
                true
            } else {
                self.bytes -= entry.bytes;
                self.lost_expired = self.lost_expired.saturating_add(1);
                false
            }
        });
        self.log_loss(now);
    }

    fn log_loss(&mut self, now: Instant) {
        if self.logged_losses != (self.lost_capacity, self.lost_expired)
            && self
                .last_loss_log
                .is_none_or(|last| now.saturating_duration_since(last) >= RETRY)
        {
            tracing::warn!(
                capacity_drops = self.lost_capacity,
                expired = self.lost_expired,
                pending = self.entries.len(),
                bytes = self.bytes,
                "historical evidence outbox lost reports",
            );
            self.last_loss_log = Some(now);
            self.logged_losses = (self.lost_capacity, self.lost_expired);
        }
    }
}

#[cfg(test)]
mod tests;
