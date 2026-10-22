//! Connection-local proof that a relay installed its sent descriptor state.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use rally_point_proto::control::{DescriptorKey, SessionDescriptor, TenantId};
use rally_point_proto::ids::{RelayId, SessionId};
use tokio::sync::{Notify, futures::Notified};

/// Installation proofs are scoped to one enrolled control connection. Reconnects
/// must acknowledge their full resync before any prior proof can be reused.
#[derive(Clone, Default)]
pub(crate) struct DescriptorDelivery {
    inner: Arc<Mutex<HashMap<RelayId, RelayDelivery>>>,
    changed: Arc<Notify>,
}

struct RelayDelivery {
    generation: u64,
    /// Retain the generation after disconnect so an old writer cannot reopen it.
    connected: bool,
    issued: u64,
    acknowledged: u64,
    sent: HashMap<DescriptorKey, SentDescriptor>,
}

struct SentDescriptor {
    descriptor: SessionDescriptor,
    changed_at: u64,
}

impl DescriptorDelivery {
    /// Starts a fresh connection, refusing any generation already seen.
    pub(crate) fn begin(&self, relay: RelayId, generation: u64) -> bool {
        let mut inner = self.inner.lock();
        if inner
            .get(&relay)
            .is_some_and(|state| state.generation >= generation)
        {
            return false;
        }
        inner.insert(
            relay,
            RelayDelivery {
                generation,
                connected: true,
                issued: 0,
                acknowledged: 0,
                sent: HashMap::new(),
            },
        );
        self.notify_changed();
        true
    }

    /// Registers the complete resulting descriptor set before its frame is sent.
    /// Ordered application makes an acknowledgement cumulative, while unchanged
    /// sessions retain their earlier proof despite unrelated descriptor traffic.
    pub(crate) fn sent(
        &self,
        relay: RelayId,
        generation: u64,
        descriptors: &[SessionDescriptor],
    ) -> Option<u64> {
        let mut inner = self.inner.lock();
        let state = inner.get_mut(&relay)?;
        if !state.connected || state.generation != generation {
            return None;
        }
        let id = state.issued.checked_add(1)?;
        let mut previous = std::mem::take(&mut state.sent);
        state.sent = descriptors
            .iter()
            .map(|descriptor| {
                let key = key(descriptor);
                let changed_at = previous
                    .remove(&key)
                    .filter(|sent| sent.descriptor == *descriptor)
                    .map_or(id, |sent| sent.changed_at);
                (
                    key,
                    SentDescriptor {
                        descriptor: descriptor.clone(),
                        changed_at,
                    },
                )
            })
            .collect();
        state.issued = id;
        Some(id)
    }

    /// Accepts only an issued id from this connection. Older duplicate replies
    /// are harmless; a future id cannot prove installation of an unsent frame.
    pub(crate) fn acknowledge(&self, relay: RelayId, generation: u64, id: u64) -> bool {
        let mut inner = self.inner.lock();
        let Some(state) = inner.get_mut(&relay) else {
            return false;
        };
        if !state.connected || state.generation != generation || id == 0 || id > state.issued {
            return false;
        }
        if id > state.acknowledged {
            state.acknowledged = id;
            self.notify_changed();
        }
        true
    }

    /// Tests the exact descriptor, not just its session key. Callers also check
    /// that the generation and descriptor still match current assignment state.
    pub(crate) fn is_ready(
        &self,
        relay: RelayId,
        generation: u64,
        descriptor: &SessionDescriptor,
    ) -> bool {
        self.inner.lock().get(&relay).is_some_and(|state| {
            state.connected
                && state.generation == generation
                && state.sent.get(&key(descriptor)).is_some_and(|sent| {
                    sent.descriptor == *descriptor && sent.changed_at <= state.acknowledged
                })
        })
    }

    /// Clears proofs without losing the generation fence against a stale writer.
    /// A forgotten relay stays absent when its writer is subsequently dropped.
    pub(crate) fn end(&self, relay: RelayId, generation: u64) {
        let mut inner = self.inner.lock();
        if let Some(state) = inner.get_mut(&relay)
            && state.generation == generation
            && state.connected
        {
            state.connected = false;
            state.sent.clear();
            self.notify_changed();
        }
    }

    /// Drops a permanently retired relay's proof and generation tombstone.
    pub(crate) fn forget(&self, relay: RelayId) {
        self.inner.lock().remove(&relay);
        self.notify_changed();
    }

    /// Registers a notification before reading readiness. Callers pin and enable
    /// it before inspecting assignment state, then await only when still pending.
    pub(crate) fn changed(&self) -> Notified<'_> {
        self.changed.notified()
    }

    pub(super) fn notify_changed(&self) {
        self.changed.notify_waiters();
    }

    pub(super) fn remove(&self, relay: RelayId, tenant: &TenantId, session: SessionId) {
        if let Some(state) = self.inner.lock().get_mut(&relay) {
            state.sent.remove(&DescriptorKey {
                tenant: tenant.clone(),
                session,
            });
        }
    }
}

fn key(descriptor: &SessionDescriptor) -> DescriptorKey {
    DescriptorKey {
        tenant: descriptor.tenant.clone(),
        session: descriptor.session,
    }
}

#[cfg(test)]
mod tests;
