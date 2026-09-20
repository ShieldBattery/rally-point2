//! Shared fixtures for the lifecycle tests: tenant/session setup helpers and
//! the relay/heartbeat staging used across the topic modules below. The webhook
//! receiver and the session builder are the crate-wide test-support ones.

use std::sync::Arc as StdArc;

use rally_point_proto::control::{BufferBounds, SessionDescriptor};
use tokio::sync::Notify as TokioNotify;
use tokio::time::timeout;

use super::*;
use crate::descriptors::SlotClose;
use crate::registry;
use crate::test_support::*;

const SHORT: Duration = Duration::from_millis(80);

fn tid() -> TenantId {
    TenantId(TEST_TENANT.to_owned())
}

/// Records a terminal notice in lifecycle-only tests, explicitly installing
/// authoritative membership and a stable synthetic connection epoch when the
/// test intentionally bypassed normal session creation and enrollment.
fn close(lifecycle: &Lifecycle, tenant: TenantId, session: SessionId, relay: RelayId) {
    if lifecycle
        .inner
        .setup
        .serving_relays(&tenant, session)
        .is_empty()
    {
        let cached = lifecycle
            .inner
            .sessions
            .lock()
            .get(&(tenant.clone(), session))
            .map(|state| state.serving_relays.clone())
            .unwrap_or_default();
        lifecycle
            .inner
            .setup
            .set_session_membership_for_test(&tenant, session, cached);
    }
    let existing = lifecycle
        .inner
        .relay_epochs
        .lock()
        .get(&relay)
        .map(|epoch| epoch.generation);
    let generation = existing.unwrap_or_else(|| {
        let generation = relay.0.max(1);
        lifecycle.on_relay_enrolled(relay, generation);
        generation
    });
    lifecycle.on_session_closed(tenant, session, relay, generation);
}

/// A bare setup with a tenant enrolled (its signing key), no relays and no
/// notify config — enough for reap tests, which never POST a webhook.
fn bare_setup() -> SessionSetup {
    SessionFixture {
        relays: vec![],
        ..Default::default()
    }
    .setup_only()
}

/// [`bare_setup`] with the tenant's webhook pointed at `url`, so a test can
/// observe what the ordered dispatch queue delivers.
fn setup_with_notify(url: String) -> SessionSetup {
    SessionFixture {
        relays: vec![],
        notify_url: Some(url),
        ..Default::default()
    }
    .setup_only()
}

/// A setup with relay 1 enrolled and the test tenant, plus a real two-player
/// session created on it — so its `session_relays`/`session_refs` membership is
/// recorded, the way a lifecycle full-close later retires. Returns the setup and
/// the created session id.
fn setup_with_relay_and_session() -> (SessionSetup, SessionId) {
    SessionFixture {
        players: plain_players(&[0, 1]),
        ..Default::default()
    }
    .build()
}

/// Stages a descriptor for `session` on each of `relays` — the declarative
/// per-relay assignment index the heartbeat's empty-roster accounting walks, so
/// a session absent from it is never considered for the empty reap.
fn stage_assignments(setup: &SessionSetup, session: SessionId, relays: &[RelayId]) {
    for &relay in relays {
        setup.descriptors().record(
            relay,
            SessionDescriptor {
                finalized_drops: false,
                tenant: tid(),
                session,
                peers: vec![],
                bounds: BufferBounds::new(1, 6).unwrap(),
                authority_order: relays.to_vec(),
                external_id: None,
                slot_refs: vec![],
                observer_slots: vec![],
                expected_slots: vec![],
                homed_slots: vec![],
                resumed: false,
                departed_slots: vec![],
                latency_estimate_ms: None,
                relay_regions: Vec::new(),
            },
        );
    }
}

/// A roster entry carrying retained load state alongside the connected slots —
/// [`presence_entry`] with the three accumulation fields named, which the
/// load-state tests vary one at a time.
fn heartbeat_load(
    session: SessionId,
    connected: &[u8],
    ever_connected: &[u8],
    started: &[u8],
    started_at_ms: Option<u64>,
) -> SessionPresence {
    SessionPresence {
        ever_connected: slots(ever_connected),
        started: slots(started),
        started_at_ms,
        ..presence_entry(&tid(), session, connected)
    }
}

mod close;
mod empty_reap;
mod notices;
mod reaps;
mod rehome;
mod sessions;
