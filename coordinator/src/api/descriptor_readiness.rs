//! Releases connection details only after capable homes install current descriptors.

use std::collections::BTreeMap;

use axum::http::StatusCode;
use rally_point_proto::control::{
    CAPABILITY_DESCRIPTOR_ACK_V1, RelayEndpoint, RelayRegionLabel, SessionResponse, SlotHome,
    TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId};

use super::CoordinatorState;
use crate::session::SessionRefs;
use crate::{registry, session};

pub(super) enum ReadinessError {
    TimedOut,
    Unavailable,
}

#[derive(Clone, Copy)]
enum ReadinessScope {
    AllHomes,
    Rehome(RelayId),
}

pub(super) async fn ready_create(
    state: &CoordinatorState,
    tenant: &TenantId,
    original: SessionResponse,
) -> Result<SessionResponse, ReadinessError> {
    wait_ready(
        state,
        tenant,
        original.session,
        ReadinessScope::AllHomes,
        |refs, endpoints| {
            // Tokens authorize slots, not homes. Retain their identity while refreshing
            // topology: a rehome during this wait must not strand every keyed retry on
            // the original cached endpoints.
            let primary = if endpoints.contains_key(&original.home_relay.relay_id) {
                original.home_relay.relay_id
            } else {
                *refs
                    .homes
                    .values()
                    .next()
                    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
            };
            let mut response = original.clone();
            response.home_relay = endpoints
                .get(&primary)
                .cloned()
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
            response.slot_homes.clear();
            for token in &response.tokens {
                let home = refs
                    .homes
                    .get(&token.slot)
                    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
                if *home != primary {
                    response.slot_homes.push(SlotHome {
                        slot: token.slot,
                        relay: endpoints
                            .get(home)
                            .cloned()
                            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?,
                    });
                }
            }
            response.slot_homes.sort_by_key(|home| home.slot);
            response.relay_regions = refs
                .relay_regions
                .iter()
                .filter_map(|(&relay_id, region)| {
                    region
                        .clone()
                        .map(|region| RelayRegionLabel { relay_id, region })
                })
                .collect();
            Ok(response)
        },
    )
    .await
}

pub(super) async fn ready_rehome(
    state: &CoordinatorState,
    tenant: &TenantId,
    session: SessionId,
    dead_relay: RelayId,
) -> Result<RelayEndpoint, StatusCode> {
    wait_ready(
        state,
        tenant,
        session,
        ReadinessScope::Rehome(dead_relay),
        |_, endpoints| {
            // The rehome scope contains only the current, checked target. Its
            // readiness check and this response share the assignment lock.
            endpoints
                .values()
                .next()
                .cloned()
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)
        },
    )
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

async fn wait_ready<T>(
    state: &CoordinatorState,
    tenant: &TenantId,
    session: SessionId,
    scope: ReadinessScope,
    mut answer: impl FnMut(&SessionRefs, &BTreeMap<RelayId, RelayEndpoint>) -> Result<T, StatusCode>,
) -> Result<T, ReadinessError> {
    let wait = async {
        loop {
            let changed = state.setup.descriptors().delivery().changed();
            let registry_changed = registry::changed(state.setup.registry());
            tokio::pin!(changed, registry_changed);
            changed.as_mut().enable();
            registry_changed.as_mut().enable();
            if let Some(value) = current_ready(state, tenant, session, scope, &mut answer)
                .map_err(|_| ReadinessError::Unavailable)?
            {
                return Ok(value);
            }
            tokio::select! {
                () = changed => {},
                () = registry_changed => {},
            }
        }
    };
    tokio::time::timeout(state.descriptor_ack_timeout, wait)
        .await
        .unwrap_or_else(|_| {
            tracing::warn!(
                tenant = tenant.as_ref(),
                session = session.0,
                "waiting for descriptor installation timed out; refusing with a retryable 503"
            );
            Err(ReadinessError::TimedOut)
        })
}

fn current_ready<T>(
    state: &CoordinatorState,
    tenant: &TenantId,
    session: SessionId,
    scope: ReadinessScope,
    answer: &mut impl FnMut(&SessionRefs, &BTreeMap<RelayId, RelayEndpoint>) -> Result<T, StatusCode>,
) -> Result<Option<T>, StatusCode> {
    let setup = &state.setup;
    let _assignment = setup.lock_assignment();
    let refs =
        session::session_refs(setup, tenant, session).ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let serving = setup.serving_relays(tenant, session);
    if serving.is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let required = match scope {
        ReadinessScope::AllHomes => serving,
        ReadinessScope::Rehome(dead_relay) => {
            // Resolve aliases on every check: another rehome can move the target
            // while this request waits. Other homes may also be disconnected;
            // their recovery must not prevent this group from reconnecting.
            let Some(target) = session::recorded_rehome(setup, tenant, session, dead_relay) else {
                return Ok(None);
            };
            if !serving.contains(&target.relay_id) {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            vec![target.relay_id]
        }
    };
    let mut endpoints = BTreeMap::new();
    for relay in required {
        let Some((entry, generation)) = registry::entry_with_generation(setup.registry(), relay)
        else {
            return Ok(None);
        };
        if refs.relay_certs.get(&relay) != Some(&registry::cert_fingerprint(&entry.cert_der)) {
            return Ok(None);
        }
        let Some(descriptor) = setup
            .descriptors()
            .current_descriptor(relay, tenant, session)
        else {
            return Ok(None);
        };
        // Absence of the capability preserves legacy admission without a timeout.
        // A capable connection must prove the exact current descriptor, including
        // changes committed while this request was waiting.
        if entry
            .capabilities
            .iter()
            .any(|c| c == CAPABILITY_DESCRIPTOR_ACK_V1)
            && !setup
                .descriptors()
                .delivery()
                .is_ready(relay, generation, &descriptor)
        {
            return Ok(None);
        }
        endpoints.insert(relay, RelayEndpoint::from(&entry));
    }
    answer(&refs, &endpoints).map(Some)
}
