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

pub(super) async fn ready_create(
    state: &CoordinatorState,
    tenant: &TenantId,
    original: SessionResponse,
) -> Result<SessionResponse, StatusCode> {
    wait_ready(state, tenant, original.session, |refs, endpoints| {
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
    })
    .await
}

pub(super) async fn ready_rehome(
    state: &CoordinatorState,
    tenant: &TenantId,
    session: SessionId,
    dead_relay: RelayId,
) -> Result<RelayEndpoint, StatusCode> {
    wait_ready(state, tenant, session, |_, endpoints| {
        // Rehome aliases follow later moves. Resolve after the wait, while the
        // assignment lock still ties the target to the acknowledged descriptors.
        let target = session::recorded_rehome(&state.setup, tenant, session, dead_relay)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        endpoints
            .get(&target.relay_id)
            .cloned()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)
    })
    .await
}

async fn wait_ready<T>(
    state: &CoordinatorState,
    tenant: &TenantId,
    session: SessionId,
    mut answer: impl FnMut(&SessionRefs, &BTreeMap<RelayId, RelayEndpoint>) -> Result<T, StatusCode>,
) -> Result<T, StatusCode> {
    let wait = async {
        loop {
            let changed = state.setup.descriptors().delivery().changed();
            let registry_changed = registry::changed(state.setup.registry());
            tokio::pin!(changed, registry_changed);
            changed.as_mut().enable();
            registry_changed.as_mut().enable();
            if let Some(value) = current_ready(state, tenant, session, &mut answer)? {
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
            Err(StatusCode::SERVICE_UNAVAILABLE)
        })
}

fn current_ready<T>(
    state: &CoordinatorState,
    tenant: &TenantId,
    session: SessionId,
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
    let mut endpoints = BTreeMap::new();
    for relay in serving {
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
