//! Reliable replication and replay of session-long disconnect debits.

use std::time::{Duration, Instant};

use rally_point_proto::ids::{RelayId, SlotId};
use rally_point_proto::messages::{
    DisconnectBudgetState, DisconnectDebit, MeshControlFrame, mesh_control_frame,
};

use crate::key::SessionKey;
use crate::session::disconnect_budget::{DisconnectBudgets, EpisodeSnapshot};

use super::MeshState;
use super::links::MeshControlTx;

pub(crate) fn disconnect_budget_frame(
    budgets: &DisconnectBudgets,
    key: &SessionKey,
    request: bool,
    bootstrap_id: u64,
) -> MeshControlFrame {
    let now = Instant::now();
    let entries = if !request && bootstrap_id != 0 {
        budgets.snapshot_for_recovery(key, now)
    } else {
        budgets.snapshot(key, now)
    };
    MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::DisconnectBudgetState(
            DisconnectBudgetState {
                debits: entries
                    .into_iter()
                    .map(|entry| DisconnectDebit {
                        slot: u32::from(entry.slot.0),
                        connection_epoch: entry.connection_epoch,
                        // Never refund a fractional millisecond in an exchanged debit.
                        elapsed_ms: entry.elapsed.as_nanos().div_ceil(1_000_000) as u64,
                        complete: entry.complete,
                    })
                    .collect(),
                request,
                bootstrap_id,
                checkpoint_id: 0,
                checkpoint_ack: false,
            },
        )),
    }
}

/// Unknown relays request a baseline; known relays advertise ordinary state.
pub(crate) fn broadcast_disconnect_budget(mesh: &MeshState, key: &SessionKey) {
    let budgets = &mesh.session.disconnect_budgets;
    let request = !budgets.is_synced(key);
    super::fan_out_control(
        &mesh.links,
        key,
        disconnect_budget_frame(
            budgets,
            key,
            request,
            if request {
                budgets.bootstrap_id(key)
            } else {
                0
            },
        ),
    );
}

/// Broadcasts a complete ledger for one pending checkpoint. The waiter
/// retries this until every configured peer acknowledges the same id.
pub(crate) fn checkpoint_disconnect_budget(mesh: &MeshState, key: &SessionKey, id: u64) {
    if id == 0 {
        return;
    }
    let mut frame = disconnect_budget_frame(&mesh.session.disconnect_budgets, key, false, 0);
    if let Some(mesh_control_frame::Kind::DisconnectBudgetState(state)) = frame.kind.as_mut() {
        state.checkpoint_id = id;
    }
    super::fan_out_control(&mesh.links, key, frame);
}

pub(super) fn reconcile_disconnect_budget(
    budgets: &DisconnectBudgets,
    control_tx: &MeshControlTx,
    key: &SessionKey,
) {
    let request = !budgets.is_synced(key);
    let _ = control_tx.send(disconnect_budget_frame(
        budgets,
        key,
        request,
        if request {
            budgets.bootstrap_id(key)
        } else {
            0
        },
    ));
}

pub(super) fn receive_disconnect_budget(
    mesh: &MeshState,
    key: &SessionKey,
    peer: RelayId,
    state: DisconnectBudgetState,
) {
    let budgets = &mesh.session.disconnect_budgets;
    if state.checkpoint_ack {
        if state.request
            || state.bootstrap_id != 0
            || state.checkpoint_id == 0
            || !state.debits.is_empty()
        {
            return;
        }
        budgets.acknowledge_checkpoint(key, peer, state.checkpoint_id);
        return;
    }
    if state.checkpoint_id != 0 && (state.request || state.bootstrap_id != 0) {
        return;
    }
    let checkpoint_id = state.checkpoint_id;
    // Do not let an invalid slot produce a partial snapshot that is then
    // mistaken for a complete baseline.
    let Ok(entries) = state
        .debits
        .into_iter()
        .map(|entry| {
            Ok(EpisodeSnapshot {
                slot: SlotId(u8::try_from(entry.slot)?),
                connection_epoch: entry.connection_epoch,
                elapsed: Duration::from_millis(entry.elapsed_ms),
                complete: entry.complete,
            })
        })
        .collect::<Result<Vec<_>, std::num::TryFromIntError>>()
    else {
        return;
    };
    let reply_id = if state.request { 0 } else { state.bootstrap_id };
    if !budgets.merge_peer_snapshot(key, peer, &entries, Instant::now(), reply_id) {
        return;
    }
    if checkpoint_id != 0 {
        // The acknowledgement attests only that this valid snapshot merged;
        // it does not imply this peer has established its own baseline.
        super::fan_out_control(
            &mesh.links,
            key,
            MeshControlFrame {
                session: key.session.0,
                kind: Some(mesh_control_frame::Kind::DisconnectBudgetState(
                    DisconnectBudgetState {
                        debits: Vec::new(),
                        request: false,
                        bootstrap_id: 0,
                        checkpoint_id,
                        checkpoint_ack: true,
                    },
                )),
            },
        );
    }
    if state.request && state.bootstrap_id != 0 && budgets.is_synced(key) {
        // Responses can be broadcast: only the requester holds this random id.
        super::fan_out_control(
            &mesh.links,
            key,
            disconnect_budget_frame(budgets, key, false, state.bootstrap_id),
        );
    }
}
