//! The bounded cumulative wait for each disconnected slot.

use std::time::{Duration, Instant};

use rally_point_proto::messages::{DisconnectBudget, DisconnectBudgets};

use crate::key::SessionKey;
use crate::mesh::MeshState;

use super::Sessions;

pub const DISCONNECT_BUDGET_CHECK_INTERVAL: Duration = Duration::from_millis(250);

/// Attempts exhausted drops through the same generation-bound finalization as a manual drop.
pub(super) fn expire_disconnect_budgets(sessions: &Sessions, mesh: &MeshState, key: &SessionKey) {
    if !mesh.session.disconnect_budgets.is_synced(key) {
        return;
    }
    for slot in mesh.session.disconnect_budgets.running_slots(key) {
        if mesh
            .session
            .disconnect_budgets
            .exhausted(key, slot, Instant::now())
        {
            super::honor_drop_request(sessions, mesh, key, slot, u32::MAX);
        }
    }
}

pub(crate) fn disconnect_budget_status(mesh: &MeshState, key: &SessionKey) -> DisconnectBudgets {
    DisconnectBudgets {
        budgets: mesh
            .session
            .disconnect_budgets
            .status(key, Instant::now())
            .into_iter()
            .map(|status| DisconnectBudget {
                slot: u32::from(status.slot.0),
                remaining_ms: status.remaining.as_millis() as u64,
                running: status.running,
            })
            .collect(),
    }
}

/// Rechecks admission independently of this sweep: a delayed task cannot extend a budget.
pub async fn run_disconnect_budget_watch(sessions: Sessions, mesh: MeshState) {
    let mut tick = tokio::time::interval(DISCONNECT_BUDGET_CHECK_INTERVAL);
    let mut heartbeat = 0u8;
    loop {
        tick.tick().await;
        for key in mesh.session.disconnect_budgets.keys() {
            let _ = mesh.session.gates.with_ingress(&key, || {
                if heartbeat == 0 {
                    crate::mesh::broadcast_disconnect_budget(&mesh, &key);
                }
                expire_disconnect_budgets(&sessions, &mesh, &key);
            });
        }
        heartbeat = (heartbeat + 1) % 4;
    }
}
