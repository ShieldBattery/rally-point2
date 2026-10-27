//! The bounded cumulative wait for each disconnected slot.

use std::time::{Duration, Instant};

use rally_point_proto::messages::{DisconnectBudget, DisconnectBudgets};

use crate::key::SessionKey;
use crate::mesh::MeshState;

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

/// Periodically shares cumulative measurements so peers can recover the ledger.
pub async fn run_disconnect_budget_watch(mesh: MeshState) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        for key in mesh.session.disconnect_budgets.keys() {
            let _ = mesh.session.gates.with_ingress(&key, || {
                crate::mesh::broadcast_disconnect_budget(&mesh, &key);
            });
        }
    }
}
