//! The writer half of a relay control connection: every coordinator→relay send.
//!
//! Owns the connect-time lead, the `biased` priority loop over the outbound
//! sources, the descriptor delta/full-set decision, reap coalescing, and the
//! per-send stall bound that tears down a relay which reads nothing.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::ws::Message;
use futures_util::SinkExt;
use rally_point_proto::control::{CoordinatorToRelay, DescriptorKey, SessionDescriptor};
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::ProtocolVersion;

use crate::descriptors::SlotClose;
use crate::registry;
use crate::session::SessionSetup;

use super::control::{ControlWrite, WriterSources};

/// Owns the write half and every coordinator→relay send. Leads with the
/// connect-time sequence in a fixed order — tenant keys, region beacons (when any),
/// the initial descriptor set, the initial mesh-peer set — strictly before any
/// steady-state push, then serves a `biased` priority loop: the drain exchange
/// first, then the latest-wins descriptor watch, the mesh-peer watch, the
/// flight-upload grants, the reap receiver, and the load-state questions last. Every
/// arm above the last is fleet machinery whose delay costs a relay correctness or a
/// session its teardown; a load-state question is tenant-driven, arrives in bursts,
/// and is cheap for its caller to repeat, so it yields to all of them — and a
/// question whose waiter has since gone is dropped rather than sent. Returns (ending
/// the connection) when a send stalls or errors, a watch closes on shutdown, or the
/// reader ends.
///
/// The connect-time descriptor set is always the full set (it seeds the relay's
/// baseline), but the steady-state descriptor arm sends only what changed — a
/// [`CoordinatorToRelay::DescriptorDelta`] — to a relay whose `negotiated` version
/// supports it, falling back to the full set for an older relay. `last_sent` tracks
/// the set the relay currently holds so each delta diffs against exactly that.
pub(super) async fn run_writer(
    write_half: &mut ControlWrite,
    sources: &mut WriterSources,
    relay_id: RelayId,
    liveness_timeout: Duration,
    negotiated: ProtocolVersion,
) {
    // Split the sources into the individual channels + payloads the loop drives;
    // they are disjoint fields, so each arm borrows its own.
    let WriterSources {
        descriptors: rx,
        mesh_peers: mesh_peers_rx,
        reaps,
        load_state: load_state_rx,
        attest,
        drain: drain_rx,
        grants: grants_rx,
        tenant_keys,
        beacon_targets,
    } = sources;
    // Tenant keys first — a descriptor is meaningless to a relay that cannot yet
    // verify the session's client tokens.
    let keys_frame = control_frame(&CoordinatorToRelay::TenantKeys {
        keys: tenant_keys.to_vec(),
    });
    if !writer_send(
        write_half,
        keys_frame,
        relay_id,
        liveness_timeout,
        "tenant-keys",
    )
    .await
    {
        return;
    }
    // Region beacons only when the coordinator configures regions: a region-blind
    // fleet has none to measure, so the frame stays off its connections entirely.
    if !beacon_targets.is_empty() {
        let beacons_frame = control_frame(&CoordinatorToRelay::RegionBeacons {
            beacons: beacon_targets.to_vec(),
        });
        if !writer_send(
            write_half,
            beacons_frame,
            relay_id,
            liveness_timeout,
            "region-beacons",
        )
        .await
        {
            return;
        }
    }
    // The initial descriptor and mesh-peer re-syncs. Clone each set out of its watch
    // borrow before awaiting — a watch borrow must never be held across an await —
    // and mark it seen so the steady-state arm does not redundantly re-push it.
    //
    // The connect-time descriptor re-sync is always the full set, whatever the
    // negotiated version: it is the baseline every later delta on this connection
    // diffs against, so `last_sent` is seeded from it before it goes out.
    let initial = rx.borrow_and_update().clone();
    let mut last_sent = index_descriptors(&initial);
    if !writer_send(
        write_half,
        descriptors_frame(initial),
        relay_id,
        liveness_timeout,
        "descriptor",
    )
    .await
    {
        return;
    }
    let initial_peers = mesh_peers_rx.borrow_and_update().clone();
    if !writer_send(
        write_half,
        control_frame(&CoordinatorToRelay::MeshPeers {
            peers: initial_peers,
        }),
        relay_id,
        liveness_timeout,
        "mesh-peers",
    )
    .await
    {
        return;
    }

    loop {
        tokio::select! {
            biased;

            directive = drain_rx.recv() => {
                // The reader marked the relay draining and asked for the exchange's
                // send half. `None` means the reader ended, so this half ends too.
                if directive.is_none() {
                    break;
                }
                // Set before ack. `borrow_and_update` reads the latest set — which
                // already reflects every descriptor staged before the reader's
                // assignment-locked mark — and marks it seen so the descriptor arm
                // does not redundantly re-push the same set right after. The drain
                // exchange always pushes the full set (rare, and self-verifying on
                // the relay), whatever the negotiated version, and refreshes the
                // baseline from it so a later steady-state delta diffs against what
                // the relay actually now holds.
                let set = rx.borrow_and_update().clone();
                if !writer_send(
                    write_half,
                    descriptors_frame(set.clone()),
                    relay_id,
                    liveness_timeout,
                    "descriptor",
                )
                .await
                {
                    break;
                }
                last_sent = index_descriptors(&set);
                if !writer_send(
                    write_half,
                    control_frame(&CoordinatorToRelay::DrainAck),
                    relay_id,
                    liveness_timeout,
                    "drain-ack",
                )
                .await
                {
                    break;
                }
            }
            changed = rx.changed() => {
                if changed.is_err() {
                    break; // the outbox was dropped: coordinator shutting down
                }
                let set = rx.borrow_and_update().clone();
                if !send_descriptor_change(
                    write_half,
                    &mut last_sent,
                    set,
                    negotiated,
                    relay_id,
                    liveness_timeout,
                )
                .await
                {
                    break;
                }
            }
            changed = mesh_peers_rx.changed() => {
                if changed.is_err() {
                    break; // the registry's mesh-peer channel was dropped: shutting down
                }
                let peers = mesh_peers_rx.borrow_and_update().clone();
                if !writer_send(
                    write_half,
                    control_frame(&CoordinatorToRelay::MeshPeers { peers }),
                    relay_id,
                    liveness_timeout,
                    "mesh-peers",
                )
                .await
                {
                    break;
                }
            }
            grant = grants_rx.recv() => {
                // A ready flight-upload grant or refusal the reader (or a presign it
                // spawned) minted. `None` means every sender is gone — the reader ended
                // and no presign is still in flight — so this half ends too.
                let Some(grant) = grant else { break };
                if !writer_send(
                    write_half,
                    control_frame(&grant),
                    relay_id,
                    liveness_timeout,
                    "flight-grant",
                )
                .await
                {
                    break;
                }
            }
            first = reaps.recv() => {
                // The reap outbox never closes on its own (the sender lives in the
                // shared outbox), so `None` here would only mean a replaced
                // subscription — treat it as end-of-stream and stop selecting.
                let Some(first) = first else { break };
                if !send_coalesced_reaps(write_half, reaps, first, relay_id, liveness_timeout).await
                {
                    break;
                }
            }
            ask = load_state_rx.recv() => {
                // A load-state question for this relay, from a tenant read blocked on
                // the answer. `None` means the broker replaced this connection's
                // channel (a reconnect took over) or is gone, so this half ends too.
                //
                // Ranked LAST deliberately. Every arm above it is the fleet's own
                // machinery — a drain exchange, the descriptor set, the mesh-peer
                // set, an upload grant, a reap directive — where a delayed frame
                // costs a relay correctness or a session its teardown. A load-state
                // read is tenant-driven, arrives in bursts, and is cheap to repeat,
                // so it yields to all of them.
                let Some(ask) = ask else { break };
                // A question nobody is waiting for is not worth a frame or the
                // relay's fence: the read that made it timed out, or its HTTP
                // request was cancelled, and either retires the request as it
                // leaves. Queued asks outlive their waiters precisely because this
                // arm yields to everything above it.
                if !attest.is_pending(ask.request_id) {
                    continue;
                }
                let frame = control_frame(&CoordinatorToRelay::LoadStateRequest {
                    tenant: ask.tenant,
                    session: ask.session,
                    request_id: ask.request_id,
                });
                if !writer_send(write_half, frame, relay_id, liveness_timeout, "load-state-request")
                    .await
                {
                    break;
                }
            }
        }
    }
}

/// Coalesces a burst of reap nudges into one `CloseSlot` frame per session, then
/// sends them. When the reap arm wakes with `first`, every other nudge already
/// queued is drained and deduped by `(tenant, session)` keeping the **last** — each
/// nudge carries the merged-so-far slot union for its session, so the last is the
/// most complete — collapsing a teardown storm's hundreds of redundant nudges into
/// at most one frame per session per wake. Returns whether the connection should
/// keep running.
async fn send_coalesced_reaps(
    write_half: &mut ControlWrite,
    reaps: &mut tokio::sync::mpsc::UnboundedReceiver<SlotClose>,
    first: SlotClose,
    relay_id: RelayId,
    liveness_timeout: Duration,
) -> bool {
    let mut received: u64 = 1;
    let mut latest: std::collections::BTreeMap<(String, u64), SlotClose> =
        std::collections::BTreeMap::new();
    latest.insert((first.tenant.as_ref().to_owned(), first.session.0), first);
    while let Ok(next) = reaps.try_recv() {
        received += 1;
        latest.insert((next.tenant.as_ref().to_owned(), next.session.0), next);
    }
    let unique = latest.len() as u64;
    crate::metrics::reap_nudges_coalesced(received - unique);
    for (_, close) in latest {
        let frame = control_frame(&CoordinatorToRelay::CloseSlot {
            tenant: close.tenant,
            session: close.session,
            slots: close.slots,
        });
        if !writer_send(write_half, frame, relay_id, liveness_timeout, "close-slot").await {
            return false;
        }
        crate::metrics::reap_directives_sent(1);
    }
    true
}

/// Serializes a coordinator→relay control message into its tagged JSON text frame.
fn control_frame(message: &CoordinatorToRelay) -> Message {
    let json =
        serde_json::to_string(message).expect("a coordinator control frame always serializes");
    Message::Text(json.into())
}

/// Wall clock as unix epoch milliseconds — the staging stamp a descriptor push
/// carries so the relay can measure its apply lag.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Builds a `Descriptors` control frame, stamping the coordinator's wall-clock at
/// the moment the set snapshot leaves the outbox so the relay can measure how far
/// its apply lags staging. Called at each `borrow_and_update` site — the
/// connect-time resync, the steady-state change arm, and the drain exchange's set
/// push — so every descriptor push carries a fresh stamp.
fn descriptors_frame(descriptors: Vec<SessionDescriptor>) -> Message {
    control_frame(&CoordinatorToRelay::Descriptors {
        descriptors,
        staged_at_unix_ms: Some(now_unix_ms()),
    })
}

/// Emits one steady-state descriptor change on the write half. A relay whose
/// negotiated version supports deltas receives only what changed since the last
/// send — a [`CoordinatorToRelay::DescriptorDelta`] diffed against `last_sent` by
/// `(tenant, session)` and by value (so an in-place descriptor mutation surfaces as
/// an upsert) — and nothing at all when the set is unchanged. An older relay
/// receives the whole set, exactly as every steady-state push did before deltas
/// existed. `last_sent` advances to the current set only after a delta send
/// succeeds, so it always mirrors what the relay actually holds. Returns whether the
/// connection should keep running.
async fn send_descriptor_change(
    write_half: &mut ControlWrite,
    last_sent: &mut std::collections::HashMap<DescriptorKey, SessionDescriptor>,
    set: Vec<SessionDescriptor>,
    negotiated: ProtocolVersion,
    relay_id: RelayId,
    liveness_timeout: Duration,
) -> bool {
    if negotiated < ProtocolVersion::DESCRIPTOR_DELTA_MIN {
        // An older relay decodes a DescriptorDelta as an unknown frame and would
        // silently drift, so it always gets the whole current set. Its baseline is
        // never diffed, so there is nothing to advance.
        if !writer_send(
            write_half,
            descriptors_frame(set),
            relay_id,
            liveness_timeout,
            "descriptor",
        )
        .await
        {
            return false;
        }
        crate::metrics::descriptor_full_set_sent();
        return true;
    }

    let (upserts, removals) = diff_descriptors(last_sent, &set);
    if upserts.is_empty() && removals.is_empty() {
        // The relay already holds exactly this set — a coalesced wake that produced
        // no net change. An empty delta would be pure overhead, so send nothing and
        // leave the metrics untouched.
        return true;
    }
    let upsert_count = upserts.len();
    let removal_count = removals.len();
    let frame = control_frame(&CoordinatorToRelay::DescriptorDelta {
        staged_at_unix_ms: Some(now_unix_ms()),
        upserts,
        removals,
    });
    if !writer_send(
        write_half,
        frame,
        relay_id,
        liveness_timeout,
        "descriptor-delta",
    )
    .await
    {
        return false;
    }
    // The send landed, so the relay now holds this set: advance the baseline to it,
    // keeping the update ordered strictly after the successful send.
    *last_sent = index_descriptors(&set);
    crate::metrics::descriptor_delta_sent(upsert_count, removal_count);
    true
}

/// Diffs the descriptor set the relay currently holds (`last_sent`, keyed by
/// `(tenant, session)`) against the coordinator's `current` set, producing the
/// upserts and removals a [`CoordinatorToRelay::DescriptorDelta`] carries. A session
/// present in `current` is an upsert when the relay holds no descriptor for it or
/// holds one that differs by value — so an in-place mutation (a rehomed
/// `homed_slots`, say) surfaces even though its key is unchanged. A session the
/// relay holds but `current` no longer names is a removal.
pub(super) fn diff_descriptors(
    last_sent: &std::collections::HashMap<DescriptorKey, SessionDescriptor>,
    current: &[SessionDescriptor],
) -> (Vec<SessionDescriptor>, Vec<DescriptorKey>) {
    let mut upserts = Vec::new();
    let mut current_keys = std::collections::HashSet::with_capacity(current.len());
    for descriptor in current {
        let key = DescriptorKey {
            tenant: descriptor.tenant.clone(),
            session: descriptor.session,
        };
        if last_sent.get(&key) != Some(descriptor) {
            upserts.push(descriptor.clone());
        }
        current_keys.insert(key);
    }
    let removals = last_sent
        .keys()
        .filter(|key| !current_keys.contains(*key))
        .cloned()
        .collect();
    (upserts, removals)
}

/// Indexes a full descriptor set by `(tenant, session)` — the baseline a later
/// [`CoordinatorToRelay::DescriptorDelta`] diffs against. Owns a clone of each
/// descriptor so the baseline is a stable snapshot of exactly what the relay was
/// sent, independent of the coordinator's live set.
pub(super) fn index_descriptors(
    set: &[SessionDescriptor],
) -> std::collections::HashMap<DescriptorKey, SessionDescriptor> {
    set.iter()
        .map(|d| {
            (
                DescriptorKey {
                    tenant: d.tenant.clone(),
                    session: d.session,
                },
                d.clone(),
            )
        })
        .collect()
}

/// Sends one frame on the write half, racing a fixed per-send stall bound measured
/// from this send's start and recording the send's duration. The bound is fixed
/// (not a reader-refreshed deadline) so a relay that keeps heartbeating but stops
/// reading — refreshing the reader's deadline forever — still cannot hold its
/// registry entry open: its stalled send trips this bound instead. Returns whether
/// the connection should keep running: `false` on a stall past `liveness_timeout`
/// or a socket error, which ends it. `what` names the frame for the log line.
async fn writer_send(
    write_half: &mut ControlWrite,
    message: Message,
    relay_id: RelayId,
    liveness_timeout: Duration,
    what: &str,
) -> bool {
    let started = tokio::time::Instant::now();
    let outcome = tokio::time::timeout(liveness_timeout, write_half.send(message)).await;
    crate::metrics::observe_control_send(started.elapsed().as_millis() as u64);
    match outcome {
        Ok(Ok(())) => true,
        Ok(Err(error)) => {
            tracing::debug!(%error, relay_id = relay_id.0, "{what} push failed");
            false
        }
        Err(_elapsed) => {
            tracing::info!(
                relay_id = relay_id.0,
                "{what} push stalled past the liveness deadline; dropping",
            );
            crate::metrics::control_connection_ended("write_stall");
            false
        }
    }
}

/// Applies the synchronous part of a relay's coordinated-drain exchange after it
/// sent a [`RelayToCoordinator::Draining`]: mark it ineligible for new assignments,
/// returning whether the mark applied (so the caller then directs the writer to send
/// the set + ack).
///
/// The mark is taken under the assignment lock ([`SessionSetup::lock_assignment`]),
/// so it linearizes against any in-flight `create_session`/`rehome`: after it lands,
/// every session that will ever name this relay has already staged its descriptor in
/// the relay's outbox, so the set the writer then reads is provably complete.
///
/// A mark that does **not** apply — a stale generation, meaning a newer connection
/// re-enrolled this relay (its fresh enroll cleared the flag) — draws no ack: that
/// live connection runs its own drain exchange when its `Draining` arrives.
pub(super) fn apply_drain_mark(setup: &SessionSetup, relay_id: RelayId, generation: u64) -> bool {
    let applied = {
        let _assign = setup.lock_assignment();
        registry::mark_draining(setup.registry(), relay_id, generation)
    };
    if !applied {
        // A stale connection's Draining: the live successor acks its own drain.
        tracing::debug!(
            relay_id = relay_id.0,
            "ignoring a Draining frame from a stale control connection",
        );
        return false;
    }
    let region = registry::entry(setup.registry(), relay_id).and_then(|entry| entry.region);
    crate::metrics::relay_drained(region.as_ref());
    tracing::info!(relay_id = relay_id.0, "relay draining; sending set + ack");
    true
}
