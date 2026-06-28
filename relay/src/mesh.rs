//! The relay mesh: peer-relay links and session-level topological dedup.
//!
//! A relay's client edge ([`routing`]) fans each validated turn out to the
//! session's local slots. The mesh adds a second fan-out path: to connected peer
//! relays, so a turn one relay receives from a local client reaches every other
//! relay's local clients too. Each relay↔relay link is a [`MeshLink`] — one QUIC
//! connection shared across every game both relays jointly serve, with per-session
//! transport state.
//!
//! Because a turn can reach a relay by more than one mesh path (A→B directly, and
//! A→C→B), the relay dedups **topologically**: it forwards each turn to its local
//! clients exactly once, on whichever copy arrives first. [`MeshSeen`] is that
//! session-level dedup — distinct from the per-link [`Dedup`] on each mesh link,
//! which drops redundant copies *within* one link. The origin `(slot, seq)`
//! identity is stable across the mesh because no hop restamps it, so the two
//! dedup layers collapse duplicates at different granularities without conflict.
//!
//! Mesh-link establishment (lower relay-id dials higher, one side dials to avoid
//! the two-way race) and authenticated relay tokens are deferred: the first
//! increment carries tenant-binding via a preamble, with no auth token. Real relay
//! auth lands with the coordinator (Phase 3).

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;
use tokio::sync::mpsc;

use crate::routing::{self, SessionKey};

/// Session-level topological dedup: records which `(slot, seq)` turns have
/// already been forwarded to this session's local clients, so a turn arriving
/// via a second mesh path is dropped rather than delivered twice.
///
/// Mirrors the per-link `Dedup`'s structure (a contiguous delivered prefix plus
/// an `ahead` set per slot) but serves a different purpose: `Dedup` is
/// receive-side (it gates delivery to the link's consumer), while `MeshSeen` is
/// forward-gate-side (it gates fan-out to local clients). It has no receive
/// window — a turn far ahead of the prefix is simply new, not rejected — because
/// the mesh trusts its peer relays and the origin seqs are client-assigned.
///
/// The prefix-slide lets it forget old seqs without unbounded growth: a late
/// redundant copy of a retired seq is dropped as `<= delivered_through` rather
/// than re-checked against a growing set.
#[derive(Default)]
pub struct MeshSeen {
    /// Per-slot forward-gate state.
    slots: HashMap<SlotId, SlotSeen>,
}

/// One slot's topological-dedup state.
struct SlotSeen {
    /// Top of the contiguous forwarded prefix; `None` until seq 0 is forwarded.
    forwarded_through: Option<u64>,
    /// Forwarded seqs above the prefix, kept until the gaps below them fill.
    /// Mirrors `Dedup::SlotDedup::ahead` so out-of-order mesh arrival doesn't
    /// cause a false "new" on a seq that was already forwarded out of order.
    ahead: BTreeSet<u64>,
}

/// Whether a `(slot, seq)` has already been forwarded to local clients.
#[derive(Debug, PartialEq, Eq)]
pub enum Seen {
    /// First time this `(slot, seq)` has been forwarded — deliver it to locals.
    New,
    /// Already forwarded (at/below the contiguous prefix, or seen out of order).
    Duplicate,
}

impl MeshSeen {
    /// Creates an empty topological-dedup set for one session.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `(slot, seq)` as forwarded and reports whether it's new or a
    /// duplicate. A duplicate is dropped silently — the turn already reached
    /// this relay's local clients via an earlier mesh path.
    pub fn mark_forwarded(&mut self, slot: SlotId, seq: u64) -> Seen {
        let state = self.slots.entry(slot).or_insert_with(|| SlotSeen {
            forwarded_through: None,
            ahead: BTreeSet::new(),
        });

        let base = state.forwarded_through.map_or(0, |t| t + 1);

        if seq < base {
            return Seen::Duplicate;
        }
        if !state.ahead.insert(seq) {
            return Seen::Duplicate;
        }

        // Absorb any now-contiguous run into the forwarded prefix, so old seqs
        // can be forgotten.
        let mut next = base;
        while state.ahead.remove(&next) {
            state.forwarded_through = Some(next);
            next += 1;
        }
        Seen::New
    }
}

/// Per-session topological-dedup registries: each `SessionKey` → the `MeshSeen`
/// for that session, shared across all slot links + mesh-link tasks so every
/// ingress — local client or mesh peer — marks before forwarding to locals.
///
/// This is the guard against echo loops: a turn relay A fanned out to relay B
/// comes back to A via the mesh, and without a shared `MeshSeen` A would deliver
/// it to its local clients a second time — a duplicate turn into a lockstep slot,
/// a desync. With the registry, A's `run_slot_link` marked the turn when it
/// validated it, so the mesh echo is caught as `Duplicate` and dropped.
pub type SeenRegistries = Arc<Mutex<HashMap<SessionKey, MeshSeen>>>;

/// Creates an empty seen-registry for a relay with no sessions yet.
pub fn new_seen_registries() -> SeenRegistries {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Marks `(slot, seq)` as forwarded for `key`'s session, returning whether it's
/// new or a duplicate. Used by both `run_slot_link` (local-client ingress) and
/// `run_mesh_link` (mesh-peer ingress) before fanning out to local clients.
pub fn mark_seen(registries: &SeenRegistries, key: &SessionKey, slot: SlotId, seq: u64) -> Seen {
    let mut roster = registries.lock().expect("seen registries lock poisoned");
    roster
        .entry(key.clone())
        .or_default()
        .mark_forwarded(slot, seq)
}

/// Removes a session's seen registry (the session has ended). Idempotent.
pub fn deregister_seen(registries: &SeenRegistries, key: &SessionKey) {
    let mut roster = registries.lock().expect("seen registries lock poisoned");
    roster.remove(key);
}

/// Live mesh links for every session on this relay: each `SessionKey` → the
/// channels that reach each connected peer-relay's mesh-link task for that
/// session. A turn fanned out to the mesh goes to every peer relay serving that
/// session — including the one it arrived from, which is why the sender marks
/// `MeshSeen` before forwarding to locals: the echo is caught and dropped there.
///
/// Shared across all connection + mesh-link tasks. A plain (non-async) mutex is
/// deliberate: every critical section is a short, await-free roster edit —
/// senders are cloned out before any send — so the lock is never held across a
/// turn's delivery, mirroring [`routing::Sessions`].
pub type MeshLinks = Arc<Mutex<HashMap<SessionKey, Vec<MeshForwardTx>>>>;

/// Creates an empty mesh-link registry for a relay with no peer-relay links yet.
/// Used by the server edge and tests to obtain a `MeshLinks` without referencing
/// the private `MeshForwardTx` type.
pub fn new_mesh_links() -> MeshLinks {
    Arc::new(Mutex::new(HashMap::new()))
}

/// The channel sink delivering payloads to one peer-relay's mesh-link task for
/// one session.
type MeshForwardTx = mpsc::Sender<Payload>;

/// What the mesh roster holds for one connected peer-relay link on one session.
pub struct MeshLinkEntry {
    /// Channel to push payloads to this peer-relay's mesh-link task.
    pub forward: MeshForwardTx,
}

/// The receiving end handed to a mesh-link task: the queue of turns to forward
/// to the peer relay, plus the session it serves.
pub struct MeshInbox {
    pub forward_rx: mpsc::Receiver<Payload>,
}

/// Adds a mesh forward channel for `key`, returning the inbox its mesh-link task
/// drains. Used when a new peer-relay link joins a session.
pub fn register_mesh_link(links: &MeshLinks, key: SessionKey) -> MeshInbox {
    let (tx, rx) = mpsc::channel(routing::FORWARD_CAPACITY);
    {
        let mut roster = links.lock().expect("mesh links lock poisoned");
        roster.entry(key).or_default().push(tx);
    }
    MeshInbox { forward_rx: rx }
}

/// Removes all mesh forward channels for `key` (the peer-relay link for that
/// session has closed). Idempotent.
pub fn deregister_mesh_link(links: &MeshLinks, key: &SessionKey) {
    let mut roster = links.lock().expect("mesh links lock poisoned");
    roster.remove(key);
}

/// Delivers `payload` to every peer-relay mesh link serving `key`, without ever
/// blocking on a slow peer. Mirrors [`routing::fan_out`] but for mesh links
/// instead of local slots.
///
/// Fans out to **all** mesh links for the session — including the one a turn
/// arrived on. The echo is caught not by excluding the ingress link (there's no
/// link id in the registry to exclude) but by `MeshSeen`: every ingress — local
/// client or mesh peer — marks `(slot, seq)` before forwarding to locals, so the
/// echo arrives, is seen as `Duplicate`, and is dropped before it reaches local
/// clients. This is why the flood-with-dedup model requires marking on *every*
/// forward-to-local, not just mesh ingress.
pub fn fan_out_to_mesh(links: &MeshLinks, key: &SessionKey, payload: Payload) {
    let targets: Vec<MeshForwardTx> = {
        let roster = links.lock().expect("mesh links lock poisoned");
        match roster.get(key) {
            Some(mesh_txs) => mesh_txs.clone(),
            None => Vec::new(),
        }
    };
    for tx in targets {
        // A full mesh forward queue is a slow peer relay — signal it later, for
        // now just drop (the per-link transport re-carries what was already sent).
        let _ = tx.try_send(payload.clone());
    }
}

/// Drives one session's mesh-link state on a shared [`MeshLink`].
///
/// A near-twin of [`routing::run_slot_link`] but for the mesh edge:
///
/// - **Receives** turns from the peer relay via `MeshLink::recv()`, which
///   demultiplexes by session. Only turns for `key`'s session are processed;
///   others are forwarded to their own session's driver (in the full multi-
///   session driver; this single-session variant filters to `key`).
/// - **No `validate_turn`** — the mesh trusts its peer relay. Validation
///   happened at the ingress client edge and is never repeated at a mesh hop.
/// - **Marks `MeshSeen`** before fanning out to local clients, so an echo (the
///   turn re-arriving via the mesh after being fanned out) is caught as
///   `Duplicate` and dropped.
/// - **Fans out** to both local slots and other mesh links, so a turn from a
///   peer relay reaches this relay's local clients and any *other* connected
///   peer relays.
///
/// This single-session variant filters `MeshLink::recv()` to `key`'s session —
/// a multi-session driver would dispatch to per-session state. Sufficient for the
/// first `C–S===S–C` E2E (one game per relay-pair).
pub async fn run_mesh_link_session(
    mut link: rally_point_transport::MeshLink,
    key: SessionKey,
    inbox: MeshInbox,
    sessions: routing::Sessions,
    mesh_links: MeshLinks,
    seen_registries: SeenRegistries,
) {
    let MeshInbox { mut forward_rx } = inbox;

    // Open this session's transport state on the mesh link (both ends).
    link.open_session(rally_point_proto::ids::SessionId(key.session.0));
    let mut flush_deadline = tokio::time::Instant::now() + routing::FLUSH_INTERVAL;

    loop {
        tokio::select! {
            received = link.recv() => {
                match received {
                    Ok((sid, r)) if sid.0 == key.session.0 => {
                        for payload in r.fresh {
                            let slot = rally_point_proto::ids::SlotId(payload.slot as u8);
                            // Mark before fanning out to locals — the echo guard.
                            if mark_seen(&seen_registries, &key, slot, payload.seq)
                                == Seen::Duplicate
                            {
                                continue;
                            }
                            // Fan out to local clients (all slots except source).
                            routing::fan_out(&sessions, &key, slot, payload.clone());
                            // Fan out to other mesh links (echo caught by their MeshSeen).
                            fan_out_to_mesh(&mesh_links, &key, payload);
                        }
                    }
                    Ok((_other, _)) => {
                        // A datagram for a different session — this single-session
                        // variant ignores it. A multi-session driver would dispatch.
                        continue;
                    }
                    Err(error) => {
                        tracing::info!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            %error,
                            "mesh link closed",
                        );
                        break;
                    }
                }
            }
            forwarded = forward_rx.recv() => {
                match forwarded {
                    Some(payload) => {
                        let session_id = rally_point_proto::ids::SessionId(key.session.0);
                        if let Err(error) = link.send(session_id, Some(payload)) {
                            tracing::info!(%error, "mesh send failed; closing link");
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep_until(flush_deadline) => {
                let session_id = rally_point_proto::ids::SessionId(key.session.0);
                if link.payloads_in_flight(session_id) > 0
                    && let Err(error) = link.send(session_id, None)
                {
                    tracing::info!(%error, "mesh flush failed; closing link");
                    break;
                }
                flush_deadline = tokio::time::Instant::now() + routing::FLUSH_INTERVAL;
            }
        }
    }

    deregister_mesh_link(&mesh_links, &key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_first_delivery_new_and_redelivery_duplicate() {
        let mut seen = MeshSeen::new();
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::Duplicate);
        assert_eq!(seen.mark_forwarded(SlotId(0), 1), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 1), Seen::Duplicate);
    }

    #[test]
    fn keeps_slots_independent() {
        let mut seen = MeshSeen::new();
        // Two slots both have seq 0; both are new — identity is (slot, seq).
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(1), 0), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::Duplicate);
        assert_eq!(seen.mark_forwarded(SlotId(1), 0), Seen::Duplicate);
    }

    #[test]
    fn collapses_out_of_order_arrival() {
        // A turn arrives via path A at seq 3 (gap at 1, 2), then via path B at
        // seq 0. Seq 3 is new; seq 0 is new (it fills the gap). A second copy of
        // seq 3 via path B is a duplicate.
        let mut seen = MeshSeen::new();
        assert_eq!(seen.mark_forwarded(SlotId(0), 3), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 1), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 2), Seen::New);
        assert_eq!(seen.mark_forwarded(SlotId(0), 3), Seen::Duplicate);
    }

    #[test]
    fn drops_late_redundant_copy_below_prefix() {
        // After forwarding 0..3, a late redundant copy of seq 0 arriving via a
        // second path is dropped as below the prefix.
        let mut seen = MeshSeen::new();
        for seq in 0..4 {
            assert_eq!(seen.mark_forwarded(SlotId(0), seq), Seen::New);
        }
        assert_eq!(seen.mark_forwarded(SlotId(0), 0), Seen::Duplicate);
    }
}
