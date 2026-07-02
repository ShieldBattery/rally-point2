//! Session presence and the buffer-authority verdict.
//!
//! The relays serving a session sit in a coordinator-assigned priority order,
//! and the *first one still serving live players* is the session's
//! latency-buffer authority. The order is policy the coordinator sets in each
//! [`SessionDescriptor`](rally_point_proto::control::SessionDescriptor); which
//! relays still serve players is a *live* fact the relays track among
//! themselves, so authority hands off the moment the deciding relay's players
//! leave — with no coordinator round-trip, and therefore no dependence on the
//! coordinator being up while a game runs.
//!
//! This module is the relay's presence bookkeeping and the verdict computed
//! from it:
//!
//! - Each relay knows its **own** live home-client count per session directly
//!   from its slot roster; the client-edge link tasks report transitions here.
//! - Each relay learns its **peers'** counts from the [`MeshPresence`] frames
//!   they push over the mesh links' reliable presence streams (see
//!   [`spawn_presence_reader`] and the send half in the mesh-link driver).
//!
//! A relay that has **never reported is assumed live**. That default is what
//! makes session start coherent: descriptors usually arrive before any client
//! has connected anywhere, and if silence meant "out", every relay would skip
//! every other in the order and each would crown a different authority (or
//! none). Assuming live, every relay independently lands on the same first
//! relay in the order, and a relay drops out of contention only on an explicit
//! zero — its own roster emptying, or a peer's frame saying so. The
//! misjudgment window this leaves (a relay presumed live that is actually
//! empty) closes as soon as the first report arrives, and a *dead* relay (the
//! link lost, no report ever coming) is failover's problem, not presence's.
//!
//! Reports only land on sessions that have an entry here, and entries are
//! created exclusively by the descriptor path ([`set_order`]). A session run
//! without descriptors — dev/loopback harnesses that inject their authority
//! verdict by hand — has no entry, so the report hooks pass through without
//! touching the verdict such a harness chose.

use std::collections::HashMap;

use rally_point_proto::ids::RelayId;
use rally_point_proto::mesh::{MESH_PRESENCE_LEN, MeshPresence};
use rally_point_transport::quinn;
use tokio::sync::mpsc;

use crate::consensus::{Authority, DecisionMakers};
use crate::routing::SessionKey;

/// One relay's place in a session's authority order, with "this relay" already
/// resolved against the order at descriptor time. Storing the resolution
/// (rather than re-deriving it from an id on every verdict) keeps the registry
/// free of a relay-id field that every reader would have to thread through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Candidate {
    /// This relay itself. Liveness comes from the local slot roster, reported
    /// by the client-edge link tasks.
    SelfRelay,
    /// A peer relay. Liveness comes from its `MeshPresence` frames.
    Peer(RelayId),
}

/// One session's presence state: the authority priority order and the last
/// reported live-player counts. `None` — never reported — is assumed live (see
/// the module docs for why).
#[derive(Debug, Default)]
pub struct SessionPresence {
    /// The authority priority order, most preferred first, self-position
    /// resolved. Set from each descriptor push.
    order: Vec<Candidate>,
    /// Last live-player count each peer relay reported for this session.
    peer_reports: HashMap<RelayId, u32>,
    /// Last live-player count this relay's own roster reported.
    own_report: Option<u32>,
}

/// Per-session presence state, shared between the descriptor path (which sets
/// the order), the client-edge link tasks (which report the local roster), and
/// the mesh-link drivers (which deliver peers' reports). A plain mutex like
/// the sibling registries: every critical section is a short, await-free
/// lookup or insert.
pub type PresenceRegistry = parking_lot::Mutex<HashMap<SessionKey, SessionPresence>>;

/// Creates an empty presence registry for a relay with no sessions yet.
pub fn new_presence_registry() -> PresenceRegistry {
    parking_lot::Mutex::new(HashMap::new())
}

/// Sets (or replaces) `key`'s authority order from a descriptor push, creating
/// the session's entry. Reports already received are kept — presence is a fact
/// about the relays, not about any one descriptor — but peer reports are
/// pruned to the relays the new order names, so departed relays' entries don't
/// accumulate across a long session's membership changes.
pub fn set_order(registry: &PresenceRegistry, key: &SessionKey, order: Vec<Candidate>) {
    let mut sessions = registry.lock();
    let entry = sessions.entry(key.clone()).or_default();
    entry
        .peer_reports
        .retain(|id, _| order.contains(&Candidate::Peer(*id)));
    entry.order = order;
}

/// Records a peer relay's reported live-player count for `key`. Returns whether
/// the report changed the peer's *liveness* (the zero-or-not the verdict reads),
/// so the caller knows whether to recompute authority. A report for a session
/// with no entry (no descriptor yet) is dropped — there is no order to judge
/// against, and creating an entry here would let a report install presence
/// state for a session this relay was never told about.
pub fn record_peer(
    registry: &PresenceRegistry,
    key: &SessionKey,
    peer: RelayId,
    live: u32,
) -> bool {
    let mut sessions = registry.lock();
    let Some(entry) = sessions.get_mut(key) else {
        return false;
    };
    let was_live = entry.peer_reports.get(&peer).is_none_or(|&c| c > 0);
    entry.peer_reports.insert(peer, live);
    was_live != (live > 0)
}

/// Records this relay's own live-player count for `key` (from its slot
/// roster). Same no-entry rule as [`record_peer`]: a session without a
/// descriptor-set order is left untouched, so harnesses that inject their
/// authority verdict by hand keep it.
pub fn record_own(registry: &PresenceRegistry, key: &SessionKey, live: u32) -> bool {
    let mut sessions = registry.lock();
    let Some(entry) = sessions.get_mut(key) else {
        return false;
    };
    let was_live = entry.own_report.is_none_or(|c| c > 0);
    entry.own_report = Some(live);
    was_live != (live > 0)
}

/// Drops `key`'s presence state (the session ended). Idempotent.
pub fn forget(registry: &PresenceRegistry, key: &SessionKey) {
    registry.lock().remove(key);
}

/// Computes the authority verdict for `key` from the current order and
/// reports: the first relay in the order still live decides. Returns `None`
/// when the session has no presence entry (no descriptor has set an order), in
/// which case the caller must leave the decision-maker's verdict alone.
///
/// When every relay in the order has reported zero, the verdict is
/// [`Authority::Peer`]: nobody is serving players, so nothing needs deciding,
/// and *not us* is the safe answer for everyone.
pub fn verdict(registry: &PresenceRegistry, key: &SessionKey) -> Option<Authority> {
    let sessions = registry.lock();
    let entry = sessions.get(key)?;
    for candidate in &entry.order {
        let live = match candidate {
            Candidate::SelfRelay => entry.own_report.is_none_or(|c| c > 0),
            Candidate::Peer(id) => entry.peer_reports.get(id).is_none_or(|&c| c > 0),
        };
        if live {
            return Some(match candidate {
                Candidate::SelfRelay => Authority::SelfRelay,
                Candidate::Peer(_) => Authority::Peer,
            });
        }
    }
    Some(Authority::Peer)
}

/// Re-derives `key`'s verdict and applies it to the session's decision-maker.
/// The presence-change hooks call this so authority follows the reports; a
/// session with no presence entry, or no decision-maker, is left untouched.
pub fn recompute(registry: &PresenceRegistry, makers: &DecisionMakers, key: &SessionKey) {
    if let Some(authority) = verdict(registry, key) {
        crate::consensus::set_authority(makers, key, authority);
    }
}

/// The presence I/O for one established mesh link, handed to the link driver:
/// which peer the link reaches, the reliable stream this relay's own reports go
/// out on, and the channel the peer's reports arrive over (fed by a
/// [`spawn_presence_reader`] task). Bundled so the driver's signature stays
/// within the argument count the codebase holds elsewhere, mirroring
/// `MeshState`.
pub struct PresenceIo {
    /// The peer relay this link reaches — what its reports are recorded under.
    pub peer_id: RelayId,
    /// The reliable uni-stream carrying this relay's own reports to the peer.
    /// On the dial side this is the hello stream, kept open past the hello; on
    /// the accept side it is a stream of its own.
    pub tx: quinn::SendStream,
    /// The peer's reports, assembled off its stream by the reader task.
    pub rx: mpsc::Receiver<MeshPresence>,
}

/// Depth of the reader-task → driver channel. Reports are rare (one per
/// roster change per session, plus a re-announce on join) and the driver
/// drains them promptly; this is a backstop, not a tuned buffer.
const PRESENCE_CHANNEL_CAPACITY: usize = 64;

/// Spawns a dedicated task that reads presence frames from `stream` —
/// the peer's presence uni-stream, already located — and forwards each over
/// the returned channel.
///
/// A dedicated task for the same reason as the client link's beacon reader: a
/// `read_exact` dropped mid-frame inside a `select!` would desync the fixed
/// framing and hand garbage counts to the registry, so the read loop never
/// crosses a `select!` boundary; the driver receives only complete frames over
/// the channel, whose `recv` is cancel-safe. The task ends (dropping its
/// sender) when the stream closes or errors; the connection's own failure
/// surfaces separately through the datagram path.
pub fn spawn_presence_reader(stream: quinn::RecvStream) -> mpsc::Receiver<MeshPresence> {
    let (tx, rx) = mpsc::channel(PRESENCE_CHANNEL_CAPACITY);
    tokio::spawn(read_presence_frames(stream, tx));
    rx
}

/// [`spawn_presence_reader`] for the side that must first *locate* the peer's
/// stream: accepts the connection's next incoming uni-stream, then reads
/// frames from it. The dial side uses this (the acceptor's presence stream is
/// the only uni-stream an acceptor ever opens); the accept side already holds
/// the dialer's stream from the hello read and uses [`spawn_presence_reader`]
/// directly. Accepting lazily inside the task means a peer that never opens
/// its stream just parks the reader harmlessly.
pub fn spawn_presence_reader_accepting(
    connection: quinn::Connection,
) -> mpsc::Receiver<MeshPresence> {
    let (tx, rx) = mpsc::channel(PRESENCE_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        let Ok(stream) = connection.accept_uni().await else {
            return;
        };
        read_presence_frames(stream, tx).await;
    });
    rx
}

/// Reads fixed-size presence frames until the stream ends or the driver drops
/// its receiver.
async fn read_presence_frames(mut stream: quinn::RecvStream, tx: mpsc::Sender<MeshPresence>) {
    let mut frame = [0u8; MESH_PRESENCE_LEN];
    while stream.read_exact(&mut frame).await.is_ok() {
        if tx.send(MeshPresence::decode(frame)).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use rally_point_proto::control::TenantId;
    use rally_point_proto::ids::SessionId;

    use super::*;

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId("t".to_owned()),
            session: SessionId(1),
        }
    }

    fn order_self_then_peer(peer: u64) -> Vec<Candidate> {
        vec![Candidate::SelfRelay, Candidate::Peer(RelayId(peer))]
    }

    #[test]
    fn with_no_reports_the_first_in_order_decides() {
        let registry = new_presence_registry();
        // Descriptors land before any client connects anywhere; silence is
        // assumed live so every relay crowns the same first-in-order relay.
        set_order(&registry, &key(), order_self_then_peer(2));
        assert_eq!(verdict(&registry, &key()), Some(Authority::SelfRelay));

        set_order(
            &registry,
            &key(),
            vec![Candidate::Peer(RelayId(2)), Candidate::SelfRelay],
        );
        assert_eq!(verdict(&registry, &key()), Some(Authority::Peer));
    }

    #[test]
    fn authority_falls_to_the_next_relay_when_the_first_reports_empty() {
        let registry = new_presence_registry();
        set_order(
            &registry,
            &key(),
            vec![Candidate::Peer(RelayId(2)), Candidate::SelfRelay],
        );

        // The authority's players leave: its report goes to zero and authority
        // falls to the next relay in the order — us.
        assert!(record_peer(&registry, &key(), RelayId(2), 0));
        assert_eq!(verdict(&registry, &key()), Some(Authority::SelfRelay));

        // Its players return (a rejoin): authority moves back up the order.
        assert!(record_peer(&registry, &key(), RelayId(2), 1));
        assert_eq!(verdict(&registry, &key()), Some(Authority::Peer));
    }

    #[test]
    fn own_empty_roster_demotes_self() {
        let registry = new_presence_registry();
        set_order(&registry, &key(), order_self_then_peer(2));

        assert!(!record_own(&registry, &key(), 2)); // still live: no change
        assert_eq!(verdict(&registry, &key()), Some(Authority::SelfRelay));

        assert!(record_own(&registry, &key(), 0));
        assert_eq!(verdict(&registry, &key()), Some(Authority::Peer));
    }

    #[test]
    fn nobody_live_means_nobody_decides() {
        let registry = new_presence_registry();
        set_order(&registry, &key(), order_self_then_peer(2));
        record_own(&registry, &key(), 0);
        record_peer(&registry, &key(), RelayId(2), 0);
        // "Not us" is the safe answer for every relay when no one serves
        // players — no decisions are needed with no one to apply them.
        assert_eq!(verdict(&registry, &key()), Some(Authority::Peer));
    }

    #[test]
    fn reports_for_sessions_without_an_order_are_dropped() {
        let registry = new_presence_registry();
        // No descriptor ever set an order: harness-driven sessions keep their
        // hand-injected verdicts, so reports must not create entries.
        assert!(!record_own(&registry, &key(), 0));
        assert!(!record_peer(&registry, &key(), RelayId(2), 0));
        assert_eq!(verdict(&registry, &key()), None);
    }

    #[test]
    fn a_repeated_report_with_the_same_liveness_is_not_a_change() {
        let registry = new_presence_registry();
        set_order(&registry, &key(), order_self_then_peer(2));
        assert!(record_peer(&registry, &key(), RelayId(2), 0));
        // The stream re-announces on reconnect; same liveness → no churn.
        assert!(!record_peer(&registry, &key(), RelayId(2), 0));
        // Coming back alive is a change again...
        assert!(record_peer(&registry, &key(), RelayId(2), 3));
        // ...but a count that moves while staying live is not.
        assert!(!record_peer(&registry, &key(), RelayId(2), 1));
    }

    #[test]
    fn a_new_order_keeps_reports_but_prunes_departed_relays() {
        let registry = new_presence_registry();
        set_order(
            &registry,
            &key(),
            vec![
                Candidate::Peer(RelayId(2)),
                Candidate::Peer(RelayId(3)),
                Candidate::SelfRelay,
            ],
        );
        record_peer(&registry, &key(), RelayId(2), 0);
        record_own(&registry, &key(), 1);

        // A re-push that drops relay 3 keeps what relay 2 (and we) reported —
        // presence is a fact about the relays, not about one descriptor.
        set_order(
            &registry,
            &key(),
            vec![Candidate::Peer(RelayId(2)), Candidate::SelfRelay],
        );
        assert_eq!(verdict(&registry, &key()), Some(Authority::SelfRelay));

        // Relay 3 rejoins the order later: its old report was pruned, so it is
        // back to assumed-live rather than resurrected as dead.
        set_order(
            &registry,
            &key(),
            vec![Candidate::Peer(RelayId(3)), Candidate::SelfRelay],
        );
        assert_eq!(verdict(&registry, &key()), Some(Authority::Peer));
    }

    #[test]
    fn forget_removes_the_session() {
        let registry = new_presence_registry();
        set_order(&registry, &key(), order_self_then_peer(2));
        forget(&registry, &key());
        assert_eq!(verdict(&registry, &key()), None);
        forget(&registry, &key()); // idempotent
    }
}
