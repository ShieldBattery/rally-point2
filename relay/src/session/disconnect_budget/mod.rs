//! Cumulative per-slot disconnect accounting, keyed by connection generation.
//!
//! Each episode is retained until session retirement so retransmitted snapshots
//! merge by episode instead of charging the same outage twice. Instants are
//! local to a relay; snapshots carry durations and establish a new local anchor.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rally_point_proto::ids::{RelayId, SlotId};
use ring::rand::{SecureRandom, SystemRandom};

use crate::key::SessionKey;

#[cfg(test)]
mod tests;

/// Cumulative disconnect grace before a survivor may immediately request a drop.
pub const DISCONNECT_ALLOWANCE: Duration = Duration::from_secs(180);

// Every completed outage costs at least one second, bounding the history
// needed before the allowance is exhausted.
const MAX_EPISODES_PER_SLOT: usize = 181;
fn new_bootstrap_id() -> u64 {
    let mut bytes = [0; 8];
    // Zero is not a valid reply id, so entropy failure leaves admission closed.
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return 0;
    }
    u64::from_ne_bytes(bytes)
}

fn completed_duration(duration: Duration) -> Duration {
    let seconds = duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0));
    Duration::from_secs(seconds.max(1)).min(DISCONNECT_ALLOWANCE)
}

/// One episode in a snapshot. `elapsed` is measured at snapshot creation;
/// a receiving relay continues measuring a running episode from its receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpisodeSnapshot {
    pub slot: SlotId,
    pub connection_epoch: u64,
    pub elapsed: Duration,
    pub complete: bool,
}

#[derive(Debug, Clone, Copy)]
struct Episode {
    elapsed: Duration,
    reported: Duration,
    locally_owned: bool,
    anchor: Instant,
    complete: bool,
}

impl Episode {
    fn elapsed_at(self, now: Instant) -> Duration {
        if self.complete {
            self.elapsed
        } else {
            self.elapsed
                .saturating_add(now.saturating_duration_since(self.anchor))
        }
        .min(DISCONNECT_ALLOWANCE)
    }
}

type Episodes = HashMap<(SessionKey, SlotId, u64), Episode>;

#[derive(Default)]
struct Registry {
    episodes: Episodes,
    sessions: HashMap<SessionKey, SessionMetadata>,
}

struct SessionMetadata {
    synced: bool,
    homed_slots: HashSet<SlotId>,
    expected_slots: HashSet<SlotId>,
    peers: HashSet<RelayId>,
    received: HashSet<RelayId>,
    bootstrap_id: u64,
    checkpoints: HashMap<u64, Checkpoint>,
}

struct Checkpoint {
    expected: HashSet<RelayId>,
    acknowledged: HashSet<RelayId>,
}

/// A slot's current allowance and whether an outage is running locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotBudgetStatus {
    pub slot: SlotId,
    pub remaining: Duration,
    pub running: bool,
}

/// Shared registry. Hold this lock before entering the decision-maker lock when
/// admission needs to resolve both accounting and connection state together.
#[derive(Clone, Default)]
pub struct DisconnectBudgets {
    inner: Arc<Mutex<Registry>>,
}

/// Why a guarded reconnect did not complete.
#[derive(Debug, PartialEq, Eq)]
pub enum ReconnectError<E> {
    /// The session is awaiting a complete peer baseline.
    Unsynced,
    /// The expected outage is no longer the sole running episode for the slot.
    StaleEpisode,
    /// The caller's connection admission failed; the episode keeps running.
    Admission(E),
}

fn spent(episodes: &Episodes, key: &SessionKey, slot: SlotId, now: Instant) -> Duration {
    episodes
        .iter()
        .filter(|((session, subject, _), _)| session == key && *subject == slot)
        .fold(Duration::ZERO, |total, (_, episode)| {
            total
                .saturating_add(episode.elapsed_at(now))
                .min(DISCONNECT_ALLOWANCE)
        })
}

impl DisconnectBudgets {
    /// Installs the descriptor and its configured peer set. A new resumed
    /// session waits for an explicit reply from every peer, and cannot infer a
    /// baseline from an empty peer set. Descriptor changes fence old replies.
    pub fn configure_session(
        &self,
        key: &SessionKey,
        resumed: bool,
        homed_slots: &[SlotId],
        expected_slots: &[SlotId],
        peers: &[RelayId],
    ) {
        let mut inner = self.inner.lock();
        let new_peers: HashSet<_> = peers.iter().copied().collect();
        let session = inner
            .sessions
            .entry(key.clone())
            .or_insert_with(|| SessionMetadata {
                synced: !resumed,
                homed_slots: HashSet::new(),
                expected_slots: HashSet::new(),
                peers: new_peers.clone(),
                received: HashSet::new(),
                bootstrap_id: new_bootstrap_id(),
                checkpoints: HashMap::new(),
            });
        if resumed
            && session.synced
            && homed_slots
                .iter()
                .any(|slot| !session.homed_slots.contains(slot))
        {
            // A relay can gain homes while already serving this session. Its
            // prior baseline does not prove it received their latest debits.
            session.synced = false;
            session.received.clear();
            session.bootstrap_id = new_bootstrap_id();
        }
        if !session.synced && session.peers != new_peers {
            session.peers = new_peers;
            session.received.clear();
            session.bootstrap_id = new_bootstrap_id();
        } else {
            session.peers = new_peers;
        }
        for checkpoint in session.checkpoints.values_mut() {
            checkpoint.expected.clone_from(&session.peers);
            checkpoint
                .acknowledged
                .retain(|peer| session.peers.contains(peer));
        }
        session.homed_slots = homed_slots.iter().copied().collect();
        session.expected_slots = expected_slots.iter().copied().collect();
        let homes = session.homed_slots.clone();
        for ((session_key, slot, _), episode) in &mut inner.episodes {
            if session_key == key && !homes.contains(slot) {
                episode.locally_owned = false;
            }
        }
    }

    /// Nonzero request identity for an unknown baseline, or zero after sync.
    pub fn bootstrap_id(&self, key: &SessionKey) -> u64 {
        self.inner
            .lock()
            .sessions
            .get(key)
            .filter(|session| !session.synced)
            .map_or(0, |session| session.bootstrap_id)
    }

    /// Whether this session has an initial accounting baseline.
    pub fn is_synced(&self, key: &SessionKey) -> bool {
        self.inner
            .lock()
            .sessions
            .get(key)
            .is_some_and(|session| session.synced)
    }

    /// Begins an independent checkpoint against the current peer set. A
    /// missing baseline or unavailable randomness fails closed. No peers means
    /// the checkpoint completes immediately without any remote copy.
    pub fn begin_checkpoint(&self, key: &SessionKey) -> Option<u64> {
        let mut inner = self.inner.lock();
        let session = inner.sessions.get_mut(key)?;
        if !session.synced {
            return None;
        }
        let id = new_bootstrap_id();
        if id == 0 || session.checkpoints.contains_key(&id) {
            return None;
        }
        session.checkpoints.insert(
            id,
            Checkpoint {
                expected: session.peers.clone(),
                acknowledged: HashSet::new(),
            },
        );
        Some(id)
    }

    /// Records a matching acknowledgement from a currently configured peer.
    pub fn acknowledge_checkpoint(&self, key: &SessionKey, peer: RelayId, id: u64) {
        let mut inner = self.inner.lock();
        let Some(session) = inner.sessions.get_mut(key) else {
            return;
        };
        let Some(checkpoint) = session.checkpoints.get_mut(&id) else {
            return;
        };
        if checkpoint.expected.contains(&peer) {
            checkpoint.acknowledged.insert(peer);
        }
    }

    /// Whether all currently configured peers acknowledged this checkpoint.
    /// A session needing a new baseline remains closed even if its peer set
    /// becomes empty during a descriptor update.
    pub fn is_checkpoint_complete(&self, key: &SessionKey, id: u64) -> bool {
        let inner = self.inner.lock();
        inner.sessions.get(key).is_some_and(|session| {
            session.synced
                && session
                    .checkpoints
                    .get(&id)
                    .is_some_and(|checkpoint| checkpoint.expected == checkpoint.acknowledged)
        })
    }

    /// Removes a checkpoint after its waiter has completed or been cancelled.
    pub fn finish_checkpoint(&self, key: &SessionKey, id: u64) {
        if let Some(session) = self.inner.lock().sessions.get_mut(key) {
            session.checkpoints.remove(&id);
        }
    }

    /// All sessions with metadata or episode records, for an expiry sweep.
    pub fn keys(&self) -> Vec<SessionKey> {
        let inner = self.inner.lock();
        let mut keys: HashSet<_> = inner.sessions.keys().cloned().collect();
        keys.extend(inner.episodes.keys().map(|(key, _, _)| key.clone()));
        keys.into_iter().collect()
    }

    /// The sole running epoch for this slot, or `None` if absent or conflicting.
    pub fn running_epoch(&self, key: &SessionKey, slot: SlotId) -> Option<u64> {
        let inner = self.inner.lock();
        let mut running =
            inner
                .episodes
                .iter()
                .filter_map(|((session, subject, epoch), episode)| {
                    (session == key && *subject == slot && !episode.complete).then_some(*epoch)
                });
        let epoch = running.next();
        if running.next().is_some() {
            None
        } else {
            epoch
        }
    }

    /// Snapshots configured local homes and every slot with recorded episodes.
    /// Unlisted slots have the full allowance and no running outage.
    pub fn status(&self, key: &SessionKey, now: Instant) -> Vec<SlotBudgetStatus> {
        let inner = self.inner.lock();
        let mut slots: HashSet<_> = inner
            .sessions
            .get(key)
            .map(|s| s.expected_slots.union(&s.homed_slots).copied().collect())
            .unwrap_or_default();
        slots.extend(
            inner
                .episodes
                .keys()
                .filter_map(|(session, slot, _)| (session == key).then_some(*slot)),
        );
        let mut result: Vec<_> = slots
            .into_iter()
            .map(|slot| SlotBudgetStatus {
                slot,
                remaining: DISCONNECT_ALLOWANCE.saturating_sub(spent(
                    &inner.episodes,
                    key,
                    slot,
                    now,
                )),
                running: inner
                    .episodes
                    .iter()
                    .any(|((session, subject, _), episode)| {
                        session == key && *subject == slot && !episode.complete
                    }),
            })
            .collect();
        result.sort_unstable_by_key(|entry| entry.slot.0);
        result
    }

    /// Starts an outage observed by its home relay. Duplicate starts are
    /// idempotent, while a completed epoch cannot be restarted.
    pub fn start_outage(&self, key: &SessionKey, slot: SlotId, epoch: u64, now: Instant) -> bool {
        self.start_outage_inner(key, slot, epoch, now, true)
    }

    /// Starts a peer-observed outage. Its local projection is never advertised
    /// as a measurement to another relay.
    pub fn start_remote_outage(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: u64,
        now: Instant,
    ) -> bool {
        self.start_outage_inner(key, slot, epoch, now, false)
    }

    fn start_outage_inner(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: u64,
        now: Instant,
        locally_owned: bool,
    ) -> bool {
        let mut inner = self.inner.lock();
        let episodes = &mut inner.episodes;
        if let Some(existing) = episodes.get(&(key.clone(), slot, epoch)) {
            return !existing.complete;
        }
        let existing_count = episodes
            .iter()
            .filter(|((session, subject, _), _)| session == key && *subject == slot)
            .count();
        if episodes.iter().any(|((session, subject, _), episode)| {
            session == key && *subject == slot && !episode.complete
        }) {
            return false;
        }
        // Once completed episodes consume the allowance, future outages cannot
        // change the balance. Avoid growing the retained history indefinitely.
        if spent(episodes, key, slot, now) >= DISCONNECT_ALLOWANCE {
            return true;
        }
        if existing_count >= MAX_EPISODES_PER_SLOT {
            return false;
        }
        episodes.insert(
            (key.clone(), slot, epoch),
            Episode {
                elapsed: Duration::ZERO,
                reported: Duration::ZERO,
                locally_owned,
                anchor: now,
                complete: false,
            },
        );
        true
    }

    /// Completes an existing outage, returning whether this call changed it.
    pub fn end_outage(&self, key: &SessionKey, slot: SlotId, epoch: u64, now: Instant) -> bool {
        let mut inner = self.inner.lock();
        let episodes = &mut inner.episodes;
        let Some(episode) = episodes.get_mut(&(key.clone(), slot, epoch)) else {
            return false;
        };
        if episode.complete {
            return false;
        }
        episode.elapsed = completed_duration(episode.elapsed_at(now).max(episode.reported));
        episode.reported = episode.elapsed;
        episode.anchor = now;
        episode.complete = true;
        true
    }

    /// Runs admission while accounting is locked. `epoch` must name the sole
    /// running outage, or be `None` when the slot has no running outage. A
    /// successful admission completes that outage; a refused one leaves it
    /// running. Exhaustion does not prevent admission.
    /// The closure must not re-enter this registry.
    pub fn try_reconnect<T, E>(
        &self,
        key: &SessionKey,
        slot: SlotId,
        epoch: Option<u64>,
        now: Instant,
        admit: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, ReconnectError<E>> {
        let mut inner = self.inner.lock();
        if inner
            .sessions
            .get(key)
            .is_some_and(|session| !session.synced)
        {
            return Err(ReconnectError::Unsynced);
        }
        let episodes = &mut inner.episodes;
        let mut running = episodes
            .iter()
            .filter_map(|((session, subject, id), episode)| {
                (session == key && *subject == slot && !episode.complete).then_some(*id)
            });
        let current = running.next();
        if running.next().is_some() || current != epoch {
            return Err(ReconnectError::StaleEpisode);
        }
        let result = admit().map_err(ReconnectError::Admission)?;
        if let Some(id) = current {
            let episode = episodes
                .get_mut(&(key.clone(), slot, id))
                .expect("running episode exists");
            episode.elapsed = completed_duration(episode.elapsed_at(now).max(episode.reported));
            episode.reported = episode.elapsed;
            episode.anchor = now;
            episode.complete = true;
        }
        Ok(result)
    }

    /// Remaining time, including every locally running episode at `now`.
    pub fn remaining(&self, key: &SessionKey, slot: SlotId, now: Instant) -> Duration {
        DISCONNECT_ALLOWANCE.saturating_sub(spent(&self.inner.lock().episodes, key, slot, now))
    }

    /// Whether the allowance has been completely spent at `now`.
    pub fn exhausted(&self, key: &SessionKey, slot: SlotId, now: Instant) -> bool {
        self.remaining(key, slot, now).is_zero()
    }

    /// Captures all known episodes of a session at one local instant. A home
    /// advertises its running measurement and retains it as a floor, including
    /// when it inherited an outage from another home. Other replicas forward
    /// only measurements already reported to them.
    pub fn snapshot(&self, key: &SessionKey, now: Instant) -> Vec<EpisodeSnapshot> {
        self.snapshot_inner(key, now, false)
    }

    /// A recovery response conservatively carries the local elapsed estimate
    /// for every running outage. A departed home may have failed before its
    /// latest measurement reached any peer, so the peer's local clock closes
    /// that gap. The advertised estimate becomes a floor against late frames.
    pub fn snapshot_for_recovery(&self, key: &SessionKey, now: Instant) -> Vec<EpisodeSnapshot> {
        self.snapshot_inner(key, now, true)
    }

    fn snapshot_inner(
        &self,
        key: &SessionKey,
        now: Instant,
        recovery: bool,
    ) -> Vec<EpisodeSnapshot> {
        let mut inner = self.inner.lock();
        let homes = inner
            .sessions
            .get(key)
            .filter(|session| session.synced)
            .map(|session| session.homed_slots.clone())
            .unwrap_or_default();
        let mut snapshot: Vec<_> = inner
            .episodes
            .iter_mut()
            .filter_map(|((session, slot, epoch), episode)| {
                if session != key {
                    return None;
                }
                let elapsed = if episode.complete {
                    episode.elapsed
                } else if recovery || episode.locally_owned || homes.contains(slot) {
                    let elapsed = episode.elapsed_at(now);
                    // The wire rounds upward to milliseconds, so preserve the
                    // same floor even when the update arrives before completion.
                    let ms = elapsed.as_nanos().div_ceil(1_000_000) as u64;
                    episode.reported = episode.reported.max(Duration::from_millis(ms));
                    episode.reported
                } else {
                    episode.reported
                };
                Some(EpisodeSnapshot {
                    slot: *slot,
                    connection_epoch: *epoch,
                    elapsed,
                    complete: episode.complete,
                })
            })
            .collect();
        snapshot.sort_unstable_by_key(|entry| (entry.slot.0, entry.connection_epoch));
        snapshot
    }

    /// Max-merges episode durations, with completion sticky. This method is
    /// for trusted local callers; mesh callers use `merge_peer_snapshot`.
    pub fn merge(&self, key: &SessionKey, incoming: &[EpisodeSnapshot], now: Instant) {
        let mut inner = self.inner.lock();
        Self::merge_inner(&mut inner.episodes, key, incoming, now);
    }

    /// Applies a whole snapshot from a configured peer and records its matching
    /// bootstrap reply atomically. Invalid slots or oversized slot histories
    /// reject the whole snapshot, which cannot establish a baseline.
    pub fn merge_peer_snapshot(
        &self,
        key: &SessionKey,
        peer: RelayId,
        incoming: &[EpisodeSnapshot],
        now: Instant,
        reply_id: u64,
    ) -> bool {
        let mut inner = self.inner.lock();
        let Some(session) = inner.sessions.get(key) else {
            return false;
        };
        if !session.peers.contains(&peer)
            || incoming
                .iter()
                .any(|entry| !session.expected_slots.contains(&entry.slot))
        {
            return false;
        }
        // Count distinct identities, not repeated copies of one entry.
        let mut counts: HashMap<SlotId, HashSet<u64>> = HashMap::new();
        for (session, slot, epoch) in inner.episodes.keys() {
            if session == key {
                counts.entry(*slot).or_default().insert(*epoch);
            }
        }
        for entry in incoming {
            counts
                .entry(entry.slot)
                .or_default()
                .insert(entry.connection_epoch);
        }
        if counts
            .values()
            .any(|epochs| epochs.len() > MAX_EPISODES_PER_SLOT)
        {
            return false;
        }
        Self::merge_inner(&mut inner.episodes, key, incoming, now);
        // A prior home may still own an episode until its descriptor changes.
        // Do not acknowledge a completed debit it declined to merge.
        if incoming.iter().filter(|entry| entry.complete).any(|entry| {
            !inner
                .episodes
                .get(&(key.clone(), entry.slot, entry.connection_epoch))
                .is_some_and(|episode| {
                    episode.complete && episode.elapsed >= completed_duration(entry.elapsed)
                })
        }) {
            return false;
        }
        let session = inner.sessions.get_mut(key).expect("session checked above");
        if !session.synced && reply_id != 0 && session.bootstrap_id == reply_id {
            session.received.insert(peer);
            if !session.peers.is_empty() && session.received == session.peers {
                session.synced = true;
            }
        }
        true
    }

    fn merge_inner(
        episodes: &mut Episodes,
        key: &SessionKey,
        incoming: &[EpisodeSnapshot],
        now: Instant,
    ) {
        for entry in incoming {
            let map_key = (key.clone(), entry.slot, entry.connection_epoch);
            if !episodes.contains_key(&map_key)
                && episodes
                    .keys()
                    .filter(|(session, slot, _)| session == key && *slot == entry.slot)
                    .count()
                    >= MAX_EPISODES_PER_SLOT
            {
                // A compliant sender cannot exceed this limit. Do not create
                // unbounded state from an inconsistent peer.
                continue;
            }
            let local = episodes.entry(map_key).or_insert(Episode {
                elapsed: Duration::ZERO,
                reported: Duration::ZERO,
                locally_owned: false,
                anchor: now,
                complete: false,
            });
            let incoming_elapsed = entry.elapsed.min(DISCONNECT_ALLOWANCE);
            if local.complete {
                if entry.complete {
                    local.elapsed = local.elapsed.max(completed_duration(incoming_elapsed));
                    local.reported = local.elapsed;
                }
            } else if local.locally_owned {
                // Only the home measures this locally running episode.
                continue;
            } else if entry.complete {
                // A completion must preserve any measurement already shared
                // by a home, even if a different home reports a lower value.
                local.elapsed = completed_duration(incoming_elapsed.max(local.reported));
                local.reported = local.elapsed;
                local.anchor = now;
                local.complete = true;
            } else {
                local.reported = local.reported.max(incoming_elapsed);
                local.elapsed = local.elapsed_at(now).max(incoming_elapsed);
                local.anchor = now;
            }
        }
    }

    /// Terminal session retirement; an ordinary empty roster must retain this state.
    pub fn retire(&self, key: &SessionKey) {
        let mut inner = self.inner.lock();
        inner.episodes.retain(|(session, _, _), _| session != key);
        inner.sessions.remove(key);
    }
}
