//! The roster itself: claiming a slot in a session's routing group, freeing it
//! again, and the read-only snapshots the drain, the heartbeat, and the
//! coordinator reporting take off it.

use super::*;

use std::sync::atomic::AtomicUsize;

use super::forward::{ForwardRx, ForwardSink};

/// A held slot registration that frees its slot when dropped.
///
/// [`register`] returns one so the slot is released on every path out of
/// connection setup — a failed acknowledgement write, a panic — rather than
/// sticking occupied until the relay restarts. Once [`run_slot_link`] takes over
/// the connection (and will deregister on its own exit), the owner calls
/// [`disarm`](Self::disarm) so the slot isn't freed twice.
pub struct SlotRegistration {
    sessions: Sessions,
    key: SessionKey,
    slot: SlotId,
    armed: bool,
}

impl SlotRegistration {
    /// Relinquishes responsibility for freeing the slot, because the running link
    /// task now owns its lifetime and will deregister when it ends.
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SlotRegistration {
    fn drop(&mut self) {
        if self.armed {
            deregister(&self.sessions, &self.key, self.slot);
        }
    }
}

/// Adds `slot` to the `key` routing group's roster, returning a guard that frees
/// the slot on drop plus the inbox its link task drains — or `None` if the slot is
/// already connected.
///
/// Refusing a duplicate keeps two connections from claiming one slot; a real
/// reconnect/takeover path is a later concern.
///
/// `connection_epoch` is the dialing connection's lifecycle epoch, recorded on the
/// entry so a reader can tell this registration apart from the one a reconnect
/// makes for the same slot. Pass the same value the slot's [`run_slot_link`] is
/// given: the entry and its link task are one generation, and anything that
/// resolves an answer from that link matches the pair.
pub fn register(
    sessions: &Sessions,
    key: &SessionKey,
    slot: SlotId,
    connection_epoch: u64,
) -> Option<(SlotRegistration, SlotInbox)> {
    let (tx, rx) = mpsc::channel(FORWARD_CAPACITY);
    // The forward queue's aggregate resident bytes, shared between the fan-out
    // producers (via the `ForwardSink` below) and the draining link task (via the
    // `ForwardRx` in the inbox), so the byte budget can bound it alongside the
    // channel's count bound.
    let forward_resident = Arc::new(AtomicUsize::new(0));
    // Leaves are rare (one per departing peer), so a small channel is ample.
    let (leave_tx, leave_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    // Session-start directives are rarer still (the fire, plus any re-push on a
    // late register or an authority handoff); the same small channel suits them.
    let (start_tx, start_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    // Connectivity changes are rare (a slot flips a small number of times over a
    // game); the same small channel suits them.
    let (conn_tx, conn_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    // Region labels arrive at most a handful of times (the gate opening, a direct
    // push on connecting after it opened, a re-fan when a re-home changes the
    // map); the same small channel suits them.
    let (region_tx, region_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    // Send-phase directives are similarly sparse (the controller dwells for
    // seconds between corrections, plus a connect-time re-push); the same small
    // channel suits them.
    let (phase_tx, phase_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    // Fence probes are rarer than any of the above (one per load-state read the
    // tenant makes, and only while this slot has connected without starting);
    // the same small channel suits them, and a full one simply leaves the slot
    // unfenced rather than blocking the relay's coordinator connection.
    let (probe_tx, probe_rx) = mpsc::channel(LEAVE_PUSH_CAPACITY);
    let shutdown = Arc::new(Notify::new());
    let close_reason = Arc::new(AtomicU8::new(SlotCloseReason::Unspecified as u8));
    let provisional_reap = Arc::new(Notify::new());
    {
        let mut roster = sessions.lock();
        let slots = roster.entry(key.clone()).or_default();
        if slots.contains_key(&slot) {
            return None;
        }
        slots.insert(
            slot,
            SlotEntry {
                forward: ForwardSink {
                    tx,
                    resident_bytes: Arc::clone(&forward_resident),
                },
                leave_push: leave_tx,
                start_push: start_tx,
                conn_push: conn_tx,
                region_push: region_tx,
                phase_push: phase_tx,
                probe_push: probe_tx,
                connection_epoch,
                shutdown: Arc::clone(&shutdown),
                close_reason: Arc::clone(&close_reason),
                provisional_reap: Arc::clone(&provisional_reap),
            },
        );
    }
    let registration = SlotRegistration {
        sessions: Arc::clone(sessions),
        key: key.clone(),
        slot,
        armed: true,
    };
    let inbox = SlotInbox {
        forward_rx: ForwardRx {
            rx,
            resident_bytes: forward_resident,
        },
        leave_push_rx: leave_rx,
        start_push_rx: start_rx,
        conn_push_rx: conn_rx,
        region_push_rx: region_rx,
        phase_push_rx: phase_rx,
        probe_push_rx: probe_rx,
        shutdown,
        close_reason,
        provisional_reap,
    };
    Some((registration, inbox))
}

/// Removes `slot` from the `key` routing group's roster, dropping the group entry
/// once its last slot leaves. Idempotent: removing an absent slot is a no-op, so a
/// guard and a link task can both run it without double-free hazard.
///
/// Returns whether this call removed the group's **last** slot — the relay now
/// serves no player for the session, so its caller fires the coordinator's
/// `SessionClosed` for it (computed under the roster lock, so two slots leaving
/// concurrently report the emptying exactly once).
pub(super) fn deregister(sessions: &Sessions, key: &SessionKey, slot: SlotId) -> bool {
    let mut roster = sessions.lock();
    if let Some(slots) = roster.get_mut(key) {
        let removed = slots.remove(&slot).is_some();
        if slots.is_empty() {
            roster.remove(key);
            return removed;
        }
    }
    false
}

/// Whether this relay currently holds any connected slot in any routing group —
/// its "am I serving a player" signal, used by the coordinated-drain shutdown path
/// to know when the relay is idle enough to exit.
///
/// A group entry is created only when a slot registers and dropped the moment its
/// last slot deregisters (see `deregister`), so the map is empty *exactly* when no
/// slot is held. A session ending therefore shrinks this — the last slot's link task
/// deregisters on exit — which is what lets the drain wait converge.
pub fn holds_any_slots(sessions: &Sessions) -> bool {
    !sessions.lock().is_empty()
}

/// The number of routing groups (distinct `(tenant, session)` keys) this relay
/// currently serves, regardless of how many slots each holds. A load signal to
/// pair with a resource sample (e.g. the task-stats reporter), not a substitute
/// for [`holds_any_slots`]: a relay can hold zero groups yet still have a slot
/// mid-deregistration, which `holds_any_slots` alone answers correctly and this
/// count does not need to.
pub fn session_count(sessions: &Sessions) -> usize {
    sessions.lock().len()
}

/// The live roster: every routing group with at least one connected slot, each
/// paired with its currently-connected slots (sorted, for a stable order).
///
/// A slot appears exactly while it is registered — the same property
/// [`holds_any_slots`] documents — so this is the truth the relay's heartbeat
/// reports up to the coordinator's active-player presence store: connected right
/// now, nothing softer. A snapshot taken under the roster lock, cheap at a
/// relay's scale (a handful of sessions, a dozen slots each).
pub fn live_slots(sessions: &Sessions) -> Vec<(SessionKey, Vec<SlotId>)> {
    sessions
        .lock()
        .iter()
        .map(|(key, slots)| {
            let mut slot_ids: Vec<SlotId> = slots.keys().copied().collect();
            slot_ids.sort_by_key(|s| s.0);
            (key.clone(), slot_ids)
        })
        .collect()
}

/// The slots currently registered for one session paired with the connection epoch
/// each is registered on, ascending by slot — [`live_slots`] for a single key,
/// without cloning the whole roster to find it, and carrying the link generation
/// alongside the seat.
///
/// The epoch is what makes two reads of this comparable across a reconnect: a slot
/// present in both with the *same* epoch was continuously the same link, while the
/// same slot with a different epoch is a second connection that took the seat over
/// in between.
pub fn live_session_slot_epochs(sessions: &Sessions, key: &SessionKey) -> Vec<(SlotId, u64)> {
    let roster = sessions.lock();
    let Some(slots) = roster.get(key) else {
        return Vec::new();
    };
    let mut links: Vec<(SlotId, u64)> = slots
        .iter()
        .map(|(slot, entry)| (*slot, entry.connection_epoch))
        .collect();
    links.sort_by_key(|(slot, _)| slot.0);
    links
}
