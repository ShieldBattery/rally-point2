//! [`MeshControl::apply_descriptor`]: turning one coordinator
//! [`SessionDescriptor`] into the session's mesh peers, authority verdict,
//! decision-maker sync, region-label fan-out, provisional-turn drain, and
//! roster reconciliation. Split out of `mod.rs` because this one method is
//! the bulk of what the driver does per descriptor push.

use std::collections::HashSet;

use rally_point_proto::control::SessionDescriptor;
use rally_point_proto::ids::{RelayId, SlotId};
use rally_point_proto::messages::RegionLabel;

use crate::consensus::{self, Authority};
use crate::mesh;
use crate::routing::{self, SessionKey};
use crate::session::presence::{self, Candidate};

use super::{MeshControl, PeerContact, publish_desired_peers, reconcile_peers};

impl MeshControl {
    /// Applies a coordinator [`SessionDescriptor`]: the session's mesh peers
    /// become exactly the descriptor's peers.
    ///
    /// Declarative — peers newly named are joined (on whichever of their links
    /// have established), peers dropped since the last descriptor for this
    /// session are left, and peers unchanged are untouched. Re-applying the same
    /// descriptor is also how a previously dropped command recovers: it
    /// reconciles the affected peers against delivered state and re-sends
    /// whatever did not get through. A named peer with no established link yet is
    /// remembered, so the join fires when [`register_link`](Self::register_link)
    /// sees it.
    pub fn apply_descriptor(&self, descriptor: &SessionDescriptor) {
        let key = SessionKey {
            tenant: descriptor.tenant.clone(),
            session: descriptor.session,
        };

        // Deliberately no close-seal clearing here: a descriptor push is
        // routinely an idempotent *replay* — a coordinator reconnect re-pushes
        // every current descriptor — and unsealing a closed-but-not-yet-retired
        // session would let a straggling mesh event conjure the empty
        // replacement recording the seal exists to prevent. A *genuine*
        // re-serve always passes through the session's retirement first (the
        // coordinator removes a descriptor before it would ever re-add one),
        // and `end_session` clears the seal there.

        // Stamp the tenant's correlation ids into the decision-maker registry
        // so a departure notice for this session can carry its own
        // `external_id`/`external_ref` without depending on the coordinator's
        // in-memory session-refs store (which a coordinator restart wipes —
        // this descriptor, once applied, does not). Always overwrites: a
        // changed re-applied descriptor's refs replace rather than accumulate
        // alongside a stale copy.
        self.decision_makers.set_session_refs(
            &key,
            descriptor.external_id.clone(),
            descriptor
                .slot_refs
                .iter()
                .map(|r| (r.slot, r.external_ref.clone()))
                .collect(),
        );

        let new_peers: HashSet<RelayId> = descriptor
            .peers
            .iter()
            .map(|p| p.relay_id)
            .filter(|id| *id != self.our_id)
            .collect();

        // Record this session's authority order and re-derive the verdict.
        // The order is the coordinator's ranking (home relay first); which of
        // those relays still serves live players is the presence the roster
        // and the mesh report between pushes. One relay decides and the rest
        // forward its stamped turns; when the deciding relay's players all
        // leave, the verdict falls to the next in the order with no
        // coordinator round-trip. A descriptor from a coordinator that
        // predates the order carries none — fall back to relay-id order over
        // the session's relay set, the interim rule the assigned order
        // replaces. Reconciling on every push — not just creating on the
        // first — keeps the verdict true as the relay set changes. (Relays
        // receive a re-push at slightly different moments, so two can
        // disagree briefly while it propagates; the directive's decision seq
        // keeps clients consistent through that window.)
        let ranked: Vec<RelayId> = if descriptor.authority_order.is_empty() {
            let mut ids: Vec<RelayId> = new_peers.iter().copied().collect();
            ids.push(self.our_id);
            ids.sort_by_key(|id| id.0);
            ids
        } else {
            descriptor.authority_order.clone()
        };
        let order: Vec<Candidate> = ranked
            .into_iter()
            .map(|id| {
                if id == self.our_id {
                    Candidate::SelfRelay
                } else {
                    Candidate::Peer(id)
                }
            })
            .collect();
        presence::set_order(&self.presence, &key, order);
        let authority = presence::verdict(&self.presence, &key).unwrap_or(Authority::Peer);
        // A verdict that promotes this relay (e.g. the coordinator dropped the
        // former authority from the order because it crashed — a case presence
        // alone can't catch, since a crashed relay sends no zero report) yields
        // the synced leaves it must re-broadcast so no leave is lost. The
        // descriptor's observer slots are seeded into the maker here — a maker
        // created by this push starts with them excluded from the desync
        // comparator, so a single-relay session (one push, before any client
        // dials) never loses its observer set; a re-push replaces the set.
        //
        // The current held-slot set is read from the drop-hold registry right
        // before syncing, so a promotion here skips a slot whose drop a client
        // could still return from — exactly like the presence-driven promotion
        // (`presence::recompute`), which gets the same set from its own caller.
        // A descriptor naming this session is a genuine (re-)serve: lift any
        // retirement gate so its ingress — clients, turns, mesh frames —
        // dispatches again. Before `sync_maker`, so no window exists where
        // the maker is visible but the gate still refuses.
        self.gates.reopen(&key);
        let held_slots = self.drop_holds.pending_slots(&key);
        // A rehome (resumed) descriptor's departed-slot seeds — and the
        // resumed latch that stops leaves decided from here on from carrying
        // exact final turn counts — install inside `sync_maker`'s registry
        // lock, atomically with the maker becoming visible: a provisionally
        // admitted client can clean-leave the instant the maker exists, and a
        // latch set by a follow-up call would lose that race and emit a count
        // the rehomed session's split forwarding history cannot support. The
        // returned batch already folds in any directive the seeding newly
        // decided, so the broadcast below also reaches local clients admitted
        // before this descriptor (whose one registration-time leave
        // reconciliation predates the seed).
        let leaves = consensus::sync_maker(
            &self.decision_makers,
            &key,
            descriptor.bounds,
            authority,
            descriptor.observer_slots.iter().copied().collect(),
            descriptor.expected_slots.iter().copied().collect(),
            descriptor.homed_slots.iter().copied().collect(),
            held_slots,
            descriptor
                .resumed
                .then_some(descriptor.departed_slots.as_slice()),
            descriptor.finalized_drops,
        );
        // A descriptor now names this session, so any provisional-admission
        // mark it carried is moot -- the bounded-admission sweep would
        // otherwise still reap it on the original deadline. A session that
        // was never provisional (a mesh Join, or a descriptor that beat every
        // client dial) has nothing here to clear.
        self.provisional.clear(&key);
        // Stamps this relay's own id onto the maker so a buffer directive it
        // queues as authority carries the deterministic decision_seq
        // tie-break (see `BufferDirective.authority_relay_id`). Idempotent;
        // run on every descriptor push, not just creation, since `sync_maker`
        // itself re-syncs an existing maker the same way.
        consensus::set_own_relay_id(&self.decision_makers, &key, self.our_id);
        // Feed the descriptor-derived inputs to the initial-depth computation: the
        // tenant's latency hint, and whether this is a single-relay session (no
        // mesh peers) — the latter decides both the fully-observed rule and the
        // multi-relay hop cushion. Set on create and every re-sync, like the
        // observer/expected/homed sets above.
        consensus::set_session_shape(
            &self.decision_makers,
            &key,
            descriptor.latency_estimate_ms,
            new_peers.is_empty(),
        );
        // Record the session's relay → region labels. They go no further until the
        // session's release gate opens on the turn path; the only thing that can
        // send from here is a *changed* map on a session whose gate is already
        // open (a re-home named a different relay), where the clients holding the
        // superseded map must be corrected.
        let relabelled = consensus::set_region_labels(
            &self.decision_makers,
            &key,
            descriptor
                .relay_regions
                .iter()
                .map(|label| RegionLabel {
                    relay_id: label.relay_id.0,
                    region: label.region.0.clone(),
                })
                .collect(),
        );
        if let Some(labels) = relabelled {
            routing::fan_out_region_labels(&self.sessions, &key, &labels);
        }
        mesh::broadcast_leaves(&self.sessions, &self.mesh_links, &key, leaves);
        if descriptor.resumed && !descriptor.departed_slots.is_empty() {
            // A seeded departed slot may still hold a live local link — a
            // provisionally admitted dial that raced the descriptor. Its
            // leave is decided, so the home-ingress turn fence already drops
            // everything it sends; close the link too rather than leaving a
            // zombie connection pumping fenced turns until it gives up on its
            // own. The subject deliberately receives no LeaveDirective of its
            // own, so the close is the only signal it gets.
            let departed: Vec<_> = descriptor.departed_slots.iter().map(|d| d.slot).collect();
            crate::routing::close_slots(&self.sessions, &key, &departed);
        }
        if descriptor.resumed {
            self.decision_makers.flight_recorder().record(
                &key,
                crate::observability::flight_recorder::FlightEvent::ResumedDescriptorApplied {
                    departed_slots: descriptor.departed_slots.len() as u32,
                },
            );
        }
        // A maker now exists, so drain the ingress journaled while the
        // session had none (pre-descriptor provisional dials) back through
        // the ordinary paths, in arrival order. This runs AFTER the seeding
        // above, so a seeded-departed slot's journaled turns hit the
        // decided-leave fence and die instead of reaching co-admitted
        // survivors; every current slot's turns flow exactly as if they had
        // arrived a moment later. A journaled departure re-announces into
        // the maker through the journal-blind inner half (the drain must not
        // re-enter the journal) — a clean leave's exact count is derived
        // HERE, over exactly the slot's own turns drained ahead of it (its
        // link was closed at the intent, so the journaled prefix is
        // complete), never from the deposit-time snapshot that was blind to
        // them. The drain is the journal's Gathering → Draining → Resolved
        // transition: deposits landing while a batch replays are journaled
        // and picked up by the next `continue_drain` pass, and only the
        // atomic empty-check resolves the session — so nothing is ever
        // announced ahead of ingress it should have ordered behind, and
        // nothing deposits past the completed drain.
        if let Some(turn_path) = &self.turn_path
            && let Some(mut batch) = turn_path.provisional_turns.begin_drain(&key)
        {
            loop {
                // The batch stays charged against the journal's byte budget
                // until replayed — the budget tracks resident memory, and
                // these allocations live until this loop drops them.
                let batch_bytes: usize = batch
                    .iter()
                    .map(crate::session::provisional_turns::ProvisionalTurnPen::entry_bytes)
                    .sum();
                for entry in batch {
                    match entry {
                        crate::session::provisional_turns::PennedIngress::Turn(slot, payload) => {
                            mesh::forward_client_turn(
                                &self.sessions,
                                turn_path,
                                &key,
                                slot,
                                payload,
                            );
                        }
                        crate::session::provisional_turns::PennedIngress::Departure {
                            slot,
                            reason,
                            connection_epoch,
                            revision,
                        } => {
                            // The revision validation and the record run as
                            // ONE exclusive gate section: every deposit runs
                            // under the gate's read side, so nothing can
                            // bump the slot's revision between "this entry
                            // is still current" and the record it licenses.
                            // A departure superseded while it sat in this
                            // drain's private batch (the queue compaction
                            // cannot reach entries already taken) is
                            // therefore skipped with certainty, never merely
                            // best-effort — an old generation's drop
                            // recorded after a newer generation's teardown
                            // would install its stale epoch first and have
                            // the real departure rejected as stale. The
                            // superseding deposit sits in the Draining
                            // queue, so a later pass of this loop replays
                            // it.
                            let _ = turn_path.gates.with_exclusive(&key, || {
                                if !turn_path
                                    .provisional_turns
                                    .departure_is_current(&key, slot, revision)
                                {
                                    tracing::debug!(
                                        tenant = key.tenant.as_ref(),
                                        session = key.session.0,
                                        slot = slot.0,
                                        revision,
                                        "skipping a superseded journaled departure",
                                    );
                                    return;
                                }
                                let exact_count = (reason == consensus::LEAVE_REASON_LEFT)
                                    .then(|| mesh::forwarded_count(&turn_path.seen, &key, slot))
                                    .flatten();
                                let _ = routing::announce_departure_recorded(
                                    &self.drop_holds,
                                    &self.decision_makers,
                                    &self.sessions,
                                    &self.mesh_links,
                                    &key,
                                    slot,
                                    reason,
                                    exact_count,
                                    connection_epoch,
                                );
                            });
                        }
                    }
                }
                turn_path.provisional_turns.release_drained(batch_bytes);
                match turn_path.provisional_turns.continue_drain(&key) {
                    crate::session::provisional_turns::DrainStep::More(next) => batch = next,
                    crate::session::provisional_turns::DrainStep::Done => break,
                }
            }
        }
        // Reconcile the roster into the maker this descriptor just created or
        // updated. A slot that dialed and registered before this descriptor
        // arrived announced its presence when the session had no maker yet, so
        // the announce found nothing to record and the presence was dropped;
        // the maker is then created with the expected set seeded but no live
        // slots, and coverage can never be reached for a session whose every
        // dial raced ahead of its descriptor. Re-note every slot the roster
        // currently holds so the maker sees the presence that was lost.
        // `note_slot_present` inserts into a set, so re-noting a slot its own
        // live announce already recorded is idempotent — no double count.
        // Registration seats a slot in the roster before its link task
        // announces, so any slot whose announce found no maker is already
        // visible in this snapshot; a slot that registers after this rescan
        // reaches the maker through its own later announce, and none can fall
        // between the two. Snapshot the slot ids under the sessions lock and
        // drop it before touching the decision makers — these two locks are
        // only ever taken sessions-then-decision-makers, never nested the other
        // way.
        let registered_slots: Vec<SlotId> = {
            let roster = self.sessions.lock();
            roster
                .get(&key)
                .map(|slots| slots.keys().copied().collect())
                .unwrap_or_default()
        };
        // A re-note that completes the expected set latches the session started
        // inside the maker, so the `maybe_start_session` below would then see an
        // already-started session and deliver nothing. Drive delivery from the
        // note that completed coverage instead: fan the start directive to every
        // local slot and across the mesh, exactly as a live announce's
        // completion does. The `|=` keeps every remaining slot seeded into the
        // live set after coverage latches, since only the first covering note
        // returns true.
        let mut reconcile_started_session = false;
        for slot in registered_slots {
            reconcile_started_session |=
                consensus::note_slot_present(&self.decision_makers, &key, slot);
        }
        if reconcile_started_session {
            crate::routing::deliver_session_start(
                &self.sessions,
                &self.decision_makers,
                &self.mesh_links,
                &key,
            );
        }
        // A descriptor push that promotes this relay to authority (the
        // coordinator dropped the former authority from the order) may make this
        // relay the one to observe full slot presence — re-evaluate and fire the
        // session-start directive if the accumulated live slots already cover the
        // expected set.
        crate::routing::maybe_start_session(
            &self.sessions,
            &self.decision_makers,
            &self.mesh_links,
            &key,
        );

        let mut inner = self.inner.lock();

        // Remember each named peer's contact details — address plus the enrolled
        // cert a dial pins — so the desired-peer set published for the dialer can
        // carry them (a relay never dials itself).
        for peer in &descriptor.peers {
            if peer.relay_id != self.our_id {
                inner.peer_contacts.insert(
                    peer.relay_id,
                    PeerContact {
                        addr: peer.relay_addr,
                        addrs: peer.relay_addrs.clone(),
                        cert_der: peer.cert_der.clone(),
                    },
                );
            }
        }

        let old_peers = inner.desired.get(&key).cloned().unwrap_or_default();

        // An empty peer set means a single-relay session (no mesh); forget the
        // entry entirely rather than leave an empty set lingering.
        if new_peers.is_empty() {
            inner.desired.remove(&key);
        } else {
            inner.desired.insert(key.clone(), new_peers.clone());
        }

        // Reconcile every peer whose membership in this session could have
        // changed: the union of the old and new peer sets.
        let affected: HashSet<RelayId> = old_peers.union(&new_peers).copied().collect();
        reconcile_peers(&mut inner, affected);
        publish_desired_peers(&mut inner);
    }
}
