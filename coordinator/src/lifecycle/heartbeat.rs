//! Heartbeat ingest: the single owner of what a relay's beat means.
//!
//! A relay restates its whole world on every beat — the sessions it still
//! holds, the slots linked into each, the load state each has accumulated, and
//! the backbone round-trips it measured — and one beat lands in five places at
//! once. [`Lifecycle::ingest_heartbeat`] is where that happens, in a fixed
//! order:
//!
//! 1. **Bound the wire shape.** A beat's vectors carry no length limit of their
//!    own, so a roster or report list past the ceilings below is truncated. A
//!    truncated roster also stops being an authoritative statement about who is
//!    *absent*, so the completeness flag is downgraded with it.
//! 2. **Fence on the connection's generation.** Only the relay's current
//!    control connection may speak for it; a superseded connection's late beat
//!    describes a view the live one has already replaced, and is dropped whole.
//! 3. **Filter to the sessions the relay serves.** Per roster entry, not per
//!    beat: a heartbeat legitimately batches many sessions, and one forged
//!    entry must not cost the rest.
//! 4. **Fan out** what survives: active-player presence, the empty-roster
//!    evidence behind the stale-session reap, each session's retained load
//!    state, and the backbone-RTT table.
//!
//! The caller decodes a frame and calls this once; it picks none of the above.

use rally_point_proto::control::{RegionId, RegionRttReport};
use rally_point_proto::time::unix_secs_fail_open;

use super::*;
use crate::ledger::RelayLedger;
use crate::pair_rtts::{self, PairRttStore};
use crate::presence;
use crate::regions::RegionsConfig;
use crate::registry;
use crate::session;

/// The most sessions a single heartbeat's roster may name — every session the
/// relay still holds, not only the occupied ones (a session whose local slots
/// have all left keeps restating its retained load state until it retires). No
/// relay's session count is tracked anywhere the coordinator could size this
/// exactly, so this is a generous ceiling rather than a tight one: bounding the
/// per-beat iteration cost against a roster a relay never legitimately grows
/// close to, while leaving enormous headroom over any real deployment.
pub const MAX_HEARTBEAT_SESSIONS: usize = 4096;

/// The most slots a single relay-reported session entry may name in any one of its
/// three slot lists — `session::MAX_SLOT` plus one, the same ceiling a session's
/// own slots are validated against at creation. Such an entry (a heartbeat's roster
/// entry, or an attested load-state snapshot) carries no length validation on the
/// wire, so one naming more slots than a session could ever legitimately have is
/// definitely forged, not just generous. (An entry naming *no* connected slot is
/// ordinary: the relay holds the session but no live link into it.)
pub const MAX_HEARTBEAT_SESSION_SLOTS: usize = session::MAX_SLOT as usize + 1;

/// The most backbone round-trip reports a single heartbeat may carry. A
/// legitimate report never exceeds the coordinator's own configured region
/// count (a report for an unconfigured region is dropped as the beat folds
/// in), so this is a large multiple of any realistic fleet region catalog —
/// bounding the per-beat iteration cost without ever crowding out real
/// headroom for the fleet to grow.
pub const MAX_HEARTBEAT_REGION_RTTS: usize = 256;

/// One relay's decoded heartbeat: everything a beat asserts about the relay's
/// world, exactly as it arrived on the wire and before any ceiling, fence or
/// ownership check has been applied.
pub(crate) struct RelayHeartbeat {
    /// Whether the relay claims `sessions` names *every* session it holds — the
    /// only thing that lets an omission count as evidence a session is empty. A
    /// partial snapshot turns omissions into unknown instead, and so does a
    /// roster this coordinator had to truncate.
    pub(crate) roster_complete: bool,
    /// The relay's roster: one entry per session it holds, naming the slots
    /// linked right now plus the load state that session has accumulated.
    pub(crate) sessions: Vec<SessionPresence>,
    /// The backbone round-trips this relay measured from its own region since
    /// the last beat.
    pub(crate) region_rtts: Vec<RegionRttReport>,
}

/// The coordinator-side context a heartbeat's `region_rtts` fold through.
///
/// `relay_region` is the reporting relay's own region — the origin of every direction
/// it measures — validated at enroll; a region-less relay reports nothing. `regions`
/// is the coordinator's configured set, so a report naming a region it does not list
/// (a stale target after a config change) is dropped. `store` is the shared pair table,
/// and `ledger` is the optional persistence a *changed* direction is written through to.
pub(crate) struct RegionRttIngest<'a> {
    pub(crate) relay_region: Option<&'a RegionId>,
    pub(crate) regions: &'a RegionsConfig,
    pub(crate) store: &'a PairRttStore,
    pub(crate) ledger: Option<&'a RelayLedger>,
}

impl RegionRttIngest<'_> {
    /// Folds a heartbeat's `region_rtts` into the backbone-RTT table: each report pairs
    /// the reporting relay's own region (the direction's origin) with the region it
    /// measured, recorded per-direction last-write-wins beyond a dead-band. A report naming
    /// a region the coordinator does not configure is dropped (a stale target list after a
    /// config change); a relay with no region contributes nothing. When a direction's value
    /// actually changed and a ledger is present, that direction is persisted (keyed by pair
    /// and origin) so last-known round-trips survive a restart — a steady-state re-report
    /// (the same value every heartbeat) changes nothing and writes nothing.
    ///
    /// `measured_at` is stamped with a plain Unix-seconds now, `0` on a pre-epoch clock
    /// rather than failing: the value is informational (it exposes a pair's age), not
    /// security-bearing like the ledger's token expiry.
    pub(crate) fn ingest(&self, relay_id: RelayId, reports: &[RegionRttReport]) {
        let Some(relay_region) = self.relay_region else {
            if !reports.is_empty() {
                tracing::debug!(
                    relay_id = relay_id.0,
                    "ignoring backbone RTT reports from a relay with no configured region",
                );
            }
            return;
        };
        let now = unix_secs_fail_open();
        for report in reports {
            if !self.regions.contains(&report.region) {
                tracing::debug!(
                    relay_id = relay_id.0,
                    region = report.region.as_ref(),
                    "dropping a backbone RTT report for a region not in the coordinator's config",
                );
                continue;
            }
            let changed = self
                .store
                .record(relay_region, &report.region, report.rtt_ms, now);
            if changed {
                let (a, b) = pair_rtts::canonical_pair(relay_region, &report.region);
                // A beyond-dead-band change is rare — a direction's first fill, or a real
                // backbone shift — so each one is worth a log line: the log stream is the
                // pair table's per-direction change history (the table itself keeps only the
                // latest value per direction).
                tracing::info!(
                    relay_id = relay_id.0,
                    pair_a = a.as_ref(),
                    pair_b = b.as_ref(),
                    origin = relay_region.as_ref(),
                    rtt_ms = report.rtt_ms,
                    "backbone RTT recorded",
                );
                if let Some(ledger) = self.ledger
                    && let Err(error) =
                        ledger.record_direction_rtt(a, b, relay_region, report.rtt_ms, now)
                {
                    tracing::warn!(
                        relay_id = relay_id.0,
                        %error,
                        "persisting a backbone RTT to the ledger failed; keeping the in-memory value",
                    );
                }
            }
        }
    }
}

/// Truncates each of a session entry's three slot lists to
/// [`MAX_HEARTBEAT_SESSION_SLOTS`], logging what was cut.
///
/// A session cannot have more slots than that ceiling, so a longer list is forged
/// (or a relay bug) whether it names the connected slots or the
/// ever-connected/ever-started ones. Applied to every relay-supplied session entry
/// — a heartbeat's roster and an attested load-state snapshot alike — since both
/// arrive on the wire with no length limit of their own and both feed the same
/// accumulated sets. Truncated rather than rejected: the legitimate entries that
/// precede the excess are still worth folding in.
pub(crate) fn bound_session_slot_lists(relay_id: RelayId, session: &mut SessionPresence) {
    for (label, slots) in [
        ("connected", &mut session.slots),
        ("ever-connected", &mut session.ever_connected),
        ("started", &mut session.started),
    ] {
        if slots.len() > MAX_HEARTBEAT_SESSION_SLOTS {
            tracing::warn!(
                relay_id = relay_id.0,
                tenant = session.tenant.as_ref(),
                session = session.session.0,
                list = label,
                reported = slots.len(),
                cap = MAX_HEARTBEAT_SESSION_SLOTS,
                "relay-reported session slot list exceeds the per-session cap; truncating",
            );
            slots.truncate(MAX_HEARTBEAT_SESSION_SLOTS);
        }
    }
}

impl Lifecycle {
    /// Ingests one heartbeat `relay` sent on the control connection that
    /// enrolled as `generation`: bound the wire shape, fence on the generation,
    /// filter the roster to the sessions this relay serves, then fan out. See
    /// this module's docs for why that order.
    ///
    /// `rtt` is the connection's view of the backbone-RTT table — the reporting
    /// relay's own region, the coordinator's configured region set, the shared
    /// pair table, and the ledger the changed directions persist through.
    ///
    /// A beat from a superseded connection has no effect at all, and a roster
    /// entry for a session this relay does not serve is dropped without costing
    /// the entries beside it. There is no second ingest path that could quietly
    /// skip either check.
    pub(crate) fn ingest_heartbeat(
        &self,
        relay: RelayId,
        generation: u64,
        beat: RelayHeartbeat,
        rtt: &RegionRttIngest<'_>,
    ) {
        let RelayHeartbeat {
            roster_complete,
            mut sessions,
            mut region_rtts,
        } = beat;
        let setup = &self.inner.setup;
        tracing::trace!(relay_id = relay.0, "relay heartbeat");
        // Shape-bound the wire data before any of it is applied: a beat's
        // vectors carry no length limit of their own, so a roster or report
        // list past the generous ceilings above is definitely forged (or a
        // relay bug), not a fleet this coordinator was ever going to see.
        // Truncated rather than the whole beat rejected — the beat still
        // carries the relay's own liveness signal and whatever legitimate
        // entries precede the excess.
        let mut complete_roster = roster_complete;
        if sessions.len() > MAX_HEARTBEAT_SESSIONS {
            tracing::warn!(
                relay_id = relay.0,
                reported = sessions.len(),
                cap = MAX_HEARTBEAT_SESSIONS,
                "heartbeat session roster exceeds the per-beat cap; truncating",
            );
            sessions.truncate(MAX_HEARTBEAT_SESSIONS);
            // Once the coordinator drops a suffix, omission is no longer an
            // authoritative statement even if the sender marked its original
            // snapshot complete. Positive entries remain useful below.
            complete_roster = false;
        }
        for session in &mut sessions {
            bound_session_slot_lists(relay, session);
        }
        if region_rtts.len() > MAX_HEARTBEAT_REGION_RTTS {
            tracing::warn!(
                relay_id = relay.0,
                reported = region_rtts.len(),
                cap = MAX_HEARTBEAT_REGION_RTTS,
                "heartbeat region-RTT report exceeds the per-beat cap; truncating",
            );
            region_rtts.truncate(MAX_HEARTBEAT_REGION_RTTS);
        }

        // The beat's roster feeds active-player presence — but only from the
        // relay's CURRENT connection. A stale connection's late beat (a
        // reconnect raced it) is dropped whole: its roster describes a
        // superseded view, and applying it would overwrite what the live
        // connection reports. (The store's own generation fences are the
        // second line of defense.)
        if !registry::generation_is_current(setup.registry(), relay, generation) {
            tracing::debug!(
                relay_id = relay.0,
                "dropping a heartbeat roster from a stale control connection",
            );
            return;
        }
        // A relay may only beat presence for sessions it actually
        // serves — the same membership check the departure/desync/result
        // arms apply, applied per roster entry rather than to the whole
        // beat, since a heartbeat legitimately batches many sessions and
        // one forged entry must not cost the rest. Unchecked, any
        // enrolled relay could name a victim `(tenant, session, slot)`
        // and forge it present: blocking that slot from re-queueing, and
        // (via `on_presence_seen` below) cancelling a reap timer that was
        // never supposed to be cancelled. `relay_serves_session` itself
        // stays fail-open when the coordinator holds no serving-relay
        // record for a session (the post-restart tail), so a legitimate
        // pre-existing session's beat is unaffected.
        sessions.retain(|session| {
            let allowed = setup.relay_serves_session(relay, &session.tenant, session.session);
            if !allowed {
                tracing::warn!(
                    relay_id = relay.0,
                    tenant = session.tenant.as_ref(),
                    session = session.session.0,
                    "heartbeat presence for a session this relay does not serve; rejecting",
                );
            }
            allowed
        });
        presence::apply_heartbeat(
            setup.presence(),
            relay,
            generation,
            &sessions,
            Instant::now(),
        );
        self.on_relay_heartbeat(
            relay,
            generation,
            &sessions,
            complete_roster,
            Instant::now(),
        );
        // The beat also restates each session's accumulated load state,
        // which is the durable record behind the droppable slot-connected
        // / session-started / slot-started notices: the notice is the fast
        // path to the tenant's webhook, this is what repairs the record
        // when one is lost or a restart forgets it. It fires no webhook of
        // its own — the facts here have already been notified, and
        // re-notifying them every beat would flood the feed. A beat says
        // nothing about *when* the relay observed any of it, which is why
        // the load-state read asks its own question rather than reading a
        // beat's arrival as a deadline.
        self.merge_load_state(&sessions);
        // Backbone RTTs fold in under the same generation fence as presence: a
        // stale connection's beat describes a superseded view, so its measured
        // pairs must not overwrite what the live connection reports. Unlike the
        // session roster, RTTs carry no per-relay ownership to check — a
        // report only ever names the relay's own measured pair.
        rtt.ingest(relay, &region_rtts);
    }
}
