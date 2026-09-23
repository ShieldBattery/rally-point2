//! Re-dialing a dropped home-relay link: the embedder-facing re-home hook and
//! its outcomes, what the driver carries across a session's life to re-dial
//! with, and the loop that retries the same relay and escalates to
//! coordinator-mediated failover when it stays unreachable.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::ids::SlotId;
use rally_point_transport::Link;
use tokio::time::Instant;

use crate::dial::{ClientEndpoint, DialError};
use crate::identity::Identity;

use super::DriverError;
use super::backoff::{Backoff, EscalationWait, WaitOutcome, await_rehome, wait_backoff};
use super::retention::{
    redivert_oversize_retention_on_same_relay_resume, rehome_own_slot_anchor, reinject_retention,
    same_relay_resume_cursors,
};
use super::state::{
    GameSeam, LoopState, OUTAGE_OUTBOUND_BUFFER_CAP, RECONNECT_DIAL_TIMEOUT,
    REHOME_PROVIDER_DEADLINE,
};

/// The embedder's answer to "where should this session re-home?" — the outcome a
/// [`RehomeProvider`] returns when the driver escalates a dead home relay to
/// coordinator-mediated failover.
///
/// The embedder does the coordinator round-trip and the cert pinning; the driver
/// never touches certs. A [`NewTarget`](Self::NewTarget) hands back a fresh
/// [`ClientEndpoint`] whose trust roots pin the *new* relay's cert — the driver
/// just dials it with the same identity and resume cursors.
pub enum RehomeOutcome {
    /// Move the session to a new relay: dial `endpoint` at `relay_addr`, then each of
    /// `fallback_addrs` in order until one connects (TLS `server_name`), with the same
    /// identity and resume cursors. The embedder built `endpoint` with the replacement
    /// relay's pinned cert.
    NewTarget {
        /// The replacement relay's id. The driver adopts this as its current relay
        /// id only on a *successful* replacement dial, so the id it next passes to
        /// [`RehomeProvider::rehome`] always names the relay the driver is actually
        /// homed on — never a relay it merely tried and failed to reach.
        relay_id: u64,
        /// The endpoint to dial the replacement relay from — its trust roots pin the
        /// new relay's cert.
        endpoint: ClientEndpoint,
        /// The replacement relay's most-preferred address.
        relay_addr: SocketAddr,
        /// The replacement relay's other addresses (typically its other IP family),
        /// dialed in order when `relay_addr` does not connect. Whichever address
        /// connects becomes the one later same-relay re-dials start from.
        fallback_addrs: Vec<SocketAddr>,
        /// The replacement relay's TLS server name.
        server_name: String,
    },
    /// The coordinator says the named relay is in fact still live: keep dialing it,
    /// resuming the same-relay backoff (the escalation window resets).
    Stay,
    /// No live relay can take the session over yet (or the session is unknown to the
    /// coordinator). Keep the same-relay backoff and let the driver re-ask on the
    /// `ESCALATE_RETRY` cadence.
    Unavailable,
}

/// A boxed future a [`RehomeProvider::rehome`] returns — the manual async-trait
/// shape, so the crate needs no proc-macro dependency and the DLL implements the
/// trait with a plain `Box::pin(async move { … })`.
pub type RehomeFuture<'a> = Pin<Box<dyn Future<Output = RehomeOutcome> + Send + 'a>>;

/// An embedder-supplied hook the driver calls when its home relay looks dead and
/// reconnection should escalate to coordinator-mediated failover.
///
/// The driver calls [`rehome`](Self::rehome) only once the game has started (it
/// tracks the relay's `SessionStart` directive itself) and only after same-relay
/// re-dials have failed long enough — immediately on a cert/pin rejection (a
/// restarted relay serving a fresh cert), otherwise after `ESCALATE_AFTER`. The
/// implementation is where the embedder enforces "only once the game has started"
/// as well, does the coordinator `POST /session/rehome` round-trip, and — for a
/// [`RehomeOutcome::NewTarget`] — builds the fresh [`ClientEndpoint`] pinning the
/// replacement relay's cert. The driver never constructs certs.
pub trait RehomeProvider: Send + Sync {
    /// Resolves where the session should re-home, given the id of the relay the
    /// driver believes is dead. The **driver owns** this id — it is the relay the
    /// driver is currently homed on, seeded from [`Reconnect::relay_id`] and advanced
    /// only on a successful re-home dial — so the embedder names it to the
    /// coordinator verbatim rather than guessing its own current relay. Called at
    /// most on the escalation cadence, never on the hot path.
    fn rehome(&self, dead_relay_id: u64) -> RehomeFuture<'_>;
}

/// What a [`LinkDriver`](super::LinkDriver) needs to re-dial its home relay itself, so
/// [`run_reconnecting`](super::LinkDriver::run_reconnecting) can resume a dropped session
/// without tearing the game seam down.
pub struct Reconnect {
    /// The endpoint to re-dial from — the one that made the initial connection, its
    /// UDP socket held open for the session's life. If it is also dialing other
    /// slots, clone the caller's via [`ClientEndpoint::from_endpoint`].
    pub endpoint: ClientEndpoint,
    /// The home relay's address to re-dial first — the one the initial connection
    /// was made over.
    pub relay_addr: SocketAddr,
    /// The home relay's other addresses (typically its other IP family). Each
    /// failed re-dial moves on to the next address, wrapping back to `relay_addr`,
    /// so a client whose path to one address dies mid-game — its IPv6 connectivity
    /// dropping while IPv4 keeps working, say — resumes over another instead of
    /// re-dialing the dead one until its drop is decided. Empty re-dials
    /// `relay_addr` alone.
    pub fallback_addrs: Vec<SocketAddr>,
    /// The relay's TLS server name, checked against its certificate.
    pub server_name: String,
    /// The home relay's id — seeds the reconnect target's current relay id. The
    /// driver owns this id from here on, passing it to [`RehomeProvider::rehome`] as
    /// the dead relay and advancing it only on a successful re-home dial, so the
    /// provider never has to guess which relay the driver is homed on.
    pub relay_id: u64,
    /// The credentials to re-authorize with. Its token names this client's slot (the
    /// subject of the self-connectivity signal) and bounds how long reconnection is
    /// attempted — an expired token ends the loop.
    pub identity: Identity,
    /// The coordinator-mediated failover hook. `None` disables re-home escalation:
    /// the driver only ever retries the *same* relay (the pre-failover behavior).
    /// `Some` enables escalation to a replacement relay when the home relay stays
    /// unreachable (see [`RehomeProvider`]).
    pub rehome: Option<Arc<dyn RehomeProvider>>,
    /// How long same-relay re-dials must keep failing before the driver escalates to
    /// the re-home provider. `None` uses `ESCALATE_AFTER`; set it only to tune the
    /// escalation aggressiveness (or shorten it in a test). A cert/pin rejection
    /// escalates immediately regardless.
    pub escalate_after: Option<Duration>,
    /// How often the driver re-escalates while the provider answers `Unavailable` or
    /// a re-home dial keeps failing. `None` uses `ESCALATE_RETRY`.
    pub escalate_retry: Option<Duration>,
}

/// The current re-dial target, mutable across sessions so a successful re-home
/// updates where subsequent drops reconnect to (the old relay is dead). The
/// identity and the [`RehomeProvider`] stay fixed for the driver's life; only the
/// endpoint/address/name move.
pub(super) struct ReconnectTarget {
    pub(super) endpoint: ClientEndpoint,
    /// Every address the relay is reachable at, never empty.
    addrs: Vec<SocketAddr>,
    /// The index into `addrs` the next same-relay re-dial dials. A failed dial
    /// advances it (wrapping), a successful one leaves it, so the address that last
    /// connected is the first one tried after a later drop.
    next_addr: usize,
    pub(super) server_name: String,
    /// The id of the relay this target dials — the driver's current relay id, passed
    /// to [`RehomeProvider::rehome`] as the dead relay. Seeded from
    /// [`Reconnect::relay_id`] and updated only on a successful re-home dial (never a
    /// failed one), so it always names the relay the driver is actually homed on.
    pub(super) relay_id: u64,
}

impl ReconnectTarget {
    /// A target over `primary` then `fallbacks`, the next re-dial starting at `addrs[first]`.
    pub(super) fn new(
        endpoint: ClientEndpoint,
        primary: SocketAddr,
        fallbacks: Vec<SocketAddr>,
        first: usize,
        server_name: String,
        relay_id: u64,
    ) -> Self {
        let mut addrs = Vec::with_capacity(1 + fallbacks.len());
        addrs.push(primary);
        addrs.extend(fallbacks);
        Self {
            endpoint,
            next_addr: first % addrs.len(),
            addrs,
            server_name,
            relay_id,
        }
    }

    /// The address the next same-relay re-dial dials.
    pub(super) fn current_addr(&self) -> SocketAddr {
        self.addrs[self.next_addr]
    }

    /// Moves the next re-dial on to the relay's next address, wrapping around.
    fn advance_addr(&mut self) {
        self.next_addr = (self.next_addr + 1) % self.addrs.len();
    }
}

/// The reconnect machinery [`run_reconnecting`](super::LinkDriver::run_reconnecting) owns
/// across a session's life: the current (mutable) re-dial target plus the fixed
/// credentials, re-home hook, and escalation timing. Bundled so `reconnect_link`
/// takes it as one argument.
pub(super) struct ReconnectDriver {
    pub(super) target: ReconnectTarget,
    pub(super) identity: Identity,
    pub(super) rehome: Option<Arc<dyn RehomeProvider>>,
    pub(super) escalate_after: Duration,
    pub(super) escalate_retry: Duration,
}

/// Whether a session ended on a link/stream failure the reconnect loop should
/// re-dial through, as opposed to a terminal condition (a stalled game, an
/// exhausted window, a relay refusal) reconnecting cannot fix.
pub(super) fn is_link_failure(error: &DriverError) -> bool {
    matches!(
        error,
        DriverError::Link(_) | DriverError::ControlStream(_) | DriverError::ControlStreamLost
    )
}

/// Whether the identity's authorization token has expired against the wall clock —
/// the relay would reject any re-dial, so reconnection stops. Matches the relay's
/// boundary: the expiry instant itself counts as expired.
pub(super) fn token_expired(identity: &Identity) -> bool {
    // Fails open on an unreadable clock: an unusable reading reads as "not
    // expired yet", leaving the re-dial to the relay's own verdict rather than
    // ending a live game on a local clock fault.
    rally_point_proto::time::unix_secs_fail_open() >= identity.token().claims.expires_at.0
}

/// The outcome of the reconnect loop for one dropped link.
pub(super) enum Reconnected {
    /// The relay accepted the re-dial and the link was rebound in place; the caller
    /// resumes the session over it.
    Resumed,
    /// Reconnection can't proceed (the slot departed, or the token expired); the
    /// caller ends the driver with this error.
    Terminal(DriverError),
    /// The game tore down its seam during the outage; end cleanly.
    GameGone,
}

/// Re-dials until the link is re-established, the game leaves, or a terminal
/// refusal — retrying the same relay, and escalating to coordinator-mediated
/// failover (the [`RehomeProvider`]) when it stays unreachable.
///
/// Backs off between attempts (buffering any turns the game produces meanwhile and
/// noticing a teardown), presents the resume cursors, and on success rebinds `link`
/// in place so the receive dedup and unacked window carry over. A slot-departed
/// refusal or an expired token ends it terminally; every other dial failure is
/// retried under a growing backoff.
///
/// **Escalation.** Once the game has started (`state.game_started`) and a
/// [`RehomeProvider`] is configured, a run of failed same-relay dials escalates to
/// the provider — immediately on a cert/pin rejection (a restarted relay serving a
/// fresh cert, which no same-relay retry can pass), otherwise after
/// [`ESCALATE_AFTER`]. [`RehomeOutcome::Stay`] resumes the same-relay backoff and
/// resets the window; [`RehomeOutcome::Unavailable`] keeps it and re-escalates on
/// the [`ESCALATE_RETRY`] cadence; [`RehomeOutcome::NewTarget`] dials the
/// replacement relay with the same identity and cursors, and on success rebinds,
/// re-injects the retained turns, and updates `target` so subsequent drops
/// reconnect there.
pub(super) async fn reconnect_link(
    rc: &mut ReconnectDriver,
    link: &mut Link,
    seam: &mut GameSeam,
    state: &mut LoopState,
    backoff: &mut Backoff,
) -> Reconnected {
    // This client's own slot, from its token — the slot whose receive window every
    // re-dial anchors on the (always fresh) relay-side link: the same-relay dial
    // below anchors from the oldest-unacked seq, the re-home dial from the retention
    // ring's front (see the NewTarget branch).
    let own_slot = rc.identity.token().claims.slot;
    // When escalation to the re-home provider is next due. It starts one window out
    // and is pulled to now on the first cert/pin rejection; each escalation advances
    // it, so continuous failures escalate on a bounded cadence, not every attempt.
    let mut next_escalate_at = Instant::now() + rc.escalate_after;
    let mut escalated_once = false;

    loop {
        // An expired token can never re-authorize: stop before wasting a dial.
        if token_expired(&rc.identity) {
            return Reconnected::Terminal(DriverError::TokenExpired);
        }
        match wait_backoff(backoff, seam, state).await {
            WaitOutcome::Elapsed => {}
            WaitOutcome::GameGone => return Reconnected::GameGone,
            WaitOutcome::BufferExhausted => {
                return Reconnected::Terminal(DriverError::OutageBufferExhausted {
                    buffered: state.outbound_buffer.len(),
                    cap: OUTAGE_OUTBOUND_BUFFER_CAP,
                });
            }
        }
        let cursors = state.reorder.cursors();
        // The relay builds a brand-new receive dedup on *every* re-dial (a fresh
        // `Link` per connection), so a same-relay resume must anchor our own slot's
        // window too — otherwise a game past ~4096 turns re-dials into an
        // out-of-window rejection that closes the link. The anchor is the oldest
        // seq this resume will actually re-send, across BOTH of its re-send
        // paths: the AckManager's oldest replayable unacked seq (the redundancy
        // pass re-carries the unacked window oldest-first over the rebound
        // connection) and the oldest retained OVERSIZE turn (restaged onto the
        // fresh control stream by the resume — it never entered the unacked
        // window, and anchoring above it would have the relay's dedup discard
        // the restaged retry as a duplicate, permanently stranding peers on its
        // seq). With neither source, it is the next seq we will produce (the
        // buffered/live turns that flush on resume) — NOT the retention ring's
        // front, whose ordinary-sized turns a same-relay resume never re-sends.
        // Selective packet acks leave the unacked window sparse, so seqs above
        // the anchor that were already acked will never be re-sent either; the
        // relay closes those holes itself, seeding the fresh window from its
        // session-lifetime receipt records. (`cursors` stays peer-only; the
        // re-home dial builds its own set below with the retention-front anchor,
        // which it *does* re-inject.)
        let same_relay_cursors = same_relay_resume_cursors(
            &cursors,
            link.oldest_replayable_seq(own_slot),
            state.retention.oldest_oversize_seq(),
            own_slot,
            state.next_outbound_seq,
        );
        let addr = rc.target.current_addr();
        match rc
            .target
            .endpoint
            .reconnect_with_timeout(
                addr,
                &rc.target.server_name,
                &rc.identity,
                &same_relay_cursors,
                RECONNECT_DIAL_TIMEOUT,
            )
            .await
        {
            Ok(fresh) => {
                // A same-relay resume: the client-side receive dedup and unacked
                // window carry over, and the datagram/ack path needs no
                // retention re-injection — the rebound link's redundancy
                // re-carries the unacked tail, and the relay seeds its fresh
                // receive window's acked holes from its own session-lifetime
                // receipt records. An OVERSIZE turn is different: it
                // never rode the datagram/ack path at all (there is no
                // per-turn acknowledgment for a control-stream write), so a
                // drop between the local `write_all` succeeding and the relay
                // actually processing it is invisible to everything else here
                // — re-divert every still-retained oversize turn onto the
                // fresh connection's control stream, exactly as a re-home
                // does. See `redivert_oversize_retention_on_same_relay_resume`
                // for why this is safe to run unconditionally. Checked after
                // rebind, against the fresh connection's own datagram budget
                // — mirroring the re-home path's own rebind-then-reinject
                // order — though an oversize turn is definitionally oversize
                // on any realistic path.
                link.rebind(fresh.connection().clone());
                redivert_oversize_retention_on_same_relay_resume(link, state);
                backoff.reset();
                tracing::info!(relay = %addr, "re-dialed the home relay");
                return Reconnected::Resumed;
            }
            // The game moved on without us: no dial can bring the slot back.
            Err(DialError::SlotDeparted) => {
                return Reconnected::Terminal(DriverError::SlotDeparted);
            }
            // A transient same-relay failure. Retry — over the relay's next address,
            // in case it was this one's path that died rather than the relay — and,
            // for an in-game session with a provider, escalate to
            // coordinator-mediated failover when the relay stays unreachable.
            Err(error) => {
                rc.target.advance_addr();
                // Clone the provider handle out so the escalation block can mutate
                // `rc.target` without holding a borrow of `rc.rehome` across it.
                let provider = rc.rehome.clone();
                if let Some(provider) = provider
                    && state.game_started
                {
                    // A cert/pin rejection can never be cured by a same-relay retry,
                    // so escalate at once rather than waiting out the timed window.
                    if !escalated_once && is_cert_rejection(&error) {
                        next_escalate_at = Instant::now();
                    }
                    if Instant::now() >= next_escalate_at {
                        escalated_once = true;
                        // The driver owns the current relay id: name the relay it is
                        // actually homed on as the dead one, never a guess. The ask
                        // runs under the driver's own deadline with the seam still
                        // serviced (see `await_rehome`), so a hung provider cannot
                        // freeze reconnection with it.
                        let answer = await_rehome(
                            &provider,
                            rc.target.relay_id,
                            REHOME_PROVIDER_DEADLINE,
                            seam,
                            state,
                        )
                        .await;
                        match answer {
                            EscalationWait::GameGone => return Reconnected::GameGone,
                            EscalationWait::BufferExhausted => {
                                return Reconnected::Terminal(DriverError::OutageBufferExhausted {
                                    buffered: state.outbound_buffer.len(),
                                    cap: OUTAGE_OUTBOUND_BUFFER_CAP,
                                });
                            }
                            EscalationWait::TimedOut => {
                                next_escalate_at = Instant::now() + rc.escalate_retry;
                                tracing::info!(
                                    "re-home escalation: provider deadline elapsed; re-asking later",
                                );
                            }
                            EscalationWait::Answered(outcome) => match outcome {
                                RehomeOutcome::Stay => {
                                    // The relay is live after all: resume same-relay
                                    // backoff, resetting the escalation window.
                                    next_escalate_at = Instant::now() + rc.escalate_after;
                                    tracing::info!("re-home escalation: coordinator says stay");
                                }
                                RehomeOutcome::Unavailable => {
                                    next_escalate_at = Instant::now() + rc.escalate_retry;
                                    tracing::info!(
                                        "re-home escalation: no relay available yet; re-asking later",
                                    );
                                }
                                RehomeOutcome::NewTarget {
                                    relay_id,
                                    endpoint,
                                    relay_addr,
                                    fallback_addrs,
                                    server_name,
                                } => {
                                    // The replacement relay has never seen this client, so
                                    // its receive-side dedup for our own slot would base at
                                    // seq 0 and reject our resumed (already high) seq stream
                                    // once it passed the window — dropping the link, and with
                                    // every re-homed slot crossing the window together, the
                                    // whole group. Declare our own-slot resume anchor at the
                                    // oldest seq the *datagram* re-send will actually replay,
                                    // so the relay bases the window there, the resumed stream
                                    // is accepted, and every seq above the anchor eventually
                                    // arrives (closing the window's contiguous prefix). Two
                                    // sources feed that re-send: the rebound link's replayable
                                    // unacked window (the redundancy pass re-carries it until
                                    // confirmed) and `reinject_retention`'s retained ring, so
                                    // the anchor is the retention front extended downward only
                                    // through contiguously unacked seqs (see
                                    // `rehome_own_slot_anchor` for the sparse-window trade).
                                    // No source means nothing to re-send, so no anchor is
                                    // needed (the window bases at 0, correct for a slot that
                                    // never sent).
                                    let mut rehome_cursors = cursors.clone();
                                    if let Some(anchor) = rehome_own_slot_anchor(
                                        link,
                                        own_slot,
                                        state.retention.front_seq(),
                                    ) {
                                        rehome_cursors.push((own_slot, anchor));
                                    }
                                    let mut new_target = ReconnectTarget::new(
                                        endpoint,
                                        relay_addr,
                                        fallback_addrs,
                                        0,
                                        server_name,
                                        relay_id,
                                    );
                                    match dial_each_address(
                                        &mut new_target,
                                        &rc.identity,
                                        &rehome_cursors,
                                    )
                                    .await
                                    {
                                        Ok(fresh) => {
                                            // A re-home resume onto a fresh relay: rebind, then
                                            // re-inject the retained turns so the new relay's
                                            // empty ring re-carries them to peers. Only now —
                                            // on a *successful* dial — does the driver adopt
                                            // the new relay id, so a failed dial never leaves
                                            // it naming a relay it isn't homed on.
                                            link.rebind(fresh.connection().clone());
                                            reinject_retention(link, state);
                                            let new_addr = new_target.current_addr();
                                            rc.target = new_target;
                                            backoff.reset();
                                            tracing::info!(
                                                relay = %new_addr,
                                                "re-homed onto a replacement relay",
                                            );
                                            return Reconnected::Resumed;
                                        }
                                        Err(DialError::SlotDeparted) => {
                                            return Reconnected::Terminal(
                                                DriverError::SlotDeparted,
                                            );
                                        }
                                        Err(new_error) => {
                                            next_escalate_at = Instant::now() + rc.escalate_retry;
                                            tracing::info!(
                                                %new_error,
                                                "re-home dial failed; retrying the old relay meanwhile",
                                            );
                                        }
                                    }
                                }
                            },
                        }
                    }
                }
                tracing::info!(%error, relay = %addr, "re-dial attempt failed; backing off");
            }
        }
    }
}

/// Dials `target`'s addresses in order from its first until one connects, leaving the
/// target's next re-dial on the address that answered. A slot refusal ends the walk at
/// once (no other address can reverse it); otherwise a total failure returns the last
/// address's error.
async fn dial_each_address(
    target: &mut ReconnectTarget,
    identity: &Identity,
    cursors: &[(SlotId, u64)],
) -> Result<Link, DialError> {
    let mut index = 0;
    loop {
        target.next_addr = index;
        let addr = target.addrs[index];
        match target
            .endpoint
            .reconnect_with_timeout(
                addr,
                &target.server_name,
                identity,
                cursors,
                RECONNECT_DIAL_TIMEOUT,
            )
            .await
        {
            Ok(link) => return Ok(link),
            Err(error)
                if index + 1 < target.addrs.len() && !matches!(error, DialError::SlotDeparted) =>
            {
                tracing::info!(%error, relay = %addr, "re-home dial failed; trying the relay's next address");
                index += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Best-effort classification of a dial failure as a TLS certificate / pin
/// rejection — a relay that restarted with a fresh keypair, which no same-relay
/// retry can ever get past, so escalation need not wait out the timed window. It
/// inspects the crypto-handshake markers noq/rustls surface; a miss only defers
/// escalation to the [`ESCALATE_AFTER`] fallback rather than breaking it, so the
/// classifier is deliberately conservative.
pub(super) fn is_cert_rejection(error: &DialError) -> bool {
    if !matches!(error, DialError::Connection(_)) {
        return false;
    }
    let text = error.to_string().to_lowercase();
    text.contains("certificate")
        || text.contains("crypto")
        || text.contains("tls")
        || text.contains("handshake")
        || text.contains("unknownissuer")
        || text.contains("bad_certificate")
}
