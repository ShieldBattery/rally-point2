//! The enroll handshake: the fixed sequence a relay's control connection runs
//! before it reaches the registry.
//!
//! Pending-Hello permit → `Hello` → version negotiate → region check → proof of
//! possession → **drop the permit** → ledger authorize → registry enroll. The
//! order is the security property, not an implementation detail: the permit
//! bounds only the window in which a caller has proven it holds the bootstrap
//! secret but not *which relay it is*, the challenge is what makes the claimed
//! id trustworthy, and the ledger check must run against a certificate the
//! connection has already proven it holds.
//!
//! [`EnrollHandshake`] is that sequence as a state machine: it is handed decoded
//! [`RelayToCoordinator`] frames one at a time and answers with the next
//! [`EnrollStep`] — a frame to send, a refusal to close on, or the enrolled
//! connection's identity. Nothing here reads or writes a socket, awaits, or
//! names a WebSocket type, so the whole order can be walked in a unit test and
//! the connection loop is left with only "send what it returns, feed it what
//! comes back".

use std::net::IpAddr;
use std::sync::Arc;

use rally_point_proto::control::{CoordinatorToRelay, RegionId, RelayHello, RelayToCoordinator};
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::{
    self, CONTROL_CLOSE_DUPLICATE_RELAY_ID, CONTROL_CLOSE_ENROLL_UNAUTHORIZED,
    CONTROL_CLOSE_IDENTITY_UNPROVEN, CONTROL_CLOSE_PROTOCOL_MISMATCH, CONTROL_CLOSE_UNKNOWN_REGION,
    ProtocolVersion,
};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::identity;
use crate::ledger::RelayLedger;
use crate::lifecycle::Lifecycle;
use crate::regions::RegionsConfig;
use crate::registry;
use crate::session::{self, SessionSetup};

/// The most control connections allowed to sit between a completed WebSocket
/// upgrade and a verified `Hello` at once. A connection in that window has
/// cleared only the bootstrap secret — proof of *a* relay, not proof of which
/// one — and the hello deadline bounds how long any single such connection may
/// sit there, but nothing bounds how many can sit there together: a caller
/// that keeps opening connections and never finishing enrollment would
/// otherwise accumulate one parked task and socket per connection, without
/// limit, for as long as it keeps churning. Sized well above a full relay
/// fleet reconnecting at once (a rolling deploy, a coordinator failover), so a
/// legitimate reconnect burst never trips it. The gate enforcing it is
/// [`CoordinatorState::pending_hellos`](super::CoordinatorState::pending_hellos),
/// shared by every control connection a coordinator serves.
pub(super) const MAX_PENDING_CONTROL_HELLOS: usize = 512;

/// The standard WebSocket "try again later" close code (RFC 6455 / the IANA
/// close-code registry), used to refuse a connection when the pending-Hello
/// gate ([`MAX_PENDING_CONTROL_HELLOS`]) is saturated. Distinct from the
/// `CONTROL_CLOSE_*` codes in [`rally_point_proto::version`]: those name a
/// specific enroll refusal a relay recognizes and reacts to individually
/// (`classify_control_close` on the relay side); this one carries no such
/// meaning; an unrecognized code already falls back to the relay's ordinary
/// short-delay reconnect, which is exactly the right reaction to a transient
/// capacity refusal.
pub(super) const CONTROL_CLOSE_TRY_AGAIN_LATER: u16 = 1013;

/// The close frame a refused connection is sent before it is dropped. The
/// refusal's own reasoning has already been logged where it was decided; this
/// carries only what goes out on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ControlClose {
    /// The WebSocket close code, which the relay classifies to pick its backoff.
    pub(super) code: u16,
    /// The human-readable reason. Deliberately generic for a ledger refusal, so
    /// a caller cannot probe which relay ids exist.
    pub(super) reason: String,
}

/// What the connection must do with the handshake's answer to a frame.
#[derive(Debug)]
pub(super) enum EnrollStep {
    /// Send this frame to the relay, then feed the handshake the next frame the
    /// relay sends (or `None` if it sends nothing before the deadline).
    Send(CoordinatorToRelay),
    /// The handshake refused this connection: send the close frame if there is
    /// one, then serve nothing. `None` is a refusal with no close to send — the
    /// socket is already unusable, or the failure is the coordinator's own.
    Refuse(Option<ControlClose>),
    /// The relay is enrolled and the pending-Hello permit released; serve the
    /// connection.
    Enrolled(Enrolled),
}

/// What a completed handshake hands the connection: the identity every later
/// frame is judged against.
#[derive(Debug)]
pub(super) struct Enrolled {
    /// The relay id this connection proved and enrolled under.
    pub(super) relay_id: RelayId,
    /// The enroll generation the registry issued, fencing this connection's
    /// effects against a reconnect that supersedes it.
    pub(super) generation: u64,
    /// The relay's own region — the near end of every backbone pair it measures.
    /// Captured before the hello is consumed by enrollment; validated against
    /// the config, so a heartbeat's reports fold against a known region.
    pub(super) relay_region: Option<RegionId>,
    /// The protocol version negotiated with this relay.
    pub(super) negotiated: ProtocolVersion,
}

/// The coordinator state one enroll handshake decides against: where the relay
/// lands, who is told about it, what regions and ledger it is checked against,
/// and the transport peer a ledger's expected-address gate compares.
pub(super) struct EnrollContext<'a> {
    setup: &'a SessionSetup,
    lifecycle: &'a Lifecycle,
    regions: &'a RegionsConfig,
    ledger: Option<&'a RelayLedger>,
    peer_ip: Option<IpAddr>,
}

impl<'a> EnrollContext<'a> {
    /// Bundles one connection's enroll inputs. Taken as arguments rather than as
    /// a struct literal so a new input lands on this signature and every
    /// construction site has to answer for it.
    pub(super) fn new(
        setup: &'a SessionSetup,
        lifecycle: &'a Lifecycle,
        regions: &'a RegionsConfig,
        ledger: Option<&'a RelayLedger>,
        peer_ip: Option<IpAddr>,
    ) -> Self {
        Self {
            setup,
            lifecycle,
            regions,
            ledger,
            peer_ip,
        }
    }
}

/// How far along the enroll sequence a handshake is, and what it carries
/// forward from the steps already taken.
enum Stage {
    /// Nothing but the pending-Hello permit yet: waiting for the opening
    /// `Hello`.
    AwaitingHello,
    /// The `Hello` negotiated a version and named a configured region; waiting
    /// for the proof that answers `nonce`. The hello is held because
    /// enrollment consumes it, and the certificate it carries is what the
    /// proof is verified against.
    AwaitingProof {
        hello: Box<RelayHello>,
        negotiated: ProtocolVersion,
        nonce: [u8; 32],
    },
    /// The sequence ended — enrolled or refused. A frame arriving now is
    /// nothing the handshake still has a step for.
    Done,
}

/// One control connection's enroll handshake: the sequence in this module's
/// docs, advanced one decoded frame at a time.
pub(super) struct EnrollHandshake<'a> {
    ctx: &'a EnrollContext<'a>,
    /// The pending-Hello slot this connection holds, released the moment its
    /// identity is proven and `None` from then on.
    permit: Option<OwnedSemaphorePermit>,
    stage: Stage,
}

impl<'a> EnrollHandshake<'a> {
    /// Claims a pending-Hello slot and starts the sequence, or refuses the
    /// connection when the gate is saturated.
    ///
    /// Claimed before anything else: a connection that never proves an identity
    /// still costs a parked task and socket for as long as the hello deadline
    /// allows, and nothing else bounds how many of those can pile up at once.
    /// `try_acquire` rather than `.acquire().await` — a caller queued on the
    /// semaphore is still an unbounded number of parked connections, just
    /// parked on the permit instead of on the Hello read.
    pub(super) fn start(
        ctx: &'a EnrollContext<'a>,
        pending_hellos: &Arc<Semaphore>,
    ) -> Result<Self, ControlClose> {
        let Ok(permit) = Arc::clone(pending_hellos).try_acquire_owned() else {
            tracing::warn!(
                "relay control connection refused: too many connections pending a Hello"
            );
            return Err(ControlClose {
                code: CONTROL_CLOSE_TRY_AGAIN_LATER,
                reason: "too many pending control connections; retry shortly".to_owned(),
            });
        };
        Ok(Self {
            ctx,
            permit: Some(permit),
            stage: Stage::AwaitingHello,
        })
    }

    /// Feeds the handshake the relay's next decoded frame, or `None` when the
    /// relay answered nothing before the deadline, and returns the next step.
    ///
    /// The stage decides which step the frame drives, so the sequence cannot be
    /// run out of order: the opening `Hello` negotiates and validates the
    /// region, and the answer to the challenge is what releases the permit and
    /// reaches the ledger and the registry. Anything that is not the frame the
    /// current stage waits for is treated exactly like no answer at all —
    /// neither proves what the step needed proven.
    pub(super) fn offer(&mut self, frame: Option<RelayToCoordinator>) -> EnrollStep {
        match (&self.stage, frame) {
            (Stage::AwaitingHello, Some(RelayToCoordinator::Hello(hello))) => self.on_hello(hello),
            (
                Stage::AwaitingProof { .. },
                Some(RelayToCoordinator::IdentityProof { signature }),
            ) => self.on_proof(Some(&signature)),
            (Stage::AwaitingProof { .. }, _) => self.on_proof(None),
            // The connection's first application frame is read as a Hello or not
            // at all, so nothing else can reach this stage; a frame after the
            // sequence ended has no step left to drive.
            (Stage::AwaitingHello | Stage::Done, _) => {
                self.stage = Stage::Done;
                EnrollStep::Refuse(None)
            }
        }
    }

    /// The relay's opening `Hello`: negotiate a protocol version, validate the
    /// advertised region, and challenge the connection to prove it holds the
    /// certificate's private key.
    fn on_hello(&mut self, hello: RelayHello) -> EnrollStep {
        self.stage = Stage::Done;
        // Negotiate before enrolling: the Hello advertises the relay's
        // `[min_protocol, protocol]` window (a relay predating the field advertises
        // the single version in `protocol`). No overlap with this build's window means
        // this coordinator cannot drive the relay at any version — refuse with a close
        // frame naming both windows rather than register a relay every session
        // assignment would then mis-speak to. The relay recognizes the close code and
        // backs off until a deploy fixes the skew.
        let window_min = hello.min_protocol.unwrap_or(hello.protocol);
        let negotiated = match version::negotiate(window_min, hello.protocol) {
            Ok(negotiated) => negotiated,
            Err(error) => {
                tracing::warn!(
                    relay_id = hello.relay_id.0,
                    %error,
                    "refusing relay control connection: no common protocol version",
                );
                return EnrollStep::Refuse(Some(ControlClose {
                    code: CONTROL_CLOSE_PROTOCOL_MISMATCH,
                    reason: error.to_string(),
                }));
            }
        };
        // Validate the relay's advertised region before enrolling: a hello carrying a
        // region the coordinator's config does not list — including the case where no
        // regions are configured at all — is refused, since a typo'd region tag that
        // silently serves nobody is worse than a failed enroll. A hello with no region
        // always enrolls (dev / loopback, or a fleet with no region config). The relay
        // recognizes the close code and backs off long, treating it as a config fix
        // rather than a redial.
        if let Some(region) = &hello.region
            && !self.ctx.regions.contains(region)
        {
            tracing::warn!(
                relay_id = hello.relay_id.0,
                region = region.as_ref(),
                "refusing relay control connection: region not in the coordinator's config",
            );
            return EnrollStep::Refuse(Some(ControlClose {
                code: CONTROL_CLOSE_UNKNOWN_REGION,
                reason: format!("unknown region: {}", region.as_ref()),
            }));
        }

        // Every accepted control connection proves possession of its certificate's
        // key before enrolling: `hello.cert_der` alone is a claim the relay
        // presented, not proof it holds the matching private key — a
        // bootstrap-secret holder could otherwise copy a victim relay's public
        // certificate into its own Hello and enroll as it. Negotiation already
        // refused any relay advertising a version below the challenge threshold, so
        // there is no un-challenged enroll path to reach.
        let mut nonce = [0u8; 32];
        if let Err(error) = SystemRandom::new().fill(&mut nonce) {
            tracing::error!(
                relay_id = hello.relay_id.0,
                %error,
                "generating the enroll challenge nonce failed; closing",
            );
            return EnrollStep::Refuse(None);
        }
        self.stage = Stage::AwaitingProof {
            hello: Box::new(hello),
            negotiated,
            nonce,
        };
        EnrollStep::Send(CoordinatorToRelay::IdentityChallenge { nonce })
    }

    /// The relay's answer to the identity challenge: verify it, release the
    /// pending-Hello permit, then authorize against the ledger and enroll.
    ///
    /// `proof` is `None` for every outcome that is not a signature — a different
    /// frame kind, an undecodable frame, a close, a stream end, a read error, or
    /// silence past the deadline. The caller treats all of them uniformly,
    /// because none proves possession of the claimed key.
    fn on_proof(&mut self, proof: Option<&[u8]>) -> EnrollStep {
        let Stage::AwaitingProof {
            hello,
            negotiated,
            nonce,
        } = std::mem::replace(&mut self.stage, Stage::Done)
        else {
            return EnrollStep::Refuse(None);
        };
        let mut hello = *hello;
        let relay_id = hello.relay_id;
        let proven = proof.is_some_and(|signature| {
            identity::verify_enroll_proof(&hello.cert_der, &nonce, signature)
        });
        if !proven {
            tracing::warn!(
                relay_id = relay_id.0,
                "refusing relay control connection: enroll proof-of-possession failed",
            );
            return EnrollStep::Refuse(Some(ControlClose {
                code: CONTROL_CLOSE_IDENTITY_UNPROVEN,
                reason: "enroll proof-of-possession failed".to_owned(),
            }));
        }
        // The connection has now proven its claimed identity, so it no longer
        // belongs to the anonymous-churn population the pending-Hello gate exists
        // to bound — release the slot regardless of how much longer ledger
        // authorization and enrollment take.
        drop(self.permit.take());

        // The relay's own region — the near end of every backbone pair it measures.
        // Captured before the hello is consumed by enrollment; validated against the
        // config above, so a heartbeat's reports fold against a known region.
        let relay_region = hello.region.clone();

        // A ledger-backed coordinator authorizes the enroll against its provisioned
        // record before touching the registry: the id must be one the ledger minted,
        // not retired, and either presenting its one-time token (first enroll, binding
        // this proof-of-possession-verified certificate) or re-presenting the bound
        // certificate (a reconnect). A refusal closes with a single generic reason so a
        // caller cannot probe which ids exist or whether a token was near-valid; the
        // specific class rides only the server-side log. A coordinator with no ledger
        // skips this entirely — the id claim is accepted as presented (dev / loopback).
        // A first enroll carries the relay's cold-start duration (launch to enroll),
        // observed into the histogram once the enroll fully succeeds. A reconnect and a
        // no-ledger enroll carry none.
        let mut cold_start_secs: Option<u64> = None;
        if let Some(ledger) = self.ctx.ledger {
            let cert_fingerprint = registry::cert_fingerprint(&hello.cert_der);
            match ledger.authorize_enroll(
                relay_id,
                cert_fingerprint,
                hello.enroll_token.as_deref(),
                self.ctx.peer_ip,
            ) {
                Ok(authorized) => {
                    if let crate::ledger::Authorized::FirstEnroll {
                        cold_start_secs: cold_start,
                    } = authorized
                    {
                        cold_start_secs = cold_start;
                    }
                    // Coordinator-sourced addresses win; the hello's self-report is the
                    // fallback. When the ledger recorded an advertise set for this id,
                    // override the hello's addresses with it (first entry is the
                    // primary) before enrolling, so the registry advertises what the
                    // coordinator resolved rather than what the relay claimed. An id
                    // with no recorded set enrolls with its self-reported addresses.
                    match ledger.advertised_addrs(relay_id) {
                        Ok(Some(addrs)) if !addrs.is_empty() => {
                            hello.relay_addr = addrs[0];
                            hello.relay_addrs = addrs;
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(
                                relay_id = relay_id.0,
                                %error,
                                "reading the ledger advertise set failed; enrolling with the hello's addresses",
                            );
                        }
                    }
                }
                Err(refusal) => {
                    tracing::warn!(
                        relay_id = relay_id.0,
                        %refusal,
                        "refusing relay control connection: ledger did not authorize the enroll",
                    );
                    return EnrollStep::Refuse(Some(ControlClose {
                        code: CONTROL_CLOSE_ENROLL_UNAUTHORIZED,
                        reason: "enrollment not authorized for this relay id".to_owned(),
                    }));
                }
            }
        }

        match self.enroll(hello, relay_id, &relay_region, negotiated, cold_start_secs) {
            Ok(generation) => EnrollStep::Enrolled(Enrolled {
                relay_id,
                generation,
                relay_region,
                negotiated,
            }),
            Err(refusal) => EnrollStep::Refuse(Some(refusal)),
        }
    }

    /// The registry half of the sequence: insert the entry, judge the relay's
    /// boot lineage, and move any session whose capability cohort this
    /// enrollment just broke. `cold_start_secs` is the ledger's launch-to-enroll
    /// measurement, observed only once the enroll has fully succeeded.
    fn enroll(
        &self,
        hello: RelayHello,
        relay_id: RelayId,
        relay_region: &Option<RegionId>,
        negotiated: ProtocolVersion,
        cold_start_secs: Option<u64>,
    ) -> Result<u64, ControlClose> {
        let setup = self.ctx.setup;
        let lifecycle = self.ctx.lifecycle;
        let registry = setup.registry();
        // Enrollment goes through `registry::try_enroll`, whose duplicate-id refusal
        // is atomic with the insert: a live entry under this id bound to a
        // *different* certificate is a second relay process colliding on the id and
        // is refused, while the same fingerprint is this relay's own control
        // connection redialing (its cert is stable across restarts of one instance)
        // and replaces the entry exactly as it always has. Proof of possession above
        // is what makes the fingerprint trustworthy to compare against.
        let finalize_capable = hello
            .capabilities
            .iter()
            .any(|c| c == rally_point_proto::control::CAPABILITY_FINALIZED_DROP_V1);
        // Read out before the hello is consumed by the enroll below.
        let boot_id = hello.boot_id;
        // The enrollment's registry mutation and the capability-transition
        // snapshot run under the assignment lock, so they land wholly before or
        // wholly after any in-flight rehome's capability-check → descriptor-commit
        // span (which holds the same lock). Without this, a rehome could validate
        // a candidate as capable, this enrollment could downgrade it and find no
        // staged finalized-drops descriptor to evict (the rehome hasn't committed
        // yet), and the commit would then hand a finalized_drops session to a
        // relay that no longer runs the handshake. Ordered either way, one side
        // sees the other: enrollment-first fails the rehome's filter;
        // rehome-first leaves a staged descriptor this snapshot picks up. The
        // eviction rehomes themselves run after the lock drops — each re-acquires
        // it internally.
        let (enroll_result, evict) = {
            let _assign = setup.lock_assignment();
            let result =
                lifecycle.enroll_relay_epoch(relay_id, || registry::try_enroll(registry, hello));
            // Whether this is the process that was here before, or a new one whose
            // memory starts empty. A break costs every session this relay serves its
            // completeness claim: the facts the old process held and never restated are
            // gone, and no snapshot from this one can cover that interval. Judged under
            // the assignment lock so it cannot land between a create's relay pick and
            // its commit and demote a session whose whole life postdates this enroll. A
            // session committed but not yet registered is likewise unaffected: its
            // create has not answered the tenant, so no client holds a token for it and
            // the relay can have observed nothing about it to lose. A refused enroll
            // changes nothing and must not update the memory.
            if result.is_ok()
                && registry::note_boot_id(registry, relay_id, boot_id)
                    == registry::BootLineage::Broken
            {
                lifecycle.on_relay_lineage_break(relay_id);
            }
            let evict = match &result {
                Ok(generation) => {
                    // Sessions whose recorded build-class cohort no longer
                    // matches this relay's advertised capability — the relay
                    // crossed the finalized-drop boundary in EITHER direction
                    // while still assigned. Both directions mix build classes
                    // that deliver dropped-leave counts differently, so both
                    // evict. Only the downgrade additionally drains the relay:
                    // an incapable build must take no new capable-cohort work,
                    // while an upgraded relay is exactly what new sessions want.
                    let mismatched: Vec<_> = setup
                        .descriptors()
                        .current_for(relay_id)
                        .iter()
                        .filter(|d| {
                            session::session_capable_cohort(setup, &d.tenant, d.session)
                                .is_some_and(|cohort| cohort != finalize_capable)
                        })
                        .map(|d| (d.tenant.clone(), d.session))
                        .collect();
                    if !mismatched.is_empty() && !finalize_capable {
                        let _ = registry::mark_draining(setup.registry(), relay_id, *generation);
                    }
                    mismatched
                }
                Err(_) => Vec::new(),
            };
            (result, evict)
        };
        let generation = match enroll_result {
            Ok(generation) => generation,
            Err(registry::EnrollConflict) => {
                tracing::warn!(
                    relay_id = relay_id.0,
                    "refusing relay control connection: relay id already enrolled under a different certificate",
                );
                return Err(ControlClose {
                    code: CONTROL_CLOSE_DUPLICATE_RELAY_ID,
                    reason: "relay id already enrolled under a different certificate".to_owned(),
                });
            }
        };
        crate::metrics::relay_enrolled(relay_region.as_ref());
        if let Some(secs) = cold_start_secs {
            crate::metrics::observe_relay_cold_start(secs);
        }
        tracing::info!(
            relay_id = relay_id.0,
            negotiated = %negotiated,
            "relay enrolled over control connection"
        );

        // A relay that re-enrolled on the other side of the finalized-drop
        // capability boundary while still assigned sessions of the old cohort
        // must never silently serve them — the two build classes deliver
        // dropped-leave counts differently (one authors/passes the historical
        // counted-drop behavior, the other strips it), so a mixed session hands
        // different clients different leave schedules. The mismatch snapshot
        // (and, for a downgrade, the drain mark) was taken under the assignment
        // lock above; move each mismatched session off it here. A session with
        // no in-cohort replacement ends (Unavailable) rather than continuing
        // mixed. In this deployment upgrades arrive as fresh relay ids, so the
        // upgrade direction firing at all is itself a signal worth the warn.
        if !evict.is_empty() {
            tracing::warn!(
                relay_id = relay_id.0,
                sessions = evict.len(),
                finalize_capable,
                "relay re-enrolled across the finalized-drop capability boundary while assigned                  sessions of the other cohort; evicting them",
            );
            for (tenant, session) in evict {
                let departed = lifecycle.departed_slots(&tenant, session);
                let outcome = session::rehome_evicting(setup, &tenant, session, relay_id, departed);
                tracing::info!(
                    relay_id = relay_id.0,
                    tenant = tenant.as_ref(),
                    session = session.0,
                    ?outcome,
                    "evicted a cohort-mismatched session from a capability-changed relay",
                );
            }
        }
        Ok(generation)
    }
}
