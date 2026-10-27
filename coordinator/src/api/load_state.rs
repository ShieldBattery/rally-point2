//! The session load-progress read and the attestation round behind it.
//!
//! `POST /session/load-state` is an exchange, not a lookup: the handler asks
//! every relay serving the session what it holds and merges the answers, so a
//! complete set of answers is what licenses reading a slot's absence as evidence.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId};
use serde::{Deserialize, Serialize};

use super::CoordinatorState;
use super::request_auth::{TenantAccess, verify_tenant_request};

/// Request body for `POST /session/load-state`: the session whose load progress
/// to read, in the coordinator's `(tenant, session)` id space.
#[derive(Debug, Deserialize)]
struct SessionLoadStateRequest {
    /// The tenant the app server is acting for — must match the request signature.
    tenant: TenantId,
    /// The session, in the coordinator's `(tenant, session)` id space.
    session: u64,
    /// Whether this failed-setup read must make a final setup-lobby ingress cut.
    #[serde(default, rename = "settleLobby")]
    settle_lobby: bool,
}

/// Response body for `POST /session/load-state`: what the coordinator knows about
/// the session's load progress. camelCase, the tenant's own convention (like the
/// webhook bodies).
///
/// Every slot set and `startedAtMs` are always whatever the coordinator has
/// accumulated, `known` or not: they are positive evidence, and the tenant merges
/// them with its own regardless. Every slot set is always present, empty when
/// nothing is known. `known` gates only the *negative* inference for
/// `connectedSlots` and `startedSlots` — reading a slot's **absence** from them as
/// proof that player never got there — and `turnsKnown` does the same for
/// `forwardedSlots` (below).
///
/// `known: true` means every relay serving the session produced a snapshot **after
/// this request reached it**, that each of those relays had **fenced** the session
/// against its own clients when it did, and that the coordinator has held the
/// session since it created it with no break in the relay memory covering it. So
/// everything that had happened by the time the caller sent this request is in the
/// sets, and an absent slot may be read as a player who never arrived. No clock on
/// either side takes part in that claim: it rests on the ordering of the exchange,
/// not on comparing timestamps across hosts.
///
/// `known: false` is "no information about who is missing" — never "nobody
/// arrived". A relay that did not answer in time, a relay with no live control
/// connection, a relay that could not fence one of its slots, a coordinator that
/// restarted, a reaped session, and a session whose serving relays changed under it
/// (a re-home, or a relay that restarted its process — either destroys memory
/// nothing later can reconstruct) all read that way. The answer is cheap to repeat,
/// so a caller with time left may simply read again; one whose deadline has passed
/// decides on the positive facts alone.
///
/// `startedSlots` is a relay-recorded *client claim*: the client says its game loop
/// is running, and nothing the relay sees backs that up. `forwardedSlots` is the
/// relays' own observation, each slot taken only from the relay that homes it (a
/// serving relay naming a slot it does not home is dropped on ingest): the slot's
/// home relay forwarded at least one of its turns — it arrived from the slot's
/// client, passed validation and the forward-once gate, and went out. That counts
/// the pipe seed a client flushes the moment its loading ends, before its loop
/// runs, so this is the relay-authored "this player's game got far enough to send
/// something", which a client whose uplink never delivered cannot claim its way
/// into. It is also the most a waiting player can show: a running loop sends
/// nothing after its seed until every player's seed has arrived, so an honest
/// player whose opponents never finished loading has forwarded its seed and
/// nothing more.
///
/// `turnsKnown: true` licenses reading a slot's absence from `forwardedSlots` as
/// "its home relay had forwarded no turn of it before this read was sent". It
/// rests on everything `known` does except the fence — every serving relay answered
/// after this request reached it, the coordinator created the session, and relay
/// memory covering it is unbroken — plus every serving relay's answer declaring
/// that it records the set at all. No fence is needed because the set holds only
/// what each relay itself forwarded, so no client can be holding back a fact they
/// owe it: a turn that has not arrived was not forwarded, which is exactly what its
/// absence says. The declaration is needed because a relay build that predates the
/// set answers without it, whatever it forwarded: a session served by one is never
/// `turnsKnown`, and its empty set carries no information.
///
/// `closedSlots` is unlike every other set here: a **current-state** fact as of
/// this read, not an ever-set. It names the slots that connected to their home
/// relay and are now disconnected without having reported their game loop running
/// — the slots no relay can fence, because there is no stream left to probe and
/// the client may be holding a report for the one it opens next. Each slot is taken
/// only from the relay that homes it. A slot that dials back in leaves the set on
/// the next read.
///
/// `closedKnown: true` licenses reading `closedSlots` as the session's whole closed
/// set, and every slot outside it as fenced: every serving relay answered after
/// this request reached it, each fenced every slot it homes except the ones it
/// named closed, and everything `turnsKnown` rests on holds. So a connected slot
/// absent from `closedSlots` is live or started, and a live slot's absence from
/// `startedSlots` is proof. What it cannot vouch for is a closed slot's own start,
/// which may still be parked in its client; `forwardedSlots`, which needs no fence,
/// is the only word on how far that slot's game got, which is why `closedKnown`
/// requires `turnsKnown`. A `known` answer has no closed slot to name: its relays
/// fenced every slot they home.
///
/// `liveSlots` is the other current-state set: the slots whose link to their home
/// relay was up when that relay snapshotted, each taken only from that home, read
/// off the same answers as `closedSlots`. It is only meaningful beside
/// `closedKnown`, which is what says every serving relay answered. A slot that
/// connected is then exactly one of live, closed, or started-and-gone: a slot
/// that reported its game loop running and then disconnected is in neither set.
///
/// `setupFinal: true` (only on a read that asked to settle the lobby) means
/// `lobbyViolationSlots` is complete and stays so: every home relay cut lobby
/// ingress before answering, and every answer fenced at least its live slots.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionLoadStateResponse {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    evidence: Vec<crate::notify::SlotEvidencePayload>,
    known: bool,
    turns_known: bool,
    closed_known: bool,
    setup_final: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at_ms: Option<u64>,
    connected_slots: Vec<u8>,
    started_slots: Vec<u8>,
    forwarded_slots: Vec<u8>,
    lobby_violation_slots: Vec<u8>,
    closed_slots: Vec<u8>,
    live_slots: Vec<u8>,
}

/// Session load-progress read: which slots ever connected, which ever reported
/// their game loop running, which had turns forwarded by their home relay, and
/// when the session started.
///
/// The tenant consults this when its **own** load deadline expires and it must
/// decide whom to blame for a game that never got going. The `slotConnected` /
/// `sessionStarted` / `slotStarted` webhooks carry the same facts as they happen,
/// but they are an optimization feed — best-effort, at-least-once, droppable —
/// so this pull is the correctness signal for load attribution: it reads the
/// coordinator's accumulated state directly rather than trusting that every
/// notification arrived.
///
/// Every slot list is an **ever**-set, ascending: a slot that connected and then
/// dropped still appears, because the question is who got here at all, not who is
/// here now (`POST /presence/query` answers the latter).
///
/// The read is an **exchange**, not a lookup of whatever happened to have arrived.
/// The coordinator asks every relay serving the session, over the control
/// connection each already holds, what it holds for that session; each relay
/// snapshots and answers with the request's own correlation id. A snapshot is built
/// after the request reached the relay, so anything the relay had observed before
/// the caller sent this read is in it — which is what makes a complete set of
/// answers evidence about *absence*, with no clock comparison anywhere. Every
/// snapshot that arrives is merged whether or not the set completes, so a silent
/// relay costs the completeness claim and never the facts its peers reported. A
/// relay silent past the state's attestation deadline, or holding no control
/// connection at all, simply did not answer.
///
/// The read is **rate-limited per tenant** ([`LoadStateLimiter`]), because the cost
/// it imposes is fleet-wide rather than per-session: each read questions every relay
/// serving the named session and holds a fence open on each while it answers. A
/// refused read is a `429` carrying `Retry-After`. Concurrent reads of the *same*
/// session share one round of questions, so a caller with several requests in flight
/// for one session multiplies nothing.
///
/// Same tenant request-signature auth as `POST /session/create` (see the module
/// docs); the `tenant` in the body must match the tenant the signature verifies
/// under. As live-game machinery this is refused only for a revoked tenant, not a
/// suspended one — a suspended tenant's running games still need adjudicating.
pub(super) async fn session_load_state(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let request: SessionLoadStateRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    verify_tenant_request(
        &state.setup,
        &request.tenant,
        &method,
        &uri,
        &headers,
        &body,
        TenantAccess::LiveGame,
    )?;
    let limiter = state.setup.load_state_limiter();
    if !limiter.check(&request.tenant) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [(RETRY_AFTER, limiter.retry_after_secs().to_string())],
        )
            .into_response());
    }
    let session = SessionId(request.session);

    // The coordinator holds nothing at all for the session: never created here and
    // no notice or beat has arrived for it, or it has been reaped. Nobody to ask,
    // and nothing to answer with.
    let Some(before) = state.lifecycle.load_state(&request.tenant, session) else {
        return Ok(Json(SessionLoadStateResponse {
            known: false,
            setup_final: false,
            started_at_ms: None,
            connected_slots: Vec::new(),
            evidence: Vec::new(),
            started_slots: Vec::new(),
            forwarded_slots: Vec::new(),
            turns_known: false,
            lobby_violation_slots: Vec::new(),
            closed_known: false,
            closed_slots: Vec::new(),
            live_slots: Vec::new(),
        })
        .into_response());
    };

    let round = attest_round(
        &state,
        &request.tenant,
        session,
        &before.serving_relays,
        request.settle_lobby,
    )
    .await;
    // Re-read after the exchange so the answer carries whatever the snapshots added.
    // A session retired while the relays were answering leaves nothing to re-read,
    // and the snapshots that landed went into a record that no longer exists — so
    // the pre-exchange facts are answered with, and no claim is made over them.
    let Some(after) = state.lifecycle.load_state(&request.tenant, session) else {
        return Ok(Json(SessionLoadStateResponse {
            known: false,
            setup_final: false,
            started_at_ms: before.started_at_ms,
            connected_slots: before.connected_slots.iter().map(|s| s.0).collect(),
            evidence: before.evidence.into_iter().map(Into::into).collect(),
            started_slots: before.started_slots.iter().map(|s| s.0).collect(),
            forwarded_slots: before.forwarded_slots.iter().map(|s| s.0).collect(),
            turns_known: false,
            lobby_violation_slots: before.lobby_violation_slots.iter().map(|s| s.0).collect(),
            closed_known: false,
            closed_slots: round.closed_slots.iter().map(|s| s.0).collect(),
            live_slots: round.live_slots.iter().map(|s| s.0).collect(),
        })
        .into_response());
    };
    // A session with no serving relays has nobody who could attest, so it can never
    // complete — the same reason a state no registration built cannot. Membership in
    // `fenced` implies membership in `fenced_live`, which implies membership in
    // `attested`, so each check here also covers the ones beneath it: every serving
    // relay answered, and every answer ruled out a report still queued in one of
    // that relay's clients (all of them, or all but the ones it named closed).
    let every_serving_relay_in = |relays: &std::collections::HashSet<RelayId>| {
        !before.serving_relays.is_empty()
            && before
                .serving_relays
                .iter()
                .all(|relay| relays.contains(relay))
    };
    let every_relay_fenced = every_serving_relay_in(&round.fenced);
    let every_relay_fenced_live = every_serving_relay_in(&round.fenced_live);
    // Turn evidence needs no fence: it holds only what each relay itself forwarded,
    // so no client can be holding a turn the set owes it. It needs everything else
    // `known` does, plus a relay build that records the set at all — an older one
    // answers without it whatever it forwarded.
    let turns_known =
        after.created_here && after.attestable && every_serving_relay_in(&round.reports_turns);
    // Each serving relay named every slot of its own that sits beyond its fence and
    // vouched for every other, so the union is the session's closed set as of this
    // round. Turn evidence is required beside it because a closed slot's own start
    // report may still be parked in its client: only the forwarded set, which needs
    // no fence, shows whether that slot's game got anywhere.
    let closed_known = turns_known && every_relay_fenced_live;
    // Setup finality claims only that the lobby-violation evidence is complete, and
    // the settle cut is what makes it so: once a home relay has settled, every lobby
    // command its clients author afterwards — including one a disconnected client
    // delivers when it dials back in — is dropped without a violation, so nothing a
    // closed slot's client still holds can add one. The fence is needed only to rule
    // out a start report still queued in a live client, which the live half of each
    // verdict covers; a closed slot is named in `closedSlots` rather than withholding
    // finality, while `known` still demands the whole fence.
    let setup_final = request.settle_lobby
        && after.created_here
        && after.attestable
        && every_relay_fenced_live
        && every_serving_relay_in(&round.setup_settled)
        && state
            .setup
            .settle_lobby(&request.tenant, session, &before.serving_relays, || {
                state
                    .lifecycle
                    .load_state(&request.tenant, session)
                    .is_some_and(|current| {
                        current.created_here
                            && current.attestable
                            && current.serving_relays == before.serving_relays
                    })
            });
    Ok(Json(SessionLoadStateResponse {
        known: after.created_here && after.attestable && every_relay_fenced,
        setup_final,
        started_at_ms: after.started_at_ms,
        connected_slots: after.connected_slots.iter().map(|s| s.0).collect(),
        evidence: after.evidence.into_iter().map(Into::into).collect(),
        started_slots: after.started_slots.iter().map(|s| s.0).collect(),
        forwarded_slots: after.forwarded_slots.iter().map(|s| s.0).collect(),
        turns_known,
        lobby_violation_slots: after.lobby_violation_slots.iter().map(|s| s.0).collect(),
        closed_known,
        closed_slots: round.closed_slots.iter().map(|s| s.0).collect(),
        live_slots: round.live_slots.iter().map(|s| s.0).collect(),
    })
    .into_response())
}

/// Obtains an attestation round covering this read: leads a fresh one, or shares the
/// round already running for the session (see [`crate::attest::shared_round`] for
/// why sharing is sound and what a joiner has to check).
async fn attest_round(
    state: &CoordinatorState,
    tenant: &TenantId,
    session: SessionId,
    serving: &[RelayId],
    settle_lobby: bool,
) -> crate::attest::AttestRound {
    crate::attest::shared_round(state.setup.attest(), tenant, session, settle_lobby, || {
        attest_serving_relays(state, tenant, session, serving, settle_lobby)
    })
    .await
}

/// Asks every relay in `serving` for its snapshot of the session and reports which
/// of them answered, which of those fenced (wholly, or all but their closed slots),
/// and which slots they named closed. Each answer's facts are merged where it is
/// received, so this only has to record who produced one and what it vouched for.
///
/// Every request goes out before any answer is waited on, and all of them share one
/// absolute deadline, so the whole exchange costs at most the state's
/// `attest_timeout` however many relays serve the session and however
/// many of them are slow. A relay that cannot be reached at all — no live control
/// connection, or a control connection whose question queue is full — is never asked
/// and counts exactly like one that stayed silent: it did not attest.
async fn attest_serving_relays(
    state: &CoordinatorState,
    tenant: &TenantId,
    session: SessionId,
    serving: &[RelayId],
    settle_lobby: bool,
) -> crate::attest::AttestRound {
    // Taken BEFORE the first question is queued, so it is a lower bound on every
    // snapshot this round collects. Stamping it after the fan-out instead would let
    // it postdate a read that arrived after the earliest-asked relay had already
    // snapshotted, and that read would then accept a round blind to the interval it
    // asked about.
    let started_before_any_request = tokio::time::Instant::now();
    let mut pending: Vec<_> = serving
        .iter()
        .filter_map(|&relay| {
            state
                .setup
                .attest()
                .request(relay, tenant, session, settle_lobby)
                .map(|waiter| (relay, waiter))
        })
        .collect();
    let deadline = tokio::time::Instant::now() + state.attest_timeout;
    let mut attested = std::collections::HashSet::new();
    let mut fenced = std::collections::HashSet::new();
    let mut fenced_live = std::collections::HashSet::new();
    let mut closed_slots = std::collections::BTreeSet::new();
    let mut live_slots = std::collections::BTreeSet::new();
    let mut setup_settled = std::collections::HashSet::new();
    let mut reports_turns = std::collections::HashSet::new();
    for (relay, waiter) in &mut pending {
        if let Ok(Some(snapshot)) = tokio::time::timeout_at(deadline, waiter.recv()).await {
            attested.insert(*relay);
            if snapshot.fenced {
                fenced.insert(*relay);
            }
            // A whole fence is a live fence with nothing closed, so a relay that
            // predates the split and answers only `fenced` still vouches for its
            // live slots and names no closed one.
            if snapshot.fenced_live || snapshot.fenced {
                fenced_live.insert(*relay);
            }
            closed_slots.extend(snapshot.closed_slots);
            live_slots.extend(snapshot.live_slots);
            if snapshot.setup_settled {
                setup_settled.insert(*relay);
            }
            if snapshot.reports_turns {
                reports_turns.insert(*relay);
            }
        }
    }
    crate::attest::AttestRound {
        started_before_any_request,
        attested: std::sync::Arc::new(attested),
        fenced: std::sync::Arc::new(fenced),
        fenced_live: std::sync::Arc::new(fenced_live),
        closed_slots: std::sync::Arc::new(closed_slots),
        live_slots: std::sync::Arc::new(live_slots),
        setup_settled: std::sync::Arc::new(setup_settled),
        reports_turns: std::sync::Arc::new(reports_turns),
    }
}
