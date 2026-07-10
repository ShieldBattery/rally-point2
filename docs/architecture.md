# Netcode v2 — Architecture Overview

This is the reference for **how netcode v2 works and why it is shaped this way**. It describes the
**final design** — the target the implementation is being built toward, not only what runs today.

> **Implementation status — temporary note, delete once complete.** What runs today is the single-relay
> core end-to-end — `client–relay–client` with the per-link transport, the relay's validating client edge,
> and the client's forward-recovery driver — plus most of the multi-relay mesh and the coordinator control
> plane. Built and wired:
>
> - **Mesh core.** The mesh-edge connection half (dial / accept with an identity hello, on-demand dialing,
>   idle teardown + reconnect supervision), topological turn dedup, and per-session `Join`/`Leave` driven by
>   coordinator descriptors. Mesh peer certs are now **pinned from the session descriptor** — the coordinator
>   carries each relay's leaf cert and the dialer trusts exactly that, mirroring how a client pins its
>   relay's cert — with a fallback to configured roots for a descriptor that predates carrying them.
> - **Coordinator↔relay control connection.** Each relay holds one persistent, bootstrap-secret-authenticated
>   connection; it **enrolls itself** over the first frame, **reports liveness** on a heartbeat (a drop or
>   silence past the deadline deregisters it, made safe against a racing reconnect by a generation fencing
>   token), and applies the **declarative descriptor set** the coordinator pushes down to drive mesh
>   membership.
> - **Latency-buffer consensus.** The per-session decision-maker is wired into the runtime: each relay feeds
>   its home clients' link stats (and peer relays' stats off the mesh) into it, and the **authority** relay —
>   first in the coordinator-assigned order still serving live players, with handoff **presence-driven** over
>   reliable mesh streams and no coordinator round-trip — stamps a `buffer_directive` onto the turns it
>   forwards, applied out of band, not a command in the byte stream. The client-side `DirectiveTracker`
>   collapses the redundant out-of-order stamp stream into at-most-one change at its apply frame; the
>   remaining seam is the game-side owner in `shieldbattery/game/` that resizes the real turn buffer.
> - **Relay-side desync detection.** The authority relay compares clients' `0x37` sync checksums off the same
>   turn stream and reports a divergence, hardened so a malicious client can only get its own game disputed,
>   never frame an honest player (see [Relay-side desync detection](#relay-side-desync-detection)).
> - **Synced player-leaves.** A clean quit sends a leave-intent up the reliable control stream; the authority
>   decides a `LeaveDirective` at a survivor-reachable apply frame — a departing client cannot inflate its own
>   leave past what survivors can reach — broadcast to clients and propagated across the mesh so every client
>   applies the same leave at the same simulated step (see [Synced player-leaves](#synced-player-leaves)).
> - **Reliable control stream, both edges.** Client↔relay and relay↔relay (one bidirectional stream per side,
>   extensible length-prefixed frames). A turn too large to ever ride a datagram diverts onto it end-to-end
>   and rejoins the ordered turn stream at the receiver — the mesh divert is now built, no longer
>   dropped-with-a-warning. Chat/resync are future frame kinds on the same channel.
> - **Coordinator control plane.** The relay registry, per-tenant connection-bound **token** issuance, session
>   setup + descriptor assignment, and the tenant-facing HTTP API. The API now **authenticates inbound tenant
>   requests** with a per-tenant Ed25519 signature (fail-closed), a **coordinator→tenant webhook** leg reports
>   player departures, desyncs, and game results (signed with the tenant's key, deduped, retried), and a
>   **session-lifecycle** layer emits a final `sessionClosed` and reaps dangling sessions (see
>   [Control plane](#control-plane-the-coordinator)).
>
> - **Relay-death failover (coordinator-mediated re-home).** In-game, whole-group failover onto a
>   replacement relay: the coordinator's tenant-authenticated, app-server-mediated `POST /session/rehome`
>   moves every slot homed on a dead relay to one live relay and rebuilds the serving relays' descriptors as
>   **resumed** (seeding the already-decided departures so a fresh relay resumes rather than waits), and the
>   client driver escalates a dead home relay to an embedder-supplied re-home provider (which reaches the
>   coordinator through the tenant's app server — clients never call the coordinator directly), re-dials the
>   replacement with its existing token + resume cursors, and re-injects a retained ring of its own sent turns
>   so the new relay's empty turn ring still fans them out (see [Failover and reconnect](#failover-and-reconnect)).
>
> Still designed but not built: **dual-stack advertise addresses**, **per-relay identity binding** on the
> control connection, production mesh **mTLS / an internal CA**, and coordinator **HA / persistence** (a
> restart still forgets the registry, tenant keys, and session accounting).

> **Read this before "fixing" the transport.** The data plane is deliberately **not** a standard
> reliable-ordered protocol (TCP, QUIC streams). Reviewers — human and automated — repeatedly
> pattern-match it against one and flag intentional choices (out-of-order delivery, no relay-side
> reordering, ack-only handling, no retransmit-on-timeout) as bugs, pushing toward something that
> *looks* correct but breaks lockstep. See [Why not a standard protocol](#why-not-a-standard-reliable-ordered-protocol).

## The shape

```
  game (BW) ─┐                                            ┌─ game (BW)
             │  turns                                turns │
        ┌────▼─────┐  QUIC datagrams   ┌────────┐   ┌──────▼───┐
        │ client   │══════════════════▶│ home   │◀══│ client   │
        │ (driver) │◀══════════════════│ relay  │══▶│ (driver) │
        └──────────┘                   └───┬────┘   └──────────┘
                                           │ S===S (mesh)
                                       ┌───▼────┐
                                       │ relay  │
                                       └────────┘
```

Each arrow is one **link**: an independent unreliable QUIC connection with its own packet loss. The
client has one link to its home relay; relays mesh to each other across the backbone. The same per-link
transport machinery runs at both ends of every link.

## Payloads and packets

Two units, often conflated — keeping them straight is the key to the whole design.

- A **payload** is the unit of meaning: one slot's command bytes for one turn, plus an origin `seq`
  (its transport identity, assigned by the sending client and preserved end-to-end, used for dedup
  and retirement) and the source `slot`. Payloads are what the game produces and consumes.
- A **packet** is a transport envelope — exactly one per QUIC datagram. It carries a packet `seq`, the
  ack state for the peer's packets (`ack` + a 32-bit `ack_bits` history), and a list of payloads.

**A packet's `seq` is only an ack handle.** It names which payloads a packet carried so that, when the
peer acks that packet, we know which payloads to retire. It is *not* an ordering key and imposes no
in-order delivery: packets may arrive in any order, and that is fine. (The per-payload `seq` is the
identity that matters; the packet `seq` is bookkeeping for acks.)

> **Why our own `seq` and acks, not QUIC's?** QUIC's datagram extension is deliberately
> fire-and-forget: a datagram carries no application-visible sequence number, and quinn surfaces no
> per-datagram delivery receipt. QUIC does ack at its own *packet-number* level for congestion control
> and loss detection, but that isn't exposed — and it would be the wrong granularity anyway, because we
> retire *payloads* and a payload rides several packets via redundancy. So the payload identity (`seq`)
> and the selective acks (`ack` + `ack_bits`) are ours by nature: QUIC gives us the encrypted,
> congestion-controlled, MTU-aware *unreliable* pipe, and nothing it could ack would map to our
> payloads.

## Loss recovery is redundancy, not retransmission

Recovery is **ours, layered on QUIC's unreliable datagrams** — QUIC supplies encryption, congestion
control, MTU sizing, migration, and a loss signal, but no per-datagram delivery receipt for our
redundantly-packed payloads.

- Each packet carries a **fresh** payload plus **still-unacked recent ones**, oldest-first, up to the
  live datagram budget. So a dropped packet's payloads ride the *next* packets automatically.
- There is **no retransmit-on-timeout**. We never wait a round-trip to notice a gap and resend — the
  redundancy already covers it. Turns are tiny, so the bandwidth cost is negligible; the latency saved
  is a whole RTT per loss, which lockstep cannot spend.
- **Acks retire payloads.** A packet acks the peer's recent packet seqs; each acked packet's payloads
  are dropped from the re-send set. An **ack-only** packet (no payloads) carries acks alone — it needs
  no ack in return, so receiving one must *not* schedule another (or two idle links would trade
  ack-only packets forever).
- A **maintenance flush** retransmits during the gaps the fresh stream can't cover: when an outbound
  turn re-carries unacked payloads (the common case) the flush timer is pushed out and never fires, so
  it costs no extra packets; it fires only when a near-MTU turn left no room for redundancy, or the
  link is idle, and re-carries the unacked payloads then.
- Under *sustained* loss where redundancy can't keep up, the unacked window is **capped** rather than
  grown without bound. Two mechanisms keep it bounded, each for a distinct failure:

  - The **ack-beacon** side-channel handles *reverse*-path loss — the peer received the turns (redundancy
    kept up) but the acks riding the datagrams back were lost. Each side opens one outbound reliable
    uni-stream and pushes its monotonic `delivered_through` cursor for a slot whenever it advances; the
    peer reads it and force-retires (`retire_through`) everything up to that cursor **for that slot**.
    The cursor is per-slot because each slot carries its own monotonic seq space starting at 0 — a
    single global cursor would retire one slot's seqs against another's. The cursor advances exactly
    when the peer is keeping up, so the beacon retires the turns the peer confirmed it got — never the
    ones it didn't. Push-on-advance, not a timer: a healthy link with a static receive prefix sends
    nothing.
  - A **hard cap** (`UNACKED_WINDOW_CAP`) handles *forward*-path sustained loss — the peer genuinely
    receives slower than the local endpoint produces, so even with the beacon the window grows (the
    beacon can only retire what the peer *got*). When `payloads_in_flight` crosses the cap the driver
    trips (`UnackedWindowExhausted` on the client, slot isolation on the relay) rather than let seqs
    race ahead until the peer's receive window rejects them and drops the link. Surfacing the condition
    is the buildable half; the resync it triggers (reconnect + replay-from-cursor) is gated on the open
    failover design (see [Failover](#failover-and-reconnect)).

  The beacon's read half runs in a dedicated task that assembles complete `(slot, cursor)` frames over
  an `mpsc` channel — a `read_exact` dropped mid-frame inside a `select!` would desync the framing and
  hand a garbage cursor to `retire_through`, so it never crosses the `select!` boundary. `retire_through`
  is guarded monotonically per slot as a second line of defense. The datagram path itself stays
  best-effort-fast by design.

## The link transport

The `transport` crate is the per-link machinery, shared by `client` and `relay` (one instance per
link). It owns no I/O — a driver pulls a built packet from it and sends it, and feeds every received
packet back in.

- `send(payload)` packages the fresh payload + redundancy into a packet sized to the live
  `max_datagram_size()`, and reports how many unacked payloads it re-carried (so a driver knows whether
  recovery is already riding the stream). A turn too large to ever fit a datagram is rejected up front
  rather than tracked as un-sendable.
- `recv()` folds in the packet's acks, dedups (each payload is delivered exactly once even though
  redundancy means it arrives several times), and reports whether the packet carried any payloads.
- It does **not** reassemble a globally-ordered stream. Each `recv()` returns one packet's new payloads
  in their own seq order, but successive calls follow arrival order. Putting turns back in game order is
  a concern of the layer above (the client).

## The relay

The relay is a **validating** relay, not a dumb forwarder. For each turn a client sends:

1. **Validate** (attacker-facing, fuzzed): bind the turn to the slot the client's token authorizes
   (never the slot on the wire), bounds-check every command against the command-length table, and strip
   control commands a live turn may not carry.
2. **Forward immediately, with no inbound reordering.** A validated turn is fanned out to the session's
   other slots the moment it arrives — a peer must hold a turn *before* it simulates that game step, so
3. **Re-package.** Each peer's link buffers that peer's unacked payloads and builds its **own** packets
   re-carrying them — its own packet seqs, multiple payloads each. The payload's `(slot, seq)` origin
   identity is preserved verbatim across the seam (assigned by the sending client and honored by every
   hop); the receiver knows whose commands these are from `slot` and dedups by `(slot, seq)`. (The
   per-client send buffer is bounded so a stuck client can't grow it without limit.)

Because the relay forwards in arrival order and preserves each payload's origin seq, the order a peer
receives turns in per slot is the relay's forward order for that slot — which matches the original
order in the common case (redundancy plus per-packet sorting keep the relay receiving each slot's
turns in order). The rare reordering that slips through (a client at near-MTU whose datagrams reorder
past what redundancy covers) is a known edge: the common case is correct, and a higher-layer resync
would also recover it (see [Failover](#failover-and-reconnect)) — the per-hop transport doesn't
try to guarantee order.

## The client

The `client` crate is the portable endpoint linked into the game DLL (so it stays `unsafe`-free and
target-agnostic across the targets the DLL ships for).

- It dials the home relay, proves possession of its per-session key with a challenge bound to the TLS
  channel, and wraps the connection as a transport link.
- A **link driver** owns that link on a Tokio task: it sends the turns the game produces, delivers the
  peers' turns the relay forwards, and runs the forward recovery above. It is the Tokio half of the game
  seam; the game DLL bridges its lock-free BW-thread ⇄ Tokio-thread handoff onto the driver's channels.
- **Ordering is restored here, per slot.** The relay→client stream is gapless but can arrive out of
  order across packets, so the driver buffers received turns by `(slot, seq)` and hands the game only
  the contiguous prefix *per slot* — the game never sees a later turn before an earlier one for the
  same slot. Each slot's seq space is independent (the sending client assigns its own slot's seqs), so
  one slot's gap never head-of-line-blocks another. This is the "client restores game order" the rest
  of the system relies on.

## Why not a standard reliable-ordered protocol

The game is **lockstep**: every player advances only as fast as the slowest turn, because a client
cannot simulate game step *N* until it has every slot's turn for *N*. Against that, the two guarantees a
reliable-ordered stream provides are actively harmful:

- **In-order delivery → head-of-line blocking.** One lost packet would stall every later turn behind it.
  In lockstep that freezes *all* players, not just the one who lost a packet.
- **Reliable delivery → retransmit-on-timeout.** Recovering each loss costs a round-trip to detect the
  gap and resend — added directly to the turn latency every other player is waiting on.

So the design forwards ASAP (no reordering latency) and recovers by redundancy (no retransmit RTT),
spending a little bandwidth — turns are only tens of bytes — to never spend that latency. The choices
that read as bugs to a standard-protocol eye are the whole point:

| Looks like a bug | Why it's intentional |
|---|---|
| Turns can be delivered out of order across packets | Packet order is only for acks; the client restores game order |
| The relay doesn't reorder incoming turns before forwarding | A peer needs each turn ASAP; reordering adds latency |
| Ack-only packets aren't themselves acked | They carry no payloads to confirm; acking them would ping-pong forever |
| There's no retransmit timer | Redundancy re-carries unacked payloads; a timeout would cost an RTT |

## Beyond one relay

A single relay is the simplest topology. The full design spans several relays and a control plane
around them, without changing the core above. These parts are less settled than the data plane; where
a mechanism is still open, it says so.

### The mesh (relay ↔ relay)

When a game's players span regions, each client connects to its own nearby relay rather than everyone
routing through one. Those relays mesh over the cloud backbone (`S===S`): a turn a relay receives from
a local client is fanned out both to its own local clients and to its peer relays, and each peer relay
forwards it on to *its* local clients. There is **one QUIC connection per relay-pair** (separate streams
don't isolate datagram congestion). Because a turn can reach a relay by more than one mesh path, the
relay **dedups topologically** — it forwards each turn to a given client exactly once, on whichever copy
arrives first, reusing the same `(slot, seq)` dedup the per-link transport already does — the origin
identity is stable across the mesh because no hop restamps it.

The mesh edge's **connection half** runs in the relay binary: each `--relay-id` + `--mesh-peer ADDR#ID`
pair dials (the lower-id side, via a `should_dial_mesh` tie-break) or accepts (the higher-id side), and
each established connection spawns a `run_mesh_link` driver. The `--relay-id`/`--mesh-peer` CLI args are
a **dev/loopback** escape hatch (two relays on one machine); in production the coordinator pushes peer
topology at runtime — relays churn under scale-to-zero (D3), so the peer set is unknowable at startup,
and the dial side needs the peer's id *before* connecting (the tie-break is a pre-connect local
decision). The dialer knows whom it dialed, but the acceptor only sees an inbound connection from an
ephemeral port, so right after connecting the dialer sends a one-way identity hello (`MeshHello`) and
the acceptor reads it; each established link is then **labeled with its peer's id**. This is labeling,
not the tie-break — it carries no authority and doesn't decide the dial. The hello also carries the
dialer's protocol version, and the **acceptor enforces negotiation** on it: an incompatible version is
refused with a QUIC application close (a named protocol-mismatch code) before the link driver ever
spawns, so an incompatible relay-pair never half-establishes. The hello being one-way is enough — every
pair has exactly one acceptor, so one side enforcing covers the pair; the dialer's reconnect supervision
just redials on its ordinary delay (naming the refusal in its logs), and the coordinator's descriptors
stop pairing the two relays once the fleet converges on one version.

The labeled links feed a **`MeshControl` Join source**: it holds each peer's `MeshCommand` sender keyed
by id, and turns a coordinator `SessionDescriptor` into targeted `MeshCommand::Join`/`Leave` on the link
to each peer the descriptor names — never a broadcast. It records *desired* membership, so a descriptor
that names a peer whose link hasn't established yet joins the moment that link registers (and vice
versa), making it robust to link-vs-descriptor arrival order. The descriptors arrive over the
relay's **control connection** to the coordinator (see [The control connection](#the-control-connection-coordinator--relay));
a relay run without a coordinator URL (pure dev/loopback) instead has its `Join`s driven directly by
the integration test on the command senders (and through `apply_descriptor`).

**On-demand dialing.** Nothing lists mesh peers at startup in production — the coordinator's descriptors
do, at runtime. So the *dial* side of the connection half is driven by the Join source: `MeshControl`
republishes a **desired-peer set** (the union of every current session's mesh peers, with addresses) as
it changes, and an **on-demand dialer** keeps one dial supervisor alive per peer this relay should dial
(the higher-id peers — lower-id peers dial *us* and arrive on the accept side). When a descriptor names a
peer with no link — a fresh pairing, or one whose link had idled out — the dialer establishes it; when a
peer is no longer named, its link idles out and its supervisor stops. This is what makes idle teardown
safe rather than stranding: a torn-down link comes back on demand the next time a session needs the pair.
(`--mesh-peer` stays the dev/loopback path — a static dial at startup with no coordinator to push
topology.)

**Mesh-link idle teardown.** A `run_mesh_link` driver tears down its connection when it has been
session-less for long enough — but only *after* it has served at least one session. The idle timer is
armed on the transition from "has sessions" to "none" (the last `Leave`), not on establishment: a
never-joined link stays parked indefinitely, ready for the coordinator's `Join` source (the
binary holds its command sender for exactly this). Tearing an idle link down doesn't strand the pair:
the reconnect supervisor leaves an intentional teardown alone, but the on-demand dialer re-establishes the
link when a later descriptor names the peer again. Re-`Join`ing before the timer
fires cancels it. This is *app-level* idle teardown, distinct from QUIC's own idle timeout (10s, on the
mesh dial side via keepalive PINGs): QUIC tears down a *dead* connection (keepalive stops
round-tripping); this tears down a *live but unused* one so a churned-out relay-pair's connection
doesn't linger forever. The driver returns a `MeshLinkExit` (`Idle` vs. `ConnectionFailed` vs.
`CommandChannelClosed`) so the dial side's **reconnect supervisor** can tell an intentional wind-down
from a dropped connection: it redials a failed connection (after a short delay, re-registering the fresh
link so the Join source re-syncs its sessions onto it) and leaves an idle teardown or a
relay-initiated shutdown alone.

**Mesh trust today vs. production.** Today the dial **pins the peer's cert from the session descriptor**:
the coordinator carries each relay's leaf cert in the descriptor, and the dialer trusts exactly that cert
for the connection — the same way a game client pins `RelayEndpoint::cert_der` for its own relay dial. A
descriptor that predates carrying peer certs (or a pin rustls can't parse) falls back to the configured
mesh roots, logged — reproducing the earlier dev/loopback behavior where a self-signed pair just works
(each relay trusting its own leaf). Pinning removes the pre-distribution problem — with scale-to-zero
relays churn constantly, so shipping every relay's cert to every potential peer ahead of time is
infeasible — but it still trusts *whatever cert the coordinator vouches for*. The longer-term production
approach is an **internal CA** (AWS Private CA, or a simple CA the coordinator runs): one CA root signs
every relay cert on startup, each relay trusts the CA root, and any two relays mesh without the
coordinator brokering each cert. The current `mesh_client_config` does server-auth only
(`with_no_client_auth`); production mTLS — both sides present certs — is a transport-level change that
lands with the internal-CA work, alongside the open `S===S` inter-relay auth question (mutual certs vs. a
coordinator-issued shared secret). Client → relay trust is the same descriptor-pinning story: it's 1:1
(one relay per client), cert pinned from the session descriptor, with an internal CA as the scale
alternative; direct IPs (D3) rule out public CA.

### Failover and reconnect

A relay dying mid-game stalls lockstep for every client it serves, so failover moves the affected clients to
another relay and recovers the turns they missed. The design is **coordinator-mediated re-home**: the
coordinator, which already knows relay liveness from the control connections, authoritatively picks the
replacement, and the clients themselves are the turn log — so nothing needs a replicated relay-side turn
store. Scope is **in-game, whole-group** failover: every slot homed on the dead relay moves together to one
replacement.

**The clients are the turn log.** Each client already holds every turn it sent (it generated them) and every
turn it received (it executed them), so a replacement relay never needs a persisted log — it asks the
returning clients to replay. Two mechanisms cover the two gaps a re-home leaves:

- **Resume cursors** (the same infrastructure a same-relay reconnect uses): on re-dial the client presents,
  per peer slot, the seq it next needs, and the relay replays from its turn ring at or past it. A fresh
  replacement relay's ring is empty, so this alone recovers nothing from it — which is what the retention
  ring below is for. Every re-dial also presents an **own-slot resume anchor** among the cursors. The relay
  builds a brand-new receive-side dedup on *every* connection (a same-relay resume or a re-home alike), which
  would base that slot's window at seq 0 — and since a resuming client keeps counting its seq stream across
  the drop, the resumed stream is rejected as out-of-window the instant its seq passes the window (~4096
  turns, ~3 min in), dropping the link. Because every slot in a group crosses the window at the same absolute
  seq, that tears the whole group down at once. The client heads it off by naming, as its own-slot cursor,
  the lowest seq it will actually re-send: **the oldest still-unacked seq on a same-relay resume** (the
  AckManager re-carries the unacked window over the rebound connection, oldest-first — anchoring below it,
  e.g. at the retention front, would strand a permanent prefix gap since a same-relay resume does not
  re-inject the ring), and **the retention ring's front on a re-home** (which *does* re-inject that ring).
  The relay reads the own-slot cursor (a slot never replays its own turns) as the window's base, so the
  resumed stream is accepted and the delivered prefix advances from there. The own-slot cursor rides the
  existing resume-cursor frame — additive, no handshake or frame-count change.
- **The outbound retention ring.** Each client retains a ring of *its own* recently-sent turns (capped at 512
  turns / 256 KiB), independent of ack retirement — a turn the dead relay had already acked is dropped from
  the unacked window but kept here. On a re-home dial (only), the client re-injects the retained turns as
  unacked into the fresh link, so the replacement relay's empty ring re-carries them to peers, which dedup by
  origin `(slot, seq)`. This closes the window where the dead relay acked a turn but died before fanning it
  out. An oversize (control-diverted) retained turn is staged for the fresh connection's reliable control
  stream and kept staged until its send succeeds, so a mid-drain stream failure retries it on the next
  session rather than losing it. An undecided drop-hold at relay death is deliberately lost — survivors
  re-wait the fresh 30s floor on the new relay.

**Coordinator `POST /session/rehome`.** Tenant-authenticated and app-server-mediated — clients never talk to
the coordinator directly. The re-home is authenticated exactly like `POST /session/create`: the tenant's app
server signs the request with its client key, and the coordinator verifies that request signature (the
domain-separated `rp2-request-v1:<ts>:<METHOD>:<path>:<body>` scheme) before doing anything. The request body
is snake_case `{ "tenant", "session", "dead_relay_id" }`; the `tenant` must match the tenant the signature
verifies under, and `session` + `dead_relay_id` are the app server's trusted assertion about one of its own
sessions. A missing/invalid signature, a stale timestamp, or an unenrolled tenant all `401`; a lenient
per-`(tenant, session)` rate limit `429`s a caller that re-asks too fast. Because the session lookup is
tenant-keyed, a `session` owned by another tenant simply finds no serving set and returns `unavailable`,
leaking nothing. The decision: a relay **still enrolled *and* still in this session's serving set** → `stay`
(the coordinator overrules a genuine false alarm); **dead** → move the whole group to a replacement — a live
relay already serving the session (earliest in the authority order) if one exists, else the lowest-id live
relay, else `unavailable` — updating the serving set (which is also the descriptors' authority order) in place,
rebuilding every serving relay's descriptor as **resumed**, and pushing R_new's first so it is staged before
the response returns (the client's backoff absorbs the residual descriptor/dial race). The response is
snake_case `{ "decision", "relay"? }`, where `relay` (present only when `decision` is `newTarget`) is
`{ "relay_id", "relay_addr", "cert_der" }` with the cert hex-encoded.
The decision is idempotent per `(session, dead_relay)`, so concurrent or repeated asks return the same target
without re-mutating — and this recorded-target lookup runs *before* the stay check, so a dead relay that has
since restarted and re-enrolled under a fresh cert does not flip an already-re-homed straggler (still pinned to
the old cert, which the re-enrolled relay's new cert can never satisfy) into a `stay` it would wedge on; it
still gets the recorded replacement. Only a relay that is both re-enrolled *and* still serving this session
(never re-homed away) reads as a false-alarm `stay`. An unknown session (a coordinator restart wiped its
membership) is `unavailable`.

**Resumed descriptors.** A `resumed` descriptor additionally carries the session's already-decided
`departed_slots` (slot + left/dropped kind, seeded from the coordinator's lifecycle accounting). A fresh relay
taking over has no mesh peer to replay `SlotDeparted` records from, so it seeds these as decided leaves — its
desync comparator, coverage check, and any later promotion re-broadcast then treat a coordinator-seeded
departure exactly like a mesh-learned one — and latches the session **started**, so it never waits on the full
expected set (which still lists the departed slots that will never dial) and never re-fires the session-start
machinery session-wide. Both fields are additive with serde defaults, so an old descriptor still parses.

**Client-side escalation.** The link driver's reconnect loop retries the same relay first, and escalates to an
embedder-supplied `RehomeProvider` only once the game has started (it tracks the relay's `SessionStart`
itself) and the relay stays unreachable — immediately on a TLS cert/pin rejection (a restarted relay serves a
fresh cert, which no same-relay retry can pass), otherwise after ~10s of failed attempts. The **driver owns
the current relay id**: it is seeded from the reconnect config, passed to `RehomeProvider::rehome(dead_relay_id)`
as the relay the driver believes is dead, and advanced to the replacement's id only on a *successful* re-home
dial — never on a guess and never on a failed dial, so the provider can never name a live replacement as dead
and get wedged on a `Stay`. The provider is where the embedder does the coordinator round-trip and builds a
fresh endpoint pinning the replacement relay's cert — the driver never touches certs. `Stay` resumes same-relay
backoff; `Unavailable` keeps it and re-escalates periodically; `NewTarget` re-dials the replacement with the
same identity, resume cursors, and own-slot window anchor, rebinds the link in place (preserving the receive
dedup so the re-home is a resume, not a restart), re-injects the retention ring, and points subsequent drops
(and the owned relay id) at the new relay. This same reconnect infrastructure also covers a client's own
transient disconnects (a same-relay resume, no re-home).

### Latency buffer

How much turn buffer the game runs with — the latency cushion that absorbs jitter — is not fixed; it has
to move as network conditions shift over the course of a game. Changing it is a decision every client
must apply *identically*, so one party decides and the rest obey. The relays are placed in a fixed
**priority order**, and the highest one still in the game (still serving live players) is the
**decision-maker**: it picks the buffer size and broadcasts it by **stamping it onto the turns it
forwards** — an envelope `buffer_directive` (not a command in the game's byte stream) naming the new
buffer, the exact future frame to apply it at, and a **decision seq** ordering it, so every client applies
it identically at the same simulated step, out of band from command processing. A command in the byte
stream was the alternative, rejected because a native latency command caps the buffer at the game's
built-in range and a client applies one turn per remote player per step, so an extra command can't just be
handed over; riding the envelope, the buffer has no ceiling and the turn it stamps is one the client
already receives. The relay stamps **every turn it forwards until the whole session has passed the apply
frame**: a client picks the change up off a peer's turn (it never receives its own turns back), and a
client whose peers aren't producing turns yet is covered automatically, because lockstep — and so the
apply frame — can't advance without it. Copies are idempotent; when decisions come quickly, the higher
decision seq tells every client which one wins, even with copies of both interleaved on the out-of-order
wire. Relays that are not the authority forward stamps untouched. The frame the whole scheme keys on is
the **slowest** per-slot frame observed from validated turns — a hostile client inflating its own
`game_frame_count` moves nothing but its own observation. If the deciding relay drops out — its players
have all left — the authority falls to the next relay in the order, with no coordinator round-trip; the
per-session decision-maker follows the coordinator's descriptor on every push, so bounds and the
authority verdict track the relay set as players come and go. **How a relay knows who still serves
players:** its own slot roster directly, and its peers via per-session live-player counts exchanged on a
reliable uni-stream per mesh-link direction (the dialer appends them to the identity-hello stream it
already opened; the acceptor opens one of its own). Presence rides a reliable stream, not the datagram
path, because the transition it reports is exactly when the sender's datagrams dry up: a relay whose
players all left forwards nothing, so a datagram sidecar would stop flowing at the one moment it
matters. Counts are pushed on change (reconciled against the roster on the mesh flush cadence), and a
relay that has *never* reported is assumed live — descriptors usually land before any client has
connected, and assuming live makes every relay independently crown the same first-in-order relay
instead of each skipping the silent others. The coordinator's only role here is to assign the **order**
(home relay first) and set the **bounds** the decision-maker stays within; it makes no per-adjustment
decision, so a running game is unaffected by a coordinator outage.

To decide well the decision-maker needs the **whole game's** network conditions, but each relay directly
observes only its *own* home clients' links — loss, RTT, and the like, which QUIC already measures per
connection. So those per-client conditions travel **with the turns**: a relay attaches its home clients'
link stats to what it forwards across the mesh, and the decision-maker combines them into the game-wide
picture (loss rate, latency, …) it decides on. The same conditions flow down to the clients, where they
can drive an in-game netgraph or other debugging output.

### Relay-side desync detection

SC:R's lockstep sim guards against divergence by exchanging a per-turn **checksum** through the command
stream: each client emits one `0x37` sync command per network turn once its sync check is active, and
because every client's Nth sync command covers the same simulated interval, two clients whose sims have
diverged produce a *different* checksum at the same ordinal. Natively each client compares its peers'
checksums and drops a mismatching peer itself — but netcode v2's transport is inert under that seam (the
relay owns the wire, and the game's own peer-drop path never fires), so a desync would be **invisible to
everyone** unless something that sees every slot's turns compares the checksums. The **authority relay
does**, off the same validated turn stream the buffer and leave consensus already read: it extracts each
slot's `hash16` (the sim-state bytes of the `0x37`, not the per-sender fog/vision bytes that legitimately
differ), places it at the right ordinal using the command's 16-entry ring index, and once every compared
slot has reported that ordinal and the frontier has advanced past it, compares them. A divergence is
reported up the coordinator webhook leg, keyed on the sync ordinal so a re-detection after an authority
handoff isn't counted twice. Observers are excluded — they don't reliably emit sync commands, so requiring
their checksums would stall the cross-check.

The comparator is **attacker-facing**, and hardened so a malicious client can only get its *own* game
disputed, never frame an honest player. The frame-anchored placement that positions a joining slot is
derived only from a corroborated median of **≥3 distinct slots'** `(ordinal, frame)` points — a lone
attacker can neither reach the threshold nor move the median — and a join with no corroborated rate is
placed only within one ring cycle of the frontier, else deferred rather than misplaced. Exactly one `0x37`
per `(slot, turn)` is enforced, removing the flooding lever both the placement-poisoning and
window-eviction attacks depended on.

### Synced player-leaves

When a player leaves mid-game, every *other* client must apply that leave at the **same simulated frame**
or their sims diverge — the same identical-application problem the latency buffer has, solved the same
way: one authority decides, and the decision rides the turn stream as envelope metadata, not a forged
command. Two paths reach a leave. A **clean quit** sends a **leave-intent** up the client's reliable
control stream before it goes, and the relay decides a leave that renders on peers as "player left." A
**drop** — the client's link simply ending, whether a quit without intent, network death, or isolation
for lagging — is decided as "player was dropped." Either way the authority relay emits a **`LeaveDirective`**
naming the slot, the reason, and the apply frame; it is broadcast to clients (idempotent, ordered by a
decision seq exactly like the buffer directive) and carried across the mesh in a **`SlotDeparted`** record
so every relay, and any relay promoted to authority afterward, derives the identical leave.

The apply frame is the subtle part. A departing client's own `game_frame_count` cannot be trusted to set
it — a malicious client could name an unreachable future frame and stall every honest survivor forever — so
the leave's apply frame is **clamped to a survivor-reachable ceiling**: the highest frame the survivors have
provably executed, computed on the departing slot's home relay from turns it validated and carried in the
`SlotDeparted` record so every relay agrees on it, never a frame the departing client merely claimed. On the
client, a `LeaveTracker` collapses the redundant directive stamps into **at-most-one leave per slot**,
surfaced at its apply frame — the leave-side mirror of the buffer `DirectiveTracker`.

### Control plane: the coordinator

The coordinator sits off the hot path. It mints per-tenant, connection-bound **tokens**, runs the
authenticated **relay registry** (relays enroll over their control connection), assigns each player a
**home relay** and region, and provisions relay capacity. Matchmaking and lobby formation stay in the
per-tenant app server; the coordinator only finds and spins up relays. Production runs its own isolated
coordinator, signing key, and relay fleet; staging and external developers share a separate one.

### The control connection (coordinator ↔ relay)

Each relay holds **one persistent control connection** open to its coordinator — a WebSocket on the
coordinator's HTTP server, dialed by the relay. The coordinator pushes the relay's **session
descriptors** down it (driving mesh `Join`/`Leave`), and the relay reports **liveness** back up the
same connection (a periodic heartbeat). One channel, authenticated once at the handshake, in both
directions.

**Enroll over the connection.** A relay's *first* frame is its `Hello` — its id and the address clients
and peer relays reach it at — which enrolls it into the coordinator's registry. So a relay registers
*and* receives its topology over one authenticated connection, not a phone-home POST plus a separate
socket; the registry membership and the descriptor stream share a lifecycle and a credential. The relay
**asserts** its address (it isn't observed from the connection's source, since a relay serves both IPv4
and IPv6 but reaches the coordinator over only one of them): a `--advertise-addr` flag, defaulting to the
listen address, with cloud-substrate auto-discovery later. One near-term simplification remains: enroll
carries a **single** address — the dual-stack model (a v4 *and* a v6 endpoint, with per-family selection
at the consumers) is a follow-up reshape of the relay-address contract.

**Version negotiation at the Hello.** The relay and coordinator deploy independently, so the `Hello`
also carries the relay's protocol **window** — `protocol` (the newest version it implements) plus an
additive `min_protocol` (the oldest it still speaks; absent on an older relay, collapsing the window to
the single `protocol`). The coordinator negotiates *before enrolling*: the highest version inside both
windows wins, which is the **downgrade rule** — a relay one version ahead that still speaks the
coordinator's newest enrolls at that version rather than being turned away, exactly what a rolling
deploy needs. No overlap means this coordinator could not drive the relay at any version, so enrolling
it would only mint sessions it mis-speaks to; instead the coordinator **refuses** with a WebSocket close
(app close code **4001**, reason naming both windows) and never registers the relay — no enrollment, no
descriptor push, nothing to clean up. The relay recognizes that close and backs off far longer than a
normal reconnect: a version mismatch is fixed by a deploy, not a redial, so hot-retrying the refused
handshake would only re-run it as log noise.

**Deregister on drop.** Registration is connection-lifetime-bound: when a relay's control connection
drops — or goes silent past the liveness deadline (below) — the coordinator deregisters it, so the
registry reflects the relays actually reachable rather than every one that ever enrolled. The race this
has to survive is a relay's *new* connection re-enrolling it while its *old* connection is still tearing
down: a naïve drop would evict the live entry the reconnect just installed. It is closed with a
**generation fencing token** — each enroll stamps the entry with a strictly-increasing generation, and a
dropping connection removes the relay only if its generation still matches the one held, so a stale drop
racing a reconnect is a no-op.

**Coordinated drain.** A relay must be able to exit on its shutdown signal without racing the coordinator
into handing it a fresh session it will never serve. When a relay receives `SIGTERM`/Ctrl-C it keeps
serving — existing games play on — but sends a **`Draining`** frame up the control connection. The
coordinator marks the relay ineligible for *new* assignments (it stays enrolled and keeps serving what it
already has), then answers **`DrainAck`** — but only *after* pushing the relay's current descriptor set
down the same socket. The **set-before-ack** ordering is the contract: a relay that sees an empty
descriptor set at ack time knows it is *provably unassigned* and can exit at once, while one still holding
sessions waits them out. The mark is race-closed by an **assignment lock**, the coordinator's outermost
control-plane lock: `create_session` (and `rehome`) hold it across the whole span from reading the registry
to pick a relay through staging that relay's descriptors, and the drain mark holds it around setting the
flag. So the two are mutually exclusive — after the mark lands, every session that will ever name the relay
has already staged its descriptor in the relay's outbox, and any create still mid-flight re-reads the
registry under the lock and sees the relay draining. A relay that reconnects mid-drain re-sends `Draining`
right after its `Hello` (a re-enroll clears the coordinator-side flag deliberately, fenced by the same
generation token as deregistration, so a stale connection's `Draining` can't mark an entry a live successor
re-enrolled).

Once acked (or after a short timeout — a coordinator that is down or predates the frame must never wedge
shutdown), the relay waits until it is **drained-idle** — it holds **no local slot** *and* its
**last-applied descriptor set is empty** — bounded by a **drain timeout** (default 90s, deliberately under
Fargate's 120s `stopTimeout` so the drain always finishes before the platform `SIGKILL`s the process). Both
halves of the predicate are load-bearing. The descriptor half is what makes the set-before-ack contract
usable: an empty set at ack time means the coordinator's post-mark truth names this relay in no session, so
the truly-idle scale-in relay exits at once (well under a second). Slot liveness alone would miss the very
sliver the ordering exists to cover — a session committed to this relay just before the drain mark, whose
clients haven't dialed yet, holds no slot; exiting then strands those clients dialing a dead relay
pre-start, which the client driver cannot recover (it escalates to re-home only after `SessionStart`). A
non-empty set therefore makes the relay wait: the assigned clients dial, register slots, and are served to
completion. The descriptor half can over-hold — a session whose clients never dial, or a multi-relay
session whose descriptor lingers while a *peer* relay still serves it after this relay's players left —
but that costs only a bounded wait: it, like any session still running at the drain timeout, is
**deliberately abandoned** — the coordinator-mediated re-home (see
[Failover and reconnect](#failover-and-reconnect)) re-homes its clients onto a live relay, which is exactly
the mechanism a hard relay death already relies on.
The drain mark also steers re-home: a draining relay is never chosen as a re-home target (it asked to stop
taking work), though a draining relay *still serving* a session it is named dead for correctly reads as a
false-alarm `stay` — drain blocks only new assignments, and a serving relay is alive.

**Logical push, physical pull.** The coordinator decides a relay's mesh membership and the relay
applies it — the data flows coordinator→relay. But the relay is what *opens* the connection, rather than
the coordinator reaching into a relay that churns under scale-to-zero and may sit behind a firewall.
Reaching out also reuses the coordinator's existing HTTP server and authenticates with an ordinary
HTTP credential, instead of standing up an inbound control surface on the attacker-facing relay.

**A held connection, not polling.** The connection stays open rather than the relay polling an endpoint.
That buys three things: the coordinator pushes a change the instant it happens (no poll interval of
staleness); the connection carries liveness directly — a clean drop is an immediate "this relay is gone"
signal, and a connection that dies *without* a close (a crashed relay, a half-open TCP, or a peer that
stopped reading and stalls the coordinator's sends under backpressure) is caught within a bounded window
by the relay's periodic heartbeat plus a coordinator-side liveness deadline that also bounds the
descriptor sends — exactly what presence tracking and failover want, instead of inferring death from
missed polls; and the two directions share one connection instead of two periodic round-trips. It is a
WebSocket rather than QUIC because the coordinator is deliberately an HTTP service and a low-frequency
control channel gains nothing from QUIC's congestion control or stream multiplexing — a held TCP
connection is plenty, and rides the server that already exists.

**Declarative current-state.** The coordinator holds, per relay, that relay's *current* descriptor set
(the descriptor for every session it should serve) behind a watch, and pushes the whole set — on connect
(a re-sync) and again on every change. The relay applies each descriptor through its idempotent Join
source, so re-pushing an unchanged set is a no-op and a reconnect converges rather than double-applies.
The set is **not** a stream of deltas; the one thing a relay must do that a delta would carry explicitly
is detect *removals* — a session gone from the set is one to leave — which it does by diffing against
what it last applied, kept across reconnects so a session removed while the relay was briefly
disconnected is left when the next connection's full set arrives without it.

**Auth.** The relay presents a coordinator-issued **bootstrap secret** (`Authorization: Bearer …`) on the
upgrade; a mismatch is rejected before the socket opens (a constant-time compare, so the secret isn't
probed a byte at a time). It **fails closed**: the coordinator refuses to start with no secret unless an
explicit insecure opt-in is set, so an unauthenticated control endpoint is never a silent default — the
open mode exists only for trusted dev/loopback that has consciously asked for it. This authenticates the
relay *to* the coordinator; the reverse direction (the relay trusting it reached the real coordinator) is
TLS's job: the connection runs over `wss://` (rustls on this workspace's ring provider, validating against
the public web PKI), so a publicly-trusted coordinator cert works today, while trusting an internal-CA or
self-signed cert (a custom root store) rides the still-open internal-CA / cert story alongside the `S===S`
inter-relay auth — until then a `wss://` coordinator needs a public cert or the secret-bearing channel
runs on trusted transport as `ws://`. **The secret today authenticates "a relay," not a specific relay
id** — a secret-holder can subscribe as any `relay_id` and read that relay's descriptor set, and the
requested id is not checked against the registry. Binding the connection to a relay identity (per-relay
credentials or a signed bootstrap token carrying the id, plus rejecting unregistered ids) lands with that
same cert work; until then the connection is for trusted (internal / loopback) deployment only. The
relay→coordinator heartbeat now rides this channel — it doubles as the keepalive that surfaces a connection
that died without a close — so per-relay identity binding is the channel's main remaining hardening.

### Tenant → coordinator requests (the app-server API)

The coordinator's tenant-facing HTTP API — `POST /session/create`, `POST /sessions/alive`, and so on — is
how a tenant's app server drives sessions. Every mutating request is **authenticated by a per-tenant
Ed25519 signature**, fail-closed. The app server signs an `x-rp2-signature` header over a domain-separated
message binding the request timestamp, HTTP method, path, and exact body bytes
(`rp2-request-v1:<ts>:<METHOD>:<path>:<body>`), and the coordinator verifies it against that tenant's
enrolled request-verifying key before doing any work. A missing, malformed, stale (outside a ±5-minute
window), or wrong-key signature all map to the same `401`, so a probe learns nothing about which check
failed, and a tenant with no enrolled key cannot make an authenticated request at all. This is a **separate
keypair from the tenant's token-signing key**: the app server holds a request-signing seed and the
coordinator stores only its public half (tenant→coordinator), while the token/webhook key signs the other
direction (coordinator→tenant). The handler reads the raw body rather than a JSON extractor precisely so
the signature covers the exact bytes on the wire. A small `GET /tenant/:tenant/pubkey` endpoint serves the
tenant's token-*verifying* key and its `kid`, so a consumer can key its verifying-key cache by the same
`kid` a webhook is signed under.

### Coordinator → tenant notifications (webhooks)

The coordinator tells a tenant about three per-game facts its relays report up their control connections — a
player **departure**, a **desync**, and a slot's end-of-game **result** — by POSTing a signed webhook to the
tenant's configured URL. Each POST is **signed with the tenant's own key** (the same key that mints tokens,
domain-separated `rp2-webhook-v1:`), not a shared secret, so there is nothing extra to provision or rotate.
Because every relay serving a session reports the same fact independently — redundancy against any one
relay's coordinator link being down — the pipeline **dedups** on first sight; it prefers the correlation
ids the relay stamped into the notice (from the descriptor it applied) over the coordinator's own in-memory
session refs, which is what lets a departure webhook survive a coordinator restart that wiped those refs.
Delivery is **at-least-once with capped-backoff retry** and eventual give-up, because the webhook is an
**optimization feed, not a correctness signal**: the app server already holds a game's terminal result and
ignores a departure for a game it has a result for, so a never-delivered webhook degrades to result-based
behavior, and the idempotent consumer absorbs the duplicate a restart-forgets-the-dedup-set redelivery
produces.

### Session lifecycle and reaps

The coordinator holds the global picture of a game's end and drives three things off it. **Ordered
dispatch:** every webhook for one `(tenant, session)` drains from a single FIFO queue, one at a time, so a
delivered `sessionClosed` implies every earlier notice for the session was delivered or exhausted.
**`sessionClosed`:** the coordinator assigned each session's serving-relay set, and when every one of them
has reported `SessionClosed` (its last local slot deregistered), the final `sessionClosed` webhook fires
and the session state is reaped. **Reaps:** two grace timers keep a session from dangling — a **holdout
reap** (all-but-one player accounted, the last silent on a live link) and a **linger reap** (all accounted
but links still open) — each closing the offending slot with a `CloseSlot` directive down the relay control
connection, which then flows through the normal link-death path, so the reap is self-resolving rather than a
second teardown mechanism. This state is in-memory: a coordinator restart forgets a session's accounting, so
a departure/result webhook for a forgotten session still delivers (a webhook-only queue is created lazily)
but its `sessionClosed` and reaps do not re-arm — the tenant's **batch liveness probe** (`POST
/sessions/alive`, asking which of a set of sessions the coordinator still holds) is the backstop that
force-reconciles the ones it no longer does.

### Active-player presence

App servers need to ask "is user U in a live game right now" — to block an in-game player from
re-queueing — and the coordinator is the one place that can answer it: relays see connections, the tenant
sees its own session bookkeeping, but only the coordinator holds both the fleet's live view and the
slot→user refs the tenant supplied at session creation. Presence **rides the heartbeat** the relay already
sends: each beat carries the relay's live roster — every session with a connected slot, and those slots —
rather than standing up a new channel, because the beat is already the relay's periodic liveness signal on
an off-hot-path connection, and piggybacking means presence can never be alive while liveness is dead (or
vice versa). Each beat carries the **whole current roster** (declarative, like the descriptor sets going
the other way): a lost or reordered beat is corrected by the next one, and the payload is bounded by the
relay's live slots. An idle relay's beat is byte-identical to the historical payload-free ping, so version
skew costs nothing.

The coordinator's store maps `(tenant, session, slot)` to the reporting relay + connection **generation** +
last-seen time. Applying a beat is a per-relay **replace** fenced by the same generation token that fences
enrollment: a stale connection's late beat (or its teardown, racing a reconnect) can neither wipe nor
overwrite what the relay's newer connection reports. Freshness is two-tier: a **control-connection drop
clears its entries immediately** — the prompt "queueable again" signal for the common case — and a **35s
TTL** (3.5× the 10s heartbeat, so two lost beats never flap an in-game player to queueable; ≥ the 30s
connection liveness deadline, so per-entry expiry never fires before the wholesale on-drop clear would)
covers a connection that is up but silent. Expiry is lazy at query time; nothing sweeps, because the
replace and the on-drop clear already bound the map by live slots.

The tenant asks over `POST /presence/query` (request-signature authed like `/session/create`), naming its
own user refs; the coordinator resolves them against the fresh entries through the stored session refs and
answers per user. The endpoint is deliberately **fail-open**: absence of evidence is `in_game: false`. A
coordinator restart wipes the store (one heartbeat interval repopulates it), a relay flap clears its
entries — and in every such window, letting an in-game player queue briefly is today's status quo, while
locking a legitimate player out of matchmaking is strictly worse. Presence means "connected to a relay
now": a just-created session whose clients haven't dialed is the tenant's own knowledge, not presence's.
The PII boundary holds throughout — the wire and the relay carry only tenant/session/slot; user identity
exists solely in the coordinator's tenant-supplied refs, resolved at query time.

## Components

| Crate | Role |
|---|---|
| `proto` | Frozen wire contracts: `Packet`/`Payload` framing, control-plane messages, tokens, protocol version, the SC:R command table. Anything crossing a component boundary is defined here first. |
| `transport` | The per-link redundancy + ack + dedup machinery above, shared by `client` and `relay`. |
| `client` | Portable client endpoint + link driver: per-slot ordering restoration and the buffer/leave directive trackers; linked into the game DLL. |
| `relay` | Validating client edge + per-session routing, the relay mesh (dial/accept, on-demand dialing, topological dedup, presence), and the authority-relay consensus off the turn stream — latency-buffer decision-maker, desync detection, and synced leaves. (A replicated turn log and flight recorder are planned, not yet built.) |
| `coordinator` | Multi-tenant control plane: per-tenant token issuance + inbound request-signature auth, the relay registry and descriptor push, session setup, region assignment/provisioning, and the tenant-notification (webhook) + session-lifecycle layer. |
