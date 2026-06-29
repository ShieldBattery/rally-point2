# Netcode v2 — Architecture Overview

This is the reference for **how netcode v2 works and why it is shaped this way**. It describes the
**final design** — the target the implementation is being built toward, not only what runs today.

> **Implementation status — temporary note, delete once complete.** What exists today is the
> single-relay core: `client–relay–client` with the per-link transport, the relay's validating client
> edge, and the client's forward-recovery driver. The mesh, resilience/failover, consensus, and
> coordinator described below are designed but not yet built.

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
    failover design (see [Failover](#failover-and-reconnect-open)).

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
would also recover it (see [Failover](#failover-and-reconnect-open)) — the per-hop transport doesn't
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
decision, not a post-connect exchange). The `MeshCommand::Join`/`Leave` that drives session membership
on a link is **not** wired from the binary yet: today the integration test sends it on the driver's
command sender directly, and in production the coordinator's session-descriptor push (Phase 3) will —
targeting the specific link serving a session, never broadcasting. So the binary establishes mesh
connections and keeps the drivers alive, but session membership is an injected input.

**Mesh trust today vs. production.** Today the dial trusts the peer's cert against the same roots a
client would — a dev/loopback pair with self-signed certs just works (each relay trusts its own leaf
as the peer's root). Self-signed doesn't scale to production: with scale-to-zero, relays churn
constantly, so pre-distributing each relay's cert to every potential peer is operationally infeasible.
The production approach is an **internal CA** (AWS Private CA, or a simple CA the coordinator runs):
one CA root signs every relay cert on startup; each relay trusts the CA root; any two relays can mesh
without pre-sharing certs. The current `mesh_client_config` does server-auth only
(`with_no_client_auth`); production mTLS — both sides present certs — is a transport-level change
that lands with the coordinator (Phase 3), alongside the open `S===S` inter-relay auth question
(mutual certs vs. a coordinator-issued shared secret). Client → relay trust is simpler: it's 1:1 (one
relay per client), so self-signed *with pinning* (the coordinator hands the client the relay's cert
in the session descriptor) or an internal CA both work; direct IPs (D3) rule out public CA.

### Failover and reconnect (open)

A relay dying mid-game stalls lockstep for every client it serves, so a production deployment needs a
real failover and reconnect story: moving affected clients to another relay and recovering the turns
they missed in the gap. How a replacement relay would have those missed turns to replay — and at what
storage and replication cost — is **not yet designed**, and the obvious answer (persisting and
replicating a full per-game turn log) is not obviously affordable. Treat this as an open question, not a
settled part of the architecture. (The client reconnect infrastructure this needs would also cover a
client's own transient disconnects.)

**Client-side turn retention (design note for D11).** The relay-side turn
log that D4 calls "open" may not be needed at all: each client already has
every turn it sent (it generated them) and every turn it received (it
executed them), so the clients *are* the turn log. A replacement relay asks
each client to replay from a target turn. The retention window a client must
keep is `executing_turn - buffer_size` through `executing_turn + buffer_size`
— roughly `2 * buffer_size` turns (typically 4–10, a few hundred bytes). The
lower bound is `E - B` because the slowest client can be at most `buffer_size`
turns behind before they stall (the buffer is exactly the cushion that absorbs
that), so `E - B` is the oldest turn the slowest client might still be
executing — and thus the oldest a replacement relay might need re-sent. The
upper bound is `E + B` (the client's own send pipe). This sidesteps the
relay-side storage/replication cost question entirely; the open work is the
coordinated resync protocol itself (how clients re-send simultaneously, how
the replacement distributes turns in lockstep order before anyone advances).

### Latency buffer

How much turn buffer the game runs with — the latency cushion that absorbs jitter — is not fixed; it has
to move as network conditions shift over the course of a game. Changing it is a decision every client
must apply *identically*, so one party decides and the rest obey. The relays are placed in a fixed
**priority order**, and the highest one still in the game (still serving live players) is the
**decision-maker**: it picks the buffer size and broadcasts a command setting it that every client
applies at the same turn. If that relay drops out — its players have all left — the authority falls to
the next relay in the order, with no coordinator round-trip. The coordinator's only role here is to set
the **bounds** the decision-maker stays within; it makes no per-adjustment decision, so a running game
is unaffected by a coordinator outage.

To decide well the decision-maker needs the **whole game's** network conditions, but each relay directly
observes only its *own* home clients' links — loss, RTT, and the like, which QUIC already measures per
connection. So those per-client conditions travel **with the turns**: a relay attaches its home clients'
link stats to what it forwards across the mesh, and the decision-maker combines them into the game-wide
picture (loss rate, latency, …) it decides on. The same conditions flow down to the clients, where they
can drive an in-game netgraph or other debugging output.

### Control plane: the coordinator

The coordinator sits off the hot path. It mints per-tenant, connection-bound **tokens**, runs the
authenticated **relay registry** (relays phone home to enroll), assigns each game its **home and backup
relays** and region, and provisions relay capacity. Matchmaking and lobby formation stay in the
per-tenant app server; the coordinator only finds and spins up relays. Production runs its own isolated
coordinator, signing key, and relay fleet; staging and external developers share a separate one.

## Components

| Crate | Role |
|---|---|
| `proto` | Frozen wire contracts: `Packet`/`Payload` framing, control-plane messages, tokens, protocol version, the SC:R command table. Anything crossing a component boundary is defined here first. |
| `transport` | The per-link redundancy + ack + dedup machinery above, shared by `client` and `relay`. |
| `client` | Portable client endpoint + link driver; linked into the game DLL. |
| `relay` | Validating client edge + per-session routing, the relay mesh, the replicated turn log, and the flight recorder. |
| `coordinator` | Multi-tenant control plane: per-tenant token issuance, the relay registry, region assignment, and provisioning. |
