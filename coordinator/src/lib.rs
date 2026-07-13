//! `rally-point-coordinator` — the multi-tenant netcode v2 control plane
//! (library half).
//!
//! The coordinator is control-plane only: it finds / spins up relays and sets
//! policy, but stays **off the turn hot path** so running games survive a
//! coordinator outage. Responsibilities:
//!
//! - **registry** ([`registry`]) — relay enrollment + fleet inventory
//! - **tenant** ([`tenant`]) — per-tenant Ed25519 signing keys + token
//!   issuance; the coordinator's counterpart to the relay's verification
//!   registry.
//! - **session** ([`session`]) — accept app-server session requests (N players
//!   / regions), assign each player a home relay, issue connection-bound tokens,
//!   and build the per-relay session descriptors that drive the mesh.
//! - **descriptors** ([`descriptors`]) — the per-relay descriptor outbox: the
//!   coordinator side of the control connection. Holds each relay's current
//!   session-descriptor set behind a watch channel and pushes it down the
//!   relay's open control connection whenever it changes.
//! - **notify** ([`notify`]) — the departure-webhook leg: dedup the departure
//!   notices relays report up their control connections, enrich each with the
//!   session's stored correlation ids + the tenant's notify config, and POST a
//!   webhook to the tenant.
//! - **presence** ([`presence`]) — active-player presence: the connected slots
//!   relays piggyback on their heartbeats, aggregated so a tenant's app server
//!   can ask "is user U in a live game" and block an in-game player from
//!   re-queueing.
//! - **api** ([`api`]) — the HTTP control-plane API: relay phone-home, session
//!   setup, and the relay's persistent control connection (an authenticated
//!   WebSocket), exposed as a testable router.
//! - **acme** ([`acme`]) — optional in-process TLS: when a public domain is
//!   configured, obtain and renew the coordinator's Let's Encrypt certificate
//!   over TLS-ALPN-01 on the listening port, so TLS terminates in the process
//!   that reads each control connection's peer address. Absent a domain, the
//!   coordinator serves plain HTTP (the dev / loopback posture).
//! - **identity** ([`identity`]) — verifies a relay's enroll proof-of-possession
//!   signature against the certificate its `Hello` presented, closing the gap
//!   where the certificate alone is a copyable claim, not proof of holding the
//!   matching private key.
//! - **ledger** ([`ledger`]) — the optional provisioned-relay ledger: a local
//!   SQLite store of minted relay ids, their one-time enroll tokens, and the
//!   certificate fingerprint each id binds to at first enroll. Present, a
//!   coordinator refuses any enroll it did not provision; absent, it keeps the
//!   dev / loopback posture of accepting the id claim as presented.
//! - **provision** ([`provision`]) — the reconcile loop that keeps each region's
//!   relay count matched to TTL'd warm demand: it mints identities through the
//!   ledger, launches relay tasks through a [`provision::Provisioner`], records
//!   their addresses, drains idle relays, and sweeps launches that never
//!   enrolled or tasks the ledger lost track of. A local
//!   [`provision::ProcessProvisioner`] spawns real relay binaries, so the whole
//!   lifecycle runs without a cloud substrate.
//! - **policy** — set latency-buffer consensus *bounds* at setup; the relay
//!   executes per-turn. The bounds type itself lives in
//!   [`rally_point_proto::control::BufferBounds`] (it crosses the
//!   coordinator→relay boundary), and the coordinator sets it via
//!   [`tenant::enroll`].
//!
//! The coordinator's logic modules are pure: no I/O, no async, no network.
//! They operate over the proto control types and the coordinator's in-memory
//! registries. The `api` module wraps them in an HTTP router; the binary half
//! ([`main`](../main.rs)) binds the listener and serves it.

pub mod acme;
pub mod api;
pub mod descriptors;
pub mod identity;
pub mod ledger;
pub mod lifecycle;
pub mod notify;
pub mod presence;
pub mod provision;
pub mod regions;
pub mod registry;
pub mod rehome;
pub mod session;
pub mod tenant;

/// Default port the coordinator serves its app-server + relay control API on.
pub const DEFAULT_PORT: u16 = 14_910;
