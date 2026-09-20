//! Region configuration: the coordinator's registry of the placement regions it
//! allows, loaded from a JSON file at startup.
//!
//! A region is an opaque placement label (see [`RegionId`]) with the client-facing
//! metadata a game client needs to measure its own latency to that region: a
//! `display_name` to show, a `beacon` (a GameLift UDP ping endpoint) as the
//! primary measurement target, and a `fallback` (an always-up TCP endpoint) for
//! when the beacon path is blocked. Ping targets live in the same registry as the
//! ids they belong to — one source of truth — so a region id and its measurement
//! targets can never disagree across configs. `beacon`/`fallback` are
//! `host:port` **strings** (DNS hostnames, not resolved [`SocketAddr`]s), because
//! the endpoints are named cloud hosts a client resolves at measurement time.
//!
//! The config is immutable after startup and its file order is the client's
//! display order, so it is preserved verbatim. A coordinator started without a
//! region config (the `--regions` flag) holds an empty config: every region
//! behavior — enroll validation, the region list endpoint, region-aware
//! placement — degrades to the region-blind path, which is exactly the dev /
//! loopback posture.
//!
//! [`SocketAddr`]: std::net::SocketAddr

use std::path::Path;
use std::sync::Arc;

use rally_point_proto::control::{RegionBeaconTarget, RegionId};
use serde::{Deserialize, Serialize};

/// The maximum length of a region id, in bytes. Region ids are short opaque
/// labels (`"us-east"`), so this is generous headroom that still bounds the field
/// against a config typo or abuse.
const MAX_REGION_ID_LEN: usize = 32;

/// One configured region: its opaque id (the wire name everywhere), the display
/// name clients show, and the two latency-measurement targets a client pings to
/// rank the region.
///
/// Serializes snake_case — the same shape the config file uses and the
/// `GET /regions` endpoint returns — so a client parses one shape for both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Region {
    /// The opaque region id — the wire name a relay enrolls with and a session
    /// slot requests. Validated at load: `[a-z0-9-]`, 1..=32 bytes.
    pub id: RegionId,
    /// The human-readable name a client shows in its server-region setting.
    pub display_name: String,
    /// `host:port` of the region's GameLift UDP ping beacon — the primary
    /// latency-measurement target. A DNS hostname, resolved by the client, not a
    /// pre-resolved socket address.
    pub beacon: String,
    /// `host:port` of an always-up TCP endpoint in the region (e.g. a regional
    /// API endpoint). A client measures TCP-connect time here when the beacon
    /// path is blocked. A DNS hostname, like `beacon`.
    pub fallback: String,
}

/// The coordinator's configured region list.
///
/// Holds the regions behind an [`Arc`] so a clone — one per HTTP request's state
/// clone and per relay control connection — is a refcount bump, not a deep copy.
/// An empty config (the [`Default`], used when no `--regions` file is given) makes
/// every region behavior dormant: [`contains`](Self::contains) is always `false`,
/// so a region-tagged relay is refused and every session slot falls back to the
/// region-blind pick.
///
/// Serializes as `{"regions": [...]}` — the config file's shape and the body
/// `GET /regions` returns. The (de)serialization is by hand rather than derived
/// because the `Arc` wrapper's serde impls sit behind serde's `rc` feature, which
/// this workspace deliberately does not enable; a `RegionsWire` helper carries the
/// plain `Vec` form across the wire and this type wraps/unwraps the `Arc`.
#[derive(Debug, Clone, Default)]
pub struct RegionsConfig {
    regions: Arc<Vec<Region>>,
}

/// The owned wire form of a [`RegionsConfig`] — the JSON object the config file
/// and the `GET /regions` response share. A separate type so [`RegionsConfig`]
/// can hold its regions behind an `Arc` without pulling in serde's `rc` feature.
#[derive(Deserialize)]
struct RegionsWire {
    #[serde(default)]
    regions: Vec<Region>,
}

/// The borrowed wire form, so serializing a [`RegionsConfig`] does not clone its
/// regions.
#[derive(Serialize)]
struct RegionsWireRef<'a> {
    regions: &'a [Region],
}

impl Serialize for RegionsConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        RegionsWireRef {
            regions: &self.regions,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RegionsConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = RegionsWire::deserialize(deserializer)?;
        Ok(Self {
            regions: Arc::new(wire.regions),
        })
    }
}

/// Why a region config file could not be loaded — a read failure, a JSON parse
/// error, or a validation failure. Every variant fails coordinator startup: a
/// coordinator that cannot trust its region list must not run, since it would
/// then mis-place or wrongly refuse relays.
#[derive(Debug, thiserror::Error)]
pub enum RegionsError {
    /// The config file could not be read.
    #[error(transparent)]
    Read(#[from] crate::config::ConfigReadError),
    /// The config file was not valid JSON in the expected shape.
    #[error("parsing region config JSON")]
    Parse(#[from] serde_json::Error),
    /// The config lists no regions. An empty list is a misconfiguration — a
    /// coordinator with regions enabled but none defined would refuse every
    /// tagged relay; omit `--regions` entirely for the region-blind posture.
    #[error("region config lists no regions")]
    Empty,
    /// A region id is empty, longer than 32 bytes, or contains a character outside
    /// `[a-z0-9-]`.
    #[error("region id {0:?} must be 1..=32 bytes of [a-z0-9-]")]
    InvalidId(String),
    /// A region has an empty `display_name`, `beacon`, or `fallback`.
    #[error("region {id:?} has an empty {field}")]
    EmptyField {
        /// The offending region's id.
        id: String,
        /// Which field was empty.
        field: &'static str,
    },
    /// Two regions share an id — the coordinator could not tell which one a relay
    /// or slot meant.
    #[error("duplicate region id {0:?}")]
    DuplicateId(String),
}

impl RegionsConfig {
    /// Loads and validates a region config from a JSON file at `path`.
    pub fn load(path: &Path) -> Result<Self, RegionsError> {
        crate::config::load_json(path, "region config", Self::from_json)
    }

    /// Parses and validates a region config from a JSON string — the testable
    /// core of [`load`](Self::load).
    pub fn from_json(json: &str) -> Result<Self, RegionsError> {
        let parsed: RegionsConfig = serde_json::from_str(json)?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Rejects an empty list, a duplicate id, or an id/field that violates its
    /// shape. File order is never disturbed, so the surviving config lists the
    /// regions in the client's intended display order.
    fn validate(&self) -> Result<(), RegionsError> {
        if self.regions.is_empty() {
            return Err(RegionsError::Empty);
        }
        let mut seen = std::collections::HashSet::with_capacity(self.regions.len());
        for region in self.regions.iter() {
            let id = region.id.as_ref();
            let id_ok = (1..=MAX_REGION_ID_LEN).contains(&id.len())
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !id_ok {
                return Err(RegionsError::InvalidId(id.to_owned()));
            }
            for (value, field) in [
                (&region.display_name, "display_name"),
                (&region.beacon, "beacon"),
                (&region.fallback, "fallback"),
            ] {
                if value.is_empty() {
                    return Err(RegionsError::EmptyField {
                        id: id.to_owned(),
                        field,
                    });
                }
            }
            if !seen.insert(id.to_owned()) {
                return Err(RegionsError::DuplicateId(id.to_owned()));
            }
        }
        Ok(())
    }

    /// Whether `id` is one of the configured regions. Always `false` for an empty
    /// config, which is what makes a region-tagged enroll refused when regions
    /// are not configured at all.
    pub fn contains(&self, id: &RegionId) -> bool {
        self.regions.iter().any(|region| &region.id == id)
    }

    /// Whether no regions are configured — the dormant, region-blind posture.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// The configured regions, in file (display) order.
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// The region ping beacon targets the coordinator distributes to relays — one
    /// per configured region, in file order, each pairing a region id with its
    /// `beacon` endpoint. An empty config yields an empty vec, which is the signal
    /// to omit the push (a region-blind fleet has no beacons to measure).
    pub fn beacon_targets(&self) -> Vec<RegionBeaconTarget> {
        self.regions
            .iter()
            .map(|region| RegionBeaconTarget {
                region: region.id.clone(),
                beacon: region.beacon.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
