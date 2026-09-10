//! Loading production tenants from a JSON registry file.
//!
//! A dev coordinator enrolls a single tenant from CLI flags (`--dev-tenant`); a
//! production coordinator instead loads its tenants from a file named by
//! `--tenants`, whose shape is:
//!
//! ```json
//! {
//!   "tenants": [
//!     {
//!       "id": "shieldbattery",
//!       "state": "active",
//!       "kid": "sb-2026-07",
//!       "signing_key_env": "COORDINATOR_TENANT_SB_SIGNING_KEY",
//!       "client_pubkeys": ["<64-hex ed25519 public>", "<optional second>"],
//!       "notify_url": "https://example.com/webhooks/netcode-v2/game-events",
//!       "bounds": { "min": 1, "max": 12 }
//!     }
//!   ]
//! }
//! ```
//!
//! # Where the secrets live
//!
//! The file never holds a private key. `signing_key_env` is the *name* of an
//! environment variable holding the coordinator's Ed25519 signing key for the
//! tenant, so the key material stays in the deployment's `.env` and out of the
//! config file (and version control). The public inbound-verification keys
//! (`client_pubkeys`), which are not secret, do ride in the file as hex.
//!
//! # Two-phase load
//!
//! [`load`] (and its testable core [`from_json`]) do everything that depends only
//! on the file: parse the JSON, validate every field, and reject duplicate ids or
//! kids — all without reading a single environment variable, so parsing is
//! testable without a process environment. [`enroll_all`] then resolves each
//! tenant's signing key from the environment (through a caller-supplied lookup, so
//! tests inject their own) and enrolls every tenant into the [`TenantStore`]. A
//! named-but-missing or empty signing-key variable fails here, loudly: a tenant
//! with no signing key could mint nothing, so it must not start.

use std::collections::HashSet;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rally_point_proto::control::{BufferBounds, GAME_SYNC_SAFE_BUFFER_MAX, TenantId};
use rally_point_proto::token::{KeyId, PUBLIC_KEY_LEN};
use serde::Deserialize;

use crate::tenant::{self, NotifyConfig, TenantState, TenantStore, default_bounds};

/// The most inbound-verification keys one tenant may list. Two lets an app server
/// rotate its request-signing key with no downtime (verification accepts either
/// while the old key is retired); a third would be a mistake, not a rotation.
const MAX_CLIENT_PUBKEYS: usize = 2;

/// The wire shape of the whole registry file: `{"tenants": [ ... ]}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantsFileRaw {
    /// The tenants listed in the file, in file order.
    #[serde(default)]
    tenants: Vec<TenantEntryRaw>,
}

/// The wire shape of one tenant entry, before validation. Unknown fields are
/// rejected so a typo'd key surfaces as a parse error rather than being silently
/// ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantEntryRaw {
    /// The tenant id.
    id: String,
    /// The tenant's operational state: `"active"`, `"suspended"`, or `"revoked"`.
    state: String,
    /// The `kid` naming this tenant's signing key in tokens.
    kid: String,
    /// The name of the environment variable holding this tenant's signing key.
    signing_key_env: String,
    /// The tenant's inbound-verification public keys, each 64 hex characters.
    client_pubkeys: Vec<String>,
    /// The departure/game-event webhook URL, if any.
    #[serde(default)]
    notify_url: Option<String>,
    /// The tenant's latency-buffer bounds, if it overrides the default.
    #[serde(default)]
    bounds: Option<BoundsRaw>,
}

/// The wire shape of a tenant's buffer bounds override.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundsRaw {
    /// The minimum buffer, in turns.
    min: u32,
    /// The maximum buffer, in turns.
    max: u32,
}

/// One validated tenant, ready to enroll: every field parsed into its domain
/// type, with the signing key still to be resolved from `signing_key_env`.
#[derive(Debug)]
struct ValidatedTenant {
    /// The tenant id.
    id: TenantId,
    /// The `kid` naming this tenant's signing key.
    kid: KeyId,
    /// The tenant's operational state.
    state: TenantState,
    /// The environment-variable name holding the signing key.
    signing_key_env: String,
    /// The inbound-verification public keys (1..=2 of them).
    client_pubkeys: Vec<[u8; PUBLIC_KEY_LEN]>,
    /// The departure/game-event notify config, if configured.
    notify: Option<NotifyConfig>,
    /// The tenant's latency-buffer bounds (the shared default when unspecified).
    bounds: BufferBounds,
}

/// A validated tenant registry: every field is well-formed and the set has no
/// duplicate ids or kids. Signing keys are still unresolved — [`enroll_all`]
/// resolves them from the environment and enrolls each tenant.
#[derive(Debug)]
pub struct TenantsConfig {
    /// The validated tenants, in file order.
    tenants: Vec<ValidatedTenant>,
}

impl TenantsConfig {
    /// How many tenants the registry holds.
    pub fn len(&self) -> usize {
        self.tenants.len()
    }

    /// Whether the registry holds no tenants.
    pub fn is_empty(&self) -> bool {
        self.tenants.is_empty()
    }
}

/// Why a tenant registry file could not be loaded. Every variant fails
/// coordinator startup: a coordinator that cannot trust its tenant list must not
/// run, since it would then mis-authenticate or wrongly serve tenants. Each names
/// the offending tenant (and field) so an operator can find the mistake.
#[derive(Debug, thiserror::Error)]
pub enum TenantConfigError {
    /// The registry file could not be read.
    #[error("reading tenant registry {path}: {source}")]
    Read {
        /// The path that failed to read.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The file was not valid JSON in the expected shape (a bad type, a missing
    /// required field, or an unknown field).
    #[error("parsing tenant registry JSON")]
    Parse(#[from] serde_json::Error),
    /// A tenant entry has an empty id, or one longer than the wire format allows.
    #[error("tenant registry entry {index} has an invalid id")]
    InvalidId {
        /// The entry's position in the file (0-based).
        index: usize,
    },
    /// A tenant has an empty `kid`, or one longer than the wire format allows.
    #[error("tenant {tenant:?} has an invalid kid")]
    InvalidKid {
        /// The offending tenant's id.
        tenant: String,
    },
    /// A tenant's `state` is not one of `active`, `suspended`, or `revoked`.
    #[error(
        "tenant {tenant:?} has unknown state {value:?} (expected active, suspended, or revoked)"
    )]
    UnknownState {
        /// The offending tenant's id.
        tenant: String,
        /// The unrecognized value from the file.
        value: String,
    },
    /// A tenant's `signing_key_env` is empty — there is no environment variable
    /// name to resolve the signing key from.
    #[error("tenant {tenant:?} has an empty signing_key_env")]
    EmptySigningKeyEnv {
        /// The offending tenant's id.
        tenant: String,
    },
    /// A tenant lists no `client_pubkeys`. A tenant that can never make an
    /// authenticated request is a mistake, not a configuration.
    #[error("tenant {tenant:?} lists no client_pubkeys")]
    NoClientPubkeys {
        /// The offending tenant's id.
        tenant: String,
    },
    /// A tenant lists more `client_pubkeys` than the two-key rotation limit
    /// allows (one current key, plus at most one successor during a rotation).
    #[error(
        "tenant {tenant:?} lists {count} client_pubkeys (at most {MAX_CLIENT_PUBKEYS} allowed)"
    )]
    TooManyClientPubkeys {
        /// The offending tenant's id.
        tenant: String,
        /// How many were listed.
        count: usize,
    },
    /// A tenant's `client_pubkeys` entry is not 64 hex characters decoding to a
    /// 32-byte Ed25519 public key.
    #[error("tenant {tenant:?} has a malformed client_pubkeys[{index}]")]
    MalformedClientPubkey {
        /// The offending tenant's id.
        tenant: String,
        /// Which key in the list was malformed (0-based).
        index: usize,
    },
    /// A tenant's `bounds` are invalid (an inverted `min > max` range).
    #[error("tenant {tenant:?} has invalid bounds: min {min} > max {max}")]
    InvalidBounds {
        /// The offending tenant's id.
        tenant: String,
        /// The configured minimum.
        min: u32,
        /// The configured maximum.
        max: u32,
    },
    /// A tenant's `bounds.max` allows a deeper latency buffer than the game's
    /// own sync validation tolerates ([`GAME_SYNC_SAFE_BUFFER_MAX`]) — a depth
    /// past that ceiling mass-drops players deterministically, so serving it
    /// would be worse than refusing to start.
    #[error(
        "tenant {tenant:?} has bounds max {max}, past the game-safe ceiling of \
         {GAME_SYNC_SAFE_BUFFER_MAX} turns"
    )]
    BoundsPastGameSafeMax {
        /// The offending tenant's id.
        tenant: String,
        /// The configured maximum.
        max: u32,
    },
    /// Two tenants share an id — the coordinator could not tell which one a
    /// request meant.
    #[error("duplicate tenant id {0:?}")]
    DuplicateId(String),
    /// Two tenants share a `kid` — a relay looking a key up by `kid` could not
    /// tell which tenant's key it is.
    #[error("duplicate tenant kid {0:?}")]
    DuplicateKid(String),
    /// A tenant's `signing_key_env` names an environment variable that is unset or
    /// empty. A tenant with no signing key could mint nothing, so this fails
    /// startup rather than enrolling a mint-less tenant.
    #[error("tenant {tenant:?} signing key env var {env:?} is unset or empty")]
    MissingSigningKey {
        /// The offending tenant's id.
        tenant: String,
        /// The environment-variable name that was unset or empty.
        env: String,
    },
    /// A tenant's signing-key environment variable is not valid base64.
    #[error("tenant {tenant:?} signing key env var {env:?} is not valid base64")]
    MalformedSigningKeyBase64 {
        /// The offending tenant's id.
        tenant: String,
        /// The environment-variable name whose value would not decode.
        env: String,
    },
    /// A tenant's signing-key bytes are not a valid Ed25519 PKCS#8 keypair.
    #[error("tenant {tenant:?} signing key env var {env:?} is not a valid Ed25519 PKCS#8 keypair")]
    InvalidSigningKey {
        /// The offending tenant's id.
        tenant: String,
        /// The environment-variable name whose decoded bytes were not a keypair.
        env: String,
    },
}

/// Loads and validates a tenant registry from a JSON file at `path`, without
/// reading any environment variable. [`enroll_all`] does the environment
/// resolution and enrollment.
pub fn load(path: &Path) -> Result<TenantsConfig, TenantConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| TenantConfigError::Read {
        path: path.display().to_string(),
        source,
    })?;
    from_json(&contents)
}

/// Parses and validates a tenant registry from a JSON string — the testable core
/// of [`load`]. Validates every field and rejects duplicate ids or kids, but
/// reads no environment: the signing keys are named here, not resolved.
pub fn from_json(json: &str) -> Result<TenantsConfig, TenantConfigError> {
    let raw: TenantsFileRaw = serde_json::from_str(json)?;

    let mut tenants = Vec::with_capacity(raw.tenants.len());
    let mut seen_ids: HashSet<String> = HashSet::with_capacity(raw.tenants.len());
    let mut seen_kids: HashSet<String> = HashSet::with_capacity(raw.tenants.len());

    for (index, entry) in raw.tenants.into_iter().enumerate() {
        let validated = validate_entry(index, entry)?;
        if !seen_ids.insert(validated.id.0.clone()) {
            return Err(TenantConfigError::DuplicateId(validated.id.0));
        }
        if !seen_kids.insert(validated.kid.0.clone()) {
            return Err(TenantConfigError::DuplicateKid(validated.kid.0));
        }
        tenants.push(validated);
    }

    Ok(TenantsConfig { tenants })
}

/// Validates one raw entry into a [`ValidatedTenant`], turning each malformed
/// field into a [`TenantConfigError`] that names the tenant and field.
fn validate_entry(
    index: usize,
    entry: TenantEntryRaw,
) -> Result<ValidatedTenant, TenantConfigError> {
    if entry.id.is_empty() {
        return Err(TenantConfigError::InvalidId { index });
    }
    let id = TenantId::new(entry.id.clone()).map_err(|_| TenantConfigError::InvalidId { index })?;

    if entry.kid.is_empty() {
        return Err(TenantConfigError::InvalidKid {
            tenant: entry.id.clone(),
        });
    }
    let kid = KeyId::new(entry.kid).map_err(|_| TenantConfigError::InvalidKid {
        tenant: entry.id.clone(),
    })?;

    let state = match entry.state.as_str() {
        "active" => TenantState::Active,
        "suspended" => TenantState::Suspended,
        "revoked" => TenantState::Revoked,
        _ => {
            return Err(TenantConfigError::UnknownState {
                tenant: entry.id.clone(),
                value: entry.state,
            });
        }
    };

    if entry.signing_key_env.is_empty() {
        return Err(TenantConfigError::EmptySigningKeyEnv {
            tenant: entry.id.clone(),
        });
    }

    if entry.client_pubkeys.is_empty() {
        return Err(TenantConfigError::NoClientPubkeys {
            tenant: entry.id.clone(),
        });
    }
    if entry.client_pubkeys.len() > MAX_CLIENT_PUBKEYS {
        return Err(TenantConfigError::TooManyClientPubkeys {
            tenant: entry.id.clone(),
            count: entry.client_pubkeys.len(),
        });
    }
    let mut client_pubkeys = Vec::with_capacity(entry.client_pubkeys.len());
    for (key_index, hex_key) in entry.client_pubkeys.iter().enumerate() {
        let bytes = hex::decode(hex_key).map_err(|_| TenantConfigError::MalformedClientPubkey {
            tenant: entry.id.clone(),
            index: key_index,
        })?;
        let key: [u8; PUBLIC_KEY_LEN] =
            bytes
                .try_into()
                .map_err(|_| TenantConfigError::MalformedClientPubkey {
                    tenant: entry.id.clone(),
                    index: key_index,
                })?;
        client_pubkeys.push(key);
    }

    let bounds = match entry.bounds {
        Some(b) => {
            let bounds =
                BufferBounds::new(b.min, b.max).map_err(|_| TenantConfigError::InvalidBounds {
                    tenant: entry.id.clone(),
                    min: b.min,
                    max: b.max,
                })?;
            // The game-side ceiling, enforced where policy enters the system: a
            // relay clamps every seed and directive to these bounds, so a `max`
            // past what the game's sync validation tolerates would kill
            // sessions rather than merely buffer deeply.
            if bounds.max > GAME_SYNC_SAFE_BUFFER_MAX {
                return Err(TenantConfigError::BoundsPastGameSafeMax {
                    tenant: entry.id.clone(),
                    max: bounds.max,
                });
            }
            bounds
        }
        None => default_bounds(),
    };

    let notify = entry.notify_url.map(|url| NotifyConfig { url });

    Ok(ValidatedTenant {
        id,
        kid,
        state,
        signing_key_env: entry.signing_key_env,
        client_pubkeys,
        notify,
        bounds,
    })
}

/// Resolves each tenant's signing key from the environment and enrolls every
/// tenant in `config` into `store`.
///
/// `lookup_env` reads an environment variable by name (the binary passes
/// `|name| std::env::var(name).ok()`; tests inject their own), which is what keeps
/// [`from_json`] free of any process-environment dependency. Each tenant's
/// `signing_key_env` variable must hold the coordinator's Ed25519 signing key for
/// that tenant as **standard (padded) base64 of a PKCS#8 v2 document** — the same
/// encoding [`tenant::enroll_from_pkcs8`] parses, only base64-wrapped for an
/// environment variable. An unset, empty, non-base64, or non-keypair value fails
/// with an error naming the tenant and the variable; the coordinator refuses to
/// start rather than serve a tenant that could authenticate requests but mint no
/// tokens.
pub fn enroll_all(
    store: &TenantStore,
    config: &TenantsConfig,
    lookup_env: impl Fn(&str) -> Option<String>,
) -> Result<(), TenantConfigError> {
    for tenant in &config.tenants {
        let raw = lookup_env(&tenant.signing_key_env)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TenantConfigError::MissingSigningKey {
                tenant: tenant.id.0.clone(),
                env: tenant.signing_key_env.clone(),
            })?;
        let pkcs8 = BASE64_STANDARD.decode(&raw).map_err(|_| {
            TenantConfigError::MalformedSigningKeyBase64 {
                tenant: tenant.id.0.clone(),
                env: tenant.signing_key_env.clone(),
            }
        })?;
        tenant::enroll_from_pkcs8(
            store,
            tenant.kid.clone(),
            tenant.id.clone(),
            tenant.bounds,
            &pkcs8,
        )
        .map_err(|_| TenantConfigError::InvalidSigningKey {
            tenant: tenant.id.0.clone(),
            env: tenant.signing_key_env.clone(),
        })?;
        tenant::set_state(store, &tenant.id, tenant.state);
        tenant::set_client_pubkeys(store, &tenant.id, tenant.client_pubkeys.clone());
        tenant::set_notify(store, &tenant.id, tenant.notify.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
