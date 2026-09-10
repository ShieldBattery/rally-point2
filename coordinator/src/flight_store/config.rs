//! Flight-store configuration: the JSON shape naming the bucket endpoint and the
//! NAMES of the credential environment variables, parsed without touching the
//! environment, and its later resolution into the material [`S3FlightStore`] connects
//! with.
//!
//! [`S3FlightStore`]: super::S3FlightStore

use std::path::Path;

use serde::Deserialize;

/// A validated flight-store configuration: where the bucket lives and the NAMES of the
/// environment variables its credentials are read from. Parsed by [`from_json`]
/// without touching the environment; the credential variables are resolved later by
/// [`resolve_secrets`](FlightStoreConfig::resolve_secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlightStoreConfig {
    /// The bucket's S3 endpoint (e.g. `https://nyc3.digitaloceanspaces.com`).
    endpoint: String,
    /// The region the SigV4 signer stamps. Spaces accepts `us-east-1`.
    region: String,
    /// The bucket recordings are stored in.
    ///
    /// `pub(super)`: the sibling `tests` module asserts on it directly.
    pub(super) bucket: String,
    /// The NAME of the environment variable holding the access key id.
    ///
    /// `pub(super)`: the sibling `tests` module asserts on it directly.
    pub(super) access_key_env: String,
    /// The NAME of the environment variable holding the secret access key.
    ///
    /// `pub(super)`: the sibling `tests` module asserts on it directly.
    pub(super) secret_key_env: String,
}

/// The wire shape of the config file, before validation. camelCase keys, and unknown
/// fields rejected so a typo surfaces as a startup error rather than a silently
/// ignored setting.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FlightStoreConfigRaw {
    endpoint: String,
    region: String,
    bucket: String,
    access_key_env: String,
    secret_key_env: String,
}

/// Why a flight-store config could not be loaded or resolved. Every variant fails
/// coordinator startup: a coordinator told to persist recordings but unable to reach
/// its store must not run, exactly like a malformed tenant registry.
#[derive(Debug, thiserror::Error)]
pub enum FlightStoreConfigError {
    /// The config file could not be read.
    #[error("reading flight store config {path}: {source}")]
    Read {
        /// The path that failed to read.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The file was not valid JSON in the expected shape (a bad type, a missing
    /// required field, or an unknown field).
    #[error("parsing flight store config JSON")]
    Parse(#[from] serde_json::Error),
    /// A required config field is empty.
    #[error("flight store config field {field} is empty")]
    EmptyField {
        /// The name of the empty field.
        field: &'static str,
    },
    /// A named credential environment variable is unset or empty. A store the
    /// coordinator cannot authenticate to must fail startup rather than silently drop
    /// every recording.
    #[error("flight store {which} env var {env:?} is unset or empty")]
    MissingEnv {
        /// Which credential the variable holds (`access-key` or `secret-key`).
        which: &'static str,
        /// The environment-variable name that was unset or empty.
        env: String,
    },
}

/// Loads and validates a flight-store config from the JSON file at `path`, without
/// reading any environment variable. [`FlightStoreConfig::resolve_secrets`] does the
/// environment resolution.
pub fn load(path: &Path) -> Result<FlightStoreConfig, FlightStoreConfigError> {
    let contents =
        std::fs::read_to_string(path).map_err(|source| FlightStoreConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
    from_json(&contents)
}

/// Parses and validates a flight-store config from a JSON string — the testable core
/// of [`load`]. Rejects an empty required field, but reads no environment: the
/// credentials are named here, not resolved.
pub fn from_json(json: &str) -> Result<FlightStoreConfig, FlightStoreConfigError> {
    let raw: FlightStoreConfigRaw = serde_json::from_str(json)?;
    Ok(FlightStoreConfig {
        endpoint: require_non_empty(raw.endpoint, "endpoint")?,
        region: require_non_empty(raw.region, "region")?,
        bucket: require_non_empty(raw.bucket, "bucket")?,
        access_key_env: require_non_empty(raw.access_key_env, "accessKeyEnv")?,
        secret_key_env: require_non_empty(raw.secret_key_env, "secretKeyEnv")?,
    })
}

/// Returns `value` when it holds a non-whitespace character, else an
/// [`FlightStoreConfigError::EmptyField`] naming `field`.
fn require_non_empty(value: String, field: &'static str) -> Result<String, FlightStoreConfigError> {
    if value.trim().is_empty() {
        Err(FlightStoreConfigError::EmptyField { field })
    } else {
        Ok(value)
    }
}

impl FlightStoreConfig {
    /// Resolves the access and secret keys from the environment (through `lookup_env`,
    /// so the binary passes `|name| std::env::var(name).ok()` and tests inject their
    /// own), failing closed if either variable is unset or empty. Returns the material
    /// [`S3FlightStore::connect`](super::S3FlightStore::connect) builds a client from;
    /// reads no environment of its own beyond `lookup_env`.
    pub fn resolve_secrets(
        &self,
        lookup_env: impl Fn(&str) -> Option<String>,
    ) -> Result<ResolvedFlightStore, FlightStoreConfigError> {
        let access_key = resolve_env(&lookup_env, &self.access_key_env, "access-key")?;
        let secret_key = resolve_env(&lookup_env, &self.secret_key_env, "secret-key")?;
        Ok(ResolvedFlightStore {
            endpoint: self.endpoint.clone(),
            region: self.region.clone(),
            bucket: self.bucket.clone(),
            access_key,
            secret_key,
        })
    }
}

/// Reads `env` through `lookup_env`, trimming it and treating an empty or
/// whitespace-only value as absent — the same fail-closed rule the tenant registry
/// applies to a signing-key variable.
fn resolve_env(
    lookup_env: &impl Fn(&str) -> Option<String>,
    env: &str,
    which: &'static str,
) -> Result<String, FlightStoreConfigError> {
    lookup_env(env)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FlightStoreConfigError::MissingEnv {
            which,
            env: env.to_owned(),
        })
}

/// A flight-store config with its credentials resolved from the environment — the
/// input to [`S3FlightStore::connect`](super::S3FlightStore::connect). Holds the
/// secret access key in memory (the coordinator is the sole credential holder by
/// design), so it deliberately derives no `Debug` that could log it.
///
/// Fields are `pub(super)`: `S3FlightStore::build`, in the sibling `s3` module,
/// reads them directly to build the S3 SDK client.
pub struct ResolvedFlightStore {
    pub(super) endpoint: String,
    pub(super) region: String,
    pub(super) bucket: String,
    pub(super) access_key: String,
    pub(super) secret_key: String,
}
