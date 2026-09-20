//! Loading a JSON config file off disk.
//!
//! The coordinator reads three of them at startup — the region list, the tenant
//! registry, the flight-store settings — and each one is the same two steps: read
//! the file, then hand its text to a parse-and-validate function that owns the
//! shape. Only the second step differs, so only the second step lives with each
//! config; the read and its error are here.

use std::path::Path;

/// A config file that could not be read off disk. `what` names the config in
/// operator terms ("region config", "tenant registry"), so the message points at
/// the switch that asked for the file rather than at a bare path.
#[derive(Debug, thiserror::Error)]
#[error("reading {what} {path}: {source}")]
pub struct ConfigReadError {
    /// What the file was meant to be, in the words the operator used to ask for it.
    pub what: &'static str,
    /// The path that failed to read.
    pub path: String,
    /// The underlying I/O error.
    pub source: std::io::Error,
}

/// Reads the JSON file at `path` and parses it with `from_json`.
///
/// Each config keeps its own `from_json` as the testable core — validation is
/// where the three differ, and a string is far easier to drive a test from than a
/// temporary file — so this only adds the read. A read failure becomes the
/// caller's own error through [`ConfigReadError`].
pub fn load_json<T, E: From<ConfigReadError>>(
    path: &Path,
    what: &'static str,
    from_json: impl FnOnce(&str) -> Result<T, E>,
) -> Result<T, E> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigReadError {
        what,
        path: path.display().to_string(),
        source,
    })?;
    from_json(&contents)
}
