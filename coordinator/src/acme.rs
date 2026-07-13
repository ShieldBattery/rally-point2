//! In-process automatic TLS for the coordinator's control-plane listener.
//!
//! When a public domain is configured, the coordinator terminates TLS itself and
//! obtains — then renews — its certificate from Let's Encrypt over the
//! TLS-ALPN-01 challenge, answered on the same listening port: no separate
//! challenge port, no external agent, no reverse proxy. Terminating TLS in the
//! coordinator process is required, not a convenience — relay enrollment
//! authorizes a control connection against the transport peer address recorded
//! when the relay's launch was provisioned, and a TLS-terminating proxy in front
//! would replace every peer address with its own, collapsing that check.
//!
//! This module assembles the ACME state from operator-supplied settings; the
//! binary derives the TLS acceptor from that state, serves the same router behind
//! it, and drives [`log_certificate_events`] as a background task.

use std::io;
use std::path::{Path, PathBuf};

use futures_util::StreamExt;
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeConfig, AcmeState};

/// The coordinator's ACME state, with the cache-error types a filesystem
/// [`DirCache`] carries. Persisting the account key and certificates to disk, its
/// certificate- and account-cache operations both fail with [`io::Error`].
pub type CoordinatorAcmeState = AcmeState<io::Error, io::Error>;

/// Inputs for running ACME certificate provisioning: the public hostname to
/// certify, the ACME account contact, where issued material is persisted, and
/// whether to draw certificates from Let's Encrypt's staging directory.
#[derive(Debug, Clone)]
pub struct AcmeSettings {
    /// Public hostname the certificate is issued for and TLS terminates under.
    pub domain: String,
    /// ACME account contact. A bare email address is turned into a `mailto:` URI;
    /// a value already carrying a URI scheme is used unchanged.
    pub contact: String,
    /// Directory the ACME account key and issued certificates are persisted to.
    pub cache_dir: PathBuf,
    /// Draw certificates from Let's Encrypt's staging directory rather than
    /// production. Staging certificates are browser-untrusted but issued under far
    /// higher rate limits, for bringing a host up without spending production
    /// issuance budget.
    pub staging: bool,
}

impl AcmeSettings {
    /// Whether to issue from Let's Encrypt's production directory. Production is
    /// the default; staging is the opt-in for standing a host up without spending
    /// the production issuance rate-limit budget.
    fn use_production_directory(&self) -> bool {
        !self.staging
    }

    /// The account contact rendered as an ACME contact URI.
    fn contact_uri(&self) -> String {
        contact_uri(&self.contact)
    }
}

/// Renders an ACME account contact as a URI: a bare email address gains a
/// `mailto:` prefix, while a value that already names a scheme (contains a `:`)
/// is returned unchanged, so an explicit `mailto:` — or any other scheme — is
/// never doubled.
fn contact_uri(contact: &str) -> String {
    if contact.contains(':') {
        contact.to_owned()
    } else {
        format!("mailto:{contact}")
    }
}

/// Creates the ACME cache directory (with any missing parents) and confirms it is
/// writable, returning the underlying [`io::Error`] otherwise.
///
/// The cache holds the ACME account key and every issued certificate. A
/// coordinator that cannot persist them would request a fresh certificate on
/// every start and quickly exhaust the CA's issuance rate limit, so an unusable
/// cache directory fails startup rather than degrading to repeated re-issuance.
fn ensure_cache_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    // `create_dir_all` succeeds on a pre-existing read-only directory, so probe
    // for actual write access — the ACME flow must be able to store the account
    // key and certificates here.
    let probe = dir.join(".rustls-acme-write-probe");
    std::fs::write(&probe, b"")?;
    // Failing to remove the probe does not compromise writability, so ignore it.
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Builds the coordinator's ACME state from `settings`: ensures the cache
/// directory is present and writable, then assembles the certificate resolver
/// over the domain, the `mailto:` contact, the on-disk cache, and the
/// production-or-staging directory.
///
/// Building the state performs no network I/O; certificate issuance and renewal
/// happen only as the returned state is polled (see [`log_certificate_events`]).
pub fn build_state(settings: &AcmeSettings) -> io::Result<CoordinatorAcmeState> {
    ensure_cache_dir(&settings.cache_dir)?;
    let state = AcmeConfig::new([settings.domain.as_str()])
        .contact_push(settings.contact_uri())
        .cache(DirCache::new(settings.cache_dir.clone()))
        .directory_lets_encrypt(settings.use_production_directory())
        .state();
    Ok(state)
}

/// Drives the ACME state forever, logging each certificate-lifecycle event:
/// successful steps (account registration, order progress, certificate deployment
/// and renewal) at info, and errors at warn so a stalled or failing renewal is
/// visible without failing the running server. The state stream never ends on its
/// own, so this runs for the process lifetime as a background task.
pub async fn log_certificate_events(mut state: CoordinatorAcmeState) {
    while let Some(event) = state.next().await {
        match event {
            Ok(ok) => tracing::info!(event = ?ok, "ACME certificate lifecycle event"),
            Err(err) => tracing::warn!(error = ?err, "ACME certificate error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A process-unique suffix so parallel tests never collide on a temp path.
    fn unique() -> String {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        format!(
            "{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// A fresh, empty temp directory this test owns, removed first so a leftover
    /// from a prior run never masks a failure.
    fn scratch_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!("rp2-acme-{}", unique()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn contact_uri_prepends_mailto_to_a_bare_email() {
        assert_eq!(contact_uri("ops@example.com"), "mailto:ops@example.com");
    }

    #[test]
    fn contact_uri_leaves_an_existing_scheme_untouched() {
        assert_eq!(
            contact_uri("mailto:ops@example.com"),
            "mailto:ops@example.com"
        );
        assert_eq!(contact_uri("tel:+15551234"), "tel:+15551234");
    }

    #[test]
    fn production_directory_selected_unless_staging() {
        let base = AcmeSettings {
            domain: "coordinator.example.com".to_owned(),
            contact: "ops@example.com".to_owned(),
            cache_dir: PathBuf::from("unused"),
            staging: false,
        };
        assert!(base.use_production_directory());
        let staging = AcmeSettings {
            staging: true,
            ..base
        };
        assert!(!staging.use_production_directory());
    }

    #[test]
    fn ensure_cache_dir_creates_missing_parents() {
        let root = scratch_root();
        let nested = root.join("nested").join("cache");
        ensure_cache_dir(&nested).expect("a deep, missing cache path is created");
        assert!(nested.is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ensure_cache_dir_rejects_a_path_blocked_by_a_file() {
        let root = scratch_root();
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("occupied");
        std::fs::write(&file, b"x").unwrap();
        // A regular file sits where a directory component is needed, so creating
        // the cache directory under it must fail rather than silently succeed.
        assert!(ensure_cache_dir(&file.join("cache")).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn build_state_fails_when_the_cache_dir_is_unusable() {
        let root = scratch_root();
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("occupied");
        std::fs::write(&file, b"x").unwrap();
        let settings = AcmeSettings {
            domain: "coordinator.example.com".to_owned(),
            contact: "ops@example.com".to_owned(),
            cache_dir: file.join("cache"),
            staging: true,
        };
        assert!(build_state(&settings).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn build_state_assembles_for_a_writable_cache_dir() {
        let root = scratch_root();
        let settings = AcmeSettings {
            domain: "coordinator.example.com".to_owned(),
            contact: "ops@example.com".to_owned(),
            cache_dir: root.join("cache"),
            staging: true,
        };
        // Assembling the state performs no network I/O, so this exercises the whole
        // config-building path without contacting a CA.
        build_state(&settings).expect("a writable cache dir yields an ACME state");
        let _ = std::fs::remove_dir_all(&root);
    }
}
