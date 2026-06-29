//! Process configuration: building the relay's TLS identity and tenant-signing-key
//! registry from inputs the binary receives (PEM files, CLI args).
//!
//! These are library functions, not binary wiring, so the binary stays a thin
//! caller and the real failure modes — PEM parsing, self-signed cert generation,
//! Ed25519 key handling — are testable without spawning a process.
//!
//! The relay is a pure verifier: it registers only tenant *public* (verifying)
//! keys. The private key that *signs* tokens stays with the issuer
//! (coordinator/app-server), never on the relay.

use color_eyre::eyre::WrapErr;
use std::net::SocketAddr;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::RelayId;
use rally_point_proto::token::KeyId;
use rally_point_transport::quic;
use rally_point_transport::quinn;
use rally_point_transport::rustls::RootCertStore;
use rally_point_transport::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use ring::signature::KeyPair;

use crate::auth::Registry;
/// A self-signed certificate + its private key, plus the certificate alone (to
/// seed a client's trust roots). For dev/loopback only — clients must trust the
/// generated cert out-of-band.
pub struct SelfSignedCert {
    /// The certificate chain (one self-signed cert).
    pub chain: Vec<CertificateDer<'static>>,
    /// The matching private key.
    pub key: PrivateKeyDer<'static>,
    /// The certificate, for seeding a client's root trust store.
    pub ca: CertificateDer<'static>,
}

/// Generates a self-signed certificate for `localhost`, for dev/loopback. A
/// client connecting to `localhost` will trust the relay if it pins this cert.
pub fn self_signed_cert() -> color_eyre::Result<SelfSignedCert> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|e| color_eyre::eyre::eyre!("generating self-signed cert: {e}"))?;
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    Ok(SelfSignedCert {
        chain: vec![cert_der.clone()],
        key: key_der,
        ca: cert_der,
    })
}

/// Loads a certificate chain + private key from PEM input. Each value is
/// either a file path (read from disk — local dev, Docker volume mounts) or
/// inline PEM content (Fargate's native secret injection sets the env var to
/// the secret's content, not a path). Detection is by the `-----BEGIN` PEM
/// sentinel: a path never contains it, PEM content always does.
///
/// The cert input may contain multiple certificates (a chain); the key input
/// must contain exactly one PKCS#8 private key.
pub fn load_cert(
    cert_input: &str,
    key_input: &str,
) -> color_eyre::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_pem = read_pem_input(cert_input, "cert")?;
    let key_pem = read_pem_input(key_input, "key")?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| color_eyre::eyre::eyre!("parsing PEM certificates: {e}"))?;
    if certs.is_empty() {
        color_eyre::eyre::bail!("no certificates found in cert input");
    }

    let keys: Vec<rally_point_transport::rustls::pki_types::PrivatePkcs8KeyDer> =
        rustls_pemfile::pkcs8_private_keys(&mut &key_pem[..])
            .collect::<Result<_, _>>()
            .map_err(|e| color_eyre::eyre::eyre!("parsing PEM private keys: {e}"))?;
    let key = PrivateKeyDer::from(
        keys.into_iter()
            .next()
            .ok_or_else(|| color_eyre::eyre::eyre!("no PKCS#8 private key found in key input"))?,
    );

    Ok((certs, key))
}

/// Resolves a PEM input value to raw bytes: if it contains the `-----BEGIN`
/// sentinel it's inline PEM content; otherwise it's a file path to read.
fn read_pem_input(input: &str, label: &str) -> color_eyre::Result<Vec<u8>> {
    if input.contains("-----BEGIN") {
        Ok(input.as_bytes().to_vec())
    } else {
        std::fs::read(input)
            .map_err(|e| color_eyre::eyre::eyre!("reading {label} file {input}: {e}"))
    }
}

/// A tenant verifying key registered on the relay, plus (when generated) the
/// PKCS#8 private key a client can use to mint tokens for loopback.
pub struct TenantKey {
    /// The kid naming this key in the registry.
    pub kid: KeyId,
    /// The tenant id bound to this key.
    pub tenant: TenantId,
    /// The 32-byte Ed25519 public (verifying) key the relay registers.
    pub verifying_key: [u8; 32],
    /// When the key was generated (not supplied), the PKCS#8 private key a
    /// client uses to mint tokens. `None` when the caller supplied only the
    /// public key — the relay never holds the private key in that case.
    pub generated_pkcs8: Option<Vec<u8>>,
}

/// Registers a tenant verifying key from a hex-encoded 32-byte Ed25519 public
/// key. The relay verifies client tokens against this; the matching private key
/// stays with the issuer, never on the relay.
pub fn tenant_key_from_pubkey(
    kid: String,
    tenant: String,
    pubkey_hex: &str,
) -> color_eyre::Result<TenantKey> {
    let bytes = hex::decode(pubkey_hex)
        .map_err(|e| color_eyre::eyre::eyre!("decoding tenant pubkey hex: {e}"))?;
    let verifying_key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        color_eyre::eyre::eyre!("tenant pubkey must be 32 bytes, got {}", bytes.len())
    })?;
    Ok(TenantKey {
        kid: KeyId(kid),
        tenant: TenantId::new(tenant)
            .map_err(|e| color_eyre::eyre::eyre!("tenant id too long (max 255 bytes): {e}"))?,
        verifying_key,
        generated_pkcs8: None,
    })
}

/// Generates a dev tenant keypair: registers the public key, and returns the
/// PKCS#8 private key so a client can mint tokens for loopback. The
/// relay itself only keeps the public half.
pub fn generate_dev_tenant_key(kid: String, tenant: String) -> color_eyre::Result<TenantKey> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| color_eyre::eyre::eyre!("generating tenant key: {e}"))?;
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|e| color_eyre::eyre::eyre!("loading generated tenant key: {e}"))?;
    let verifying_key: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();

    Ok(TenantKey {
        kid: KeyId(kid),
        tenant: TenantId::new(tenant)
            .map_err(|e| color_eyre::eyre::eyre!("tenant id too long (max 255 bytes): {e}"))?,
        verifying_key,
        generated_pkcs8: Some(pkcs8.as_ref().to_vec()),
    })
}

/// Builds a `Registry` from a tenant verifying key.
pub fn registry_from_tenant_key(key: &TenantKey) -> Registry {
    let mut registry = Registry::new();
    registry.insert(key.kid.clone(), key.tenant.clone(), key.verifying_key);
    registry
}

/// Builds a `quinn::ServerConfig` from a self-signed cert (dev/loopback).
pub fn server_config_from_self_signed(
    cert: &SelfSignedCert,
) -> color_eyre::Result<quinn::ServerConfig> {
    // PrivateKeyDer doesn't impl Clone, so re-serialize from the raw DER.
    let key = rally_point_transport::rustls::pki_types::PrivateKeyDer::try_from(
        cert.key.secret_der().to_vec(),
    )
    .unwrap();
    quic::server_config(cert.chain.clone(), key)
        .map_err(|e| color_eyre::eyre::eyre!("building QUIC server config: {e}"))
}

/// A parsed mesh-peer entry: the peer relay's listen endpoint and its id.
///
/// Dev/loopback only as a CLI-parsed value. In production the coordinator
/// pushes peer topology to each relay at runtime (relays churn under
/// scale-to-zero, so the peer set is unknowable at startup), and the dial
/// side needs the peer's id before connecting — `should_dial_mesh` is a
/// pre-connect local decision, not a post-connect exchange.
#[derive(Debug)]
pub struct MeshPeer {
    /// The peer relay's listen endpoint (client + mesh ALPN on one socket).
    pub addr: SocketAddr,
    /// The peer relay's id — the lower-id side dials.
    pub id: RelayId,
}

/// Parses each `ADDR#ID` entry from `--mesh-peer` (dev/loopback).
///
/// `ADDR` is a `SocketAddr` (IPv4 or bracketed IPv6); `ID` is a `u64` relay
/// id. The `#` separator splits them — it can't appear in a `SocketAddr`, so
/// `rsplit_once('#')` is unambiguous. Malformed entries (missing `#`,
/// unparseable address, non-numeric id) return an error naming the bad entry.
pub fn parse_mesh_peers(specs: &[String]) -> color_eyre::Result<Vec<MeshPeer>> {
    let mut peers = Vec::new();
    for spec in specs {
        let (addr_str, id_str) = spec.rsplit_once('#').ok_or_else(|| {
            color_eyre::eyre::eyre!("mesh-peer `{spec}` missing `#ID` suffix (expected ADDR#ID)")
        })?;
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| color_eyre::eyre::eyre!("mesh-peer `{spec}` address parse failed: {e}"))?;
        let id: u64 = id_str
            .parse()
            .map_err(|e| color_eyre::eyre::eyre!("mesh-peer `{spec}` id parse failed: {e}"))?;
        peers.push(MeshPeer {
            addr,
            id: RelayId(id),
        });
    }
    Ok(peers)
}

/// Loads the PEM root certificate(s) for verifying mesh peers (dev/loopback).
///
/// `mesh_roots` is either a file path or inline PEM content (detected by the
/// `-----BEGIN` sentinel, same as [`load_cert`]). When absent, falls back to
/// `own_ca` — the dev/loopback case where two relays share one self-signed
/// cert, so each trusts its own leaf as the peer's root.
///
/// In production, relay-to-relay trust comes from an internal CA (both relays
/// trust the same CA root; each relay's cert is signed by it on startup), not
/// from this dev fallback. That lands with the coordinator (Phase 3).
pub fn load_mesh_roots(
    mesh_roots: &Option<String>,
    own_ca: &CertificateDer<'_>,
) -> color_eyre::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    match mesh_roots {
        Some(input) => {
            let pem = read_pem_input(input, "mesh-roots")?;
            for cert in rustls_pemfile::certs(&mut &pem[..]) {
                roots
                    .add(cert.context("parsing mesh-roots PEM")?)
                    .map_err(|e| color_eyre::eyre::eyre!("adding mesh-roots cert: {e}"))?;
            }
        }
        None => {
            // Dev/loopback: trust our own cert as the peer's root (two relays
            // sharing one self-signed cert).
            roots
                .add(own_ca.clone())
                .map_err(|e| color_eyre::eyre::eyre!("adding own cert as mesh root: {e}"))?;
        }
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pem_cert_and_key() -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();
        (cert_pem, key_pem)
    }

    #[test]
    fn read_pem_input_returns_inline_bytes_for_pem_content() {
        let (cert_pem, _) = pem_cert_and_key();
        let bytes = read_pem_input(&cert_pem, "cert").unwrap();
        assert!(bytes.windows(10).any(|w| w == b"-----BEGIN"));
    }

    #[test]
    fn read_pem_input_reads_a_file_for_a_path() {
        let (cert_pem, _) = pem_cert_and_key();
        let dir = std::env::temp_dir();
        let path = dir.join("relay_config_test_cert.pem");
        std::fs::write(&path, cert_pem.as_bytes()).unwrap();
        let bytes = read_pem_input(path.to_str().unwrap(), "cert").unwrap();
        assert!(bytes.windows(10).any(|w| w == b"-----BEGIN"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_cert_parses_inline_pem_content() {
        let (cert_pem, key_pem) = pem_cert_and_key();
        let (certs, key) = load_cert(&cert_pem, &key_pem).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!key.secret_der().is_empty());
    }

    #[test]
    fn load_cert_parses_a_file_path() {
        let (cert_pem, key_pem) = pem_cert_and_key();
        let dir = std::env::temp_dir();
        let cert_path = dir.join("relay_config_test_cert2.pem");
        let key_path = dir.join("relay_config_test_key2.pem");
        std::fs::write(&cert_path, cert_pem.as_bytes()).unwrap();
        std::fs::write(&key_path, key_pem.as_bytes()).unwrap();
        let (certs, key) =
            load_cert(cert_path.to_str().unwrap(), key_path.to_str().unwrap()).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!key.secret_der().is_empty());
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }

    // --- parse_mesh_peers ---

    #[test]
    fn parse_mesh_peers_parses_ipv4_addr_and_id() {
        let peers = parse_mesh_peers(&["127.0.0.1:9000#1".to_owned()]).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(peers[0].id, RelayId(1));
    }

    #[test]
    fn parse_mesh_peers_parses_ipv6_bracketed_addr() {
        let peers = parse_mesh_peers(&["[::1]:9000#2".to_owned()]).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, "[::1]:9000".parse().unwrap());
        assert_eq!(peers[0].id, RelayId(2));
    }

    #[test]
    fn parse_mesh_peers_parses_multiple_entries() {
        let peers =
            parse_mesh_peers(&["127.0.0.1:9000#1".to_owned(), "127.0.0.1:9001#2".to_owned()])
                .unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].id, RelayId(1));
        assert_eq!(peers[1].id, RelayId(2));
    }

    #[test]
    fn parse_mesh_peers_rejects_missing_hash() {
        let err = parse_mesh_peers(&["127.0.0.1:9000".to_owned()]).unwrap_err();
        assert!(err.to_string().contains("missing `#ID` suffix"));
    }

    #[test]
    fn parse_mesh_peers_rejects_bad_address() {
        let err = parse_mesh_peers(&["not-an-addr#1".to_owned()]).unwrap_err();
        assert!(err.to_string().contains("address parse failed"));
    }

    #[test]
    fn parse_mesh_peers_rejects_non_numeric_id() {
        let err = parse_mesh_peers(&["127.0.0.1:9000#abc".to_owned()]).unwrap_err();
        assert!(err.to_string().contains("id parse failed"));
    }

    #[test]
    fn parse_mesh_peers_empty_input_yields_empty() {
        let peers = parse_mesh_peers(&[]).unwrap();
        assert!(peers.is_empty());
    }

    // --- load_mesh_roots ---

    #[test]
    fn load_mesh_roots_falls_back_to_own_ca_when_absent() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let own_ca = CertificateDer::from(cert.cert.der().to_vec());
        let roots = load_mesh_roots(&None, &own_ca).unwrap();
        // The store should have exactly our own cert as a trusted root.
        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn load_mesh_roots_parses_inline_pem() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_pem = cert.cert.pem();
        let own_ca = CertificateDer::from(cert.cert.der().to_vec());
        let roots = load_mesh_roots(&Some(cert_pem), &own_ca).unwrap();
        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn load_mesh_roots_reads_a_pem_file() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_pem = cert.cert.pem();
        let own_ca = CertificateDer::from(cert.cert.der().to_vec());
        let dir = std::env::temp_dir();
        let path = dir.join("relay_config_mesh_roots.pem");
        std::fs::write(&path, cert_pem.as_bytes()).unwrap();
        let roots = load_mesh_roots(&Some(path.to_str().unwrap().to_owned()), &own_ca).unwrap();
        assert_eq!(roots.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_mesh_roots_rejects_missing_file() {
        let own_ca = CertificateDer::from(vec![0x30; 10]); // junk; never read
        let err = load_mesh_roots(&Some("/nonexistent/path.pem".to_owned()), &own_ca).unwrap_err();
        assert!(err.to_string().contains("reading mesh-roots file"));
    }
}
