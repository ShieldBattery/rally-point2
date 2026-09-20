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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::RelayId;
use rally_point_proto::token::KeyId;
use rally_point_transport::noq;
use rally_point_transport::quic;
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
pub struct TenantKeyMaterial {
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
) -> color_eyre::Result<TenantKeyMaterial> {
    let bytes = hex::decode(pubkey_hex)
        .map_err(|e| color_eyre::eyre::eyre!("decoding tenant pubkey hex: {e}"))?;
    let verifying_key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        color_eyre::eyre::eyre!("tenant pubkey must be 32 bytes, got {}", bytes.len())
    })?;
    Ok(TenantKeyMaterial {
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
pub fn generate_dev_tenant_key(
    kid: String,
    tenant: String,
) -> color_eyre::Result<TenantKeyMaterial> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| color_eyre::eyre::eyre!("generating tenant key: {e}"))?;
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|e| color_eyre::eyre::eyre!("loading generated tenant key: {e}"))?;
    let verifying_key: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();

    Ok(TenantKeyMaterial {
        kid: KeyId(kid),
        tenant: TenantId::new(tenant)
            .map_err(|e| color_eyre::eyre::eyre!("tenant id too long (max 255 bytes): {e}"))?,
        verifying_key,
        generated_pkcs8: Some(pkcs8.as_ref().to_vec()),
    })
}

/// Builds a `Registry` from a tenant verifying key.
pub fn registry_from_tenant_key(key: &TenantKeyMaterial) -> Registry {
    let mut registry = Registry::new();
    registry.insert(key.kid.clone(), key.tenant.clone(), key.verifying_key);
    registry
}

/// Builds a `noq::ServerConfig` from a self-signed cert (dev/loopback).
pub fn server_config_from_self_signed(
    cert: &SelfSignedCert,
) -> color_eyre::Result<noq::ServerConfig> {
    // PrivateKeyDer doesn't impl Clone, so re-serialize from the raw DER.
    let key = rally_point_transport::rustls::pki_types::PrivateKeyDer::try_from(
        cert.key.secret_der().to_vec(),
    )
    .unwrap();
    quic::server_config(cert.chain.clone(), key)
        .map_err(|e| color_eyre::eyre::eyre!("building QUIC server config: {e}"))
}

/// Resolves the addresses a relay advertises to the coordinator — where clients
/// and peer relays reach it, carried in the relay's enroll `Hello` — from the
/// repeatable `--advertise-addr` flags and the `--listen` address. Returns
/// `(primary, complete_set)` matching the hello's `relay_addr`/`relay_addrs`
/// contract: the first flag is the primary and its order is the advertised
/// preference; the set is empty (kept off the wire) for a single-address
/// advertise, and includes the primary whenever it is non-empty.
///
/// Explicit flags always win. With none, the listen address is used when it
/// names a concrete IP; when listen is the unspecified address (`[::]` /
/// `0.0.0.0` — the default, and not a routable destination) it falls back to
/// loopback on the listen port, a working dev/loopback default — always a
/// single-address advertise. Production sets the flags explicitly for each
/// family it serves; deriving them from the cloud substrate (ECS metadata) is
/// a follow-up. Deliberately *not* observed from the control connection's
/// source IP: the relay reaches the coordinator over one family but must
/// advertise both.
pub fn resolve_advertise_addrs(
    advertise: &[SocketAddr],
    listen: SocketAddr,
) -> (SocketAddr, Vec<SocketAddr>) {
    match advertise {
        [] if listen.ip().is_unspecified() => (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen.port()),
            Vec::new(),
        ),
        [] => (listen, Vec::new()),
        [single] => (*single, Vec::new()),
        [primary, ..] => (*primary, advertise.to_vec()),
    }
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
/// from this dev fallback.
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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    fn pem_cert_and_key() -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();
        (cert_pem, key_pem)
    }

    /// A file under the system temp dir, unique to this process and this call,
    /// removed when the guard drops — so two concurrent `cargo test` invocations
    /// never collide on a fixed name and a panicking test leaves nothing behind.
    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn write(label: &str, contents: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let unique = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rp2-relay-config-{label}-{}-{unique}.pem",
                std::process::id(),
            ));
            std::fs::write(&path, contents.as_bytes()).unwrap();
            Self { path }
        }

        fn as_str(&self) -> &str {
            self.path.to_str().expect("a UTF-8 temp path")
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn load_cert_parses_pem_passed_inline_or_as_a_path() {
        // Both branches of the `-----BEGIN` sentinel: Fargate injects the
        // secret's content into the env var, local dev and Docker mounts pass a
        // path. Either way the same chain and key come back.
        let (cert_pem, key_pem) = pem_cert_and_key();
        let cert_file = TempFile::write("cert", &cert_pem);
        let key_file = TempFile::write("key", &key_pem);

        for (label, cert_input, key_input) in [
            ("inline PEM", cert_pem.as_str(), key_pem.as_str()),
            ("a file path", cert_file.as_str(), key_file.as_str()),
        ] {
            let (certs, key) = load_cert(cert_input, key_input).unwrap();
            assert_eq!(certs.len(), 1, "{label}");
            assert!(!key.secret_der().is_empty(), "{label}");
        }
    }

    // --- resolve_advertise_addrs ---

    /// One advertise-resolution case: a label, the `--advertise-addr` flags, the
    /// `--listen` address, and the `(primary, complete set)` expected back.
    type AdvertiseCase<'a> = (
        &'a str,
        &'a [SocketAddr],
        SocketAddr,
        (SocketAddr, Vec<SocketAddr>),
    );

    #[test]
    fn resolve_advertise_addrs_prefers_explicit_flags_over_the_listen_address() {
        let v4: SocketAddr = "203.0.113.7:14900".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::7]:14900".parse().unwrap();
        let concrete: SocketAddr = "192.0.2.10:14900".parse().unwrap();
        let unspecified: SocketAddr = "[::]:14900".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:14900".parse().unwrap();

        let cases: [AdvertiseCase<'_>; 4] = [
            // One flag: it is the primary and the set stays empty, so a
            // single-address advertise keeps the wire form byte-stable.
            ("a single override", &[v4], unspecified, (v4, vec![])),
            // Two flags (a v4 + a v6): the first is the primary, and the
            // complete set — including the primary, in flag order, which is the
            // relay's preference — rides alongside.
            ("dual stack", &[v4, v6], unspecified, (v4, vec![v4, v6])),
            // No flags: a concrete listen address is a routable destination.
            ("no override", &[], concrete, (concrete, vec![])),
            // The default `[::]` listen is not a routable address to hand a
            // client, so the relay advertises loopback on the same port (dev).
            (
                "an unspecified listen",
                &[],
                unspecified,
                (loopback, vec![]),
            ),
        ];

        for (label, advertise, listen, expected) in cases {
            assert_eq!(
                resolve_advertise_addrs(advertise, listen),
                expected,
                "{label}"
            );
        }
    }

    // --- parse_mesh_peers ---

    /// One mesh-peer parse case: a label, the `--mesh-peer` specs, and the
    /// `(addr, id)` pairs expected back.
    type MeshPeerCase<'a> = (&'a str, &'a [&'a str], &'a [(&'a str, u64)]);

    #[test]
    fn parse_mesh_peers_parses_each_addr_and_id_form() {
        let cases: [MeshPeerCase<'_>; 4] = [
            ("IPv4", &["127.0.0.1:9000#1"], &[("127.0.0.1:9000", 1)]),
            ("bracketed IPv6", &["[::1]:9000#2"], &[("[::1]:9000", 2)]),
            (
                "multiple entries",
                &["127.0.0.1:9000#1", "127.0.0.1:9001#2"],
                &[("127.0.0.1:9000", 1), ("127.0.0.1:9001", 2)],
            ),
            ("no entries", &[], &[]),
        ];

        for (label, specs, expected) in cases {
            let specs: Vec<String> = specs.iter().map(|s| (*s).to_owned()).collect();
            let peers = parse_mesh_peers(&specs).unwrap();
            assert_eq!(peers.len(), expected.len(), "{label}");
            for (peer, (addr, id)) in peers.iter().zip(expected) {
                assert_eq!(peer.addr, addr.parse().unwrap(), "{label}");
                assert_eq!(peer.id, RelayId(*id), "{label}");
            }
        }
    }

    #[test]
    fn parse_mesh_peers_rejects_a_malformed_entry_naming_what_was_wrong() {
        for (spec, expected) in [
            ("127.0.0.1:9000", "missing `#ID` suffix"),
            ("not-an-addr#1", "address parse failed"),
            ("127.0.0.1:9000#abc", "id parse failed"),
        ] {
            let err = parse_mesh_peers(&[spec.to_owned()]).unwrap_err();
            assert!(
                err.to_string().contains(expected),
                "`{spec}` reports `{expected}`, got: {err}",
            );
        }
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
    fn load_mesh_roots_trusts_the_supplied_pem_inline_or_from_a_file() {
        // The supplied root is deliberately a *different* certificate from the
        // relay's own: a `load_mesh_roots` that ignored its input and fell back
        // to `own_ca` would still produce a one-entry store, so only comparing
        // the trust anchors catches it.
        let supplied = rcgen::generate_simple_self_signed(vec!["mesh-root".to_owned()]).unwrap();
        let supplied_pem = supplied.cert.pem();
        let supplied_ca = CertificateDer::from(supplied.cert.der().to_vec());
        let own = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let own_ca = CertificateDer::from(own.cert.der().to_vec());

        let expected = load_mesh_roots(&None, &supplied_ca).unwrap();
        let fallback = load_mesh_roots(&None, &own_ca).unwrap();
        let pem_file = TempFile::write("mesh-roots", &supplied_pem);

        for (label, input) in [
            ("inline PEM", supplied_pem.clone()),
            ("a file path", pem_file.as_str().to_owned()),
        ] {
            let roots = load_mesh_roots(&Some(input), &own_ca).unwrap();
            assert_eq!(roots.len(), 1, "{label}");
            assert_eq!(
                roots.roots, expected.roots,
                "{label}: the supplied root is trusted"
            );
            assert_ne!(
                roots.roots, fallback.roots,
                "{label}: the own-CA fallback contributed nothing",
            );
        }
    }

    #[test]
    fn load_mesh_roots_rejects_missing_file() {
        let own_ca = CertificateDer::from(vec![0x30; 10]); // junk; never read
        let err = load_mesh_roots(&Some("/nonexistent/path.pem".to_owned()), &own_ca).unwrap_err();
        assert!(err.to_string().contains("reading mesh-roots file"));
    }
}
