//! TLS: the server configuration, the reloading certificate resolver and
//! the client-certificate handling.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use arc_swap::ArcSwap;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};

/// The cipher suites and groups the server offers: AES-GCM with ECDHE
/// only, which is what small clients (MbedTLS builds without ChaCha20 or
/// CBC) and browsers have in common.
pub fn provider() -> Arc<CryptoProvider> {
    let base = ring::default_provider();
    Arc::new(CryptoProvider {
        cipher_suites: vec![
            ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
            ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ],
        kx_groups: vec![
            ring::kx_group::X25519,
            ring::kx_group::SECP256R1,
            ring::kx_group::SECP384R1,
        ],
        ..base
    })
}

/// Build the server configuration: TLS 1.2 and 1.3, the certificate
/// from `resolver`, a client certificate asked for but not required.
pub fn server_config(resolver: Arc<ReloadingCert>) -> anyhow::Result<ServerConfig> {
    let provider = provider();
    let verifier = Arc::new(AnyClientCert {
        algs: provider.signature_verification_algorithms,
    });
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("TLS versions")?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Asks every client for a certificate and accepts whatever it presents,
/// as long as it proves possession of the key (rustls checks the
/// handshake signature through [`ClientCertVerifier::verify_tls12_signature`]
/// / [`ClientCertVerifier::verify_tls13_signature`]).
///
/// Whether the chain is trusted is decided per request, against the
/// trust anchors of the label the request is for (see `peer`): a client
/// whose certificate the server doesn't know is treated like a client
/// without one, so it can still be put up for approval, instead of
/// failing in the handshake.
#[derive(Debug)]
struct AnyClientCert {
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for AnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No hints: clients pick their certificate themselves (an empty
        // list means "any CA").
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// The server certificate, read from PEM files and re-read when their
/// content changes (a renewed cert-manager secret, `tls.auto`).
#[derive(Debug)]
pub struct ReloadingCert {
    cert_path: PathBuf,
    key_path: PathBuf,
    current: ArcSwap<Loaded>,
}

#[derive(Debug)]
struct Loaded {
    files: (Vec<u8>, Vec<u8>),
    key: Arc<CertifiedKey>,
}

impl ReloadingCert {
    pub fn load(cert_path: &Path, key_path: &Path) -> anyhow::Result<Arc<Self>> {
        let loaded = load_pair(cert_path, key_path)?;
        Ok(Arc::new(Self {
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            current: ArcSwap::from_pointee(loaded),
        }))
    }

    /// Re-read the files if they changed. A broken pair keeps the
    /// current certificate.
    pub fn reload(&self) -> anyhow::Result<bool> {
        let files = (
            std::fs::read(&self.cert_path)?,
            std::fs::read(&self.key_path)?,
        );
        if files == self.current.load().files {
            return Ok(false);
        }
        self.current
            .store(Arc::new(load_pair(&self.cert_path, &self.key_path)?));
        Ok(true)
    }

    /// Poll the files every `interval`, forever.
    pub async fn watch(self: Arc<Self>, interval: Duration) {
        let mut tick = tokio::time::interval(interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            match self.reload() {
                Ok(true) => {
                    tracing::info!(cert = %self.cert_path.display(), "server certificate reloaded")
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(cert = %self.cert_path.display(), "server certificate not reloaded: {e:#}")
                }
            }
        }
    }

    /// The leaf currently served (DER).
    pub fn leaf(&self) -> CertificateDer<'static> {
        self.current.load().key.cert[0].clone()
    }
}

impl ResolvesServerCert for ReloadingCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load().key.clone())
    }
}

fn load_pair(cert_path: &Path, key_path: &Path) -> anyhow::Result<Loaded> {
    let cert_pem =
        std::fs::read(cert_path).with_context(|| format!("read {}", cert_path.display()))?;
    let key_pem =
        std::fs::read(key_path).with_context(|| format!("read {}", key_path.display()))?;
    let chain = parse_certs(&cert_pem).with_context(|| format!("parse {}", cert_path.display()))?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| anyhow!("parse {}: {e}", key_path.display()))?;
    let signing_key = ring::sign::any_supported_type(&key).context("server key type")?;
    let certified = CertifiedKey::new(chain, signing_key);
    certified
        .keys_match()
        .context("server certificate and key don't match")?;
    Ok(Loaded {
        files: (cert_pem, key_pem),
        key: Arc::new(certified),
    })
}

/// All certificates in a PEM buffer; at least one.
pub fn parse_certs(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("{e}"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificate in PEM data"));
    }
    Ok(certs)
}

/// All certificates in a PEM file; at least one.
pub fn read_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    parse_certs(&pem).with_context(|| format!("parse {}", path.display()))
}
