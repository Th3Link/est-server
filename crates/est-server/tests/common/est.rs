//! The client side: a device that behaves like the homeautomation gateway
//! (P-256 key kept forever, CSR with CN and SAN only, base64 in 64
//! character lines, the issued certificate for renewal), and an EST
//! client over reqwest.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use est_proto::{cms, wire};
use est_server::ca::{LeafSpec, LocalCa};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PublicKeyData};
use reqwest::StatusCode;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::setup::{SERVER_NAME, Setup};

/// Which address family the client connects over.
#[derive(Clone, Copy, Debug)]
pub enum Ip {
    V4,
    V6,
}

/// The TLS client certificate the client presents.
pub enum Auth<'a> {
    None,
    /// The device's current certificate, as for `simplereenroll`.
    Current(&'a Device),
    /// Some other certificate, e.g. a device identity.
    Custom(&'a Credential),
}

pub struct Credential {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: KeyPair,
}

impl Credential {
    /// A certificate for `names` from `ca`, like a device identity.
    pub fn issued_by(ca: &LocalCa, names: &[&str]) -> Self {
        let key = KeyPair::generate().unwrap();
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let cert = ca
            .issue(
                &key,
                &LeafSpec {
                    common_name: None,
                    dns_names: &names,
                    ip_addresses: &[],
                    validity: Duration::from_secs(3600),
                    rsa: false,
                },
            )
            .unwrap();
        Self {
            chain: vec![cert],
            key,
        }
    }
}

/// A gateway: a name, a key that never changes, and the certificate it
/// has installed.
pub struct Device {
    pub fqdn: String,
    pub key: KeyPair,
    pub chain: Vec<CertificateDer<'static>>,
}

impl Device {
    pub fn new(fqdn: &str) -> Self {
        Self {
            fqdn: fqdn.to_string(),
            key: KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
            chain: Vec::new(),
        }
    }

    /// The device's CSR for its own name.
    pub fn csr(&self) -> String {
        self.csr_for(&self.fqdn)
    }

    /// A CSR like the gateway's (CN and SAN DNS name, nothing else) for
    /// any name, with the device's key.
    pub fn csr_for(&self, fqdn: &str) -> String {
        let mut params = CertificateParams::new(vec![fqdn.to_string()]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, fqdn);
        let der = params.serialize_request(&self.key).unwrap().der().to_vec();
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        b64.as_bytes()
            .chunks(64)
            .map(|c| format!("{}\n", std::str::from_utf8(c).unwrap()))
            .collect()
    }

    /// Check an issued chain the way the gateway does before installing
    /// it, and install it. Returns the leaf's serial number.
    pub fn install(&mut self, chain: Vec<CertificateDer<'static>>) -> String {
        assert!(chain.len() <= 5, "chain too long for the gateway");
        let size: usize = chain.iter().map(|c| c.len()).sum();
        assert!(size <= 6 * 1024, "chain too large for the gateway: {size}");
        let (_, cert) = X509Certificate::from_der(&chain[0]).unwrap();
        assert_eq!(
            cert.public_key().raw,
            self.key.subject_public_key_info().as_slice(),
            "the leaf carries the device key"
        );
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert_eq!(
            format!("{:?}", san.value.general_names),
            format!("[DNSName(\"{}\")]", self.fqdn)
        );
        assert!(
            cert.extended_key_usage()
                .unwrap()
                .unwrap()
                .value
                .server_auth
        );
        assert!(cert.key_usage().unwrap().unwrap().value.digital_signature());
        assert!(cert.validity().is_valid());
        let serial = cert.raw_serial_as_string();
        self.chain = chain;
        serial
    }
}

/// What the server answered to an enrollment.
#[derive(Debug, PartialEq)]
pub enum Answer {
    Issued(Vec<CertificateDer<'static>>),
    /// `202` with its `Retry-After` in seconds.
    Pending(u64),
    Refused(StatusCode),
}

impl Answer {
    pub fn issued(self) -> Vec<CertificateDer<'static>> {
        match self {
            Answer::Issued(chain) => chain,
            other => panic!("expected a certificate, got {other:?}"),
        }
    }
}

/// An EST client for one server, over one address family, under one
/// label.
#[derive(Clone)]
pub struct Est {
    ca: CertificateDer<'static>,
    port: u16,
    ip: Ip,
    base_path: String,
    suites: Option<Vec<rustls::SupportedCipherSuite>>,
}

impl Est {
    pub fn new(setup: &Setup) -> Self {
        Self {
            ca: setup.ca_der.clone(),
            port: setup.est_port,
            ip: Ip::V4,
            base_path: est_proto::WELL_KNOWN_PREFIX.to_string(),
            suites: None,
        }
    }

    pub fn over(&self, ip: Ip) -> Self {
        Self { ip, ..self.clone() }
    }

    /// The label at `/.well-known/est/<label>`.
    pub fn label(&self, label: &str) -> Self {
        Self {
            base_path: format!("{}/{label}", est_proto::WELL_KNOWN_PREFIX),
            ..self.clone()
        }
    }

    /// Offer only these cipher suites.
    pub fn suites(&self, suites: Vec<rustls::SupportedCipherSuite>) -> Self {
        Self {
            suites: Some(suites),
            ..self.clone()
        }
    }

    fn addr(&self) -> SocketAddr {
        match self.ip {
            Ip::V4 => SocketAddr::from(([127, 0, 0, 1], self.port)),
            Ip::V6 => SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, self.port)),
        }
    }

    fn client(&self, auth: Auth<'_>) -> reqwest::Client {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.ca.clone()).unwrap();
        let mut provider = rustls::crypto::ring::default_provider();
        if let Some(suites) = &self.suites {
            provider.cipher_suites = suites.clone();
        }
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        let (chain, key) = match auth {
            Auth::None => (None, None),
            // A device without a certificate yet presents none.
            Auth::Current(device) if device.chain.is_empty() => (None, None),
            Auth::Current(device) => (Some(device.chain.clone()), Some(&device.key)),
            Auth::Custom(cred) => (Some(cred.chain.clone()), Some(&cred.key)),
        };
        let config = match (chain, key) {
            (Some(chain), Some(key)) => builder
                .with_client_auth_cert(chain, PrivateKeyDer::Pkcs8(key.serialize_der().into()))
                .unwrap(),
            _ => builder.with_no_client_auth(),
        };
        reqwest::Client::builder()
            .tls_backend_preconfigured(config)
            // `resolve` ignores the port; it goes into the URL.
            .resolve(SERVER_NAME, self.addr())
            .build()
            .unwrap()
    }

    pub fn url(&self, op: &str) -> String {
        format!("https://{SERVER_NAME}:{}{}/{op}", self.port, self.base_path)
    }

    pub async fn get(&self, op: &str, auth: Auth<'_>) -> reqwest::Result<reqwest::Response> {
        self.client(auth).get(self.url(op)).send().await
    }

    pub async fn post(
        &self,
        op: &str,
        content_type: &str,
        body: String,
        auth: Auth<'_>,
    ) -> reqwest::Result<reqwest::Response> {
        self.client(auth)
            .post(self.url(op))
            .header("Content-Type", content_type)
            .header("Content-Transfer-Encoding", "base64")
            .body(body)
            .send()
            .await
    }

    /// `simpleenroll` with the device's CSR.
    pub async fn enroll(&self, device: &Device, auth: Auth<'_>) -> Result<Answer> {
        answer(
            self.post("simpleenroll", "application/pkcs10", device.csr(), auth)
                .await?,
        )
        .await
    }

    /// `simplereenroll` with the device's CSR and current certificate.
    pub async fn reenroll(&self, device: &Device) -> Result<Answer> {
        answer(
            self.post(
                "simplereenroll",
                "application/pkcs10",
                device.csr(),
                Auth::Current(device),
            )
            .await?,
        )
        .await
    }

    /// `simpleenroll` again and again (as the gateway does after a `202`,
    /// only faster) until the server answers something else.
    pub async fn enroll_until_decided(&self, device: &Device, timeout: Duration) -> Result<Answer> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.enroll(device, Auth::None).await? {
                Answer::Pending(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(500)).await
                }
                Answer::Pending(_) => bail!("still pending after {timeout:?}"),
                other => return Ok(other),
            }
        }
    }

    pub async fn cacerts(&self) -> Result<Vec<CertificateDer<'static>>> {
        Ok(answer(self.get("cacerts", Auth::None).await?)
            .await?
            .issued())
    }
}

/// Read an EST answer; asserts the framing the gateway relies on.
async fn answer(resp: reqwest::Response) -> Result<Answer> {
    match resp.status() {
        StatusCode::OK => {}
        StatusCode::ACCEPTED => {
            let retry_after = resp.headers()["retry-after"].to_str()?.parse()?;
            return Ok(Answer::Pending(retry_after));
        }
        status => return Ok(Answer::Refused(status)),
    }
    assert_eq!(
        resp.headers()["content-type"],
        "application/pkcs7-mime; smime-type=certs-only"
    );
    assert_eq!(resp.headers()["content-transfer-encoding"], "base64");
    let body = resp.bytes().await?;
    assert!(
        body.len() < 12 * 1024,
        "answer too large for the gateway: {}",
        body.len()
    );
    let der = wire::decode_body(&body)?;
    Ok(Answer::Issued(
        cms::decode_certs_only(&der)?
            .into_iter()
            .map(CertificateDer::from)
            .collect(),
    ))
}
