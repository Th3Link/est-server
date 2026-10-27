//! End-to-end: a client that behaves like the homeautomation gateway
//! (P-256 key kept forever, CSR with CN and SAN only, base64 in 64
//! character lines, mTLS with the issued certificate for renewal),
//! against a server on a dual-stack socket, over IPv4 and IPv6.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use est_proto::{cms, wire};
use est_server::ca::LocalCa;
use est_server::config::Config;
use est_server::pending::PendingStore;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PublicKeyData};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::{FromDer, X509Certificate};

const SERVER: &str = "est.test";

struct Setup {
    _dir: tempfile::TempDir,
    state: std::path::PathBuf,
    ca_der: CertificateDer<'static>,
    identity: LocalCa,
    stranger: LocalCa,
    v4: SocketAddr,
    v6: SocketAddr,
    health: SocketAddr,
    _server: est_server::app::Running,
}

fn write(path: &Path, data: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
}

fn new_ca(name: &str) -> (LocalCa, String) {
    let (cert, key) = LocalCa::generate_root(name, &rcgen::PKCS_ECDSA_P256_SHA256, 1).unwrap();
    (LocalCa::from_pem(name, &cert, &key, vec![]).unwrap(), cert)
}

async fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (cert, key) =
        LocalCa::generate_root("Test EST CA", &rcgen::PKCS_ECDSA_P256_SHA256, 1).unwrap();
    write(&root.join("ca/ca.crt"), &cert);
    write(&root.join("ca/ca.key"), &key);
    let (identity, identity_pem) = new_ca("Device Identity CA");
    write(&root.join("identity.pem"), &identity_pem);
    let (stranger, _) = new_ca("Stranger CA");
    write(
        &root.join("est-server.toml"),
        r#"
        [server]
        listen = ["[::]:0"]
        health_listen = ["[::]:0"]
        state_dir = "state"
        [server.tls]
        cert = "tls/tls.crt"
        key = "tls/tls.key"
        auto = { ca = "local", dns_names = ["est.test"], ip_addresses = ["127.0.0.1", "::1"] }

        [[ca]]
        name = "local"
        cert = "ca/ca.crt"
        key = "ca/ca.key"

        [[label]]
        signer = { type = "local", ca = "local", validity = "30d" }
        allow = ["*.auto.test"]
        identity_cas = ["identity.pem"]
        manual_approval = true
        retry_after = "2m"

        [[label]]
        name = "strict"
        signer = { type = "local", ca = "local" }
        "#,
    );
    let config = Config::load(&root.join("est-server.toml")).unwrap();
    let server = est_server::app::start(&config).await.unwrap();
    let port = server.est_addrs[0].port();
    Setup {
        state: root.join("state"),
        ca_der: est_server::tls::parse_certs(cert.as_bytes())
            .unwrap()
            .remove(0),
        identity,
        stranger,
        v4: format!("127.0.0.1:{port}").parse().unwrap(),
        v6: format!("[::1]:{port}").parse().unwrap(),
        health: format!("[::1]:{}", server.health_addrs[0].port())
            .parse()
            .unwrap(),
        _dir: dir,
        _server: server,
    }
}

fn tls_config(
    s: &Setup,
    client: Option<(&[CertificateDer<'static>], &KeyPair)>,
    suites: Option<Vec<rustls::SupportedCipherSuite>>,
) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(s.ca_der.clone()).unwrap();
    let mut provider = rustls::crypto::ring::default_provider();
    if let Some(suites) = suites {
        provider.cipher_suites = suites;
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    match client {
        Some((chain, key)) => builder
            .with_client_auth_cert(
                chain.to_vec(),
                PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    }
}

/// An HTTPS client for `https://est.test:<port>` pinned to `addr`
/// (`resolve` ignores the port, so it goes into the URL).
struct Client {
    http: reqwest::Client,
    base: String,
}

impl Client {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
    async fn get(&self, path: &str) -> reqwest::Result<reqwest::Response> {
        self.http.get(self.url(path)).send().await
    }
}

fn http(config: rustls::ClientConfig, addr: SocketAddr) -> Client {
    Client {
        http: reqwest::Client::builder()
            .tls_backend_preconfigured(config)
            .resolve(SERVER, addr)
            .build()
            .unwrap(),
        base: format!("https://{SERVER}:{}", addr.port()),
    }
}

/// A CSR like the gateway's: CN and SAN DNS name, nothing else.
fn gateway_csr(key: &KeyPair, fqdn: &str) -> String {
    let mut params = CertificateParams::new(vec![fqdn.to_string()]).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, fqdn);
    let der = params.serialize_request(key).unwrap().der().to_vec();
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    b64.as_bytes()
        .chunks(64)
        .map(|c| format!("{}\n", std::str::from_utf8(c).unwrap()))
        .collect()
}

async fn post(client: &Client, path: &str, body: String) -> reqwest::Response {
    client
        .http
        .post(client.url(path))
        .header("Content-Type", "application/pkcs10")
        .header("Content-Transfer-Encoding", "base64")
        .body(body)
        .send()
        .await
        .unwrap()
}

/// The answer's certificates; asserts the EST framing.
async fn certs(resp: reqwest::Response) -> Vec<CertificateDer<'static>> {
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["content-type"],
        "application/pkcs7-mime; smime-type=certs-only"
    );
    assert_eq!(resp.headers()["content-transfer-encoding"], "base64");
    let body = resp.bytes().await.unwrap();
    assert!(
        body.len() < 12 * 1024,
        "answer too large for the gateway: {}",
        body.len()
    );
    let der = wire::decode_body(&body).unwrap();
    cms::decode_certs_only(&der)
        .unwrap()
        .into_iter()
        .map(CertificateDer::from)
        .collect()
}

fn check_leaf(leaf: &[u8], key: &KeyPair, fqdn: &str) -> String {
    let (_, cert) = X509Certificate::from_der(leaf).unwrap();
    assert_eq!(
        cert.public_key().raw,
        key.subject_public_key_info().as_slice()
    );
    let san = cert.subject_alternative_name().unwrap().unwrap();
    assert_eq!(
        format!("{:?}", san.value.general_names),
        format!("[DNSName(\"{fqdn}\")]")
    );
    let eku = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.server_auth);
    assert!(cert.key_usage().unwrap().unwrap().value.digital_signature());
    assert!(cert.validity().is_valid());
    cert.raw_serial_as_string()
}

#[tokio::test]
async fn enroll_with_approval_then_renew_over_both_families() {
    let s = setup().await;
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let fqdn = "gw1.home.test";
    let anon_v4 = http(tls_config(&s, None, None), s.v4);

    // First enrollment without identity: waits for approval.
    let resp = post(
        &anon_v4,
        "/.well-known/est/simpleenroll",
        gateway_csr(&key, fqdn),
    )
    .await;
    assert_eq!(resp.status(), 202);
    assert_eq!(resp.headers()["retry-after"], "120");

    let store = PendingStore::open(&s.state).unwrap();
    let entries = store.list().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].names, vec![fqdn]);
    assert!(
        entries[0].client.starts_with("127.0.0.1:"),
        "mapped address normalised: {}",
        entries[0].client
    );
    store.decide(&entries[0].id[..8], true).unwrap();

    // The poll after approval carries a freshly signed CSR for the same key.
    let chain = certs(
        post(
            &anon_v4,
            "/.well-known/est/simpleenroll",
            gateway_csr(&key, fqdn),
        )
        .await,
    )
    .await;
    assert_eq!(
        chain.len(),
        1,
        "the self-signed root stays out of the answer"
    );
    let first_serial = check_leaf(&chain[0], &key, fqdn);

    // Renewal over IPv6, authenticated with the issued certificate, same key.
    let mtls_v6 = http(tls_config(&s, Some((&chain, &key)), None), s.v6);
    let renewed = certs(
        post(
            &mtls_v6,
            "/.well-known/est/simplereenroll",
            gateway_csr(&key, fqdn),
        )
        .await,
    )
    .await;
    let second_serial = check_leaf(&renewed[0], &key, fqdn);
    assert_ne!(first_serial, second_serial);

    // Renewal for another name, or without a certificate, is refused.
    let resp = post(
        &mtls_v6,
        "/.well-known/est/simplereenroll",
        gateway_csr(&key, "gw2.home.test"),
    )
    .await;
    assert_eq!(resp.status(), 403);
    let resp = post(
        &anon_v4,
        "/.well-known/est/simplereenroll",
        gateway_csr(&key, fqdn),
    )
    .await;
    assert_eq!(resp.status(), 401);

    let log = std::fs::read_to_string(s.state.join("issued.jsonl")).unwrap();
    assert_eq!(log.lines().count(), 2);
    assert!(log.contains("\"reason\":\"renewal\""));
}

#[tokio::test]
async fn allowlist_identity_and_strict_label() {
    let s = setup().await;
    let key = KeyPair::generate().unwrap();
    let anon = http(tls_config(&s, None, None), s.v6);

    let chain = certs(
        post(
            &anon,
            "/.well-known/est/simpleenroll",
            gateway_csr(&key, "x.auto.test"),
        )
        .await,
    )
    .await;
    check_leaf(&chain[0], &key, "x.auto.test");

    // Device identity for the requested name: approved at once.
    let id_key = KeyPair::generate().unwrap();
    let names = vec!["gw9.home.test".to_string()];
    let spec = est_server::ca::LeafSpec {
        common_name: None,
        dns_names: &names,
        ip_addresses: &[],
        validity: std::time::Duration::from_secs(3600),
        rsa: false,
    };
    let id_cert = s.identity.issue(&id_key, &spec).unwrap();
    let with_id = http(tls_config(&s, Some((&[id_cert], &id_key)), None), s.v4);
    let chain = certs(
        post(
            &with_id,
            "/.well-known/est/simpleenroll",
            gateway_csr(&key, "gw9.home.test"),
        )
        .await,
    )
    .await;
    check_leaf(&chain[0], &key, "gw9.home.test");

    // A certificate from an unknown CA doesn't break the handshake; the
    // request is treated as anonymous and waits.
    let st_key = KeyPair::generate().unwrap();
    let st_cert = s.stranger.issue(&st_key, &spec).unwrap();
    let stranger = http(tls_config(&s, Some((&[st_cert], &st_key)), None), s.v4);
    let resp = post(
        &stranger,
        "/.well-known/est/simpleenroll",
        gateway_csr(&key, "gw9.home.test"),
    )
    .await;
    assert_eq!(resp.status(), 202);

    // A label without allowlist and approval refuses.
    let resp = post(
        &anon,
        "/.well-known/est/strict/simpleenroll",
        gateway_csr(&key, "x.auto.test"),
    )
    .await;
    assert_eq!(resp.status(), 403);

    // Wrong content type, garbage, unknown operation.
    let resp = anon
        .http
        .post(anon.url("/.well-known/est/simpleenroll"))
        .header("Content-Type", "text/plain")
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 415);
    assert_eq!(
        post(&anon, "/.well-known/est/simpleenroll", "!!".into())
            .await
            .status(),
        400
    );
    assert_eq!(
        anon.get("/.well-known/est/csrattrs")
            .await
            .unwrap()
            .status(),
        404
    );

    // cacerts carries the CA.
    let resp = anon.get("/.well-known/est/cacerts").await.unwrap();
    assert_eq!(certs(resp).await, vec![s.ca_der.clone()]);
}

#[tokio::test]
async fn tls_parameters_and_health() {
    use rustls::crypto::ring::cipher_suite as cs;
    let s = setup().await;

    for suite in [
        cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cs::TLS13_AES_128_GCM_SHA256,
        cs::TLS13_AES_256_GCM_SHA384,
    ] {
        let client = http(tls_config(&s, None, Some(vec![suite])), s.v4);
        let resp = client.get("/.well-known/est/cacerts").await;
        assert!(resp.is_ok(), "{suite:?} must work");
    }
    for suite in [
        cs::TLS13_CHACHA20_POLY1305_SHA256,
        cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ] {
        let client = http(tls_config(&s, None, Some(vec![suite])), s.v4);
        let resp = client.get("/.well-known/est/cacerts").await;
        assert!(resp.is_err(), "{suite:?} must not be offered");
    }

    let resp = reqwest::Client::new()
        .get(format!("http://{}/readyz", s.health))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
