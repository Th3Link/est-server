//! One server per test: its own config directory, CA, ports and (for
//! cert-manager) namespace, started through `est_server::run::run`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use est_server::ca::LocalCa;
use est_server::config::Config;
use est_server::pending::{PendingStore, Status};
use rustls::pki_types::CertificateDer;
use tokio::sync::oneshot;

use super::cluster::Cluster;
use super::helper::{find_free_port, replace_in_file, write};

/// The name the server certificate is issued for; the client resolves it
/// to 127.0.0.1 or ::1.
pub const SERVER_NAME: &str = "est.test";

/// Who signs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Backend {
    /// `type = "local"`, approval through the pending store.
    LocalCa,
    /// `type = "cert-manager"` against the cluster in
    /// `EST_E2E_KUBECONFIG`, approval through the `CertificateRequest`.
    CertManager,
}

/// A request waiting for approval, as an administrator sees it.
#[derive(Debug)]
pub struct Waiting {
    pub names: Vec<String>,
    /// Client address as the server saw it.
    pub client: String,
}

pub struct Setup {
    pub backend: Backend,
    pub config: Config,
    pub conf_dir: tempfile::TempDir,
    /// The CA that signs the server certificate and the clients'.
    pub ca_der: CertificateDer<'static>,
    /// CA of device identities (`identity_cas`).
    pub identity: LocalCa,
    /// A CA the server knows nothing about.
    pub stranger: LocalCa,
    pub est_port: u16,
    pub health_port: u16,
    pub cluster: Option<Cluster>,
    stop: Option<oneshot::Sender<()>>,
    teardown_rx: Option<oneshot::Receiver<Result<()>>>,
}

fn new_ca(name: &str) -> (String, String) {
    LocalCa::generate_root(name, &rcgen::PKCS_ECDSA_P256_SHA256, 1).unwrap()
}

impl Setup {
    pub async fn new(backend: Backend, test_name: &'static str) -> Self {
        Self::with_config(backend, |_| {}, test_name).await
    }

    /// Like `new`, with a chance to change the configuration before the
    /// server starts.
    pub async fn with_config(
        backend: Backend,
        customize: impl FnOnce(&mut Config),
        test_name: &'static str,
    ) -> Self {
        // reqwest is built without a provider of its own.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let conf_dir = tempfile::tempdir().unwrap();
        let dir = conf_dir.path();

        let (ca_cert, ca_key) = new_ca("Test EST CA");
        write(&dir.join("ca/ca.crt"), &ca_cert).unwrap();
        write(&dir.join("ca/ca.key"), &ca_key).unwrap();
        let (identity_cert, identity_key) = new_ca("Device Identity CA");
        write(&dir.join("identity.pem"), &identity_cert).unwrap();
        std::fs::create_dir_all(dir.join("clients.d")).unwrap();
        let (stranger_cert, stranger_key) = new_ca("Stranger CA");

        let est_port = find_free_port().unwrap();
        let health_port = find_free_port().unwrap();
        let (cluster, template) = match backend {
            Backend::LocalCa => (None, "local_ca.toml"),
            Backend::CertManager => (
                Some(
                    Cluster::new(test_name, &ca_cert, &ca_key)
                        .await
                        .expect("test namespace with a CA issuer"),
                ),
                "cert_manager.toml",
            ),
        };
        let (namespace, issuer, kubeconfig) = match &cluster {
            Some(c) => (
                c.namespace.clone(),
                c.issuer.clone(),
                c.kubeconfig.display().to_string(),
            ),
            None => Default::default(),
        };
        let conf_path = dir.join("est-server.toml");
        replace_in_file(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/config")
                .join(template),
            &conf_path,
            &[
                ("@EST_PORT@", &est_port.to_string()),
                ("@HEALTH_PORT@", &health_port.to_string()),
                ("@SERVER_NAME@", SERVER_NAME),
                ("@NAMESPACE@", &namespace),
                ("@ISSUER@", &issuer),
                ("@KUBECONFIG@", &kubeconfig),
            ],
        )
        .unwrap();
        let mut config = Config::load(&conf_path).unwrap();
        customize(&mut config);

        let (stop, stop_rx) = oneshot::channel();
        let (teardown_tx, teardown_rx) = oneshot::channel();
        let config_clone = config.clone();
        tokio::spawn(async move {
            let result = est_server::run::run(config_clone, async {
                let _ = stop_rx.await;
            })
            .await;
            if let Err(e) = &result {
                eprintln!("{test_name}: server: {e:#}");
            }
            let _ = teardown_tx.send(result);
        });

        let mut setup = Setup {
            backend,
            config,
            conf_dir,
            ca_der: est_server::tls::parse_certs(ca_cert.as_bytes())
                .unwrap()
                .remove(0),
            identity: LocalCa::from_pem("identity", &identity_cert, &identity_key, vec![]).unwrap(),
            stranger: LocalCa::from_pem("stranger", &stranger_cert, &stranger_key, vec![]).unwrap(),
            est_port,
            health_port,
            cluster,
            stop: Some(stop),
            teardown_rx: Some(teardown_rx),
        };
        setup.wait_ready().await.expect("server ready");
        setup
    }

    /// Poll `/readyz` until the server answers, or fail early if it
    /// stopped.
    async fn wait_ready(&mut self) -> Result<()> {
        let url = format!("http://127.0.0.1:{}/readyz", self.health_port);
        let client = reqwest::Client::new();
        for _ in 0..100 {
            if let Some(rx) = &mut self.teardown_rx
                && let Ok(result) = rx.try_recv()
            {
                self.teardown_rx = None;
                result?;
                bail!("server stopped");
            }
            if let Ok(resp) = client.get(&url).send().await
                && resp.status().is_success()
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("no answer on {url}")
    }

    pub fn state_dir(&self) -> PathBuf {
        self.config.server.state_dir.clone()
    }

    fn cluster(&self) -> &Cluster {
        self.cluster.as_ref().expect("cert-manager backend")
    }

    /// Requests that wait for an administrator.
    pub async fn waiting(&self) -> Result<Vec<Waiting>> {
        match self.backend {
            Backend::LocalCa => Ok(PendingStore::open(&self.state_dir())?
                .list()?
                .into_iter()
                .filter(|e| e.status == Status::Pending)
                .map(|e| Waiting {
                    names: e.names,
                    client: e.client,
                })
                .collect()),
            Backend::CertManager => Ok(self
                .cluster()
                .requests()
                .await?
                .into_iter()
                .filter(|r| {
                    !r.conditions
                        .iter()
                        .any(|(t, _)| t == "Approved" || t == "Denied")
                })
                .map(|r| Waiting {
                    names: r.names,
                    client: r.client,
                })
                .collect()),
        }
    }

    /// Approve the waiting request for `names` as an administrator would.
    pub async fn approve(&self, names: &[&str]) -> Result<()> {
        self.decide(names, true).await
    }

    pub async fn deny(&self, names: &[&str]) -> Result<()> {
        self.decide(names, false).await
    }

    async fn decide(&self, names: &[&str], approve: bool) -> Result<()> {
        match self.backend {
            Backend::LocalCa => {
                let store = PendingStore::open(&self.state_dir())?;
                let entry = store
                    .list()?
                    .into_iter()
                    .find(|e| e.names == names)
                    .with_context(|| format!("no pending request for {names:?}"))?;
                store.decide(&entry.id, approve)?;
                Ok(())
            }
            Backend::CertManager if approve => self.cluster().approve(names).await,
            Backend::CertManager => self.cluster().deny(names).await,
        }
    }

    /// Register a client (names, key pins) the way an administrator
    /// would, and wait until the server knows it.
    pub async fn register(&self, name: &str, names: &[&str], pins: &[String]) -> Result<()> {
        match self.backend {
            Backend::LocalCa => {
                let names: Vec<String> = names.iter().map(|n| format!("{n:?}")).collect();
                let keys: Vec<String> = pins
                    .iter()
                    .map(|p| format!("{{ pin_sha256 = {p:?} }}"))
                    .collect();
                write(
                    &self
                        .conf_dir
                        .path()
                        .join("clients.d")
                        .join(format!("{name}.toml")),
                    &format!(
                        "dns_names = [{}]\npublic_keys = [{}]\n",
                        names.join(", "),
                        keys.join(", ")
                    ),
                )?;
                // Re-read every 300 ms (local_ca.toml).
                tokio::time::sleep(Duration::from_millis(1000)).await;
                Ok(())
            }
            Backend::CertManager => self.cluster().register(name, names, pins).await,
        }
    }

    /// The lines of the issue log.
    pub fn issued_log(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.state_dir().join("issued.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    pub async fn teardown(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(rx) = self.teardown_rx.take() {
            let _ = rx.await;
        }
        if let Some(cluster) = &mut self.cluster {
            cluster.teardown().await;
        }
    }
}
