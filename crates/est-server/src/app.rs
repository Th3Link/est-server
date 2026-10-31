//! Building the server from the configuration, and running it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::audit::AuditLog;
use crate::ca::LocalCa;
use crate::clients::Registry;
use crate::config::{Config, KubernetesConfig, SignerConfig};
use crate::names::NamePattern;
use crate::peer::TrustStore;
use crate::pending::PendingStore;
use crate::policy::Policy;
use crate::signer::Signer;
use crate::signer::cert_manager::{CaSource, CertManagerSigner, Settings};
use crate::signer::local::LocalSigner;
use crate::tls::{ReloadingCert, read_certs};

/// How often the server certificate files are checked for changes.
const CERT_RELOAD_INTERVAL: Duration = Duration::from_secs(30);

pub struct Label {
    pub name: String,
    pub base_path: String,
    pub policy: Policy,
    pub signer: Signer,
    pub retry_after: Duration,
}

pub struct App {
    labels: Vec<Label>,
    pub audit: AuditLog,
    pub clients: Arc<Registry>,
}

impl App {
    /// The label and operation a request path is for.
    pub fn route<'a>(&'a self, path: &'a str) -> Option<(&'a Label, &'a str)> {
        let (base, op) = path.trim_end_matches('/').rsplit_once('/')?;
        self.labels
            .iter()
            .find(|l| l.base_path == base)
            .map(|l| (l, op))
    }
}

/// A running server; dropping it stops it.
pub struct Running {
    pub est_addrs: Vec<SocketAddr>,
    pub health_addrs: Vec<SocketAddr>,
    tasks: JoinSet<()>,
}

impl Running {
    /// Wait until a listener task ends (which it doesn't, normally).
    pub async fn wait(mut self) {
        self.tasks.join_next().await;
    }
}

/// Load everything, bind the sockets and start serving.
pub async fn start(config: &Config) -> anyhow::Result<Running> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    std::fs::create_dir_all(&config.server.state_dir)
        .with_context(|| format!("create {}", config.server.state_dir.display()))?;

    let mut cas = HashMap::new();
    for ca in &config.cas {
        cas.insert(
            ca.name.clone(),
            Arc::new(LocalCa::load(ca).with_context(|| format!("CA {}", ca.name))?),
        );
    }

    // Everything the server runs in the background lives here, so that
    // dropping `Running` stops all of it.
    let mut tasks = JoinSet::new();
    if let Some(auto) = &config.server.tls.auto {
        let ca = cas[&auto.ca].clone();
        crate::autotls::ensure(&config.server.tls, auto, &ca)?;
        tasks.spawn(crate::autotls::renew_loop(
            config.server.tls.clone(),
            auto.clone(),
            ca,
        ));
    }
    let cert = ReloadingCert::load(&config.server.tls.cert, &config.server.tls.key)?;
    tasks.spawn(cert.clone().watch(CERT_RELOAD_INTERVAL));

    let pending = Arc::new(PendingStore::open(&config.server.state_dir)?);
    let mut kube = LazyKube::new(&config.kubernetes);

    let clients = Arc::new(Registry::default());
    if let Some(cc) = &config.clients {
        if let Some(dir) = &cc.dir {
            crate::clients::file::init(&clients, dir)?;
            tasks.spawn(crate::clients::file::watch(
                clients.clone(),
                dir.clone(),
                cc.reload,
            ));
        }
        if let Some(k) = &cc.kubernetes {
            let client = kube.get().await?;
            let namespace = k
                .namespace
                .clone()
                .unwrap_or_else(|| client.default_namespace().to_string());
            tasks.spawn(crate::clients::k8s::init(clients.clone(), client, &namespace).await?);
        }
    }

    let mut labels = Vec::new();
    for lc in &config.labels {
        let signer = match &lc.signer {
            SignerConfig::Local { ca, validity } => Signer::Local(LocalSigner::new(
                cas[ca].clone(),
                *validity,
                lc.include_root,
                pending.clone(),
            )?),
            SignerConfig::CertManager {
                namespace,
                issuer,
                duration,
                cacerts,
                wait,
                reuse_window,
                keep,
            } => {
                let client = kube.get().await?;
                let namespace = namespace
                    .clone()
                    .unwrap_or_else(|| client.default_namespace().to_string());
                let ca_certs = match cacerts {
                    Some(path) => CaSource::Fixed(read_certs(path)?),
                    None => {
                        let name = if lc.name.is_empty() {
                            "default"
                        } else {
                            &lc.name
                        };
                        CaSource::Learn(
                            config
                                .server
                                .state_dir
                                .join(format!("learned-ca-{name}.json")),
                        )
                    }
                };
                let signer = Arc::new(CertManagerSigner::new(
                    client,
                    Settings {
                        namespace,
                        issuer: issuer.clone(),
                        duration: *duration,
                        wait: *wait,
                        reuse_window: *reuse_window,
                        keep: *keep,
                        include_root: lc.include_root,
                        ca_certs,
                    },
                )?);
                if let Err(e) = signer.learn_from_cluster().await {
                    tracing::warn!(label = %lc.name, "learning the CA certificates: {e:#}");
                }
                tasks.spawn(signer.clone().cleanup_loop());
                Signer::CertManager(signer)
            }
        };
        let mut identity = Vec::new();
        for path in &lc.identity_cas {
            identity.extend(read_certs(path)?);
        }
        let policy = Policy {
            label: lc.name.clone(),
            allow: lc
                .allow
                .iter()
                .map(|p| NamePattern::parse(p).map_err(anyhow::Error::msg))
                .collect::<Result<_, _>>()?,
            identity: TrustStore::new(&identity)?,
            identity_name_match: lc.identity_name_match,
            manual_approval: lc.manual_approval,
            renew: signer.cas().anchors(),
            registration: lc.registered,
            clients: clients.clone(),
        };
        tracing::info!(
            label = %lc.name, path = %lc.base_path(), signer = signer.kind(),
            registered = ?lc.registered, "EST endpoint"
        );
        labels.push(Label {
            name: lc.name.clone(),
            base_path: lc.base_path(),
            policy,
            signer,
            retry_after: lc.retry_after,
        });
    }
    let app = Arc::new(App {
        labels,
        audit: AuditLog::new(&config.server.state_dir),
        clients,
    });

    let acceptor = TlsAcceptor::from(Arc::new(crate::tls::server_config(cert)?));
    let router = crate::http::router(app);
    let mut est_addrs = Vec::new();
    for listener in crate::net::bind_all(&config.server.listen)? {
        est_addrs.push(listener.local_addr()?);
        tasks.spawn(crate::net::serve_tls(
            listener,
            acceptor.clone(),
            router.clone(),
        ));
    }
    let ready = Arc::new(AtomicBool::new(false));
    let mut health_addrs = Vec::new();
    for listener in crate::net::bind_all(&config.server.health_listen)? {
        health_addrs.push(listener.local_addr()?);
        let router = crate::http::health_router(ready.clone());
        tasks.spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!("health listener: {e}");
            }
        });
    }
    let prune = pending.clone();
    tasks.spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            match prune.prune(Duration::from_secs(30 * 86_400)) {
                Ok(0) => {}
                Ok(n) => tracing::info!("removed {n} pending requests untouched for 30 days"),
                Err(e) => tracing::warn!("pruning pending requests: {e:#}"),
            }
        }
    });
    ready.store(true, Ordering::Relaxed);
    tracing::info!(est = ?est_addrs, health = ?health_addrs, "listening");
    Ok(Running {
        est_addrs,
        health_addrs,
        tasks,
    })
}

/// One Kubernetes client, made when first needed.
struct LazyKube<'a> {
    config: &'a KubernetesConfig,
    client: Option<kube::Client>,
}

impl<'a> LazyKube<'a> {
    fn new(config: &'a KubernetesConfig) -> Self {
        Self {
            config,
            client: None,
        }
    }

    async fn get(&mut self) -> anyhow::Result<kube::Client> {
        if self.client.is_none() {
            self.client = Some(
                kube_client_for(self.config)
                    .await
                    .context("Kubernetes client")?,
            );
        }
        Ok(self.client.clone().expect("set above"))
    }
}

async fn kube_client_for(k: &KubernetesConfig) -> anyhow::Result<kube::Client> {
    let options = kube::config::KubeConfigOptions {
        context: k.context.clone(),
        ..Default::default()
    };
    let config = match &k.kubeconfig {
        Some(path) => {
            let file = kube::config::Kubeconfig::read_from(path)
                .with_context(|| format!("read {}", path.display()))?;
            kube::Config::from_custom_kubeconfig(file, &options).await?
        }
        None if k.context.is_some() => kube::Config::from_kubeconfig(&options).await?,
        None => kube::Config::infer().await?,
    };
    Ok(kube::Client::try_from(config)?)
}
