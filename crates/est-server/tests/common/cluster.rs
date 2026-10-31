//! A namespace of its own in a real cluster with cert-manager, with a CA
//! issuer in it, for one test.
//!
//! The cluster comes from `EST_E2E_KUBECONFIG` only, never from the
//! default kubeconfig, so the tests can't wander into a cluster that
//! matters. cert-manager must run without its built-in approver
//! (`scripts/e2e-cluster.sh` sets that up in kind).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::{Namespace, Secret};
use kube::api::{Api, ApiResource, DeleteParams, DynamicObject, Patch, PatchParams, PostParams};
use kube::core::{GroupVersionKind, ObjectMeta};
use serde_json::json;

use super::helper::random_string;

pub const KUBECONFIG_ENV: &str = "EST_E2E_KUBECONFIG";
/// Label on every namespace the tests create; `kubectl delete ns -l
/// est-server-e2e` clears what failed tests left behind.
pub const NAMESPACE_LABEL: &str = "est-server-e2e";

pub struct Cluster {
    pub client: kube::Client,
    pub kubeconfig: PathBuf,
    pub namespace: String,
    pub issuer: String,
    deleted: bool,
}

/// A `CertificateRequest` the server created.
pub struct Request {
    pub name: String,
    pub names: Vec<String>,
    pub client: String,
    pub operation: String,
    /// `(type, reason)` of its conditions.
    pub conditions: Vec<(String, String)>,
}

fn certificate_requests() -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind::gvk(
        "cert-manager.io",
        "v1",
        "CertificateRequest",
    ))
}

fn issuers() -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind::gvk("cert-manager.io", "v1", "Issuer"))
}

pub fn kubeconfig() -> PathBuf {
    std::env::var_os(KUBECONFIG_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!("{KUBECONFIG_ENV} must point to the kubeconfig of a test cluster, see scripts/e2e-cluster.sh")
        })
}

async fn client(kubeconfig: &PathBuf) -> Result<kube::Client> {
    let file = kube::config::Kubeconfig::read_from(kubeconfig)?;
    let config = kube::Config::from_custom_kubeconfig(file, &Default::default()).await?;
    Ok(kube::Client::try_from(config)?)
}

impl Cluster {
    /// Create the namespace, the CA secret from `ca_cert`/`ca_key` and a
    /// CA issuer over it; returns once the issuer is ready.
    pub async fn new(test_name: &str, ca_cert: &str, ca_key: &str) -> Result<Self> {
        let kubeconfig = kubeconfig();
        let client = client(&kubeconfig).await?;
        let namespace = format!("est-e2e-{}", random_string(8));
        let issuer = format!("ca-{}", random_string(6));

        let ns = Namespace {
            metadata: ObjectMeta {
                name: Some(namespace.clone()),
                labels: Some(BTreeMap::from([(NAMESPACE_LABEL.into(), "true".into())])),
                annotations: Some(BTreeMap::from([(
                    "est-server-e2e/test".into(),
                    test_name.into(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };
        Api::<Namespace>::all(client.clone())
            .create(&PostParams::default(), &ns)
            .await
            .context("create namespace")?;
        let cluster = Self {
            client,
            kubeconfig,
            namespace,
            issuer,
            deleted: false,
        };

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(cluster.issuer.clone()),
                ..Default::default()
            },
            type_: Some("kubernetes.io/tls".into()),
            data: Some(BTreeMap::from([
                ("tls.crt".into(), ByteString(ca_cert.as_bytes().to_vec())),
                ("tls.key".into(), ByteString(ca_key.as_bytes().to_vec())),
            ])),
            ..Default::default()
        };
        Api::<Secret>::namespaced(cluster.client.clone(), &cluster.namespace)
            .create(&PostParams::default(), &secret)
            .await
            .context("create CA secret")?;

        let issuer: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Issuer",
            "metadata": { "name": cluster.issuer },
            "spec": { "ca": { "secretName": cluster.issuer } },
        }))?;
        let api = Api::<DynamicObject>::namespaced_with(
            cluster.client.clone(),
            &cluster.namespace,
            &issuers(),
        );
        api.create(&PostParams::default(), &issuer)
            .await
            .context("create issuer (is cert-manager installed?)")?;
        cluster
            .wait_for(Duration::from_secs(30), || async {
                let obj = api.get(&cluster.issuer).await?;
                Ok(has_true_condition(&obj, "Ready"))
            })
            .await
            .context("issuer not ready")?;
        Ok(cluster)
    }

    fn requests_api(&self) -> Api<DynamicObject> {
        Api::namespaced_with(
            self.client.clone(),
            &self.namespace,
            &certificate_requests(),
        )
    }

    /// The `CertificateRequest`s the server created, oldest first.
    pub async fn requests(&self) -> Result<Vec<Request>> {
        let mut list = self
            .requests_api()
            .list(
                &kube::api::ListParams::default().labels("app.kubernetes.io/managed-by=est-server"),
            )
            .await?
            .items;
        list.sort_by_key(|o| o.metadata.creation_timestamp.clone());
        Ok(list.iter().map(Request::from).collect())
    }

    /// The request for exactly these names.
    pub async fn request_for(&self, names: &[&str]) -> Result<Request> {
        let want = names.join(",");
        self.requests()
            .await?
            .into_iter()
            .find(|r| r.names.join(",") == want)
            .with_context(|| format!("no CertificateRequest for {want}"))
    }

    /// Set a condition the way `cmctl approve` / `cmctl deny` do.
    pub async fn set_condition(&self, request: &str, kind: &str, reason: &str) -> Result<()> {
        let api = self.requests_api();
        let obj = api.get(request).await?;
        let mut conditions = obj.data["status"]["conditions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        conditions.push(json!({
            "type": kind,
            "status": "True",
            "reason": reason,
            "message": format!("{kind} by the end-to-end test"),
            "lastTransitionTime": rfc3339_now(),
        }));
        api.patch_status(
            request,
            &PatchParams::default(),
            &Patch::Merge(json!({ "status": { "conditions": conditions } })),
        )
        .await?;
        Ok(())
    }

    /// Register a client as `EstClient` and wait until the server has
    /// accepted it (`Valid=True`).
    pub async fn register(&self, name: &str, names: &[&str], pins: &[String]) -> Result<()> {
        use est_server::clients::k8s::{EstClient, EstClientSpec, PublicKeyPin};
        let api: Api<EstClient> = Api::namespaced(self.client.clone(), &self.namespace);
        let obj = EstClient::new(
            name,
            EstClientSpec {
                dns_names: names.iter().map(|n| n.to_string()).collect(),
                public_keys: pins
                    .iter()
                    .map(|p| PublicKeyPin {
                        pin_sha256: p.clone(),
                    })
                    .collect(),
                labels: vec![],
            },
        );
        api.create(&PostParams::default(), &obj)
            .await
            .context("create EstClient (CRD installed?)")?;
        self.wait_for(Duration::from_secs(30), || async {
            let obj = api.get(name).await?;
            Ok(obj.status.is_some_and(|s| {
                s.conditions
                    .iter()
                    .any(|c| c.type_ == "Valid" && c.status == "True")
            }))
        })
        .await
        .context("EstClient not accepted by the server")
    }

    /// `status.lastIssued` of an `EstClient`.
    pub async fn last_issued(
        &self,
        name: &str,
    ) -> Result<Option<est_server::clients::k8s::LastIssued>> {
        use est_server::clients::k8s::EstClient;
        let api: Api<EstClient> = Api::namespaced(self.client.clone(), &self.namespace);
        Ok(api.get(name).await?.status.and_then(|s| s.last_issued))
    }

    pub async fn approve(&self, names: &[&str]) -> Result<()> {
        let r = self.request_for(names).await?;
        self.set_condition(&r.name, "Approved", "e2e-test").await
    }

    pub async fn deny(&self, names: &[&str]) -> Result<()> {
        let r = self.request_for(names).await?;
        self.set_condition(&r.name, "Denied", "e2e-test").await
    }

    async fn wait_for<F, Fut>(&self, timeout: Duration, mut check: F) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<bool>>,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if check().await? {
                return Ok(());
            }
            if tokio::time::Instant::now() > deadline {
                bail!("timed out after {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn teardown(&mut self) {
        if !self.deleted {
            delete_namespace(&self.client, &self.namespace).await;
            self.deleted = true;
        }
    }
}

async fn delete_namespace(client: &kube::Client, namespace: &str) {
    if let Err(e) = Api::<Namespace>::all(client.clone())
        .delete(namespace, &DeleteParams::background())
        .await
    {
        eprintln!("deleting namespace {namespace}: {e}");
    }
}

impl Drop for Cluster {
    /// A test that panicked never reached `teardown`; clean up anyway. The
    /// client belongs to the test's runtime, which is going away, so this
    /// uses a runtime and client of its own.
    fn drop(&mut self) {
        if self.deleted {
            return;
        }
        let kubeconfig = self.kubeconfig.clone();
        let namespace = self.namespace.clone();
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                if let Ok(client) = client(&kubeconfig).await {
                    delete_namespace(&client, &namespace).await;
                }
            });
        })
        .join();
    }
}

impl From<&DynamicObject> for Request {
    fn from(obj: &DynamicObject) -> Self {
        let annotation = |key: &str| {
            obj.metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get(key))
                .cloned()
                .unwrap_or_default()
        };
        Request {
            name: obj.metadata.name.clone().unwrap_or_default(),
            names: annotation("est-server/names")
                .split(',')
                .map(str::to_string)
                .collect(),
            client: annotation("est-server/client"),
            operation: annotation("est-server/operation"),
            conditions: obj.data["status"]["conditions"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|c| {
                    (
                        c["type"].as_str().unwrap_or_default().to_string(),
                        c["reason"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect(),
        }
    }
}

fn has_true_condition(obj: &DynamicObject, kind: &str) -> bool {
    obj.data["status"]["conditions"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|c| c["type"] == kind && c["status"] == "True")
}

fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}
