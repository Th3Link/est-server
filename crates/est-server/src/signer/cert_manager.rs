//! Signing through cert-manager: one `CertificateRequest` per request,
//! approved by the server when its policy approves, otherwise left for
//! `cmctl approve` or approver-policy.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use kube::Client;
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, PostParams,
};
use kube::core::GroupVersionKind;
use rustls::pki_types::CertificateDer;
use serde_json::{Value, json};

use super::{CaCerts, Outcome, SignRequest};
use crate::ca::is_self_signed;
use crate::config::IssuerRef;
use crate::tls::parse_certs;

const MANAGED_BY: &str = "app.kubernetes.io/managed-by=est-server";
/// Unfinished requests are given up after this long.
const MAX_PENDING: Duration = Duration::from_secs(7 * 86_400);

pub struct CertManagerSigner {
    api: Api<DynamicObject>,
    issuer: IssuerRef,
    duration: Option<Duration>,
    wait: Duration,
    reuse_window: Duration,
    keep: Duration,
    include_root: bool,
    pub cas: CaCerts,
    /// Set when no `cacerts` are configured.
    learned: Option<Mutex<Learned>>,
}

/// CA certificates learned from issued chains, kept in the state
/// directory across restarts.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Learned {
    #[serde(skip)]
    path: PathBuf,
    /// Above the leaf in the newest chain: what `/cacerts` answers.
    latest: Vec<String>,
    /// Every CA certificate seen in a chain and not expired: what
    /// renewals are checked against (an issuer may switch between
    /// intermediates from one certificate to the next).
    seen: Vec<String>,
}

/// At most this many learned CA certificates are kept.
const MAX_LEARNED: usize = 20;

/// Where a `CertificateRequest` stands.
#[derive(Debug, PartialEq)]
enum State {
    InProgress,
    Ready(String, Option<String>),
    Denied(String),
    Failed(String),
}

pub struct Settings {
    pub namespace: String,
    pub issuer: IssuerRef,
    pub duration: Option<Duration>,
    pub wait: Duration,
    pub reuse_window: Duration,
    pub keep: Duration,
    pub include_root: bool,
    pub ca_certs: CaSource,
}

/// Where the issuer's CA certificates come from.
pub enum CaSource {
    /// Configured (`cacerts`).
    Fixed(Vec<CertificateDer<'static>>),
    /// Learned from the issued chains, kept in this file.
    Learn(PathBuf),
}

impl CertManagerSigner {
    pub fn new(client: Client, s: Settings) -> anyhow::Result<Self> {
        let ar = ApiResource::from_gvk(&GroupVersionKind::gvk(
            "cert-manager.io",
            "v1",
            "CertificateRequest",
        ));
        let (cas, learned) = match s.ca_certs {
            CaSource::Fixed(certs) => (CaCerts::new(certs)?, None),
            CaSource::Learn(path) => {
                let mut learned: Learned = std::fs::read(&path)
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or_default();
                learned.path = path;
                let cas = CaCerts::new(Vec::new())?;
                cas.set(decode_ders(&learned.latest), &decode_ders(&learned.seen))?;
                (cas, Some(Mutex::new(learned)))
            }
        };
        Ok(Self {
            api: Api::namespaced_with(client, &s.namespace, &ar),
            issuer: s.issuer,
            duration: s.duration,
            wait: s.wait,
            reuse_window: s.reuse_window,
            keep: s.keep,
            include_root: s.include_root,
            cas,
            learned,
        })
    }

    /// With nothing learned yet (a first start, or no state kept), learn
    /// from the newest finished request in the namespace.
    pub async fn learn_from_cluster(&self) -> anyhow::Result<()> {
        if self.learned.is_none() || !self.cas.certs().is_empty() {
            return Ok(());
        }
        let mut objects = self
            .api
            .list(&ListParams::default().labels(MANAGED_BY))
            .await
            .context("list CertificateRequests")?
            .items;
        objects.sort_by_key(|o| std::cmp::Reverse(o.metadata.creation_timestamp.clone()));
        for obj in objects {
            if let State::Ready(cert, ca) = state(&obj) {
                let mut chain = parse_certs(cert.as_bytes()).context("status.certificate")?;
                if let Some(ca) = ca.filter(|s| !s.trim().is_empty()) {
                    chain.extend(parse_certs(ca.as_bytes()).context("status.ca")?);
                }
                self.learn(&chain[1..]);
                break;
            }
        }
        Ok(())
    }

    /// Note the CA certificates of an issued chain.
    fn learn(&self, above_leaf: &[CertificateDer<'static>]) {
        let Some(learned) = &self.learned else {
            return;
        };
        if above_leaf.is_empty() {
            return;
        }
        let mut l = learned.lock().unwrap_or_else(|e| e.into_inner());
        let latest = encode_ders(above_leaf);
        if l.latest == latest && latest.iter().all(|c| l.seen.contains(c)) {
            return;
        }
        let mut seen = latest.clone();
        seen.extend(l.seen.iter().filter(|c| !latest.contains(c)).cloned());
        seen.retain(|c| !expired(c));
        seen.truncate(MAX_LEARNED);
        if let Err(e) = self.cas.set(above_leaf.to_vec(), &decode_ders(&seen)) {
            tracing::warn!("learning the CA certificates: {e:#}");
            return;
        }
        tracing::info!(
            certificates = above_leaf.len(),
            known = seen.len(),
            "learned the CA certificates from cert-manager"
        );
        l.latest = latest;
        l.seen = seen;
        match serde_json::to_vec_pretty(&*l) {
            Ok(json) => {
                if let Err(e) = crate::ca::write_file(&l.path, &json, false) {
                    tracing::warn!("keeping the learned CA certificates: {e:#}");
                }
            }
            Err(e) => tracing::warn!("keeping the learned CA certificates: {e}"),
        }
    }

    pub async fn sign(&self, req: &SignRequest<'_>, approved: bool) -> anyhow::Result<Outcome> {
        let name = format!("est-{}", &req.id[..20]);
        let mut existing = self
            .api
            .get_opt(&name)
            .await
            .context("get CertificateRequest")?;
        if let Some(obj) = &existing
            && state(obj) != State::InProgress
            && age(obj) > self.reuse_window
        {
            // An old answer for the same key and names: start over.
            self.api
                .delete(&name, &DeleteParams::default())
                .await
                .context("delete CertificateRequest")?;
            existing = None;
        }
        let obj = match existing {
            Some(obj) => obj,
            None => self.create(&name, req).await?,
        };
        if approved && !has_condition(&obj, "Approved") && !has_condition(&obj, "Denied") {
            self.approve(&obj, req).await?;
        }

        let deadline = Instant::now() + self.wait;
        loop {
            let obj = self
                .api
                .get(&name)
                .await
                .context("get CertificateRequest")?;
            if !approved && approved_by_default_approver(&obj) {
                // cert-manager's built-in approver approves everything, which
                // would turn "needs approval" into "open to anyone".
                tracing::error!(
                    cr = %name,
                    "cert-manager's default approver approved a request that needs manual approval; \
                     disable it (--controllers=*,-certificaterequests-approver) and approve with cmctl or approver-policy"
                );
                return Ok(Outcome::Denied(
                    "approval is misconfigured on the server".into(),
                ));
            }
            match state(&obj) {
                State::Ready(cert, ca) => {
                    return self.answer(req, &cert, ca.as_deref()).map(Outcome::Issued);
                }
                State::Denied(msg) => {
                    return Ok(Outcome::Denied(format!(
                        "CertificateRequest {name} denied: {msg}"
                    )));
                }
                State::Failed(msg) => {
                    return Err(anyhow!("CertificateRequest {name} failed: {msg}"));
                }
                State::InProgress if Instant::now() >= deadline => {
                    if !has_condition(&obj, "Approved") {
                        tracing::info!(
                            cr = %name, names = ?req.names, client = %req.client,
                            "request waits for approval: cmctl approve -n {} {name}",
                            self.api.namespace().unwrap_or_default()
                        );
                    }
                    return Ok(Outcome::Pending(req.retry_after));
                }
                State::InProgress => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }

    async fn create(&self, name: &str, req: &SignRequest<'_>) -> anyhow::Result<DynamicObject> {
        let mut usages = vec!["digital signature", "server auth", "client auth"];
        if req.csr.key.is_rsa() {
            usages.push("key encipherment");
        }
        let mut spec = json!({
            "request": base64_pem(&req.csr.der),
            "issuerRef": { "name": self.issuer.name, "kind": self.issuer.kind, "group": self.issuer.group },
            "usages": usages,
        });
        if let Some(d) = self.duration {
            spec["duration"] = json!(format!("{}s", d.as_secs()));
        }
        let label = if req.label.is_empty() {
            "default"
        } else {
            req.label
        };
        let annotations: BTreeMap<&str, String> = [
            ("est-server/names", req.names.join(",")),
            ("est-server/client", req.client.to_string()),
            ("est-server/operation", req.operation.to_string()),
        ]
        .into_iter()
        .chain(
            req.client_cert
                .map(|s| ("est-server/client-cert", s.to_string())),
        )
        .collect();
        let body = json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "CertificateRequest",
            "metadata": {
                "name": name,
                "labels": { "app.kubernetes.io/managed-by": "est-server", "est-server/label": label },
                "annotations": annotations,
            },
            "spec": spec,
        });
        let obj: DynamicObject = serde_json::from_value(body)?;
        match self.api.create(&PostParams::default(), &obj).await {
            Ok(created) => Ok(created),
            // A concurrent request of the same client got there first.
            Err(kube::Error::Api(s)) if s.is_already_exists() => Ok(self.api.get(name).await?),
            Err(e) => Err(e).context("create CertificateRequest"),
        }
    }

    async fn approve(&self, obj: &DynamicObject, req: &SignRequest<'_>) -> anyhow::Result<()> {
        let mut conditions = obj.data["status"]["conditions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        conditions.push(json!({
            "type": "Approved",
            "status": "True",
            "reason": "est-server",
            "message": format!("approved by est-server ({}) for {}", req.operation, req.client),
            "lastTransitionTime": rfc3339_now(),
        }));
        let name = obj.metadata.name.as_deref().unwrap_or_default();
        self.api
            .patch_status(name, &PatchParams::default(), &Patch::Merge(json!({ "status": { "conditions": conditions } })))
            .await
            .context("approve CertificateRequest (does the service account may approve for this issuer?)")?;
        Ok(())
    }

    fn answer(
        &self,
        req: &SignRequest<'_>,
        cert_pem: &str,
        ca_pem: Option<&str>,
    ) -> anyhow::Result<Vec<CertificateDer<'static>>> {
        let mut chain = parse_certs(cert_pem.as_bytes()).context("status.certificate")?;
        let leaf = crate::peer::describe(&chain[0])
            .ok_or_else(|| anyhow!("status.certificate: unreadable leaf"))?;
        if leaf.spki_der != req.csr.spki_der {
            return Err(anyhow!(
                "issued certificate has another public key than the request"
            ));
        }
        if let Some(ca) = ca_pem.filter(|s| !s.trim().is_empty()) {
            for c in parse_certs(ca.as_bytes()).context("status.ca")? {
                if !chain.contains(&c) {
                    chain.push(c);
                }
            }
        }
        self.learn(&chain[1..]);
        let leaf = chain.remove(0);
        Ok(std::iter::once(leaf)
            .chain(
                chain
                    .into_iter()
                    .filter(|c| self.include_root || !is_self_signed(c)),
            )
            .collect())
    }

    /// Delete finished requests older than `keep`, unfinished ones older
    /// than a week. Runs every ten minutes, forever.
    pub async fn cleanup_loop(self: std::sync::Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(600));
        loop {
            tick.tick().await;
            if let Err(e) = self.cleanup().await {
                tracing::warn!("CertificateRequest cleanup: {e:#}");
            }
        }
    }

    async fn cleanup(&self) -> anyhow::Result<()> {
        for obj in self
            .api
            .list(&ListParams::default().labels(MANAGED_BY))
            .await?
        {
            let limit = if state(&obj) == State::InProgress {
                MAX_PENDING
            } else {
                self.keep
            };
            if age(&obj) > limit
                && let Some(name) = &obj.metadata.name
            {
                self.api.delete(name, &DeleteParams::default()).await?;
                tracing::debug!(cr = %name, "deleted old CertificateRequest");
            }
        }
        Ok(())
    }
}

fn conditions(obj: &DynamicObject) -> impl Iterator<Item = &Value> {
    obj.data["status"]["conditions"]
        .as_array()
        .into_iter()
        .flatten()
}

fn condition<'a>(obj: &'a DynamicObject, kind: &str) -> Option<&'a Value> {
    conditions(obj).find(|c| c["type"] == kind)
}

fn has_condition(obj: &DynamicObject, kind: &str) -> bool {
    condition(obj, kind).is_some_and(|c| c["status"] == "True")
}

/// Approved by cert-manager's built-in approver (reason
/// `cert-manager.io`), not by est-server, cmctl or approver-policy.
fn approved_by_default_approver(obj: &DynamicObject) -> bool {
    condition(obj, "Approved")
        .is_some_and(|c| c["status"] == "True" && c["reason"] == "cert-manager.io")
}

fn message(c: Option<&Value>) -> String {
    c.and_then(|c| c["message"].as_str())
        .unwrap_or_default()
        .to_string()
}

fn state(obj: &DynamicObject) -> State {
    if has_condition(obj, "Denied") {
        return State::Denied(message(condition(obj, "Denied")));
    }
    if has_condition(obj, "InvalidRequest") {
        return State::Failed(message(condition(obj, "InvalidRequest")));
    }
    let ready = condition(obj, "Ready");
    match ready.map(|c| (c["status"].as_str(), c["reason"].as_str())) {
        Some((Some("True"), _)) => {
            let decode = |v: &Value| v.as_str().and_then(decode_b64);
            match decode(&obj.data["status"]["certificate"]) {
                Some(cert) => State::Ready(cert, decode(&obj.data["status"]["ca"])),
                None => State::InProgress,
            }
        }
        Some((Some("False"), Some("Failed"))) => State::Failed(message(ready)),
        _ => State::InProgress,
    }
}

fn age(obj: &DynamicObject) -> Duration {
    obj.metadata
        .creation_timestamp
        .as_ref()
        .and_then(|t| {
            let created = std::time::SystemTime::UNIX_EPOCH
                + Duration::from_secs(u64::try_from(t.0.as_second()).ok()?);
            std::time::SystemTime::now().duration_since(created).ok()
        })
        .unwrap_or_default()
}

fn base64_pem(der: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .encode(est_proto::wire::to_pem("CERTIFICATE REQUEST", der))
}

fn encode_ders(certs: &[CertificateDer<'static>]) -> Vec<String> {
    use base64::Engine as _;
    certs
        .iter()
        .map(|c| base64::engine::general_purpose::STANDARD.encode(c))
        .collect()
}

fn decode_ders(certs: &[String]) -> Vec<CertificateDer<'static>> {
    use base64::Engine as _;
    certs
        .iter()
        .filter_map(|c| base64::engine::general_purpose::STANDARD.decode(c).ok())
        .map(CertificateDer::from)
        .collect()
}

fn expired(b64_der: &str) -> bool {
    decode_ders(&[b64_der.to_string()])
        .first()
        .is_none_or(|der| {
            x509_parser::parse_x509_certificate(der)
                .map(|(_, c)| {
                    c.validity().not_after.timestamp()
                        < time::OffsetDateTime::now_utc().unix_timestamp()
                })
                .unwrap_or(true)
        })
}

fn decode_b64(s: &str) -> Option<String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    String::from_utf8(bytes).ok()
}

pub fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(status: Value) -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "cert-manager.io/v1", "kind": "CertificateRequest",
            "metadata": { "name": "est-x" }, "status": status,
        }))
        .unwrap()
    }

    #[test]
    fn reads_states() {
        use base64::Engine as _;
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        assert_eq!(state(&obj(json!({}))), State::InProgress);
        assert_eq!(
            state(&obj(
                json!({ "conditions": [{ "type": "Approved", "status": "True" }, { "type": "Ready", "status": "False", "reason": "Pending" }] })
            )),
            State::InProgress
        );
        assert_eq!(
            state(&obj(
                json!({ "conditions": [{ "type": "Denied", "status": "True", "message": "no" }] })
            )),
            State::Denied("no".into())
        );
        assert_eq!(
            state(&obj(
                json!({ "conditions": [{ "type": "Ready", "status": "False", "reason": "Failed", "message": "boom" }] })
            )),
            State::Failed("boom".into())
        );
        assert_eq!(
            state(&obj(
                json!({ "conditions": [{ "type": "Ready", "status": "True" }], "certificate": b64("C"), "ca": b64("A") })
            )),
            State::Ready("C".into(), Some("A".into()))
        );
    }

    #[test]
    fn spots_the_default_approver() {
        let by = |reason: &str| {
            obj(
                json!({ "conditions": [{ "type": "Approved", "status": "True", "reason": reason }] }),
            )
        };
        assert!(approved_by_default_approver(&by("cert-manager.io")));
        assert!(!approved_by_default_approver(&by("est-server")));
        assert!(!approved_by_default_approver(&by("policy.cert-manager.io")));
    }
}
