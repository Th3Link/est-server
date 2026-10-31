//! Who signs: a local CA or cert-manager.

pub mod cert_manager;
pub mod local;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use est_proto::csr::Csr;
use rustls::pki_types::CertificateDer;

use crate::peer::TrustStore;

/// A request the policy has looked at.
pub struct SignRequest<'a> {
    /// Stable for one key asking for one set of names on one label, so
    /// that a client polling after `202` finds its request again even
    /// though every CSR it sends is signed anew.
    pub id: String,
    pub label: &'a str,
    pub operation: &'a str,
    pub csr: &'a Csr,
    pub names: &'a [String],
    pub client: SocketAddr,
    pub client_cert: Option<&'a str>,
    pub retry_after: Duration,
}

pub enum Outcome {
    /// Leaf first, then the CA certificates to send along.
    Issued(Vec<CertificateDer<'static>>),
    /// Ask again after this long.
    Pending(Duration),
    Denied(String),
}

pub enum Signer {
    Local(local::LocalSigner),
    CertManager(std::sync::Arc<cert_manager::CertManagerSigner>),
}

impl Signer {
    /// Sign, or (if `approved` is false) put the request up for approval.
    pub async fn sign(&self, req: &SignRequest<'_>, approved: bool) -> anyhow::Result<Outcome> {
        match self {
            Signer::Local(s) => s.sign(req, approved),
            Signer::CertManager(s) => s.sign(req, approved).await,
        }
    }

    /// The CA certificates behind this signer: `/cacerts`, and the trust
    /// anchors for renewals.
    pub fn cas(&self) -> &CaCerts {
        match self {
            Signer::Local(s) => &s.cas,
            Signer::CertManager(s) => &s.cas,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Signer::Local(_) => "local",
            Signer::CertManager(_) => "cert-manager",
        }
    }
}

/// What `/cacerts` answers, and the anchors a renewal's client
/// certificate is checked against. Fixed for a local CA or configured
/// `cacerts`; learned from what cert-manager returns otherwise.
pub struct CaCerts {
    certs: ArcSwap<Vec<CertificateDer<'static>>>,
    anchors: Arc<ArcSwap<TrustStore>>,
}

impl CaCerts {
    pub fn new(certs: Vec<CertificateDer<'static>>) -> anyhow::Result<Self> {
        Ok(Self {
            anchors: Arc::new(ArcSwap::from_pointee(TrustStore::new(&certs)?)),
            certs: ArcSwap::from_pointee(certs),
        })
    }

    /// The certificates for `/cacerts`; empty while none is known yet.
    pub fn certs(&self) -> Arc<Vec<CertificateDer<'static>>> {
        self.certs.load_full()
    }

    /// Shared with the policy, which sees updates.
    pub fn anchors(&self) -> Arc<ArcSwap<TrustStore>> {
        self.anchors.clone()
    }

    /// Serve `certs`, trust `anchors`.
    pub fn set(
        &self,
        certs: Vec<CertificateDer<'static>>,
        anchors: &[CertificateDer<'static>],
    ) -> anyhow::Result<()> {
        self.anchors.store(Arc::new(TrustStore::new(anchors)?));
        self.certs.store(Arc::new(certs));
        Ok(())
    }
}

/// See [`SignRequest::id`]: SHA-256 over label, sorted names and public
/// key, 32 hex digits.
pub fn request_id(label: &str, names: &[String], spki_der: &[u8]) -> String {
    let mut sorted = names.to_vec();
    sorted.sort();
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(label.as_bytes());
    ctx.update(&[0]);
    for n in &sorted {
        ctx.update(n.as_bytes());
        ctx.update(&[0]);
    }
    ctx.update(spki_der);
    hex::encode(&ctx.finish().as_ref()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_ignores_name_order() {
        let a = request_id("", &["a.test".into(), "b.test".into()], b"key");
        let b = request_id("", &["b.test".into(), "a.test".into()], b"key");
        assert_eq!(a, b);
        assert_ne!(
            a,
            request_id("x", &["a.test".into(), "b.test".into()], b"key")
        );
        assert_eq!(a.len(), 32);
    }
}
