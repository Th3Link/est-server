//! Who signs: a local CA or cert-manager.

pub mod cert_manager;
pub mod local;

use std::net::SocketAddr;
use std::time::Duration;

use est_proto::csr::Csr;
use rustls::pki_types::CertificateDer;

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
    pub fn ca_certs(&self) -> &[CertificateDer<'static>] {
        match self {
            Signer::Local(s) => &s.ca_certs,
            Signer::CertManager(s) => &s.ca_certs,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Signer::Local(_) => "local",
            Signer::CertManager(_) => "cert-manager",
        }
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
