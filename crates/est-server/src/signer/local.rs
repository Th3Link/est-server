//! Signing with a local CA; approvals through the pending store.

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use rcgen::CertificateSigningRequestParams;
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer};

use super::{CaCerts, Outcome, SignRequest};
use crate::ca::{LeafSpec, LocalCa, answer_chain};
use crate::pending::{Entry, PendingStore, Status, now};

pub struct LocalSigner {
    pub ca: Arc<LocalCa>,
    pub validity: Duration,
    pub include_root: bool,
    pub pending: Arc<PendingStore>,
    pub ca_certs: Vec<CertificateDer<'static>>,
    pub cas: CaCerts,
}

impl LocalSigner {
    pub fn new(
        ca: Arc<LocalCa>,
        validity: Duration,
        include_root: bool,
        pending: Arc<PendingStore>,
    ) -> anyhow::Result<Self> {
        let ca_certs = ca.ca_certs();
        Ok(Self {
            cas: CaCerts::new(ca_certs.clone())?,
            ca,
            validity,
            include_root,
            pending,
            ca_certs,
        })
    }

    pub fn sign(&self, req: &SignRequest<'_>, approved: bool) -> anyhow::Result<Outcome> {
        if !approved && let Some(outcome) = self.check_approval(req)? {
            return Ok(outcome);
        }
        let csr_der = CertificateSigningRequestDer::from(req.csr.der.as_slice());
        let public_key = CertificateSigningRequestParams::from_der(&csr_der)
            .map_err(|e| anyhow!("CSR public key: {e}"))?
            .public_key;
        // The CN only if it is one of the names (a CN is optional; the
        // SAN carries the names).
        let common_name = req
            .csr
            .common_name
            .as_deref()
            .filter(|cn| req.names.iter().any(|n| n.eq_ignore_ascii_case(cn)));
        let leaf = self.ca.issue(
            &public_key,
            &LeafSpec {
                common_name,
                dns_names: req.names,
                ip_addresses: &[],
                validity: self.validity,
                rsa: req.csr.key.is_rsa(),
            },
        )?;
        Ok(Outcome::Issued(answer_chain(
            leaf,
            &self.ca_certs,
            self.include_root,
        )))
    }

    /// `None` if an administrator approved the request; otherwise what
    /// to answer.
    fn check_approval(&self, req: &SignRequest<'_>) -> anyhow::Result<Option<Outcome>> {
        let now = now();
        let csr_pem = est_proto::wire::to_pem("CERTIFICATE REQUEST", &req.csr.der);
        let mut entry = match self.pending.get(&req.id)? {
            Some(e) => e,
            None => Entry {
                id: req.id.clone(),
                label: req.label.to_string(),
                names: req.names.to_vec(),
                client: req.client.to_string(),
                client_cert: None,
                csr_pem: String::new(),
                status: Status::Pending,
                created: now,
                last_seen: now,
                decided: None,
                issued: None,
            },
        };
        entry.last_seen = now;
        entry.client = req.client.to_string();
        entry.client_cert = req.client_cert.map(str::to_string);
        entry.csr_pem = csr_pem;
        let outcome = if entry.approval_valid(now) {
            entry.issued = Some(now);
            None
        } else if entry.status == Status::Denied {
            Some(Outcome::Denied("denied by an administrator".into()))
        } else {
            if entry.status == Status::Approved {
                // The approval ran out: ask again.
                entry.status = Status::Pending;
                entry.decided = None;
            }
            if entry.created == now {
                tracing::info!(
                    id = %entry.id, label = req.label, names = ?req.names, client = %req.client,
                    "request waits for approval: est-server pending approve {}", entry.id
                );
            }
            Some(Outcome::Pending(req.retry_after))
        };
        self.pending.put(&entry)?;
        Ok(outcome)
    }
}
