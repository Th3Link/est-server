//! Who gets a certificate for which names.

use axum::http::StatusCode;
use rustls::pki_types::CertificateDer;

use crate::names::NamePattern;
use crate::peer::{TrustStore, VerifiedPeer};

/// Why a request may be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// `simplereenroll` with the certificate being renewed.
    Renewal,
    /// A client certificate from a device identity CA.
    Identity,
    /// The names are on the allowlist.
    Allowlist,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Renewal => "renewal",
            Reason::Identity => "identity",
            Reason::Allowlist => "allowlist",
        }
    }
}

#[derive(Debug)]
pub enum Decision {
    Approved(Reason, Option<VerifiedPeer>),
    /// An administrator has to approve.
    NeedsApproval(Option<VerifiedPeer>),
    Refused(StatusCode, String),
}

pub struct Policy {
    pub allow: Vec<NamePattern>,
    pub identity: TrustStore,
    pub identity_name_match: bool,
    pub manual_approval: bool,
    /// Anchors of the certificates this label issues.
    pub renew: TrustStore,
}

impl Policy {
    /// `simpleenroll`: device identity, then allowlist, then approval.
    pub fn enroll(&self, names: &[String], chain: &[CertificateDer<'static>]) -> Decision {
        let identity = self.identity.verify(chain);
        if let Some(id) = &identity
            && (!self.identity_name_match || names.iter().all(|n| id.names.contains(n)))
        {
            return Decision::Approved(Reason::Identity, identity);
        }
        if names
            .iter()
            .all(|n| self.allow.iter().any(|p| p.matches(n)))
        {
            return Decision::Approved(Reason::Allowlist, identity);
        }
        if self.manual_approval {
            return Decision::NeedsApproval(identity.or_else(|| self.renew.verify(chain)));
        }
        let why = match identity {
            Some(id) => format!(
                "{:?} is not covered by the device identity {}",
                names, id.subject
            ),
            None => format!("{names:?} needs a device identity or approval"),
        };
        Decision::Refused(StatusCode::FORBIDDEN, why)
    }

    /// `simplereenroll`: the client certificate must be one this label
    /// issued, for the same names (RFC 7030 4.2.2). The key may stay.
    pub fn reenroll(&self, names: &[String], chain: &[CertificateDer<'static>]) -> Decision {
        if chain.is_empty() {
            return Decision::Refused(
                StatusCode::UNAUTHORIZED,
                "renewal needs the current certificate as TLS client certificate".into(),
            );
        }
        let Some(peer) = self.renew.verify(chain) else {
            return Decision::Refused(
                StatusCode::FORBIDDEN,
                "client certificate is not a valid certificate from this CA".into(),
            );
        };
        if !same_names(names, &peer.names) {
            return Decision::Refused(
                StatusCode::FORBIDDEN,
                format!(
                    "renewal must request the names of the current certificate {:?}, not {names:?}",
                    peer.names
                ),
            );
        }
        Decision::Approved(Reason::Renewal, Some(peer))
    }
}

fn same_names(a: &[String], b: &[String]) -> bool {
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.sort();
    a.dedup();
    b.sort();
    b.dedup();
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::{LeafSpec, LocalCa};
    use std::time::Duration;

    fn ca(cn: &str) -> LocalCa {
        let (c, k) = LocalCa::generate_root(cn, &rcgen::PKCS_ECDSA_P256_SHA256, 1).unwrap();
        LocalCa::from_pem(cn, &c, &k, vec![]).unwrap()
    }

    fn leaf(ca: &LocalCa, names: &[&str]) -> Vec<CertificateDer<'static>> {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let key = rcgen::KeyPair::generate().unwrap();
        let spec = LeafSpec {
            common_name: None,
            dns_names: &names,
            ip_addresses: &[],
            validity: Duration::from_secs(3600),
            rsa: false,
        };
        vec![ca.issue(&key, &spec).unwrap()]
    }

    fn policy(issuing: &LocalCa, identity: &LocalCa, manual: bool) -> Policy {
        Policy {
            allow: vec![NamePattern::parse("*.auto.test").unwrap()],
            identity: TrustStore::new(&identity.ca_certs()).unwrap(),
            identity_name_match: true,
            manual_approval: manual,
            renew: TrustStore::new(&issuing.ca_certs()).unwrap(),
        }
    }

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn enroll_matrix() {
        let issuing = ca("issuing");
        let identity = ca("identity");
        let stranger = ca("stranger");
        let p = policy(&issuing, &identity, true);

        let id_chain = leaf(&identity, &["gw1.home.test"]);
        assert!(matches!(
            p.enroll(&names(&["gw1.home.test"]), &id_chain),
            Decision::Approved(Reason::Identity, _)
        ));
        // Identity for another name: falls through to approval.
        assert!(matches!(
            p.enroll(&names(&["gw2.home.test"]), &id_chain),
            Decision::NeedsApproval(_)
        ));
        assert!(matches!(
            p.enroll(&names(&["x.auto.test"]), &[]),
            Decision::Approved(Reason::Allowlist, _)
        ));
        assert!(matches!(
            p.enroll(&names(&["x.auto.test", "y.other.test"]), &[]),
            Decision::NeedsApproval(_)
        ));
        assert!(matches!(
            p.enroll(&names(&["a.home.test"]), &leaf(&stranger, &["a.home.test"])),
            Decision::NeedsApproval(None)
        ));

        let strict = policy(&issuing, &identity, false);
        assert!(matches!(
            strict.enroll(&names(&["a.home.test"]), &[]),
            Decision::Refused(StatusCode::FORBIDDEN, _)
        ));
    }

    #[test]
    fn reenroll_matrix() {
        let issuing = ca("issuing");
        let identity = ca("identity");
        let p = policy(&issuing, &identity, false);
        let current = leaf(&issuing, &["gw1.home.test"]);
        assert!(matches!(
            p.reenroll(&names(&["gw1.home.test"]), &current),
            Decision::Approved(Reason::Renewal, _)
        ));
        assert!(matches!(
            p.reenroll(&names(&["gw2.home.test"]), &current),
            Decision::Refused(StatusCode::FORBIDDEN, _)
        ));
        assert!(matches!(
            p.reenroll(&names(&["gw1.home.test"]), &[]),
            Decision::Refused(StatusCode::UNAUTHORIZED, _)
        ));
        let foreign = leaf(&identity, &["gw1.home.test"]);
        assert!(matches!(
            p.reenroll(&names(&["gw1.home.test"]), &foreign),
            Decision::Refused(StatusCode::FORBIDDEN, _)
        ));
    }
}
