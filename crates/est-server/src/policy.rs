//! Who gets a certificate for which names.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::http::StatusCode;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;

use crate::clients::{Client, Lookup, Registry};
use crate::names::NamePattern;
use crate::peer::{TrustStore, VerifiedPeer, describe};

/// Why a request may be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// `simplereenroll` with the certificate being renewed.
    Renewal,
    /// A client certificate from a device identity CA.
    Identity,
    /// The names are on the allowlist.
    Allowlist,
    /// The key is registered for the names.
    Registered,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Renewal => "renewal",
            Reason::Identity => "identity",
            Reason::Allowlist => "allowlist",
            Reason::Registered => "registered",
        }
    }
}

/// How a label treats registered clients (`registered = …`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Registration {
    /// Not looked at.
    #[default]
    Off,
    /// A registered key gets its names; everything else as without.
    Optional,
    /// Only registered keys get anything, renewals included.
    Required,
}

#[derive(Debug)]
pub enum Decision {
    /// With the verified client certificate and the registered client,
    /// where there is one.
    Approved(Reason, Option<VerifiedPeer>, Option<Arc<Client>>),
    /// An administrator has to approve.
    NeedsApproval(Option<VerifiedPeer>),
    Refused(StatusCode, String),
}

pub struct Policy {
    /// The label's name, for registrations limited to labels.
    pub label: String,
    pub allow: Vec<NamePattern>,
    pub identity: TrustStore,
    pub identity_name_match: bool,
    pub manual_approval: bool,
    /// Anchors of the certificates this label issues; the signer may
    /// learn them as it goes.
    pub renew: Arc<ArcSwap<TrustStore>>,
    pub registration: Registration,
    pub clients: Arc<Registry>,
}

impl Policy {
    /// `simpleenroll` for the key `spki_der`: registration, device
    /// identity, allowlist, approval.
    pub fn enroll(
        &self,
        names: &[String],
        spki_der: &[u8],
        chain: &[CertificateDer<'static>],
    ) -> Decision {
        let identity = self.identity.verify(chain);
        match self.registration {
            Registration::Off => {}
            Registration::Optional => {
                if let Ok(client) = self.clients.authorize(spki_der, names, &self.label) {
                    return Decision::Approved(Reason::Registered, identity, Some(client));
                }
            }
            Registration::Required => {
                return match self.clients.authorize(spki_der, names, &self.label) {
                    Ok(client) => Decision::Approved(Reason::Registered, identity, Some(client)),
                    Err(why) => Decision::Refused(StatusCode::FORBIDDEN, why),
                };
            }
        }
        if let Some(id) = &identity
            && (!self.identity_name_match || names.iter().all(|n| id.names.contains(n)))
        {
            return Decision::Approved(Reason::Identity, identity, None);
        }
        if names
            .iter()
            .all(|n| self.allow.iter().any(|p| p.matches(n)))
        {
            return Decision::Approved(Reason::Allowlist, identity, None);
        }
        if self.manual_approval {
            return Decision::NeedsApproval(identity.or_else(|| self.renew.load().verify(chain)));
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

    /// `simplereenroll` for the key `spki_der`. Without registration the
    /// client certificate must be one this label issued, for the same
    /// names (RFC 7030 4.2.2). With it, the client certificate's key and
    /// the requested key must belong to the same registered client, which
    /// is registered for the names; the TLS handshake has shown the
    /// client holds the certificate's key.
    pub fn reenroll(
        &self,
        names: &[String],
        spki_der: &[u8],
        chain: &[CertificateDer<'static>],
    ) -> Decision {
        let Some(leaf) = chain.first() else {
            return Decision::Refused(
                StatusCode::UNAUTHORIZED,
                "renewal needs the current certificate as TLS client certificate".into(),
            );
        };
        if self.registration != Registration::Off {
            match self.registered_renewal(names, spki_der, leaf) {
                Ok(client) => {
                    return Decision::Approved(Reason::Renewal, describe(leaf), Some(client));
                }
                Err(why) if self.registration == Registration::Required => {
                    return Decision::Refused(StatusCode::FORBIDDEN, why);
                }
                Err(_) => {}
            }
        }
        let Some(peer) = self.renew.load().verify(chain) else {
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
        Decision::Approved(Reason::Renewal, Some(peer), None)
    }

    fn registered_renewal(
        &self,
        names: &[String],
        spki_der: &[u8],
        leaf: &CertificateDer<'static>,
    ) -> Result<Arc<Client>, String> {
        let current = describe(leaf).ok_or("unreadable client certificate")?;
        let holder = match self.clients.owner(&current.spki_der) {
            Lookup::One(c) => c,
            Lookup::Unknown => return Err("the client certificate's key is not registered".into()),
            Lookup::Ambiguous(ids) => {
                return Err(format!(
                    "the client certificate's key is registered more than once ({})",
                    ids.join(", ")
                ));
            }
        };
        let client = self.clients.authorize(spki_der, names, &self.label)?;
        if client.id != holder.id {
            return Err(format!(
                "the client certificate belongs to {}, the requested key to {}",
                holder.id, client.id
            ));
        }
        Ok(client)
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
        leaf_with(ca, names, &rcgen::KeyPair::generate().unwrap())
    }

    fn leaf_with(
        ca: &LocalCa,
        names: &[&str],
        key: &rcgen::KeyPair,
    ) -> Vec<CertificateDer<'static>> {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let spec = LeafSpec {
            common_name: None,
            dns_names: &names,
            ip_addresses: &[],
            validity: Duration::from_secs(3600),
            rsa: false,
        };
        vec![ca.issue(key, &spec).unwrap()]
    }

    fn policy(issuing: &LocalCa, identity: &LocalCa, manual: bool) -> Policy {
        Policy {
            label: String::new(),
            allow: vec![NamePattern::parse("*.auto.test").unwrap()],
            identity: TrustStore::new(&identity.ca_certs()).unwrap(),
            identity_name_match: true,
            manual_approval: manual,
            renew: Arc::new(ArcSwap::from_pointee(
                TrustStore::new(&issuing.ca_certs()).unwrap(),
            )),
            registration: Registration::Off,
            clients: Arc::default(),
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
            p.enroll(&names(&["gw1.home.test"]), b"key", &id_chain),
            Decision::Approved(Reason::Identity, ..)
        ));
        // Identity for another name: falls through to approval.
        assert!(matches!(
            p.enroll(&names(&["gw2.home.test"]), b"key", &id_chain),
            Decision::NeedsApproval(_)
        ));
        assert!(matches!(
            p.enroll(&names(&["x.auto.test"]), b"key", &[]),
            Decision::Approved(Reason::Allowlist, ..)
        ));
        assert!(matches!(
            p.enroll(&names(&["x.auto.test", "y.other.test"]), b"key", &[]),
            Decision::NeedsApproval(_)
        ));
        assert!(matches!(
            p.enroll(
                &names(&["a.home.test"]),
                b"key",
                &leaf(&stranger, &["a.home.test"])
            ),
            Decision::NeedsApproval(None)
        ));

        let strict = policy(&issuing, &identity, false);
        assert!(matches!(
            strict.enroll(&names(&["a.home.test"]), b"key", &[]),
            Decision::Refused(StatusCode::FORBIDDEN, ..)
        ));
    }

    #[test]
    fn reenroll_matrix() {
        let issuing = ca("issuing");
        let identity = ca("identity");
        let p = policy(&issuing, &identity, false);
        let current = leaf(&issuing, &["gw1.home.test"]);
        assert!(matches!(
            p.reenroll(&names(&["gw1.home.test"]), b"key", &current),
            Decision::Approved(Reason::Renewal, ..)
        ));
        assert!(matches!(
            p.reenroll(&names(&["gw2.home.test"]), b"key", &current),
            Decision::Refused(StatusCode::FORBIDDEN, ..)
        ));
        assert!(matches!(
            p.reenroll(&names(&["gw1.home.test"]), b"key", &[]),
            Decision::Refused(StatusCode::UNAUTHORIZED, ..)
        ));
        let foreign = leaf(&identity, &["gw1.home.test"]);
        assert!(matches!(
            p.reenroll(&names(&["gw1.home.test"]), b"key", &foreign),
            Decision::Refused(StatusCode::FORBIDDEN, ..)
        ));
    }

    fn spki(key: &rcgen::KeyPair) -> Vec<u8> {
        rcgen::PublicKeyData::subject_public_key_info(key)
    }

    /// `gw1.home.test` registered with keys `a` and `b`.
    fn registered(mode: Registration, issuing: &LocalCa, a: &[u8], b: &[u8]) -> Policy {
        use crate::clients::{Client, ClientSpec, Source, encode_pin, pin};
        let clients = Registry::default();
        clients.set_file(vec![
            Client::new(
                "file:gw1".into(),
                Source::File,
                &ClientSpec {
                    dns_names: names(&["gw1.home.test"]),
                    pins: vec![encode_pin(&pin(a)), encode_pin(&pin(b))],
                    labels: vec![],
                },
            )
            .unwrap(),
        ]);
        Policy {
            registration: mode,
            clients: Arc::new(clients),
            ..policy(issuing, &ca("identity"), false)
        }
    }

    #[test]
    fn registered_enroll() {
        let issuing = ca("issuing");
        let (a, b) = (
            rcgen::KeyPair::generate().unwrap(),
            rcgen::KeyPair::generate().unwrap(),
        );
        let required = registered(Registration::Required, &issuing, &spki(&a), &spki(&b));
        assert!(matches!(
            required.enroll(&names(&["gw1.home.test"]), &spki(&a), &[]),
            Decision::Approved(Reason::Registered, _, Some(_))
        ));
        // Another key, or another name: refused, allowlist or not.
        assert!(matches!(
            required.enroll(&names(&["gw1.home.test"]), b"other", &[]),
            Decision::Refused(StatusCode::FORBIDDEN, _)
        ));
        assert!(matches!(
            required.enroll(&names(&["x.auto.test"]), &spki(&a), &[]),
            Decision::Refused(StatusCode::FORBIDDEN, _)
        ));

        let optional = registered(Registration::Optional, &issuing, &spki(&a), &spki(&b));
        assert!(matches!(
            optional.enroll(&names(&["gw1.home.test"]), &spki(&a), &[]),
            Decision::Approved(Reason::Registered, _, Some(_))
        ));
        assert!(matches!(
            optional.enroll(&names(&["x.auto.test"]), b"other", &[]),
            Decision::Approved(Reason::Allowlist, _, None)
        ));
    }

    #[test]
    fn registered_reenroll() {
        let issuing = ca("issuing");
        let (a, b, c) = (
            rcgen::KeyPair::generate().unwrap(),
            rcgen::KeyPair::generate().unwrap(),
            rcgen::KeyPair::generate().unwrap(),
        );
        let required = registered(Registration::Required, &issuing, &spki(&a), &spki(&b));
        // Any CA will do (a public CA, say): the key counts.
        let stranger = ca("stranger");
        let current = leaf_with(&stranger, &["gw1.home.test"], &a);
        assert!(matches!(
            required.reenroll(&names(&["gw1.home.test"]), &spki(&a), &current),
            Decision::Approved(Reason::Renewal, Some(_), Some(_))
        ));
        // Changing to the second registered key.
        assert!(matches!(
            required.reenroll(&names(&["gw1.home.test"]), &spki(&b), &current),
            Decision::Approved(Reason::Renewal, _, Some(_))
        ));
        // A certificate of our own CA for the name, with an unregistered key.
        let ours = leaf_with(&issuing, &["gw1.home.test"], &c);
        assert!(matches!(
            required.reenroll(&names(&["gw1.home.test"]), &spki(&c), &ours),
            Decision::Refused(StatusCode::FORBIDDEN, _)
        ));
        // A registered certificate asking for an unregistered key.
        assert!(matches!(
            required.reenroll(&names(&["gw1.home.test"]), &spki(&c), &current),
            Decision::Refused(StatusCode::FORBIDDEN, _)
        ));
        assert!(matches!(
            required.reenroll(&names(&["gw1.home.test"]), &spki(&a), &[]),
            Decision::Refused(StatusCode::UNAUTHORIZED, _)
        ));

        // Optional: an unregistered certificate of our CA renews as before.
        let optional = registered(Registration::Optional, &issuing, &spki(&a), &spki(&b));
        assert!(matches!(
            optional.reenroll(&names(&["gw1.home.test"]), &spki(&c), &ours),
            Decision::Approved(Reason::Renewal, Some(_), None)
        ));
    }
}
