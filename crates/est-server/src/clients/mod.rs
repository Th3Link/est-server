//! Registered clients: the names a client may get certificates for,
//! bound to its public key(s). Read from a directory (`[clients] dir`)
//! and/or from `EstClient` objects in Kubernetes (`[clients] kubernetes`).

pub mod file;
pub mod k8s;

use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use base64::Engine as _;

use crate::names::is_valid_dns_name;

/// The pin of a public key: SHA-256 over its DER `SubjectPublicKeyInfo`
/// (the `pin-sha256` of RFC 7469).
pub type Pin = [u8; 32];

pub fn pin(spki_der: &[u8]) -> Pin {
    let digest = ring::digest::digest(&ring::digest::SHA256, spki_der);
    digest.as_ref().try_into().expect("SHA-256 is 32 bytes")
}

/// A pin as written in client entries: base64.
pub fn encode_pin(pin: &Pin) -> String {
    base64::engine::general_purpose::STANDARD.encode(pin)
}

pub fn decode_pin(s: &str) -> Result<Pin, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()
        .and_then(|b| Pin::try_from(b).ok())
        .ok_or_else(|| format!("{s:?} is not a pin-sha256 (base64 of 32 bytes)"))
}

/// The public key (DER `SubjectPublicKeyInfo`) in a CSR, certificate,
/// public key or PKCS#8 private key, PEM or DER: what `est-server pin`
/// reads.
pub fn spki_of(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use rustls::pki_types::pem::{PemObject, SectionKind};
    let pem = std::str::from_utf8(data).is_ok_and(|s| s.contains("-----BEGIN"));
    let ders: Vec<(Option<SectionKind>, Vec<u8>)> = if pem {
        <(SectionKind, Vec<u8>)>::pem_slice_iter(data)
            .map(|r| r.map(|(k, d)| (Some(k), d)))
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("PEM: {e}"))?
    } else {
        vec![(None, data.to_vec())]
    };
    for (kind, der) in ders {
        let any = kind.is_none();
        if (any || kind == Some(SectionKind::Csr))
            && let Ok(csr) = est_proto::csr::Csr::parse(&der)
        {
            return Ok(csr.spki_der);
        }
        if (any || kind == Some(SectionKind::Certificate))
            && let Some(cert) = crate::peer::describe(&der)
        {
            return Ok(cert.spki_der);
        }
        if (any || kind == Some(SectionKind::PublicKey))
            && let Ok((rest, _)) =
                <x509_parser::x509::SubjectPublicKeyInfo as x509_parser::prelude::FromDer<
                    x509_parser::error::X509Error,
                >>::from_der(&der)
            && rest.is_empty()
        {
            return Ok(der);
        }
        if (any || kind == Some(SectionKind::PrivateKey))
            && let Ok(key) = rcgen::KeyPair::try_from(der.as_slice())
        {
            return Ok(rcgen::PublicKeyData::subject_public_key_info(&key));
        }
        if matches!(
            kind,
            Some(SectionKind::EcPrivateKey | SectionKind::RsaPrivateKey)
        ) {
            anyhow::bail!(
                "SEC1/PKCS#1 private key: convert it (openssl pkcs8 -topk8 -nocrypt) or use the CSR or certificate"
            );
        }
    }
    anyhow::bail!("no CSR, certificate, public key or PKCS#8 private key found")
}

/// What an entry says, before it is checked.
#[derive(Debug, Clone, Default)]
pub struct ClientSpec {
    pub dns_names: Vec<String>,
    pub pins: Vec<String>,
    pub labels: Vec<String>,
}

/// Where an entry comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    File,
    Kubernetes { namespace: String, name: String },
}

/// A checked entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// For logs and the issue log: `file:<name>` or
    /// `kubernetes:<namespace>/<name>`.
    pub id: String,
    pub source: Source,
    /// Lowercased.
    pub dns_names: Vec<String>,
    pub pins: Vec<Pin>,
    /// EST labels the entry is for; empty for all.
    pub labels: Vec<String>,
}

impl Client {
    pub fn new(id: String, source: Source, spec: &ClientSpec) -> Result<Self, String> {
        if spec.dns_names.is_empty() {
            return Err("no dnsNames".into());
        }
        if spec.pins.is_empty() {
            return Err("no publicKeys".into());
        }
        let dns_names = spec
            .dns_names
            .iter()
            .map(|n| {
                let n = n.trim().to_ascii_lowercase();
                if is_valid_dns_name(&n) {
                    Ok(n)
                } else {
                    Err(format!("{n:?} is not a host name"))
                }
            })
            .collect::<Result<_, _>>()?;
        let pins = spec
            .pins
            .iter()
            .map(|p| decode_pin(p))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            id,
            source,
            dns_names,
            pins,
            labels: spec.labels.clone(),
        })
    }

    /// Whether this entry lets its key get a certificate for `names` on
    /// `label`; the reason if not.
    pub fn check(&self, names: &[String], label: &str) -> Result<(), String> {
        if !self.labels.is_empty() && !self.labels.iter().any(|l| l == label) {
            return Err(format!("{} is not registered for this label", self.id));
        }
        match names.iter().find(|n| !self.dns_names.contains(n)) {
            Some(n) => Err(format!("{} is not registered for {n}", self.id)),
            None => Ok(()),
        }
    }
}

/// Entries left out, with the reason: `(entry, why)`.
pub type Rejected = Vec<(String, String)>;

/// Drop entries whose pins another entry of the same source has too; a
/// key must belong to one client. Returns the dropped ones with the
/// reason.
pub fn drop_duplicates(clients: &mut Vec<Client>) -> Rejected {
    let mut dropped = Vec::new();
    let mut keep = vec![true; clients.len()];
    for (i, a) in clients.iter().enumerate() {
        for (j, b) in clients.iter().enumerate() {
            if i != j && a.pins.iter().any(|p| b.pins.contains(p)) {
                keep[i] = false;
                dropped.push((a.id.clone(), format!("a key is registered by {} too", b.id)));
                break;
            }
        }
    }
    let mut keep = keep.into_iter();
    clients.retain(|_| keep.next().unwrap_or(false));
    dropped
}

/// The owner of a key.
#[derive(Debug)]
pub enum Lookup {
    Unknown,
    One(Arc<Client>),
    /// Registered in both sources.
    Ambiguous(Vec<String>),
}

/// The registered clients of all sources; read lock-free per request.
#[derive(Default)]
pub struct Registry {
    file: ArcSwap<Vec<Arc<Client>>>,
    kubernetes: ArcSwap<Vec<Arc<Client>>>,
    /// Set when the entries come from Kubernetes: where issues are
    /// recorded in `status.lastIssued`.
    status: OnceLock<k8s::StatusWriter>,
}

impl Registry {
    pub fn set_file(&self, clients: Vec<Client>) {
        self.file
            .store(Arc::new(clients.into_iter().map(Arc::new).collect()));
    }

    pub fn set_kubernetes(&self, clients: Vec<Client>) {
        self.kubernetes
            .store(Arc::new(clients.into_iter().map(Arc::new).collect()));
    }

    pub fn len(&self) -> usize {
        self.file.load().len() + self.kubernetes.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Who registered the key `spki_der`.
    pub fn owner(&self, spki_der: &[u8]) -> Lookup {
        let pin = pin(spki_der);
        let mut found: Vec<Arc<Client>> = Vec::new();
        for source in [self.file.load(), self.kubernetes.load()] {
            found.extend(source.iter().filter(|c| c.pins.contains(&pin)).cloned());
        }
        match found.len() {
            0 => Lookup::Unknown,
            1 => Lookup::One(found.remove(0)),
            _ => Lookup::Ambiguous(found.iter().map(|c| c.id.clone()).collect()),
        }
    }

    /// The entry that lets key `spki_der` get `names` on `label`, or why
    /// there is none.
    pub fn authorize(
        &self,
        spki_der: &[u8],
        names: &[String],
        label: &str,
    ) -> Result<Arc<Client>, String> {
        match self.owner(spki_der) {
            Lookup::Unknown => Err("the key is not registered".into()),
            Lookup::Ambiguous(ids) => Err(format!(
                "the key is registered more than once ({})",
                ids.join(", ")
            )),
            Lookup::One(client) => client.check(names, label).map(|()| client),
        }
    }

    /// Note an issued certificate on the entry (Kubernetes only); in the
    /// background, failures are logged.
    pub fn issued(&self, client: &Client, issue: k8s::LastIssued) {
        if let (Source::Kubernetes { namespace, name }, Some(status)) =
            (&client.source, self.status.get())
        {
            status.last_issued(namespace.clone(), name.clone(), issue);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(names: &[&str], pins: &[&Pin], labels: &[&str]) -> ClientSpec {
        ClientSpec {
            dns_names: names.iter().map(|s| s.to_string()).collect(),
            pins: pins.iter().map(|p| encode_pin(p)).collect(),
            labels: labels.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn pin_is_rfc7469() {
        // openssl pkey -pubout -outform DER | openssl dgst -sha256 -binary | base64
        let key = rcgen::KeyPair::from_pem(
            "-----BEGIN PRIVATE KEY-----\n\
             MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvWSKhGLiyLhPkH1B\n\
             HfRz/DWSdlOtir8Ldg2rprYbweqhRANCAATac0KvQPTDwbVZ8iNC3UeCzzxhcYAX\n\
             JY841r2wddaJQN8CAEbB2/ek6MvdiMen3TIbA6+tX4o4PghRj5QhhjzJ\n\
             -----END PRIVATE KEY-----\n",
        )
        .unwrap();
        assert_eq!(
            encode_pin(&pin(&rcgen::PublicKeyData::subject_public_key_info(&key))),
            "n+ySAtnNUmtp0GQTO6oZUJn+dFSHlAfPhBunhhOkG9Q="
        );
        assert!(decode_pin("n+ySAtnNUmtp0GQTO6oZUJn+dFSHlAfPhBunhhOkG9Q=").is_ok());
        assert!(decode_pin("AAAA").is_err());
        assert!(decode_pin("not base64!").is_err());
    }

    #[test]
    fn pins_every_form_of_a_key() {
        let key = rcgen::KeyPair::generate().unwrap();
        let want = rcgen::PublicKeyData::subject_public_key_info(&key);
        let mut params = rcgen::CertificateParams::new(vec!["gw1.test".into()]).unwrap();
        let csr = params.serialize_request(&key).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let cert = params.self_signed(&key).unwrap();
        for data in [
            csr.pem().unwrap().into_bytes(),
            csr.der().to_vec(),
            cert.pem().into_bytes(),
            cert.der().to_vec(),
            key.public_key_pem().into_bytes(),
            key.serialize_pem().into_bytes(),
            key.serialize_der(),
        ] {
            assert_eq!(spki_of(&data).unwrap(), want);
        }
        assert!(spki_of(b"nothing").is_err());
    }

    #[test]
    fn checks_entries() {
        let p = pin(b"a");
        assert!(Client::new("x".into(), Source::File, &spec(&[], &[&p], &[])).is_err());
        assert!(Client::new("x".into(), Source::File, &spec(&["a.test"], &[], &[])).is_err());
        assert!(Client::new("x".into(), Source::File, &spec(&["*.a.test"], &[&p], &[])).is_err());
        let c = Client::new("x".into(), Source::File, &spec(&["GW1.test"], &[&p], &[])).unwrap();
        assert_eq!(c.dns_names, ["gw1.test"]);
    }

    #[test]
    fn authorizes_key_names_and_label() {
        let (a, b, c) = (pin(b"a"), pin(b"b"), pin(b"c"));
        let r = Registry::default();
        r.set_file(vec![
            Client::new(
                "file:gw1".into(),
                Source::File,
                &spec(&["gw1.test", "alt.test"], &[&a, &b], &[]),
            )
            .unwrap(),
            Client::new(
                "file:gw2".into(),
                Source::File,
                &spec(&["gw2.test"], &[&c], &["strict"]),
            )
            .unwrap(),
        ]);
        assert_eq!(r.len(), 2);
        // Both keys of gw1, any subset of its names.
        assert!(r.authorize(b"a", &names(&["gw1.test"]), "").is_ok());
        assert!(
            r.authorize(b"b", &names(&["alt.test", "gw1.test"]), "")
                .is_ok()
        );
        // Someone else's name, an unknown key.
        assert!(r.authorize(b"a", &names(&["gw2.test"]), "").is_err());
        assert!(r.authorize(b"d", &names(&["gw1.test"]), "").is_err());
        // gw2 only on its label.
        assert!(r.authorize(b"c", &names(&["gw2.test"]), "strict").is_ok());
        assert!(r.authorize(b"c", &names(&["gw2.test"]), "").is_err());
    }

    #[test]
    fn a_key_belongs_to_one_client() {
        let (a, b) = (pin(b"a"), pin(b"b"));
        let mut clients = vec![
            Client::new(
                "file:x".into(),
                Source::File,
                &spec(&["x.test"], &[&a], &[]),
            )
            .unwrap(),
            Client::new(
                "file:y".into(),
                Source::File,
                &spec(&["y.test"], &[&a, &b], &[]),
            )
            .unwrap(),
            Client::new(
                "file:z".into(),
                Source::File,
                &spec(&["z.test"], &[&b], &[]),
            )
            .unwrap(),
        ];
        let dropped = drop_duplicates(&mut clients);
        assert_eq!(clients.len(), 0);
        assert_eq!(dropped.len(), 3);

        // The same key in both sources: refused, whichever it is.
        let r = Registry::default();
        r.set_file(vec![
            Client::new(
                "file:x".into(),
                Source::File,
                &spec(&["x.test"], &[&a], &[]),
            )
            .unwrap(),
        ]);
        r.set_kubernetes(vec![
            Client::new(
                "kubernetes:est/x".into(),
                Source::Kubernetes {
                    namespace: "est".into(),
                    name: "x".into(),
                },
                &spec(&["x.test"], &[&a], &[]),
            )
            .unwrap(),
        ]);
        assert!(matches!(r.owner(b"a"), Lookup::Ambiguous(_)));
        assert!(r.authorize(b"a", &names(&["x.test"]), "").is_err());
    }
}
