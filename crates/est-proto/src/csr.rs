//! PKCS#10 requests (RFC 2986).

use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;

use crate::error::{Error, Result};

/// Type and size of the requested public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// ECDSA on P-256.
    EcP256,
    /// ECDSA on P-384.
    EcP384,
    /// RSA with the given modulus size in bits.
    Rsa(usize),
}

impl KeyKind {
    /// Whether the key can be used for RSA key transport (TLS 1.2 static
    /// RSA), so the certificate gets `keyEncipherment` too.
    pub fn is_rsa(self) -> bool {
        matches!(self, KeyKind::Rsa(_))
    }
}

/// A parsed PKCS#10 request whose signature has been verified.
#[derive(Debug, Clone)]
pub struct Csr {
    /// The request as received (DER).
    pub der: Vec<u8>,
    /// The subject name (DER), possibly an empty sequence.
    pub subject_der: Vec<u8>,
    /// The subject's common name, if it has one.
    pub common_name: Option<String>,
    /// The requested SAN DNS names, lowercased, in request order.
    pub dns_names: Vec<String>,
    /// The public key (DER `SubjectPublicKeyInfo`).
    pub spki_der: Vec<u8>,
    /// Type of the public key.
    pub key: KeyKind,
}

impl Csr {
    /// Parse DER, verify the self-signature and check that the request
    /// only asks for what the server issues: DNS names and nothing else
    /// in the SAN, an ECDSA P-256/P-384 or RSA (>= 2048 bit) key.
    pub fn parse(der: &[u8]) -> Result<Self> {
        let (rest, req) = X509CertificationRequest::from_der(der)
            .map_err(|e| Error::MalformedCsr(e.to_string()))?;
        if !rest.is_empty() {
            return Err(Error::MalformedCsr(
                "trailing data after the request".into(),
            ));
        }
        req.verify_signature()
            .map_err(|e| Error::CsrSignature(e.to_string()))?;

        let info = &req.certification_request_info;
        let common_name = match info.subject.iter_common_name().next() {
            Some(cn) => Some(
                cn.as_str()
                    .map_err(|e| Error::MalformedCsr(format!("common name: {e}")))?
                    .to_string(),
            ),
            None => None,
        };

        let mut dns_names = Vec::new();
        if let Some(exts) = req.requested_extensions() {
            for ext in exts {
                if let ParsedExtension::SubjectAlternativeName(san) = ext {
                    for name in &san.general_names {
                        match name {
                            GeneralName::DNSName(n) => dns_names.push(n.to_ascii_lowercase()),
                            other => {
                                return Err(Error::UnsupportedCsr(format!(
                                    "only DNS names are issued, the request has {other}"
                                )));
                            }
                        }
                    }
                }
            }
        }

        let key = match info.subject_pki.parsed() {
            Ok(PublicKey::EC(ec)) => match ec.key_size() {
                256 => KeyKind::EcP256,
                384 => KeyKind::EcP384,
                n => return Err(Error::UnsupportedCsr(format!("EC key of {n} bits"))),
            },
            Ok(PublicKey::RSA(rsa)) if rsa.key_size() >= 2048 => KeyKind::Rsa(rsa.key_size()),
            Ok(PublicKey::RSA(rsa)) => {
                return Err(Error::UnsupportedCsr(format!(
                    "RSA key of {} bits",
                    rsa.key_size()
                )));
            }
            Ok(_) => return Err(Error::UnsupportedCsr("key type".into())),
            Err(e) => return Err(Error::MalformedCsr(format!("public key: {e}"))),
        };

        Ok(Csr {
            der: der.to_vec(),
            subject_der: info.subject.as_raw().to_vec(),
            common_name,
            dns_names,
            spki_der: info.subject_pki.raw.to_vec(),
            key,
        })
    }

    /// The names the certificate is for: the SAN DNS names, or the
    /// common name if the request has no SAN.
    pub fn requested_names(&self) -> Vec<String> {
        if !self.dns_names.is_empty() {
            return self.dns_names.clone();
        }
        self.common_name
            .iter()
            .map(|cn| cn.to_ascii_lowercase())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    fn csr(names: &[&str], cn: Option<&str>, extra: Option<SanType>) -> Vec<u8> {
        let mut params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        params.distinguished_name = DistinguishedName::new();
        if let Some(cn) = cn {
            params.distinguished_name.push(DnType::CommonName, cn);
        }
        if let Some(extra) = extra {
            params.subject_alt_names.push(extra);
        }
        let key = KeyPair::generate().unwrap();
        params.serialize_request(&key).unwrap().der().to_vec()
    }

    #[test]
    fn parses_gateway_style_request() {
        let der = csr(
            &["GW1.home.example.com"],
            Some("gw1.home.example.com"),
            None,
        );
        let c = Csr::parse(&der).unwrap();
        assert_eq!(c.dns_names, vec!["gw1.home.example.com"]);
        assert_eq!(c.common_name.as_deref(), Some("gw1.home.example.com"));
        assert_eq!(c.key, KeyKind::EcP256);
        assert_eq!(c.requested_names(), vec!["gw1.home.example.com"]);
    }

    #[test]
    fn falls_back_to_common_name() {
        let c = Csr::parse(&csr(&[], Some("Box.Example.com"), None)).unwrap();
        assert_eq!(c.requested_names(), vec!["box.example.com"]);
    }

    #[test]
    fn refuses_ip_san_and_tampering() {
        let ip = SanType::IpAddress("10.0.0.1".parse().unwrap());
        assert!(matches!(
            Csr::parse(&csr(&["a.test"], None, Some(ip))),
            Err(Error::UnsupportedCsr(_))
        ));

        let mut der = csr(&["a.test"], None, None);
        let n = der.len();
        der[n - 5] ^= 0x01;
        assert!(Csr::parse(&der).is_err());
    }
}
