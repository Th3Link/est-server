//! What the client's TLS certificate says, once it is verified against a
//! label's trust anchors.

use std::net::SocketAddr;

use rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, KeyUsage};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Per connection: the client's address and the certificate chain it
/// presented (empty without one). Unverified: see [`TrustStore`].
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub remote: SocketAddr,
    pub chain: Vec<CertificateDer<'static>>,
}

/// Normalise an IPv4-mapped IPv6 address (`::ffff:192.0.2.1`) to the
/// IPv4 address, as a dual-stack socket reports IPv4 clients that way.
pub fn normalize(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => addr,
        },
        v4 => v4,
    }
}

/// Trust anchors for one purpose (renewal, device identities).
#[derive(Debug, Default)]
pub struct TrustStore {
    anchors: Vec<TrustAnchor<'static>>,
}

/// A client certificate that chains to a [`TrustStore`].
#[derive(Debug, Clone)]
pub struct VerifiedPeer {
    pub subject_der: Vec<u8>,
    pub subject: String,
    /// SAN DNS names, lowercased; the CN if there are none.
    pub names: Vec<String>,
    pub spki_der: Vec<u8>,
}

impl TrustStore {
    pub fn new(certs: &[CertificateDer<'static>]) -> anyhow::Result<Self> {
        let anchors = certs
            .iter()
            .map(|c| {
                webpki::anchor_from_trusted_cert(c)
                    .map(|a| a.to_owned())
                    .map_err(|e| anyhow::anyhow!("trust anchor: {e}"))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(Self { anchors })
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Verify `chain` (leaf first) against these anchors, now. The
    /// leaf may carry `clientAuth` or `serverAuth` (or no extended key
    /// usage): a client renewing a TLS server certificate presents that
    /// certificate.
    pub fn verify(&self, chain: &[CertificateDer<'static>]) -> Option<VerifiedPeer> {
        let (leaf, intermediates) = chain.split_first()?;
        if self.anchors.is_empty() {
            return None;
        }
        let ee = EndEntityCert::try_from(leaf).ok()?;
        let algs = crate::tls::provider().signature_verification_algorithms.all;
        let now = UnixTime::now();
        let ok = [KeyUsage::client_auth(), KeyUsage::server_auth()]
            .into_iter()
            .any(|usage| {
                ee.verify_for_usage(algs, &self.anchors, intermediates, now, usage, None, None)
                    .is_ok()
            });
        if !ok {
            return None;
        }
        describe(leaf)
    }
}

/// Subject, names and key of a certificate.
pub fn describe(der: &[u8]) -> Option<VerifiedPeer> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let mut names: Vec<String> = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for n in &san.value.general_names {
            if let GeneralName::DNSName(d) = n {
                names.push(d.to_ascii_lowercase());
            }
        }
    }
    if names.is_empty() {
        names.extend(
            cert.subject()
                .iter_common_name()
                .filter_map(|cn| cn.as_str().ok())
                .map(str::to_ascii_lowercase),
        );
    }
    Some(VerifiedPeer {
        subject_der: cert.subject().as_raw().to_vec(),
        subject: cert.subject().to_string(),
        names,
        spki_der: cert.public_key().raw.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_mapped_addresses() {
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:443".parse().unwrap();
        assert_eq!(
            normalize(mapped),
            "192.0.2.7:443".parse::<SocketAddr>().unwrap()
        );
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(normalize(v6), v6);
    }
}
