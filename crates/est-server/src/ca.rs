//! A local CA: a certificate and key on disk that sign leaves.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, anyhow};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData, SanType, SerialNumber,
};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::CertificateDer;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::config::CaConfig;
use crate::tls::read_certs;

/// Clock skew a client may have: certificates start this much in the
/// past.
const BACKDATE: Duration = Duration::from_secs(300);

pub struct LocalCa {
    pub name: String,
    issuer: rcgen::Issuer<'static, KeyPair>,
    cert: CertificateDer<'static>,
    /// Certificates above the signing CA.
    chain: Vec<CertificateDer<'static>>,
    not_after: OffsetDateTime,
}

/// What a leaf is for.
pub struct LeafSpec<'a> {
    pub common_name: Option<&'a str>,
    pub dns_names: &'a [String],
    pub ip_addresses: &'a [IpAddr],
    pub validity: Duration,
    /// Add `keyEncipherment` (RSA keys).
    pub rsa: bool,
}

impl LocalCa {
    pub fn load(cfg: &CaConfig) -> anyhow::Result<Self> {
        let cert_pem = std::fs::read_to_string(&cfg.cert)
            .with_context(|| format!("read {}", cfg.cert.display()))?;
        let key_pem = std::fs::read_to_string(&cfg.key)
            .with_context(|| format!("read {}", cfg.key.display()))?;
        let chain = match &cfg.chain {
            Some(path) => read_certs(path)?,
            None => Vec::new(),
        };
        Self::from_pem(&cfg.name, &cert_pem, &key_pem, chain)
    }

    pub fn from_pem(
        name: &str,
        cert_pem: &str,
        key_pem: &str,
        chain: Vec<CertificateDer<'static>>,
    ) -> anyhow::Result<Self> {
        let cert = crate::tls::parse_certs(cert_pem.as_bytes())?.remove(0);
        let key = KeyPair::from_pem(key_pem).map_err(|e| anyhow!("CA {name}: key: {e}"))?;
        let (_, parsed) =
            X509Certificate::from_der(&cert).map_err(|e| anyhow!("CA {name}: certificate: {e}"))?;
        if parsed.public_key().raw != key.subject_public_key_info().as_slice() {
            return Err(anyhow!("CA {name}: certificate and key don't match"));
        }
        if !parsed.is_ca() {
            return Err(anyhow!(
                "CA {name}: certificate is not a CA (basicConstraints)"
            ));
        }
        let not_after = parsed.validity().not_after.to_datetime();
        let issuer =
            rcgen::Issuer::from_ca_cert_der(&cert, key).map_err(|e| anyhow!("CA {name}: {e}"))?;
        Ok(Self {
            name: name.to_string(),
            issuer,
            cert,
            chain,
            not_after,
        })
    }

    /// Generate a self-signed root CA (for `init`); returns the
    /// certificate and key as PEM.
    pub fn generate_root(
        common_name: &str,
        alg: &'static rcgen::SignatureAlgorithm,
        years: u32,
    ) -> anyhow::Result<(String, String)> {
        let key = KeyPair::generate_for(alg)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - BACKDATE;
        params.not_after = now + time::Duration::days(365 * i64::from(years));
        params.serial_number = Some(random_serial()?);
        let cert = params.self_signed(&key)?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    /// Sign a TLS leaf (serverAuth and clientAuth) for `public_key`.
    pub fn issue(
        &self,
        public_key: &impl PublicKeyData,
        spec: &LeafSpec<'_>,
    ) -> anyhow::Result<CertificateDer<'static>> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        if let Some(cn) = spec.common_name {
            params.distinguished_name.push(DnType::CommonName, cn);
        }
        for name in spec.dns_names {
            params
                .subject_alt_names
                .push(SanType::DnsName(name.as_str().try_into()?));
        }
        params
            .subject_alt_names
            .extend(spec.ip_addresses.iter().map(|ip| SanType::IpAddress(*ip)));
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        if spec.rsa {
            params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
        }
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.use_authority_key_identifier_extension = true;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - BACKDATE;
        params.not_after = std::cmp::min(now + spec.validity, self.not_after);
        params.serial_number = Some(random_serial()?);
        Ok(params.signed_by(public_key, &self.issuer)?.der().clone())
    }

    /// The signing CA and the certificates above it.
    pub fn ca_certs(&self) -> Vec<CertificateDer<'static>> {
        std::iter::once(self.cert.clone())
            .chain(self.chain.iter().cloned())
            .collect()
    }
}

/// The chain to send with a leaf: the CA certificates, without
/// self-signed roots unless `include_root`.
pub fn answer_chain(
    leaf: CertificateDer<'static>,
    ca_certs: &[CertificateDer<'static>],
    include_root: bool,
) -> Vec<CertificateDer<'static>> {
    std::iter::once(leaf)
        .chain(
            ca_certs
                .iter()
                .filter(|c| include_root || !is_self_signed(c))
                .cloned(),
        )
        .collect()
}

pub fn is_self_signed(der: &[u8]) -> bool {
    X509Certificate::from_der(der).is_ok_and(|(_, c)| c.subject().as_raw() == c.issuer().as_raw())
}

/// 20 random bytes, positive as an INTEGER (RFC 5280 4.1.2.2).
fn random_serial() -> anyhow::Result<SerialNumber> {
    let mut bytes = [0u8; 20];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("system RNG failed"))?;
    bytes[0] = (bytes[0] & 0x7f) | 0x01;
    Ok(SerialNumber::from_slice(&bytes))
}

/// Write `data` atomically (temp file + rename), with mode 0600 if
/// `private`.
pub fn write_file(path: &Path, data: &[u8], private: bool) -> anyhow::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name()
            .ok_or_else(|| anyhow!("no file name: {}", path.display()))?
            .to_string_lossy()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(&tmp)
        .with_context(|| format!("write {}", tmp.display()))?;
    file.write_all(data)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_server_and_client_leaf() {
        let (cert, key) =
            LocalCa::generate_root("Test CA", &rcgen::PKCS_ECDSA_P256_SHA256, 1).unwrap();
        let ca = LocalCa::from_pem("t", &cert, &key, vec![]).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let names = vec!["gw1.home.example.com".to_string()];
        let der = ca
            .issue(
                &leaf_key,
                &LeafSpec {
                    common_name: Some("gw1.home.example.com"),
                    dns_names: &names,
                    ip_addresses: &[],
                    validity: Duration::from_secs(86400),
                    rsa: false,
                },
            )
            .unwrap();
        let (_, leaf) = X509Certificate::from_der(&der).unwrap();
        let eku = leaf.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.server_auth && eku.client_auth);
        assert!(leaf.key_usage().unwrap().unwrap().value.digital_signature());
        assert!(!leaf.is_ca());
        assert_eq!(
            leaf.issuer().as_raw(),
            X509Certificate::from_der(&ca.ca_certs()[0])
                .unwrap()
                .1
                .subject()
                .as_raw()
        );

        let chain = answer_chain(der.clone(), &ca.ca_certs(), false);
        assert_eq!(chain.len(), 1, "a self-signed root stays out");
        assert_eq!(answer_chain(der, &ca.ca_certs(), true).len(), 2);
    }

    #[test]
    fn refuses_mismatched_key() {
        let (cert, _) = LocalCa::generate_root("A", &rcgen::PKCS_ECDSA_P256_SHA256, 1).unwrap();
        let (_, other_key) =
            LocalCa::generate_root("B", &rcgen::PKCS_ECDSA_P256_SHA256, 1).unwrap();
        assert!(LocalCa::from_pem("t", &cert, &other_key, vec![]).is_err());
    }
}
