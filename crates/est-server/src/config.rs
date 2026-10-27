//! The configuration file (TOML).

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::names::NamePattern;

const DAY: u64 = 86_400;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    /// Local CAs, referenced by name from `signer` and `server.tls.auto`.
    #[serde(default, rename = "ca")]
    pub cas: Vec<CaConfig>,
    /// The enrollment endpoints. The label with the empty name answers
    /// under `/.well-known/est`, the others under
    /// `/.well-known/est/<name>`.
    #[serde(rename = "label")]
    pub labels: Vec<LabelConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// EST listeners. `[::]:port` alone serves IPv6 and IPv4 on one
    /// socket; listing `0.0.0.0:port` too gives each family its own.
    #[serde(default = "default_listen")]
    pub listen: Vec<SocketAddr>,
    /// Plain HTTP listeners for `/healthz` and `/readyz`; empty turns
    /// them off.
    #[serde(default = "default_health_listen")]
    pub health_listen: Vec<SocketAddr>,
    /// Pending requests, the issue log and the server's own key live
    /// here.
    pub state_dir: PathBuf,
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Server certificate chain (PEM), leaf first. Re-read when it
    /// changes, e.g. when cert-manager renews a mounted secret.
    pub cert: PathBuf,
    /// Server private key (PEM, PKCS#8, SEC1 or PKCS#1).
    pub key: PathBuf,
    /// Issue and renew `cert`/`key` from a local CA.
    pub auto: Option<AutoTls>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoTls {
    pub ca: String,
    pub dns_names: Vec<String>,
    #[serde(default)]
    pub ip_addresses: Vec<IpAddr>,
    #[serde(default = "default_validity", with = "humantime_serde")]
    pub validity: Duration,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    pub name: String,
    /// The signing CA certificate (PEM).
    pub cert: PathBuf,
    /// Its private key (PEM).
    pub key: PathBuf,
    /// Certificates above the signing CA (PEM): intermediates, and the
    /// root if it isn't the signing CA itself.
    pub chain: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelConfig {
    #[serde(default)]
    pub name: String,
    /// Serve this label under a path of its own instead of
    /// `/.well-known/est[/<name>]`.
    pub path: Option<String>,
    pub signer: SignerConfig,
    /// Names that get a certificate on first enrollment without further
    /// authentication (`*.example.com`, `**.example.com`, exact names).
    #[serde(default)]
    pub allow: Vec<String>,
    /// CAs (PEM files) of device identities. A first enrollment with a
    /// client certificate from one of them is approved.
    #[serde(default)]
    pub identity_cas: Vec<PathBuf>,
    /// Requested names must appear in the device identity (SAN or CN).
    #[serde(default = "yes")]
    pub identity_name_match: bool,
    /// First enrollments that nothing else approves wait for an
    /// administrator (`202`) instead of being refused.
    #[serde(default)]
    pub manual_approval: bool,
    /// `Retry-After` of a `202`.
    #[serde(default = "default_retry_after", with = "humantime_serde")]
    pub retry_after: Duration,
    /// Put the root CA into the answer too.
    #[serde(default)]
    pub include_root: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SignerConfig {
    /// Sign with a local CA from `[[ca]]`.
    Local {
        ca: String,
        #[serde(default = "default_validity", with = "humantime_serde")]
        validity: Duration,
    },
    /// Hand the request to cert-manager as a `CertificateRequest`.
    CertManager {
        /// Namespace of the requests; defaults to the pod's namespace.
        namespace: Option<String>,
        issuer: IssuerRef,
        /// Requested lifetime; the issuer's default if unset.
        #[serde(default, with = "humantime_serde")]
        duration: Option<Duration>,
        /// The issuer's CA certificates (PEM): served at `/cacerts` and
        /// trusted for `simplereenroll`.
        cacerts: PathBuf,
        /// How long one EST request waits for the certificate before it
        /// answers `202`.
        #[serde(default = "default_wait", with = "humantime_serde")]
        wait: Duration,
        /// A finished request older than this is replaced by a new one
        /// when the same key asks for the same names again.
        #[serde(default = "default_reuse_window", with = "humantime_serde")]
        reuse_window: Duration,
        /// Finished requests are deleted after this time.
        #[serde(default = "default_keep", with = "humantime_serde")]
        keep: Duration,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerRef {
    pub name: String,
    #[serde(default = "default_issuer_kind")]
    pub kind: String,
    #[serde(default = "default_issuer_group")]
    pub group: String,
}

fn default_listen() -> Vec<SocketAddr> {
    vec!["[::]:8443".parse().expect("valid address")]
}
fn default_health_listen() -> Vec<SocketAddr> {
    vec!["[::]:8080".parse().expect("valid address")]
}
fn default_validity() -> Duration {
    Duration::from_secs(90 * DAY)
}
fn default_retry_after() -> Duration {
    Duration::from_secs(120)
}
fn default_wait() -> Duration {
    Duration::from_secs(20)
}
fn default_reuse_window() -> Duration {
    Duration::from_secs(3600)
}
fn default_keep() -> Duration {
    Duration::from_secs(DAY)
}
fn default_issuer_kind() -> String {
    "Issuer".into()
}
fn default_issuer_group() -> String {
    "cert-manager.io".into()
}
fn yes() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let mut config: Config =
            toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        config.resolve_paths(base);
        config.validate()?;
        Ok(config)
    }

    /// Relative paths in the file are relative to the file.
    fn resolve_paths(&mut self, base: &Path) {
        let fix = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        fix(&mut self.server.state_dir);
        fix(&mut self.server.tls.cert);
        fix(&mut self.server.tls.key);
        for ca in &mut self.cas {
            fix(&mut ca.cert);
            fix(&mut ca.key);
            if let Some(chain) = &mut ca.chain {
                fix(chain);
            }
        }
        for label in &mut self.labels {
            label.identity_cas.iter_mut().for_each(fix);
            if let SignerConfig::CertManager { cacerts, .. } = &mut label.signer {
                fix(cacerts);
            }
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.server.listen.is_empty() {
            bail!("server.listen is empty");
        }
        if self.labels.is_empty() {
            bail!("no [[label]] configured");
        }
        let ca_exists = |name: &str| self.cas.iter().any(|c| c.name == name);
        if let Some(auto) = &self.server.tls.auto {
            if !ca_exists(&auto.ca) {
                bail!("server.tls.auto: no [[ca]] named {:?}", auto.ca);
            }
            if auto.dns_names.is_empty() && auto.ip_addresses.is_empty() {
                bail!("server.tls.auto needs dns_names or ip_addresses");
            }
        }
        let mut paths = std::collections::HashSet::new();
        for label in &self.labels {
            if !label.name.is_empty()
                && !label
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                bail!(
                    "label name {:?}: only letters, digits, '-' and '_'",
                    label.name
                );
            }
            if let Some(p) = &label.path
                && (!p.starts_with('/') || p.ends_with('/'))
            {
                bail!(
                    "label {:?}: path must start with '/' and not end with '/'",
                    label.name
                );
            }
            if !paths.insert(label.base_path()) {
                bail!("two labels answer under {}", label.base_path());
            }
            for pattern in &label.allow {
                NamePattern::parse(pattern).map_err(anyhow::Error::msg)?;
            }
            if let SignerConfig::Local { ca, validity } = &label.signer {
                if !ca_exists(ca) {
                    bail!("label {:?}: no [[ca]] named {ca:?}", label.name);
                }
                if *validity < Duration::from_secs(3600) {
                    bail!("label {:?}: validity below one hour", label.name);
                }
            }
        }
        Ok(())
    }
}

impl LabelConfig {
    /// The path the operations hang off, without a trailing slash.
    pub fn base_path(&self) -> String {
        match (&self.path, self.name.as_str()) {
            (Some(p), _) => p.clone(),
            (None, "") => est_proto::WELL_KNOWN_PREFIX.to_string(),
            (None, name) => format!("{}/{name}", est_proto::WELL_KNOWN_PREFIX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example() {
        let text = r#"
            [server]
            state_dir = "/var/lib/est-server"
            [server.tls]
            cert = "tls/tls.crt"
            key = "tls/tls.key"
            auto = { ca = "home", dns_names = ["est.home.example.com"] }

            [[ca]]
            name = "home"
            cert = "ca/ca.crt"
            key = "ca/ca.key"

            [[label]]
            signer = { type = "local", ca = "home", validity = "60d" }
            allow = ["*.home.example.com"]
            manual_approval = true

            [[label]]
            name = "k8s"
            signer = { type = "cert-manager", issuer = { name = "home-ca", kind = "ClusterIssuer" }, cacerts = "/etc/est/ca.crt" }
        "#;
        let mut c: Config = toml::from_str(text).unwrap();
        c.resolve_paths(Path::new("/etc/est-server"));
        c.validate().unwrap();
        assert_eq!(c.server.listen, default_listen());
        assert_eq!(
            c.server.tls.cert,
            PathBuf::from("/etc/est-server/tls/tls.crt")
        );
        assert_eq!(c.labels[0].base_path(), "/.well-known/est");
        assert_eq!(c.labels[1].base_path(), "/.well-known/est/k8s");
        assert!(
            matches!(c.labels[0].signer, SignerConfig::Local { validity, .. } if validity == Duration::from_secs(60 * DAY))
        );
        assert!(
            matches!(&c.labels[1].signer, SignerConfig::CertManager { issuer, wait, .. }
            if issuer.group == "cert-manager.io" && *wait == Duration::from_secs(20))
        );
    }
}
