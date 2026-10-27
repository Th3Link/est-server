//! `est-server init`: a CA, a server certificate and a configuration for
//! a standalone server.

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::bail;

use crate::ca::{LocalCa, write_file};
use crate::config::Config;

pub struct InitOptions {
    pub dir: PathBuf,
    pub ca_name: String,
    pub p384: bool,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
    pub allow: Vec<String>,
    pub force: bool,
}

pub fn run(o: &InitOptions) -> anyhow::Result<()> {
    let config_path = o.dir.join("est-server.toml");
    let ca_cert = o.dir.join("ca/ca.crt");
    let ca_key = o.dir.join("ca/ca.key");
    for p in [&config_path, &ca_cert, &ca_key] {
        if p.exists() && !o.force {
            bail!("{} exists (use --force to overwrite)", p.display());
        }
    }
    if o.dns_names.is_empty() && o.ip_addresses.is_empty() {
        bail!("give the server's name with --dns-name (and/or --ip)");
    }

    let alg = if o.p384 {
        &rcgen::PKCS_ECDSA_P384_SHA384
    } else {
        &rcgen::PKCS_ECDSA_P256_SHA256
    };
    let (cert_pem, key_pem) = LocalCa::generate_root(&o.ca_name, alg, 20)?;
    write_file(&ca_key, key_pem.as_bytes(), true)?;
    write_file(&ca_cert, cert_pem.as_bytes(), false)?;
    write_file(&config_path, config_text(o).as_bytes(), false)?;

    // Issue the server certificate now, so the setup is complete.
    let config = Config::load(&config_path)?;
    let auto = config.server.tls.auto.as_ref().expect("written above");
    let ca = LocalCa::load(&config.cas[0])?;
    crate::autotls::ensure(&config.server.tls, auto, &ca)?;

    let der = crate::tls::parse_certs(cert_pem.as_bytes())?.remove(0);
    let fingerprint = ring::digest::digest(&ring::digest::SHA256, &der);
    let host = o
        .dns_names
        .first()
        .cloned()
        .unwrap_or_else(|| o.ip_addresses[0].to_string());
    println!("Created in {}:", o.dir.display());
    println!("  configuration   {}", config_path.display());
    println!(
        "  CA certificate  {}  (install this on clients as trust anchor)",
        ca_cert.display()
    );
    println!(
        "  CA key          {}  (keep it secret, back it up)",
        ca_key.display()
    );
    println!("  CA SHA-256      {}", hex_colon(fingerprint.as_ref()));
    println!();
    println!(
        "Start with:  est-server --config {} serve",
        config_path.display()
    );
    println!("EST URL:     https://{host}:8443/.well-known/est");
    Ok(())
}

fn config_text(o: &InitOptions) -> String {
    let list = |items: &[String]| {
        items
            .iter()
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let ips: Vec<String> = o.ip_addresses.iter().map(|ip| ip.to_string()).collect();
    format!(
        r#"# est-server configuration. Relative paths are relative to this file.

[server]
# "[::]:8443" alone serves IPv6 and IPv4 on one socket.
listen = ["[::]:8443"]
health_listen = ["[::]:8080"]
state_dir = "."

[server.tls]
cert = "tls/tls.crt"
key = "tls/tls.key"
# Issued and renewed from the CA below.
auto = {{ ca = "local", dns_names = [{dns}], ip_addresses = [{ips}] }}

[[ca]]
name = "local"
cert = "ca/ca.crt"
key = "ca/ca.key"

# https://<host>:8443/.well-known/est
[[label]]
signer = {{ type = "local", ca = "local", validity = "90d" }}
# Names that get a certificate without approval, e.g. "*.home.example.com".
allow = [{allow}]
# PEM files of device identity CAs; a client certificate from one of them
# approves a first enrollment for the names it carries.
identity_cas = []
# Everything else waits for: est-server pending approve <id>
manual_approval = true
retry_after = "2m"
"#,
        dns = list(&o.dns_names),
        ips = list(&ips),
        allow = list(&o.allow),
    )
}

fn hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
