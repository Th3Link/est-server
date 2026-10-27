//! `server.tls.auto`: the server issues its own certificate from a local
//! CA and renews it when a third of its lifetime is left.

use std::sync::Arc;
use std::time::Duration;

use rcgen::{KeyPair, PublicKeyData};

use crate::ca::{LeafSpec, LocalCa, answer_chain};
use crate::config::{AutoTls, TlsConfig};
use crate::peer::TrustStore;
use crate::tls::parse_certs;

/// Make sure `tls.cert`/`tls.key` hold a current certificate for the
/// configured names from `ca`. Returns whether it issued one. The key is
/// kept if there is one.
pub fn ensure(tls: &TlsConfig, auto: &AutoTls, ca: &LocalCa) -> anyhow::Result<bool> {
    let key_pem = std::fs::read_to_string(&tls.key).ok();
    let key = key_pem
        .as_deref()
        .and_then(|pem| KeyPair::from_pem(pem).ok());
    if let Some(key) = &key
        && is_current(tls, auto, ca, key)
    {
        return Ok(false);
    }
    let key = match key {
        Some(k) => k,
        None => {
            let k = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            crate::ca::write_file(&tls.key, k.serialize_pem().as_bytes(), true)?;
            k
        }
    };
    let dns_names: Vec<String> = auto
        .dns_names
        .iter()
        .map(|n| n.to_ascii_lowercase())
        .collect();
    let leaf = ca.issue(
        &key,
        &LeafSpec {
            common_name: dns_names.first().map(String::as_str),
            dns_names: &dns_names,
            ip_addresses: &auto.ip_addresses,
            validity: auto.validity,
            rsa: false,
        },
    )?;
    let pem: String = answer_chain(leaf, &ca.ca_certs(), false)
        .iter()
        .map(|c| est_proto::wire::to_pem("CERTIFICATE", c))
        .collect();
    crate::ca::write_file(&tls.cert, pem.as_bytes(), false)?;
    tracing::info!(cert = %tls.cert.display(), names = ?dns_names, ips = ?auto.ip_addresses, "issued the server certificate");
    Ok(true)
}

fn is_current(tls: &TlsConfig, auto: &AutoTls, ca: &LocalCa, key: &KeyPair) -> bool {
    let Ok(chain) = std::fs::read(&tls.cert)
        .map_err(anyhow::Error::from)
        .and_then(|pem| parse_certs(&pem))
    else {
        return false;
    };
    let Ok(anchors) = TrustStore::new(&ca.ca_certs()) else {
        return false;
    };
    let Some(peer) = anchors.verify(&chain) else {
        return false;
    };
    if peer.spki_der != key.subject_public_key_info() {
        return false;
    }
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(&chain[0]) else {
        return false;
    };
    let mut want_dns: Vec<String> = auto
        .dns_names
        .iter()
        .map(|n| n.to_ascii_lowercase())
        .collect();
    let mut have_dns = Vec::new();
    let mut have_ips = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for n in &san.value.general_names {
            match n {
                x509_parser::extensions::GeneralName::DNSName(d) => {
                    have_dns.push(d.to_ascii_lowercase())
                }
                x509_parser::extensions::GeneralName::IPAddress(b) => have_ips.push(b.to_vec()),
                _ => {}
            }
        }
    }
    want_dns.sort();
    have_dns.sort();
    let mut want_ips: Vec<Vec<u8>> = auto
        .ip_addresses
        .iter()
        .map(|ip| match ip {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        })
        .collect();
    want_ips.sort();
    have_ips.sort();
    let v = cert.validity();
    let lifetime = v.not_after.timestamp() - v.not_before.timestamp();
    let left = v.not_after.timestamp() - time::OffsetDateTime::now_utc().unix_timestamp();
    want_dns == have_dns && want_ips == have_ips && left > lifetime / 3
}

/// Check twice a day, forever.
pub async fn renew_loop(tls: TlsConfig, auto: AutoTls, ca: Arc<LocalCa>) {
    let mut tick = tokio::time::interval(Duration::from_secs(12 * 3600));
    tick.tick().await;
    loop {
        tick.tick().await;
        if let Err(e) = ensure(&tls, &auto, &ca) {
            tracing::error!("renewing the server certificate: {e:#}");
        }
    }
}
