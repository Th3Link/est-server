//! Registered clients from a directory: one TOML file per client, named
//! after it (`gw1.toml`):
//!
//! ```toml
//! dns_names = ["gw1.example.com"]
//! public_keys = [{ pin_sha256 = "…" }]
//! labels = []
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use serde::Deserialize;

use super::{Client, ClientSpec, Registry, Rejected, Source, drop_duplicates};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileClient {
    dns_names: Vec<String>,
    public_keys: Vec<FileKey>,
    #[serde(default)]
    labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileKey {
    pin_sha256: String,
}

/// Read every `*.toml` in `dir`. Entries that don't check out are left
/// out and come back as `(file, reason)`.
pub fn load(dir: &Path) -> anyhow::Result<(Vec<Client>, Rejected)> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "toml") && p.is_file())
        .collect();
    paths.sort();
    let mut clients = Vec::new();
    let mut invalid = Vec::new();
    for path in paths {
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let id = format!("file:{name}");
        let parsed = std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|text| {
                toml::from_str::<FileClient>(&text).map_err(|e| e.message().to_string())
            })
            .and_then(|f| {
                let spec = ClientSpec {
                    dns_names: f.dns_names,
                    pins: f.public_keys.into_iter().map(|k| k.pin_sha256).collect(),
                    labels: f.labels,
                };
                Client::new(id.clone(), Source::File, &spec)
            });
        match parsed {
            Ok(c) => clients.push(c),
            Err(e) => invalid.push((path.display().to_string(), e)),
        }
    }
    invalid.extend(drop_duplicates(&mut clients));
    Ok((clients, invalid))
}

/// Load `dir` into the registry; fails if the directory can't be read.
pub fn init(registry: &Registry, dir: &Path) -> anyhow::Result<()> {
    let (clients, invalid) = load(dir)?;
    for (what, why) in &invalid {
        tracing::warn!("registered client {what} ignored: {why}");
    }
    tracing::info!(dir = %dir.display(), count = clients.len(), "registered clients");
    registry.set_file(clients);
    Ok(())
}

/// Re-read `dir` every `interval`, forever, and log what changed.
pub async fn watch(registry: Arc<Registry>, dir: PathBuf, interval: Duration) {
    let mut last = load(&dir).ok();
    let mut tick = tokio::time::interval(interval);
    tick.tick().await;
    loop {
        tick.tick().await;
        match load(&dir) {
            Ok(now) if last.as_ref() != Some(&now) => {
                for (what, why) in &now.1 {
                    tracing::warn!("registered client {what} ignored: {why}");
                }
                tracing::info!(dir = %dir.display(), count = now.0.len(), "registered clients changed");
                registry.set_file(now.0.clone());
                last = Some(now);
            }
            Ok(_) => {}
            // Keep what we have; a directory being replaced (a ConfigMap
            // update) can be briefly unreadable.
            Err(e) => tracing::warn!("registered clients: {e:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clients::{encode_pin, pin};

    #[test]
    fn loads_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let p = encode_pin(&pin(b"a"));
        std::fs::write(
            dir.path().join("gw1.toml"),
            format!("dns_names = [\"gw1.test\"]\npublic_keys = [{{ pin_sha256 = \"{p}\" }}]\n"),
        )
        .unwrap();
        std::fs::write(dir.path().join("typo.toml"), "dns_name = [\"x.test\"]\n").unwrap();
        std::fs::write(dir.path().join("README"), "not a client").unwrap();
        let (clients, invalid) = load(dir.path()).unwrap();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].id, "file:gw1");
        assert_eq!(invalid.len(), 1);
        assert!(invalid[0].0.ends_with("typo.toml"));
        assert!(load(&dir.path().join("missing")).is_err());
    }
}
