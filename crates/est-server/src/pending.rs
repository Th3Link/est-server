//! Requests waiting for an administrator (local CA). One JSON file per
//! request under `<state_dir>/pending/`; the server and the `pending`
//! commands share the directory.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

/// An approval stays good for this long: a client that missed the
/// answer, or asks again with the same key and names, gets its
/// certificate without a new approval.
pub const APPROVAL_TTL: Duration = Duration::from_secs(7 * 86_400);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub label: String,
    pub names: Vec<String>,
    /// Address of the last request.
    pub client: String,
    /// Subject of the client certificate, if it presented one.
    pub client_cert: Option<String>,
    pub csr_pem: String,
    pub status: Status,
    /// Unix seconds.
    pub created: u64,
    pub last_seen: u64,
    pub decided: Option<u64>,
    pub issued: Option<u64>,
}

impl Entry {
    /// Approved, and not longer ago than [`APPROVAL_TTL`].
    pub fn approval_valid(&self, now: u64) -> bool {
        self.status == Status::Approved
            && self
                .decided
                .is_some_and(|d| now.saturating_sub(d) < APPROVAL_TTL.as_secs())
    }
}

pub struct PendingStore {
    dir: PathBuf,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl PendingStore {
    pub fn open(state_dir: &Path) -> anyhow::Result<Self> {
        let dir = state_dir.join("pending");
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(Self { dir })
    }

    fn path(&self, id: &str) -> anyhow::Result<PathBuf> {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("invalid request id {id:?}");
        }
        Ok(self.dir.join(format!("{id}.json")))
    }

    pub fn get(&self, id: &str) -> anyhow::Result<Option<Entry>> {
        let path = self.path(id)?;
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(
                serde_json::from_slice(&data)
                    .with_context(|| format!("parse {}", path.display()))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn put(&self, entry: &Entry) -> anyhow::Result<()> {
        let data = serde_json::to_vec_pretty(entry)?;
        crate::ca::write_file(&self.path(&entry.id)?, &data, false)
    }

    /// All entries, oldest first.
    pub fn list(&self) -> anyhow::Result<Vec<Entry>> {
        let mut entries = Vec::new();
        for item in std::fs::read_dir(&self.dir)? {
            let path = item?.path();
            if path.extension().is_some_and(|e| e == "json") {
                let data = std::fs::read(&path)?;
                match serde_json::from_slice::<Entry>(&data) {
                    Ok(e) => entries.push(e),
                    Err(e) => tracing::warn!("skipping {}: {e}", path.display()),
                }
            }
        }
        entries.sort_by_key(|e| e.created);
        Ok(entries)
    }

    /// Approve or deny; a unique prefix of the id is enough.
    pub fn decide(&self, id_prefix: &str, approve: bool) -> anyhow::Result<Entry> {
        let mut entry = self.find(id_prefix)?;
        entry.status = if approve {
            Status::Approved
        } else {
            Status::Denied
        };
        entry.decided = Some(now());
        self.put(&entry)?;
        Ok(entry)
    }

    pub fn find(&self, id_prefix: &str) -> anyhow::Result<Entry> {
        let matches: Vec<Entry> = self
            .list()?
            .into_iter()
            .filter(|e| e.id.starts_with(id_prefix))
            .collect();
        match matches.len() {
            1 => Ok(matches.into_iter().next().expect("one match")),
            0 => bail!("no request {id_prefix}"),
            n => bail!("{n} requests start with {id_prefix}; give more of the id"),
        }
    }

    pub fn remove(&self, id: &str) -> anyhow::Result<()> {
        std::fs::remove_file(self.path(id)?)?;
        Ok(())
    }

    /// Delete entries untouched for `age`.
    pub fn prune(&self, age: Duration) -> anyhow::Result<usize> {
        let cutoff = now().saturating_sub(age.as_secs());
        let mut removed = 0;
        for e in self.list()? {
            if e.last_seen.max(e.decided.unwrap_or(0)) < cutoff {
                self.remove(&e.id)?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str) -> Entry {
        Entry {
            id: id.into(),
            label: String::new(),
            names: vec!["a.test".into()],
            client: "192.0.2.1:1234".into(),
            client_cert: None,
            csr_pem: String::new(),
            status: Status::Pending,
            created: now(),
            last_seen: now(),
            decided: None,
            issued: None,
        }
    }

    #[test]
    fn decide_by_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let store = PendingStore::open(dir.path()).unwrap();
        store.put(&entry("abc123")).unwrap();
        store.put(&entry("abd456")).unwrap();
        assert!(store.decide("ab", true).is_err(), "ambiguous");
        let e = store.decide("abc", true).unwrap();
        assert!(e.approval_valid(now()));
        assert_eq!(
            store.get("abc123").unwrap().unwrap().status,
            Status::Approved
        );
        assert!(store.get("../etc").is_err());
    }
}
