//! The issue log: one JSON line per certificate in
//! `<state_dir>/issued.jsonl`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Record<'a> {
    pub time: u64,
    pub label: &'a str,
    pub operation: &'a str,
    pub reason: &'a str,
    pub names: &'a [String],
    pub serial: String,
    pub not_after: i64,
    pub client: String,
    pub client_cert: Option<&'a str>,
    /// The registered client, if one was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<&'a str>,
    pub signer: &'a str,
}

pub struct AuditLog {
    path: PathBuf,
    lock: Mutex<()>,
}

impl AuditLog {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join("issued.jsonl"),
            lock: Mutex::new(()),
        }
    }

    pub fn write(&self, record: &Record<'_>) {
        let Ok(mut line) = serde_json::to_vec(record) else {
            return;
        };
        line.push(b'\n');
        let _guard = self.lock.lock();
        let result = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| f.write_all(&line));
        if let Err(e) = result {
            tracing::warn!("issue log {}: {e}", self.path.display());
        }
    }
}
