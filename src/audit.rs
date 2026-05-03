use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{self, Sender};

use crate::errors::Result;

#[derive(Debug, Clone, Serialize)]
struct AuditEntryOwned {
    ts: String,
    host: Arc<str>,
    tool: &'static str,
    cmd: Option<String>,
    exit_code: Option<i32>,
    duration_ms: Option<u128>,
    bytes_in: Option<usize>,
    bytes_out: Option<usize>,
    blocked: Option<String>,
    error: Option<String>,
}

const AUDIT_QUEUE_CAP: usize = 1024;
const AUDIT_BATCH: usize = 32;

/// Append-only NDJSON audit log writer. Backed by a bounded mpsc channel +
/// a dedicated task that writes batches, so callers never block the runtime
/// on disk I/O. A full queue drops the entry and emits a tracing warning;
/// audit records are not flow-critical.
pub struct AuditLog {
    tx: Option<Sender<AuditEntryOwned>>,
}

impl AuditLog {
    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self { tx: None });
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let (tx, mut rx) = mpsc::channel::<AuditEntryOwned>(AUDIT_QUEUE_CAP);
        tokio::spawn(async move {
            let mut file = match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
            {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!(?e, path = %path.display(), "audit open failed");
                    return;
                }
            };
            let mut buf = String::with_capacity(8192);
            let mut batch: Vec<AuditEntryOwned> = Vec::with_capacity(AUDIT_BATCH);
            loop {
                batch.clear();
                buf.clear();
                let count = rx.recv_many(&mut batch, AUDIT_BATCH).await;
                if count == 0 {
                    break;
                }
                for entry in &batch {
                    match serde_json::to_string(entry) {
                        Ok(s) => {
                            buf.push_str(&s);
                            buf.push('\n');
                        }
                        Err(e) => {
                            tracing::error!(?e, "audit serialize failed");
                        }
                    }
                }
                if let Err(e) = file.write_all(buf.as_bytes()).await {
                    tracing::error!(?e, "audit write failed");
                }
            }
            let _ = file.flush().await;
        });
        Ok(Self { tx: Some(tx) })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn write(
        &self,
        host: &str,
        tool: &'static str,
        cmd: Option<&str>,
        exit_code: Option<i32>,
        duration_ms: Option<u128>,
        bytes_in: Option<usize>,
        bytes_out: Option<usize>,
        blocked: Option<&str>,
        error: Option<String>,
    ) {
        let Some(tx) = &self.tx else { return };
        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::new());
        let entry = AuditEntryOwned {
            ts,
            host: Arc::from(host),
            tool,
            cmd: cmd.map(|s| s.to_string()),
            exit_code,
            duration_ms,
            bytes_in,
            bytes_out,
            blocked: blocked.map(|s| s.to_string()),
            error,
        };
        if let Err(e) = tx.try_send(entry) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!("audit queue full, dropping entry");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::error!("audit channel closed");
                }
            }
        }
    }
}
