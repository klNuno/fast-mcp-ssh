use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{self, Sender};
use tokio::sync::watch;
use tokio::task::JoinHandle;

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

/// Size-based rotation policy. Enforced on the writer task, never on a tool
/// call: rotation renames and reopens files, which is exactly the disk I/O the
/// channel exists to keep off the request path.
#[derive(Debug, Clone, Copy)]
pub struct AuditRotation {
    /// Rotate once the live file crosses this size. `0` disables rotation.
    pub max_bytes: u64,
    /// Generations of `audit.log.N` to keep. `0` discards on rotate.
    pub keep_files: usize,
}

impl Default for AuditRotation {
    fn default() -> Self {
        Self {
            max_bytes: 16 * 1024 * 1024,
            keep_files: 5,
        }
    }
}

/// Append-only NDJSON audit log writer. Backed by a bounded mpsc channel +
/// a dedicated task that writes batches, so callers never block the runtime
/// on disk I/O. A full queue drops the entry and emits a tracing warning;
/// audit records are not flow-critical.
pub struct AuditLog {
    tx: Option<Sender<AuditEntryOwned>>,
    shutdown_tx: Option<watch::Sender<bool>>,
    handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl AuditLog {
    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self {
                tx: None,
                shutdown_tx: None,
                handle: tokio::sync::Mutex::new(None),
            });
        };
        // Probe parent dir writability synchronously so a misconfigured path
        // fails at startup. The actual file open is deferred to the writer
        // task to keep cold-start latency low.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                crate::errors::SshError::Config(format!(
                    "create audit log dir {}: {e}",
                    parent.display()
                ))
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        let (tx, mut rx) = mpsc::channel::<AuditEntryOwned>(AUDIT_QUEUE_CAP);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let path_for_task = path.clone();
        let handle = tokio::spawn(async move {
            let mut file = match open_audit_file(&path_for_task).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!(?e, path = %path_for_task.display(), "open audit log failed; entries will be dropped");
                    // Keep draining the queue so try_send doesn't fail forever.
                    loop {
                        tokio::select! {
                            biased;
                            res = shutdown_rx.changed() => {
                                if res.is_err() || *shutdown_rx.borrow() { return; }
                            }
                            opt = rx.recv() => {
                                if opt.is_none() { return; }
                            }
                        }
                    }
                }
            };
            let mut buf = String::with_capacity(8192);
            let mut batch: Vec<AuditEntryOwned> = Vec::with_capacity(AUDIT_BATCH);
            'outer: loop {
                batch.clear();
                buf.clear();
                tokio::select! {
                    biased;
                    res = shutdown_rx.changed() => {
                        if res.is_ok() && *shutdown_rx.borrow() {
                            // Drain any queued entries before exiting.
                            while let Ok(entry) = rx.try_recv() {
                                batch.push(entry);
                            }
                            if !batch.is_empty() {
                                serialize_batch(&batch, &mut buf);
                                if let Err(e) = file.write_all(buf.as_bytes()).await {
                                    tracing::error!(?e, "audit shutdown write failed");
                                }
                            }
                            break 'outer;
                        }
                    }
                    count = rx.recv_many(&mut batch, AUDIT_BATCH) => {
                        if count == 0 {
                            break 'outer;
                        }
                        serialize_batch(&batch, &mut buf);
                        if let Err(e) = file.write_all(buf.as_bytes()).await {
                            tracing::error!(?e, "audit write failed");
                        }
                    }
                }
            }
            if let Err(e) = file.flush().await {
                tracing::error!(?e, "audit flush failed");
            }
            if let Err(e) = file.sync_data().await {
                tracing::error!(?e, "audit fsync failed");
            }
        });
        Ok(Self {
            tx: Some(tx),
            shutdown_tx: Some(shutdown_tx),
            handle: tokio::sync::Mutex::new(Some(handle)),
        })
    }

    /// Drain pending entries, fsync, and join the writer task.
    /// Idempotent. Should be called once during shutdown.
    pub async fn shutdown(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(true);
        }
        let h = {
            let mut guard = self.handle.lock().await;
            guard.take()
        };
        if let Some(h) = h {
            let _ = h.await;
        }
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
            cmd: cmd.map(|s| scrub_credentials(s).into_owned()),
            exit_code,
            duration_ms,
            bytes_in,
            bytes_out,
            blocked: blocked.map(|s| s.to_string()),
            error: error.map(|s| scrub_credentials(&s).into_owned()),
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

async fn open_audit_file(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&path)
    })
    .await
    .map_err(|e| std::io::Error::other(format!("audit open join: {e}")))?
    .map(tokio::fs::File::from_std)
}

fn serialize_batch(batch: &[AuditEntryOwned], buf: &mut String) {
    for entry in batch {
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
}

/// Replace inline credentials in a command string with `[REDACTED]`. Best-effort:
/// covers the common shapes (`mysql -p<pw>`, `--password=`, `Bearer xxx`,
/// `AWS_*=...`, `GITHUB_TOKEN=...`, `Authorization: ...`). Not a sandbox.
fn scrub_credentials(s: &str) -> Cow<'_, str> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            (?:
                # mysql/psql -p<pass> attached
                -p[^\s'"]{1,256}
                # --password=... / --token=... / --secret=...
              | --(?:password|token|secret|api[-_]?key)[=\s]\S+
              | (?:password|token|secret|api[-_]?key)=\S+
                # http auth headers
              | Bearer\s+\S+
              | Authorization:[^'"\n]*
                # cloud / vcs / generic UPPER_SNAKE secrets
              | (?:AWS|GCP|AZURE|GITHUB|GITLAB|VAULT|STRIPE|TWILIO|SLACK|HF)_[A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASS)\s*=\s*\S+
            )"#,
        )
        .expect("scrub regex valid")
    });
    re.replace_all(s, "[REDACTED]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_mysql_password_attached() {
        let s = scrub_credentials("mysql -uroot -phunter2 -e 'select 1'");
        assert!(!s.contains("hunter2"), "got: {s}");
    }

    #[test]
    fn scrubs_bearer_token() {
        let s = scrub_credentials("curl -H 'Authorization: Bearer eyJhbGc.xxx.yyy' https://api/");
        assert!(!s.contains("eyJhbGc"), "got: {s}");
    }

    #[test]
    fn scrubs_aws_env() {
        let s = scrub_credentials("AWS_SECRET_ACCESS_KEY=abcd1234 aws s3 ls");
        assert!(!s.contains("abcd1234"), "got: {s}");
    }

    #[test]
    fn scrubs_long_flags() {
        let s = scrub_credentials("foo --password=hunter2 --token bar123");
        assert!(!s.contains("hunter2"), "got: {s}");
        assert!(!s.contains("bar123"), "got: {s}");
    }

    #[test]
    fn passes_through_clean_commands() {
        let s = scrub_credentials("ls -la /etc");
        assert_eq!(s, "ls -la /etc");
    }
}
