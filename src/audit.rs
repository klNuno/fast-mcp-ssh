use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::Mutex,
};

use chrono::Utc;
use serde::Serialize;

use crate::errors::Result;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry<'a> {
    pub ts: String,
    pub host: &'a str,
    pub tool: &'a str,
    pub cmd: Option<&'a str>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u128>,
    pub bytes_in: Option<usize>,
    pub bytes_out: Option<usize>,
    pub blocked: Option<&'a str>,
    pub error: Option<String>,
}

pub struct AuditLog {
    file: Mutex<Option<std::fs::File>>,
}

impl AuditLog {
    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        if let Some(p) = &path {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = OpenOptions::new().create(true).append(true).open(p)?;
            Ok(Self { file: Mutex::new(Some(file)) })
        } else {
            Ok(Self { file: Mutex::new(None) })
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn write(
        &self,
        host: &str,
        tool: &str,
        cmd: Option<&str>,
        exit_code: Option<i32>,
        duration_ms: Option<u128>,
        bytes_in: Option<usize>,
        bytes_out: Option<usize>,
        blocked: Option<&str>,
        error: Option<String>,
    ) {
        let entry = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            host,
            tool,
            cmd,
            exit_code,
            duration_ms,
            bytes_in,
            bytes_out,
            blocked,
            error,
        };
        let mut guard = match self.file.lock() {
            Ok(g) => g,
            Err(e) => {
                tracing::error!(?e, "audit lock poisoned");
                return;
            }
        };
        if let Some(file) = guard.as_mut() {
            let line = match serde_json::to_string(&entry) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(?e, "audit serialize failed");
                    return;
                }
            };
            if let Err(e) = writeln!(file, "{line}") {
                tracing::error!(?e, "audit write failed");
            }
        }
    }

}
