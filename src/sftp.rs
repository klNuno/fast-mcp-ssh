use std::path::Path;
use std::time::Instant;

use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::AsyncWriteExt;

use crate::errors::{Result, SshError};
use crate::session::Session;

const UPLOAD_CHUNK: usize = 32 * 1024;

pub struct SftpResult {
    pub bytes: usize,
    pub duration_ms: u128,
}

pub struct ListEntry {
    pub name: String,
    pub kind: &'static str,
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
}

pub async fn upload(session: &Session, local: &Path, remote: &str) -> Result<SftpResult> {
    let start = Instant::now();
    let sftp = session.sftp().await?;
    let mut local_file = tokio::fs::File::open(local).await?;
    let mut remote_file = sftp
        .open_with_flags(
            remote,
            OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
        )
        .await
        .map_err(SshError::from)?;
    let mut buf = vec![0u8; UPLOAD_CHUNK];
    let mut total = 0usize;
    loop {
        use tokio::io::AsyncReadExt;
        let n = local_file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        remote_file.write_all(&buf[..n]).await?;
        total += n;
    }
    remote_file.shutdown().await?;
    drop(remote_file);
    session.touch();
    Ok(SftpResult { bytes: total, duration_ms: start.elapsed().as_millis() })
}

pub async fn download(session: &Session, remote: &str, local: Option<&Path>) -> Result<(SftpResult, Option<Vec<u8>>)> {
    let start = Instant::now();
    let sftp = session.sftp().await?;
    let content = sftp.read(remote).await.map_err(SshError::from)?;
    let total = content.len();
    session.touch();
    if let Some(path) = local {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
        tokio::fs::write(path, &content).await?;
        return Ok((SftpResult { bytes: total, duration_ms: start.elapsed().as_millis() }, None));
    }
    Ok((
        SftpResult { bytes: total, duration_ms: start.elapsed().as_millis() },
        Some(content),
    ))
}

pub async fn write_inline(
    session: &Session,
    remote: &str,
    content: &[u8],
    mode: Option<u32>,
) -> Result<SftpResult> {
    let start = Instant::now();
    let sftp = session.sftp().await?;
    let attrs = FileAttributes {
        permissions: mode,
        ..Default::default()
    };
    let mut file = sftp
        .open_with_flags_and_attributes(
            remote,
            OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
            attrs,
        )
        .await
        .map_err(SshError::from)?;
    file.write_all(content).await?;
    file.shutdown().await?;
    drop(file);
    session.touch();
    Ok(SftpResult { bytes: content.len(), duration_ms: start.elapsed().as_millis() })
}

pub async fn list_dir(session: &Session, path: &str) -> Result<Vec<ListEntry>> {
    let sftp = session.sftp().await?;
    let entries = sftp.read_dir(path).await.map_err(SshError::from)?;
    let mut out = Vec::new();
    for entry in entries {
        let attrs = entry.metadata();
        let kind = if attrs.is_dir() {
            "dir"
        } else if attrs.is_symlink() {
            "link"
        } else if attrs.is_regular() {
            "file"
        } else {
            "other"
        };
        out.push(ListEntry {
            name: entry.file_name(),
            kind,
            size: attrs.size.unwrap_or(0),
            mode: attrs.permissions.unwrap_or(0),
            mtime: attrs.mtime.unwrap_or(0) as u64,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    session.touch();
    Ok(out)
}

/// Heuristic binary detection: any NUL byte, or >5% non-printable / non-UTF8
/// content. Used by `dn` inline to decide between text passthrough and base64.
pub fn looks_binary(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.contains(&0) {
        return true;
    }
    if std::str::from_utf8(bytes).is_err() {
        return true;
    }
    let weird = bytes
        .iter()
        .filter(|&&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')
        .count();
    weird * 20 > bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_binary() {
        assert!(looks_binary(&[0, 1, 2, 3]));
        assert!(looks_binary(&[0xff, 0xfe, 0xfd]));
        assert!(!looks_binary(b"hello world\n"));
        assert!(!looks_binary(b""));
    }
}
