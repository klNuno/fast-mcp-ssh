use std::path::Path;
use std::time::Instant;

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::AsyncWriteExt;

use crate::errors::{Result, SshError};
use crate::session::Session;

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

async fn open_sftp(session: &Session) -> Result<SftpSession> {
    let channel = session
        .handle
        .channel_open_session()
        .await
        .map_err(SshError::from)?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(SshError::from)?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(SshError::from)?;
    Ok(sftp)
}

pub async fn upload(session: &Session, local: &Path, remote: &str) -> Result<SftpResult> {
    let start = Instant::now();
    let sftp = open_sftp(session).await?;
    let bytes = tokio::fs::read(local).await?;
    let total = bytes.len();
    let mut file = sftp
        .open_with_flags(
            remote,
            OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
        )
        .await
        .map_err(SshError::from)?;
    file.write_all(&bytes).await?;
    file.shutdown().await?;
    drop(file);
    session.touch().await;
    Ok(SftpResult { bytes: total, duration_ms: start.elapsed().as_millis() })
}

pub async fn download(session: &Session, remote: &str, local: Option<&Path>) -> Result<(SftpResult, Option<Vec<u8>>)> {
    let start = Instant::now();
    let sftp = open_sftp(session).await?;
    let content = sftp.read(remote).await.map_err(SshError::from)?;
    let total = content.len();
    session.touch().await;
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
    let sftp = open_sftp(session).await?;
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
    session.touch().await;
    Ok(SftpResult { bytes: content.len(), duration_ms: start.elapsed().as_millis() })
}

pub async fn list_dir(session: &Session, path: &str) -> Result<Vec<ListEntry>> {
    let sftp = open_sftp(session).await?;
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
    session.touch().await;
    Ok(out)
}
