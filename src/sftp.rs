use std::path::Path;
use std::time::{Duration, Instant};

use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::errors::{Result, SshError};
use crate::session::Session;

const TRANSFER_CHUNK: usize = 256 * 1024;

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

pub struct StatEntry {
    pub kind: &'static str,
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub uid: u32,
    pub gid: u32,
}

async fn with_timeout<T, F>(label: &'static str, secs: u64, fut: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match timeout(Duration::from_secs(secs), fut).await {
        Ok(r) => r,
        Err(_) => Err(SshError::Other(format!(
            "sftp {label} timed out after {secs}s"
        ))),
    }
}

pub async fn upload(session: &Session, local: &Path, remote: &str) -> Result<SftpResult> {
    let start = Instant::now();
    let sftp = session.sftp().await?;
    let mut local_file = tokio::fs::File::open(local).await?;
    // Stream into `<remote>.partial` then atomically rename on success so a
    // network blip mid-transfer can't leave a half-written file at the final
    // path. Caller-visible failure preserves the previous file (if any).
    let partial = format!("{remote}.partial");
    let mut remote_file = sftp
        .open_with_flags(
            &partial,
            OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
        )
        .await
        .map_err(SshError::from)?;
    let mut buf = vec![0u8; TRANSFER_CHUNK];
    let mut total = 0usize;
    let copy_result: Result<()> = async {
        loop {
            let n = local_file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            remote_file.write_all(&buf[..n]).await?;
            total += n;
        }
        remote_file.shutdown().await?;
        Ok(())
    }
    .await;
    drop(remote_file);
    if let Err(e) = copy_result {
        // Best-effort cleanup; ignore errors.
        let _ = sftp.remove_file(&partial).await;
        return Err(e);
    }
    sftp.rename(&partial, remote).await.map_err(SshError::from)?;
    session.touch();
    Ok(SftpResult { bytes: total, duration_ms: start.elapsed().as_millis() })
}

pub async fn download(
    session: &Session,
    remote: &str,
    local: Option<&Path>,
) -> Result<(SftpResult, Option<Vec<u8>>)> {
    let start = Instant::now();
    let sftp = session.sftp().await?;
    let mut remote_file = sftp
        .open_with_flags(remote, OpenFlags::READ)
        .await
        .map_err(SshError::from)?;
    session.touch();

    if let Some(path) = local {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
        let mut local_file = tokio::fs::File::create(path).await?;
        let mut buf = vec![0u8; TRANSFER_CHUNK];
        let mut total = 0usize;
        loop {
            let n = remote_file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            local_file.write_all(&buf[..n]).await?;
            total += n;
        }
        local_file.shutdown().await?;
        return Ok((
            SftpResult { bytes: total, duration_ms: start.elapsed().as_millis() },
            None,
        ));
    }

    let mut content = Vec::with_capacity(TRANSFER_CHUNK);
    let mut buf = vec![0u8; TRANSFER_CHUNK];
    loop {
        let n = remote_file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        content.extend_from_slice(&buf[..n]);
    }
    let total = content.len();
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

pub async fn mkdir(session: &Session, path: &str, parents: bool) -> Result<()> {
    let sftp = session.sftp().await?;
    if parents {
        let mut acc = String::new();
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let absolute = path.starts_with('/');
        for (i, seg) in segments.iter().enumerate() {
            if absolute || i > 0 {
                acc.push('/');
            }
            acc.push_str(seg);
            if sftp.metadata(acc.clone()).await.is_ok() {
                continue;
            }
            with_timeout("mkdir", 30, async {
                sftp.create_dir(acc.clone())
                    .await
                    .map_err(SshError::from)
            })
            .await?;
        }
    } else {
        with_timeout("mkdir", 30, async {
            sftp.create_dir(path.to_string())
                .await
                .map_err(SshError::from)
        })
        .await?;
    }
    session.touch();
    Ok(())
}

pub async fn remove(session: &Session, path: &str, recursive: bool) -> Result<u64> {
    let sftp = session.sftp().await?;
    let meta = with_timeout("stat", 30, async {
        sftp.metadata(path.to_string())
            .await
            .map_err(SshError::from)
    })
    .await?;
    if meta.is_dir() {
        if !recursive {
            return Err(SshError::Other(format!(
                "{path} is a directory; pass recursive=true"
            )));
        }
        let removed = remove_dir_recursive(session, path).await?;
        session.touch();
        Ok(removed)
    } else {
        with_timeout("rm", 30, async {
            sftp.remove_file(path.to_string())
                .await
                .map_err(SshError::from)
        })
        .await?;
        session.touch();
        Ok(1)
    }
}

async fn remove_dir_recursive(session: &Session, path: &str) -> Result<u64> {
    let sftp = session.sftp().await?;
    let mut count = 0u64;
    // Iterative DFS to keep the recursion budget bounded.
    let mut stack = vec![(path.to_string(), false)];
    while let Some((dir, visited)) = stack.pop() {
        if visited {
            with_timeout("rmdir", 30, async {
                sftp.remove_dir(dir.clone())
                    .await
                    .map_err(SshError::from)
            })
            .await?;
            count += 1;
            continue;
        }
        stack.push((dir.clone(), true));
        let entries = with_timeout("readdir", 30, async {
            sftp.read_dir(dir.clone())
                .await
                .map_err(SshError::from)
        })
        .await?;
        for entry in entries {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let child = if dir.ends_with('/') {
                format!("{dir}{name}")
            } else {
                format!("{dir}/{name}")
            };
            if entry.metadata().is_dir() {
                stack.push((child, false));
            } else {
                with_timeout("rm", 30, async {
                    sftp.remove_file(child)
                        .await
                        .map_err(SshError::from)
                })
                .await?;
                count += 1;
            }
        }
    }
    Ok(count)
}

pub async fn stat(session: &Session, path: &str) -> Result<StatEntry> {
    let sftp = session.sftp().await?;
    let attrs = with_timeout("stat", 30, async {
        sftp.metadata(path.to_string())
            .await
            .map_err(SshError::from)
    })
    .await?;
    let kind = if attrs.is_dir() {
        "dir"
    } else if attrs.is_symlink() {
        "link"
    } else if attrs.is_regular() {
        "file"
    } else {
        "other"
    };
    session.touch();
    Ok(StatEntry {
        kind,
        size: attrs.size.unwrap_or(0),
        mode: attrs.permissions.unwrap_or(0),
        mtime: u64::from(attrs.mtime.unwrap_or(0)),
        uid: attrs.uid.unwrap_or(0),
        gid: attrs.gid.unwrap_or(0),
    })
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
            // mtime is `Option<u32>` upstream (seconds since epoch). Avoid
            // sign-loss surprises by going through `From` rather than `as`.
            mtime: u64::from(attrs.mtime.unwrap_or(0)),
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
