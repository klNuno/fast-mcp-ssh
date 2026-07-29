use std::path::Path;
use std::time::{Duration, Instant};

use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::errors::{Result, SshError};
use crate::session::Session;

const TRANSFER_CHUNK: usize = 256 * 1024;
/// Downloads at or above this size (with a known size) are striped across
/// several concurrent SFTP file handles. russh-sftp reads are strictly
/// sequential per handle (one FXP_READ in flight), so a single stream is
/// capped at ~one `read_len` (~255 KiB with OpenSSH) per round-trip;
/// N handles multiply that.
const PARALLEL_DOWNLOAD_MIN: u64 = 4 * 1024 * 1024;
const PARALLEL_DOWNLOAD_WORKERS: u64 = 6;
/// Max in-flight SFTP delete requests during a recursive remove.
const RM_CONCURRENCY: usize = 16;
/// A host-to-host copy pays a read *and* a write round-trip per chunk, so it
/// stripes earlier and wider than a download: both sides pipeline.
const PARALLEL_COPY_MIN: u64 = 1024 * 1024;
const PARALLEL_COPY_WORKERS: u64 = 4;

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
    /// Resolved target when `kind == "link"`. `None` for everything else, or
    /// when the link dangles.
    pub target: Option<String>,
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

/// Resolve `path` server-side via FXP_REALPATH so a path guard can be re-run
/// against what the path actually points at. SFTP follows symlinks, so
/// `ln -s /etc/shadow /tmp/s` would otherwise launder a blocked read through a
/// harmless-looking string. One round-trip; two only when the path does not
/// exist yet (normal for `wr` / `up`), in which case the parent is resolved and
/// the leaf re-joined so a symlinked parent directory can't dodge the guard
/// either. Never returns Ok on total failure — a guard must not be skipped
/// because a lookup errored.
pub async fn resolve_path(session: &Session, path: &str) -> Result<String> {
    let sftp = session.sftp().await?;
    let direct = with_timeout("realpath", 30, async {
        sftp.canonicalize(path.to_string())
            .await
            .map_err(SshError::from)
    })
    .await;
    if let Ok(p) = direct {
        return Ok(p);
    }
    let (parent, leaf) = split_parent(path);
    let base = with_timeout("realpath", 30, async {
        sftp.canonicalize(parent.to_string())
            .await
            .map_err(SshError::from)
    })
    .await?;
    Ok(join_remote(&base, leaf))
}

/// Split a POSIX remote path into `(parent, leaf)`. Trailing slashes are
/// trimmed first so `/tmp/d/` yields `("/tmp", "d")`.
fn split_parent(path: &str) -> (&str, &str) {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return ("/", "");
    }
    match trimmed.rfind('/') {
        Some(0) => ("/", trimmed.get(1..).unwrap_or("")),
        Some(i) => (
            trimmed.get(..i).unwrap_or("/"),
            trimmed.get(i + 1..).unwrap_or(""),
        ),
        None => (".", trimmed),
    }
}

fn join_remote(base: &str, leaf: &str) -> String {
    if leaf.is_empty() {
        base.to_string()
    } else if base.ends_with('/') {
        format!("{base}{leaf}")
    } else {
        format!("{base}/{leaf}")
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
    sftp.rename(&partial, remote)
        .await
        .map_err(SshError::from)?;
    session.touch();
    Ok(SftpResult {
        bytes: total,
        duration_ms: start.elapsed().as_millis(),
    })
}

/// Download `remote`. With `local`, streams (or stripes) to disk and returns
/// `None` content. Without, returns the bytes inline — unless the file
/// exceeds `inline_max`, in which case nothing is transferred beyond the
/// probe and the content is `None` with `bytes` set to the remote size
/// (previously the whole file was downloaded and then thrown away).
pub async fn download(
    session: &Session,
    remote: &str,
    local: Option<&Path>,
    inline_max: usize,
) -> Result<(SftpResult, Option<Vec<u8>>)> {
    let start = Instant::now();
    let sftp = session.sftp().await?;
    let mut remote_file = sftp
        .open_with_flags(remote, OpenFlags::READ)
        .await
        .map_err(SshError::from)?;
    // fstat on the already-open handle: one round-trip buys the size for
    // the too-large-for-inline early exit, exact preallocation, and the
    // striped-download split.
    let size = remote_file.metadata().await.ok().and_then(|m| m.size);
    session.touch();

    if let Some(path) = local {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await?;
        }
        if let Some(sz) = size
            && sz >= PARALLEL_DOWNLOAD_MIN
        {
            drop(remote_file);
            let total = download_striped(&sftp, remote, path, sz).await?;
            session.touch();
            return Ok((
                SftpResult {
                    bytes: total,
                    duration_ms: start.elapsed().as_millis(),
                },
                None,
            ));
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
            SftpResult {
                bytes: total,
                duration_ms: start.elapsed().as_millis(),
            },
            None,
        ));
    }

    // Inline: refuse before transferring when the size is known to exceed
    // the cap. Unknown or lying sizes are still bounded by the capped read.
    if let Some(sz) = size
        && sz as usize > inline_max
    {
        return Ok((
            SftpResult {
                bytes: sz as usize,
                duration_ms: start.elapsed().as_millis(),
            },
            None,
        ));
    }
    let cap = inline_max + 1;
    let mut content = Vec::with_capacity(size.map_or(TRANSFER_CHUNK, |s| (s as usize).min(cap)));
    let mut buf = vec![0u8; TRANSFER_CHUNK];
    loop {
        let room = cap - content.len();
        if room == 0 {
            break;
        }
        let want = room.min(TRANSFER_CHUNK);
        let n = remote_file.read(&mut buf[..want]).await?;
        if n == 0 {
            break;
        }
        content.extend_from_slice(&buf[..n]);
    }
    let total = content.len();
    if total > inline_max {
        return Ok((
            SftpResult {
                bytes: total,
                duration_ms: start.elapsed().as_millis(),
            },
            None,
        ));
    }
    Ok((
        SftpResult {
            bytes: total,
            duration_ms: start.elapsed().as_millis(),
        },
        Some(content),
    ))
}

/// Stripe a large download across several SFTP file handles on the shared
/// subsystem channel. Each worker opens its own handle, seeks to its stripe,
/// and streams it to its own handle on the pre-sized local file. Requests
/// from all handles pipeline on the wire, lifting the one-read-in-flight
/// ceiling of a single handle (~read_len per RTT).
async fn download_striped(
    sftp: &std::sync::Arc<russh_sftp::client::SftpSession>,
    remote: &str,
    path: &Path,
    size: u64,
) -> Result<usize> {
    let workers = PARALLEL_DOWNLOAD_WORKERS
        .min(size.div_ceil(PARALLEL_DOWNLOAD_MIN))
        .max(1);
    let stripe = size.div_ceil(workers);
    // Pre-size the file so workers can write their stripes independently.
    {
        let f = tokio::fs::File::create(path).await?;
        f.set_len(size).await?;
    }
    let mut set = tokio::task::JoinSet::new();
    for w in 0..workers {
        let offset = w * stripe;
        let len = stripe.min(size - offset);
        if len == 0 {
            break;
        }
        let sftp = std::sync::Arc::clone(sftp);
        let remote = remote.to_string();
        let path = path.to_path_buf();
        set.spawn(async move {
            let mut rf = sftp
                .open_with_flags(remote, OpenFlags::READ)
                .await
                .map_err(SshError::from)?;
            rf.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut lf = tokio::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .await?;
            lf.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut buf = vec![0u8; TRANSFER_CHUNK];
            let mut left = len as usize;
            while left > 0 {
                let want = left.min(TRANSFER_CHUNK);
                let n = rf.read(&mut buf[..want]).await?;
                if n == 0 {
                    return Err(SshError::Other(format!(
                        "sftp download: short read at offset {}",
                        offset + (len as usize - left) as u64
                    )));
                }
                lf.write_all(&buf[..n]).await?;
                left -= n;
            }
            lf.flush().await?;
            Ok::<usize, SshError>(len as usize)
        });
    }
    let mut total = 0usize;
    while let Some(joined) = set.join_next().await {
        total += joined.map_err(|e| SshError::Other(format!("download worker: {e}")))??;
    }
    Ok(total)
}

/// Copy `src_path` on one host to `dst_path` on another, splicing the two SFTP
/// sessions directly. The bytes cross this process but never touch its disk and
/// never enter the model's context, and the two hosts do not need to reach each
/// other: the usual alternative is `dn` to a local file followed by `up`, which
/// writes the whole payload to the operator's disk and pays for the round-trip
/// twice.
///
/// Large files stripe the same way `download_striped` does, except each worker
/// owns a read handle on the source *and* a write handle on the destination.
/// One handle can only keep a single request in flight per side, so a plain
/// read-then-write loop spends every round-trip waiting; N pairs pipeline.
pub async fn copy_between(
    src: &Session,
    src_path: &str,
    dst: &Session,
    dst_path: &str,
    mode: Option<u32>,
) -> Result<SftpResult> {
    let start = Instant::now();
    let src_sftp = src.sftp().await?;
    let dst_sftp = dst.sftp().await?;

    let mut reader = src_sftp
        .open_with_flags(src_path, OpenFlags::READ)
        .await
        .map_err(SshError::from)?;
    let meta = reader.metadata().await.ok();
    let size = meta.as_ref().and_then(|m| m.size);
    // Preserve the source mode unless the caller pinned one: a copied script
    // that lost its exec bit is a silent failure at the far end.
    let attrs = FileAttributes {
        permissions: Some(
            mode.or_else(|| meta.as_ref().and_then(|m| m.permissions))
                .unwrap_or(0o644),
        ),
        ..Default::default()
    };

    // Same `.partial` + rename discipline as `upload`, so a blip mid-copy
    // cannot leave a truncated file at the destination path.
    let partial = format!("{dst_path}.partial");
    let mut writer = dst_sftp
        .open_with_flags_and_attributes(
            &partial,
            OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
            attrs,
        )
        .await
        .map_err(SshError::from)?;

    let striped = size.is_some_and(|s| s >= PARALLEL_COPY_MIN);
    let copied: Result<usize> = if striped {
        drop(reader);
        writer.shutdown().await?;
        drop(writer);
        copy_striped(&src_sftp, src_path, &dst_sftp, &partial, size.unwrap_or(0)).await
    } else {
        async {
            let mut buf = vec![0u8; TRANSFER_CHUNK];
            let mut total = 0usize;
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                writer.write_all(&buf[..n]).await?;
                total += n;
            }
            writer.shutdown().await?;
            Ok(total)
        }
        .await
    };

    let total = match copied {
        Ok(n) => n,
        Err(e) => {
            let _ = dst_sftp.remove_file(&partial).await;
            return Err(e);
        }
    };
    dst_sftp
        .rename(&partial, dst_path)
        .await
        .map_err(SshError::from)?;
    src.touch();
    dst.touch();
    Ok(SftpResult {
        bytes: total,
        duration_ms: start.elapsed().as_millis(),
    })
}

/// Stripe a copy across `PARALLEL_COPY_WORKERS` read/write handle pairs. The
/// destination file already exists and is truncated; each worker seeks both
/// sides to its own offset, so the stripes never overlap.
async fn copy_striped(
    src_sftp: &std::sync::Arc<russh_sftp::client::SftpSession>,
    src_path: &str,
    dst_sftp: &std::sync::Arc<russh_sftp::client::SftpSession>,
    dst_path: &str,
    size: u64,
) -> Result<usize> {
    let workers = PARALLEL_COPY_WORKERS
        .min(size.div_ceil(PARALLEL_COPY_MIN))
        .max(1);
    let stripe = size.div_ceil(workers);
    let mut set = tokio::task::JoinSet::new();
    for w in 0..workers {
        let offset = w * stripe;
        let len = stripe.min(size - offset);
        if len == 0 {
            break;
        }
        let src_sftp = std::sync::Arc::clone(src_sftp);
        let dst_sftp = std::sync::Arc::clone(dst_sftp);
        let src_path = src_path.to_string();
        let dst_path = dst_path.to_string();
        set.spawn(async move {
            let mut rf = src_sftp
                .open_with_flags(src_path, OpenFlags::READ)
                .await
                .map_err(SshError::from)?;
            rf.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut wf = dst_sftp
                .open_with_flags(dst_path, OpenFlags::WRITE)
                .await
                .map_err(SshError::from)?;
            wf.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut buf = vec![0u8; TRANSFER_CHUNK];
            let mut left = len as usize;
            while left > 0 {
                let want = left.min(TRANSFER_CHUNK);
                let n = rf.read(&mut buf[..want]).await?;
                if n == 0 {
                    return Err(SshError::Other(format!(
                        "sftp copy: short read at offset {}",
                        offset + (len as usize - left) as u64
                    )));
                }
                wf.write_all(&buf[..n]).await?;
                left -= n;
            }
            wf.shutdown().await?;
            Ok::<usize, SshError>(len as usize)
        });
    }
    let mut total = 0usize;
    while let Some(joined) = set.join_next().await {
        total += joined.map_err(|e| SshError::Other(format!("copy worker: {e}")))??;
    }
    Ok(total)
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
    Ok(SftpResult {
        bytes: content.len(),
        duration_ms: start.elapsed().as_millis(),
    })
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
            // No pre-flight stat: try the create and, on failure, stat once
            // to see whether the directory already existed. Halves the SFTP
            // round-trips per component in the common "parents exist" case
            // (SFTPv3 has no distinct exists code — OpenSSH returns FAILURE).
            let res = with_timeout("mkdir", 30, async {
                sftp.create_dir(acc.clone()).await.map_err(SshError::from)
            })
            .await;
            if let Err(e) = res {
                let is_dir = sftp
                    .metadata(acc.clone())
                    .await
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                if !is_dir {
                    return Err(e);
                }
            }
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
    // lstat, not stat: FXP_STAT follows the link, so `ln -s /etc /tmp/x`
    // followed by `rm /tmp/x recursive=true` would walk into /etc. Child
    // entries were already safe (readdir carries lstat attrs); the entry point
    // was the hole.
    let meta = with_timeout("lstat", 30, async {
        sftp.symlink_metadata(path.to_string())
            .await
            .map_err(SshError::from)
    })
    .await?;
    if meta.is_symlink() {
        if recursive {
            return Err(SshError::Other(format!(
                "{path} is a symlink; refusing recursive delete because it would \
                 delete the link target's tree, not the link. Re-run with \
                 recursive=false to remove the symlink itself."
            )));
        }
        with_timeout("rm", 30, async {
            sftp.remove_file(path.to_string())
                .await
                .map_err(SshError::from)
        })
        .await?;
        session.touch();
        return Ok(1);
    }
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
                sftp.remove_dir(dir.clone()).await.map_err(SshError::from)
            })
            .await?;
            count += 1;
            continue;
        }
        stack.push((dir.clone(), true));
        let entries = with_timeout("readdir", 30, async {
            sftp.read_dir(dir.clone()).await.map_err(SshError::from)
        })
        .await?;
        // Deletes are independent request/response pairs on the shared SFTP
        // channel: pipeline up to RM_CONCURRENCY in flight instead of paying
        // one full round-trip per file. Drained before this directory's own
        // rmdir (pushed above) is popped.
        let mut inflight = tokio::task::JoinSet::new();
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
                if inflight.len() >= RM_CONCURRENCY
                    && let Some(joined) = inflight.join_next().await
                {
                    joined.map_err(|e| SshError::Other(format!("rm worker: {e}")))??;
                    count += 1;
                }
                let sftp = std::sync::Arc::clone(&sftp);
                inflight.spawn(async move {
                    match timeout(Duration::from_secs(30), sftp.remove_file(child)).await {
                        Ok(r) => r.map_err(SshError::from),
                        Err(_) => Err(SshError::Other("sftp rm timed out after 30s".into())),
                    }
                });
            }
        }
        while let Some(joined) = inflight.join_next().await {
            joined.map_err(|e| SshError::Other(format!("rm worker: {e}")))??;
            count += 1;
        }
    }
    Ok(count)
}

pub async fn stat(session: &Session, path: &str) -> Result<StatEntry> {
    let sftp = session.sftp().await?;
    // lstat, not stat: FXP_STAT follows the link and reports the target's
    // attributes, so a symlink is indistinguishable from what it points at.
    // The link itself is what the caller asked about; the target is reported
    // separately below.
    let attrs = with_timeout("lstat", 30, async {
        sftp.symlink_metadata(path.to_string())
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
    // A dangling link still stats fine but fails to resolve. That is reported
    // as an absent target, not as a failed `stat`.
    let target = if kind == "link" {
        with_timeout("readlink", 30, async {
            sftp.read_link(path.to_string())
                .await
                .map_err(SshError::from)
        })
        .await
        .ok()
    } else {
        None
    };
    session.touch();
    Ok(StatEntry {
        kind,
        size: attrs.size.unwrap_or(0),
        mode: attrs.permissions.unwrap_or(0),
        mtime: u64::from(attrs.mtime.unwrap_or(0)),
        uid: attrs.uid.unwrap_or(0),
        gid: attrs.gid.unwrap_or(0),
        target,
    })
}

pub async fn list_dir(session: &Session, path: &str) -> Result<Vec<ListEntry>> {
    let sftp = session.sftp().await?;
    let entries = sftp.read_dir(path).await.map_err(SshError::from)?;
    let mut out = Vec::with_capacity(entries.size_hint().0);
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
