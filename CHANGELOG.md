# Changelog

## Unreleased

### Added

- `local_read_allow` / `local_write_allow` in the guards block: the operator can
  name one file, or one directory subtree, that `up` may read or `dn` and `shot`
  may write despite the sensitive-path banks. Entries are resolved and validated
  at config load; a glob, a filesystem root or the home directory is refused.
  Until now a blocked local path had no way out at all, so a deploy that had to
  ship a `.key` simply stopped.

### Changed

- `guard_blocked` errors hint `recovery: "edit_config"`, not `"ask_user"`. No
  answer given back through a tool call can lift a guard, and callers were
  spending a round trip collecting an approval they could not use.

## 0.5.1 - 2026-09-24

### Added

- `max_connections_per_host` (default 2). A burst of `exec` that fills every
  channel slot on a host opens a second SSH connection instead of queueing,
  since sshd caps channels per connection. 16 parallel `exec` of a 0.5 s
  command: 1.5 s before, 0.51 s now. The extra connection closes after two idle
  minutes.

### Changed

- Truncated output keeps its end as well as its start, and the marker counts
  every byte the command printed. Past `max_capture_bytes` it used to report
  only what had been captured: 254 KB cut on a 1.1 MB output.

### Fixed

- Bursts of `exec` failed now and then with `Failed to open channel
  (ConnectFailed)`: sshd frees a channel slot after the client has already
  reused it ("no more sessions"). A call now keeps its slot until the server's
  `Close`, and a refused open is retried.
- A call queued for a channel slot waited on the semaphore alone and missed a
  channel parked by the pre-warm task in the meantime, costing a whole command
  length.
- `sh` output no longer carries `\e[?2004h`/`\e[?2004l` from bash 5.1+ readline.

## 0.5.0 — 2026-08-13

### Added

- MCP revision `2026-07-28`, negotiated per peer, alongside every revision back
  to `2024-11-05`.
- Confirmations over multi round-trip requests on `2026-07-28` peers (SEP-2322):
  the call returns `input_required`, the client answers and retries it. Older
  peers keep `elicitation/create`.
- Task handles for long calls when the client declares the extension
  (SEP-2663): `exec` past its timeout, `tail` with `follow=true`.
- `tools/list` carries `ttlMs` and `cacheScope` on peers that read them.

### Changed

- `tools/list` is sorted by name. The order came from a hash map, so it moved
  between processes and defeated prompt caching.
- `exec_batch` asks for every distinct guard pattern in one round trip instead
  of one per pattern.
- `rmcp` 3.0 to 3.1.2.

## 0.4.5 — 2026-08-07

- `server.json` description now fits the MCP registry's cap.

## 0.4.4 — 2026-08-07

- Lib target added, so docs.rs has something to render.

## 0.4.3 — 2026-08-03

- **Security**: `tail` read remote paths with no guard. It now runs the same
  checks as `dn`, string then resolved, and refuses a path it cannot resolve.
- `russh` 0.62.4 to 0.62.5.

## 0.4.2 — 2026-07-29

- `cp`: host-to-host file copy over two spliced SFTP sessions.
- `shot`: remote screenshot, downscaled and re-encoded before it is returned.

## 0.4.1 — 2026-07-29

- Published to the MCP registry on tag.

## 0.4.0 — 2026-07-29

- First release with the current tool surface.
