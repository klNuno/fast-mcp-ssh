# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-07-09

### Added
- Every channel counts against `max_channels_per_host`: PTY, cached SFTP
  subsystem, each forwarded connection, ProxyJump transport. Pool refill waits
  on the semaphore instead of polling.

### Changed
- PTY init is deterministic. A printf-split readiness marker cannot appear in
  the PTY echo, so a single occurrence means ready. Removes the 800 ms settle
  heuristic and two round-trips.
- `dn` inline stats the file first and refuses oversized ones without
  transferring. Local downloads of 4 MB or more stripe across 6 SFTP handles.
- `tail follow` pipes through `head -c` and returns when the capture cap fills
  instead of sitting out the whole window.
- `rm recursive` pipelines 16 deletes in flight; `mkdir -p` drops the per-segment
  pre-flight stat.
- The current-thread runtime never blocks on disk: known_hosts flush, key loads
  and reload moved to `spawn_blocking`. Stderr logging is non-blocking.
- `exec_batch` elicits once per confirm pattern instead of once per command.

### Fixed
- The `rm-rf-root` guard regex matched any absolute path through its trailing
  `/` alternative, so `rm -f /tmp/x.log` was denied. Only root itself and
  first-level root directories match now.
- Stale parked channels retry once on a fresh channel, and only when zero bytes
  were received, so commands never run twice.

## [0.2.1] - 2026-06

### Added
- ProxyJump. The bastion connection is opened recursively through the pool and
  the target handshake runs over a direct-tcpip channel on it.
- `reload` re-reads `hosts.toml`, validates it, atomically swaps guards and
  drops sessions for removed or changed hosts.
- Named PTYs: `sh shell=<name>` opens an independent persistent shell.
- Local TCP port forwarding (`forward`, `forwards`, `unforward`).
- `interrupt` sends Ctrl-C to every PTY on a host and aborts every in-flight
  `exec` / `exec_batch` on it.

## [0.2.0] - 2026-05

### Added
- SFTP tools: `mkdir`, `rm`, `stat`, paginated `ls`.
- Multi-key auth: a host can list several keys and the pool remembers which one
  authenticated.
- `disconnect_all`.

### Fixed
- PTY readiness race and sentinel spoofing.
- SFTP read guards on sensitive paths.

## [0.1.5] - 2026-05

### Changed
- mimalloc global allocator, current-thread runtime, channel pre-warm pool,
  RegexSet guard matching, audit writes offloaded to a dedicated task.

## [0.1.2] - 2026-05

### Added
- `exec_batch` runs N commands in parallel on one host in one round-trip.
- `host` is optional on every tool when `[defaults] default_host` is set.

### Changed
- `nodelay = true` (TCP_NODELAY) on the russh client config, which removed
  roughly 40 ms from every small-command round-trip on LAN.
- SFTP transfers stream in 256 KB chunks.
- Tool descriptions rewritten to 8-12 words each to cut the `tools/list` cost.

## [0.1.1] - 2026-05

### Added
- MCP tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
  `openWorldHint`).
- TOFU host-key pinning in `known_hosts.toml`.
- Asynchronous NDJSON audit log.

## [0.1.0] - 2026-05

Initial release. Persistent session per host, `exec`, `sh` PTY, SFTP upload and
download, regex guards with MCP elicitation, TOON output.
