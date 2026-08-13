# Changelog

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
