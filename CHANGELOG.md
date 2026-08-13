# Changelog

Versions follow [semver](https://semver.org). Dates are the tag's.

## 0.5.0 — 2026-08-13

### Protocol

- Speaks MCP revision `2026-07-28` alongside every revision back to
  `2024-11-05`, and adapts per peer. Nothing changes for an older client.
- **Confirmations cross the wire differently on `2026-07-28`.** A server may no
  longer open a request of its own (SEP-2322), so a guarded command comes back
  as an `input_required` result carrying the elicitation; the client answers and
  retries the same call with `inputResponses`. Older peers keep getting a plain
  `elicitation/create`. Both paths live in one place, so no tool knows which era
  its caller belongs to.
- **Long operations can return a task handle** (SEP-2663) when the client
  declares the extension: `exec` past the default 60 s timeout, and `tail` with
  `follow=true`. Everything else, and every client without the extension, keeps
  the blocking call it always had. `tasks/get`, `tasks/update` and `tasks/cancel`
  are wired.
- **`tools/list` is cacheable and deterministically ordered.** It now carries
  `ttlMs` and `cacheScope: public` for peers that understand them, and sorts by
  name. The order used to come from a hash map, so it changed per process and
  defeated client-side prompt caching.
- Persistent PTY sessions are unaffected. A shell has always been addressed by
  the `host` and `session` arguments of the call, which is the explicit handle
  the stateless core asks for (SEP-2567).

### Fixed

- `exec_batch` asks for every distinct pattern in the batch in a single round
  trip instead of one round trip per pattern.

### Internal

- `rmcp` 3.0 to 3.1.2.
- `scripts/stateless-smoke.py` drives the new path against a real host: a
  confirmation that survives the retry and then runs the command, a decline that
  fails closed, and a task polled until it returns its output. The PowerShell
  smokes all speak the legacy handshake and covered none of it.
- Benchmarks rerun on this build, with a token table for the first time. The
  counter now takes any OpenAI-shaped endpoint and subtracts the provider's chat
  template, which a raw `prompt_tokens` reading had been charging to the
  response.

## 0.4.5 — 2026-08-07

- Keep the `server.json` description under the MCP registry's cap.

## 0.4.4 — 2026-08-07

- Split out a lib target so docs.rs has something to show.
- Gate publishing behind the GitHub release, and mint the registry token per
  run.

## 0.4.3 — 2026-08-03

- **Security.** `tail` read a remote file with no path guard at all, so
  `tail path=/etc/shadow` walked past the sensitive-read list every other read
  tool enforces. It now runs the same two checks as `dn`, string then resolved,
  and a path that cannot be resolved refuses the call instead of skipping the
  check.
- `russh` 0.62.4 to 0.62.5.

## 0.4.2 — 2026-07-29

- `cp` copies a file straight from one configured host to another, splicing two
  SFTP sessions so the bytes never touch local disk or the model's context.
- `shot` captures the remote desktop and returns an image, downscaled and
  re-encoded locally.

## 0.4.1 — 2026-07-29

- Publish to the MCP registry on tag.
- Pin CI actions, check the tag against the manifests, one checksum file per
  release.

## 0.4.0 — 2026-07-29

First release with the current tool surface. Earlier tags are in the repository
history.
