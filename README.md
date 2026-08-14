<h1 align="center">fast-mcp-ssh</h1>
<p align="center">SSH, SFTP and persistent shells for AI agents. One Rust binary, no runtime.</p>

<p align="center">
  <a href="https://crates.io/crates/fast-mcp-ssh"><img src="https://img.shields.io/crates/v/fast-mcp-ssh?logo=rust&color=b7410e" alt="crates.io" /></a>
  <a href="https://github.com/klNuno/fast-mcp-ssh/actions/workflows/ci.yml"><img src="https://github.com/klNuno/fast-mcp-ssh/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License" /></a>
  <img src="https://img.shields.io/badge/rust-1.89%2B-b7410e?logo=rust" alt="Rust 1.89+" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-0078D6" alt="Platform" />
</p>

An MCP server that gives a model real SSH access:

- One connection per host, held open across calls.
- A PTY shell that remembers `cd` and `export`.
- SFTP instead of `cat > file`, and host-to-host copies that skip your disk.
- A screenshot of the remote desktop.
- Regex guards before anything leaves your machine.
- An append-only audit log of every call.

Answers come back as TOON, roughly 40 percent fewer
tokens than JSON on tabular data.

## Install

```bash
cargo install fast-mcp-ssh
```

Or a prebuilt binary from the
[latest release](https://github.com/klNuno/fast-mcp-ssh/releases/latest),
checked against `SHA256SUMS.txt`. Linux and macOS ship x86_64 and aarch64,
Windows x86_64.

Copy [`hosts.example.toml`](./hosts.example.toml) to `~/.fast-mcp-ssh/hosts.toml`
and fill in your hosts. Keys go in `~/.fast-mcp-ssh/keys/<name>`; `auth` is
`key`, `agent` or `password`.

## Wire it up

`.mcp.json`, or `claude_desktop_config.json` for Claude Desktop:

```json
{
  "mcpServers": {
    "ssh": {
      "type": "stdio",
      "command": "fast-mcp-ssh"
    }
  }
}
```

Same block in Claude Code, Cursor, Windsurf, Zed, VS Code Copilot and anything
else that speaks MCP over stdio.

In the [MCP registry](https://registry.modelcontextprotocol.io) it is
`mcp-name: io.github.klNuno/fast-mcp-ssh`.

## Tools

`host` is optional on every tool once `[defaults] default_host` is set.

| Group | Tools | |
|---|---|---|
| Run | `exec` `exec_batch` `sh` `interrupt` | One-shot, parallel fan-out, persistent PTY, Ctrl-C |
| Files | `ls` `stat` `dn` `up` `cp` `wr` `mkdir` `rm` `tail` | SFTP, plus `tail -n` / `tail -F` in a bounded window |
| Visual | `shot` | Screenshots the remote desktop, downscaled before it reaches the model |
| Ops | `facts` `sys` `svc` | Cached host profile, parsed `ps`/`df`/`mem`/`net`, systemd units |
| Session | `hosts` `ping` `disconnect` `disconnect_all` `reload` `shells` | Discovery and lifecycle; `reload` swaps config without a restart, `shells` closes named PTYs |
| Network | `forward` `unforward` `forwards` | Local TCP forwards over the same connection |

Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`) so a client can gate destructive calls.

### Host-to-host copy

`cp` moves a file from one configured host to another. The bytes never land on
your disk and never reach the model, and a sha256 is compared on both ends
before success. Guards cover the destination too, so a read-only target still
refuses the write.

### Remote screenshots

`shot` hands the model an image instead of a wall of text. It uses whichever of
`grim`, `gnome-screenshot`, `spectacle`, ImageMagick `import` or `scrot` the
host has, covering X11 and wlroots Wayland, and downscales locally so a 4K
screen is not a multi-megabyte payload.

## Protocol

Speaks stateless MCP (`2026-07-28`) and every revision back to `2024-11-05`,
picked per peer. Stateless changes three things:

- Confirmations come back as an `input_required` result the client answers and
  retries (SEP-2322), because a server may no longer open a request of its own.
  Older peers keep `elicitation/create`.
- Long calls hand back a task handle to poll (SEP-2663): `exec` past its 60s
  timeout, `tail` with `follow=true`. Clients without the extension keep the
  blocking call.
- `tools/list` is sorted, so it is byte-identical between restarts, and carries
  a one hour `ttlMs` (SEP-2549). A client's prompt cache keeps hitting.

Shells are unaffected. A PTY has always been addressed by the `host` and
`session` arguments of the call, which is the explicit handle stateless wants.

## Security

Guards run before any SSH packet leaves. `deny_patterns` refuse outright,
`confirm_patterns` ask the user, a client that cannot answer is denied, and
`read_only = true` blocks anything that looks like a write.

Paths are checked on both sides: remote reads of keys, shadow files and cloud
credentials, local writes into your `~/.bashrc` or an autostart folder. Every
path-taking tool runs both checks, `tail` included, and re-checks once the
server has resolved the path, so a symlink cannot launder a blocked target. A
path that will not resolve refuses the call.

Host keys are pinned, TOFU by default, `strict` and per-host fingerprints
available. Every call lands in `~/.fast-mcp-ssh/audit.log` as NDJSON, with
credentials scrubbed.

Guards stop accidents, not an adversary who controls the model. Scope the
remote account accordingly. Threat model: [SECURITY.md](./SECURITY.md).
Version history: [CHANGELOG.md](./CHANGELOG.md).

## Benchmark

50 iterations per scenario, same Linux host, same LAN, same SSH key, client on
Windows 11. Medians, lower is better, measured on `0.5.0`. Reproduce with
[`benchmark/`](./benchmark), raw runs in
[`benchmark/results/`](./benchmark/results).

| | `fast-mcp-ssh` | [`mcp-ssh-manager`][mgr] | [`ssh-mcp-server`][fj] |
|---|---:|---:|---:|
| Cold start | **48 ms** | 280 ms | 260 ms |
| `exec echo ok` | **2.2 ms** | 89.7 ms | 46.7 ms |
| `exec uname -a; whoami; pwd` | **3.6 ms** | 90.9 ms | 50.6 ms |
| `exec seq 1 5000` (~29 KB) | **19.6 ms** | 90.4 ms [^1] | 49.2 ms |
| Write a 1 KB file | **1.1 ms** | 89.9 ms | 47.9 ms |
| Read a 1 KB file | **1.7 ms** | 90.3 ms | 48.9 ms |
| Tool surface, sent every session | 26 tools, 21.1 KB | 37 tools, 39.9 KB | **4 tools, 1.7 KB** |

Both alternatives are Node, so ~250 ms of their cold start is the runtime
booting. The steady-state gap is the connection: `fast-mcp-ssh` holds one SSH
session per host and opens a channel per call, the other two reconnect. Writes
go over SFTP here, through a `cat > file` heredoc there.

[^1]: `mcp-ssh-manager` truncates that response to 12 KB, so it is not
returning the same output. `ssh-mcp-server` returns raw stdout with no exit
code, which is why its replies are the shortest and why a failed command looks
like a successful one.

[mgr]: https://www.npmjs.com/package/mcp-ssh-manager
[fj]: https://www.npmjs.com/package/@fangjunjie/ssh-mcp-server

## Development

```bash
cargo install --path .        # build and install from a clone
cargo test                    # unit tests
cargo clippy --all-targets    # no warnings allowed in CI
./scripts/test-sh.ps1         # end-to-end against a real host (Windows)
```

Never write to stdout outside the MCP transport: a stray `println!` corrupts
the JSON-RPC stream and the client disconnects without an error. `tracing`
macros go to stderr and are safe.

## License

MIT.
