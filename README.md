<h1 align="center">fast-mcp-ssh</h1>
<p align="center">SSH, SFTP and persistent shells for AI agents. One Rust binary, no runtime.</p>

<p align="center">
  <a href="https://crates.io/crates/fast-mcp-ssh"><img src="https://img.shields.io/crates/v/fast-mcp-ssh?logo=rust&color=b7410e" alt="crates.io" /></a>
  <a href="https://github.com/klNuno/fast-mcp-ssh/actions/workflows/ci.yml"><img src="https://github.com/klNuno/fast-mcp-ssh/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License" /></a>
  <img src="https://img.shields.io/badge/rust-1.89%2B-b7410e?logo=rust" alt="Rust 1.89+" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-0078D6" alt="Platform" />
</p>

An MCP server that gives a model real SSH access: one connection per host kept
alive across calls, a PTY shell that remembers `cd` and `export`, SFTP instead
of `cat > file`, host-to-host copies that never touch your disk, a screenshot
of the remote desktop, regex guards before anything leaves your machine, and an
append-only audit log. Answers come back as TOON, roughly 40 percent fewer
tokens than JSON on tabular data.

## Install

```bash
cargo install fast-mcp-ssh
```

Or take a prebuilt binary from the
[latest release](https://github.com/klNuno/fast-mcp-ssh/releases/latest) and
check it against the matching `.sha256`. Linux and macOS ship x86_64 and
aarch64, Windows ships x86_64.

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
| Session | `hosts` `ping` `disconnect` `disconnect_all` `reload` | Discovery and lifecycle; `reload` swaps config without a restart |
| Network | `forward` `unforward` `forwards` | Local TCP forwards over the same connection |

Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`) so a client can gate destructive calls.

## Security

- **Guards run before any SSH packet.** `deny_patterns` refuse outright,
  `confirm_patterns` trigger an MCP elicitation, and a client that cannot
  elicit is denied. `read_only = true` blocks anything that looks like a write.
- **Paths are checked on both sides.** Remote reads of keys, shadow files and
  cloud credentials are refused, and so are local writes that would land in
  your `~/.bashrc` or an autostart folder. Paths are re-checked after the
  server resolves them, so a symlink cannot launder a blocked target.
- **Host keys are pinned** (TOFU by default, `strict` and per-host fingerprints
  available). Every call is appended to `~/.fast-mcp-ssh/audit.log` as NDJSON,
  with credentials scrubbed.

Guards are a speed bump against accidents, not a boundary against an adversary
who controls the model. Scope the remote account accordingly: full threat model
in [SECURITY.md](./SECURITY.md).

## Benchmark

50 iterations per scenario against the same Linux host over the same LAN, same
SSH key, bench client on Windows 11. Medians, lower is better. Reproduce with
[`benchmark/`](./benchmark); raw runs in
[`benchmark/results/`](./benchmark/results).

| | `fast-mcp-ssh` | [`mcp-ssh-manager`][mgr] | [`ssh-mcp-server`][fj] |
|---|---:|---:|---:|
| Cold start | **41 ms** | 289 ms | 279 ms |
| `exec echo ok` | **1.5 ms** | 89.9 ms | 45.1 ms |
| `exec uname -a; whoami; pwd` | **2.4 ms** | 89.0 ms | 46.1 ms |
| `exec seq 1 5000` (~29 KB) | **18.7 ms** | 90.5 ms [^1] | 46.3 ms |
| Write a 1 KB file | **1.4 ms** | 90.9 ms | 45.7 ms |
| Read a 1 KB file | **2.1 ms** | 90.8 ms | 45.8 ms |
| Tool surface, sent every session | 23 tools, 17.6 KB | 37 tools, 39.9 KB | **4 tools, 1.7 KB** |

Both alternatives are Node processes, so ~250 ms of their cold start is the
runtime booting. The steady-state gap is the connection: `fast-mcp-ssh` keeps
one SSH session per host and spawns a channel per call, while the other two
reconnect. Writes go over SFTP here and through a `cat > file` heredoc there.

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
