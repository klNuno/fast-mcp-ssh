# fast-mcp-ssh

MCP server in Rust that exposes SSH over stdio. Persistent connection per host, PTY shell sessions, SFTP, regex guards, NDJSON audit log. Single binary, ~10 MB resident, ~50 ms start.

## Install

```bash
cargo install --path .
# or
cargo build --release
# binary: target/release/fast-mcp-ssh
```

Config goes in `~/.fast-mcp-ssh/hosts.toml` (template at `examples/hosts.toml`). Keys live in `~/.fast-mcp-ssh/keys/<name>`.

## Wire into Claude Code or Claude Desktop

`.mcp.json` or `claude_desktop_config.json`:

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

Optional `--config <path>`. Default is `$FAST_MCP_SSH_HOME/hosts.toml`, falling back to `~/.fast-mcp-ssh/hosts.toml`.

## Tools

| Tool    | Args                                 | Notes |
|---------|--------------------------------------|-------|
| `hosts`     | none                                                  | List configured hosts and their session state. |
| `ping`      | `host?`, `password?`                                  | Health check. With no arg, probes all hosts in parallel (password ignored in that case). |
| `exec`      | `host?`, `cmd`, `timeout?`, `password?`, `confirm?`     | One-shot command on a fresh exec channel. Stateless, parallel-safe. |
| `exec_batch`| `host?`, `cmds[]`, `timeout?`, `password?`, `confirm?`, `verbose?` | Run N commands in parallel on one host in one round-trip. `verbose=true` widens success preview to 200 chars; failures always show 200. |
| `sh`        | `host?`, `cmd`, `timeout?`, `password?`, `confirm?`, `cols?`, `rows?` | Persistent PTY shell. `cd` / `export` survive between calls. PTY size is configurable on first call per host. |
| `disconnect`| `host?`                                                | Close the persistent session. Reopens automatically on next call. |
| `interrupt` | `host?`                                                | Send Ctrl-C to the foreground command on the persistent PTY. Independent of in-flight `sh` (split read/write). |
| `disconnect_all` | none                                              | Close every live session in one shot. |
| `up`        | `host?`, `local`, `remote`                              | SFTP upload (streamed, 256 KB chunks). |
| `dn`        | `host?`, `remote`, `local?`                             | SFTP download (streamed). With no `local`, returns content inline (text under 256 KB; binary returned base64-encoded). Refuses sensitive paths (shadow, ssh privkeys, cloud creds…). |
| `ls`        | `host?`, `path`, `limit?`, `offset?`                    | SFTP directory listing. Paginated (default 1000 per page). |
| `wr`        | `host?`, `remote`, `content`, `mode?`                   | Write a file inline. Optional octal mode applied at create time. Hard cap 8 MB; larger files via `up`. |
| `mkdir`     | `host?`, `path`, `parents?`                             | SFTP create directory. `parents=true` for `mkdir -p`. |
| `rm`        | `host?`, `path`, `recursive?`                           | SFTP remove file. `recursive=true` for directories — always elicits confirmation. |
| `stat`      | `host?`, `path`                                         | SFTP stat: kind, size, mode, mtime, uid, gid. |
| `tail`      | `host?`, `path`, `lines?`, `follow?`, `seconds?`         | `tail -n` (default) or `timeout N tail -F` (returns at end of window). |

`host` is optional on every tool when `[defaults] default_host = "<alias>"` is set in `hosts.toml`.

All tools carry MCP tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) so MCP-aware clients can gate destructive calls automatically.

Tool names are short because the MCP client prefixes them with the server name; an additional `ssh_` prefix is dead weight in every tool description.

## Auth

- `auth = "key"` with `key = "~/path/to/private_key"`. Ed25519, RSA, ECDSA.
- `auth = "agent"`. Uses ssh-agent. Windows: OpenSSH service named pipe. Unix: `$SSH_AUTH_SOCK`.
- `auth = "password"`. The agent passes the password per call (`exec password=...`). Cached in process memory only, never written to disk.

## Output format

Output uses TOON, a denser text format. Same information as JSON, about 40 percent fewer tokens for tabular data.

```
hosts(3):
  name addr user port auth session
  bastion 203.0.113.5 ops 22 agent live
  box1 10.0.0.1 root 22 key idle
  prod-db db.internal deploy 22 key idle
hint: exec host=<name> cmd=<...>  |  sh host=<name> cmd=<...>  |  ping
```

JSON for the same data:

```json
{"hosts":[{"name":"bastion","addr":"203.0.113.5","user":"ops","port":22,"auth":"agent","session":"live"},{"name":"box1","addr":"10.0.0.1","user":"root","port":22,"auth":"key","session":"idle"},{"name":"prod-db","addr":"db.internal","user":"deploy","port":22,"auth":"key","session":"idle"}]}
```

## Security

Three checks run per call before any SSH packet leaves the box.

1. `deny_patterns`. Regex match means the call returns an error, gets logged, and never opens a channel. Defaults block `rm -rf /<top-level>`, `dd of=/dev/sd*`, `mkfs`, fork bombs, redirects to a disk device, recursive root chmod.
2. `confirm_patterns`. Match triggers an MCP elicitation request: the user gets a yes/no prompt in the host UI. Reply must be literally `yes` to proceed. If the client doesn't support elicitation the call is denied. Defaults match `shutdown`, `reboot`, `DROP TABLE`, `systemctl stop`, `docker rm`.
3. `read_only = true` on a host blocks anything that looks like a write (`>`, `rm`, `mv`, `chmod`, `systemctl restart`, `docker run`, package installs).

Audit log at `~/.fast-mcp-ssh/audit.log`. Append-only NDJSON, one record per call, with timestamp, host, tool, command, exit code, duration, byte counts, blocking reason. Writes are batched on a dedicated tokio task so they never block tool calls.

Server fingerprints are pinned via TOFU by default. The first time fast-mcp-ssh connects to a host, the SHA-256 fingerprint of its public key is recorded in `~/.fast-mcp-ssh/known_hosts.toml`. On every subsequent connection the fingerprint must match — a mismatch aborts the handshake with `fingerprint_mismatch`. Override globally via `[defaults] strict_host_key_checking = "tofu" | "strict" | "off"`, or pin a specific value per host with `known_host_fingerprint = "..."`.

## Tests

```bash
cargo test                    # 27 unit tests
./scripts/test-sh.ps1         # end-to-end smoke against real hosts (Windows)
```

## Benchmark vs `mcp-ssh-manager`

50 iterations per scenario. Identical SSH key for both servers, identical target. Per-version
runs live under [`benchmark/results/v<version>/`](benchmark/results/) (one folder each).
The numbers below are from the **v0.1.2** run: bench client on a Windows workstation,
target an x86_64 Linux host on the same gigabit LAN. Reproducible via [`benchmark/`](benchmark/).

### Summary (v0.1.2, median)

| Metric | `fast-mcp-ssh` | `mcp-ssh-manager` | Ratio |
|---|---:|---:|---:|
| Cold start | 26 ms | 217 ms | 8× faster |
| Warm `exec` `echo ok` | 2.5 ms | 90 ms | 36× |
| Warm `exec` `seq 1 5000` (~12 KB) | 9 ms | 90 ms | 10× |
| Write 1 KB file | 2.4 ms | 90 ms | 38× |
| Read 1 KB file | 2.8 ms | 90 ms | 32× |
| Tokens, small command response (v0.1.1) | 35 | 49 | −29% |
| Tokens, write-status response (v0.1.1) | 31 | 202 | −85% |

The exec gap widened a lot in 0.1.2 — `nodelay = true` (TCP_NODELAY) on the russh client
config alone shaved ~40 ms off every small-command round-trip on LAN.

### Warm latency, median ms (lower is better)

| Scenario | `fast-mcp-ssh` | `mcp-ssh-manager` | Ratio |
|----------|---:|---:|---:|
| `exec` `echo ok`                  | 2.5 |  90 | 36× |
| `exec` `uname -a; whoami; pwd`     | 4.0 |  91 | 23× |
| `exec` `seq 1 5000` (~12 KB)      | 9.0 |  90 | 10× |
| `exec` `ls -la /etc \| head -100` | 7.1 |  91 | 13× |
| `exec` `ls /nonexistent` (stderr) | 3.7 |  90 | 24× |
| `exec` `cat /etc/passwd \| wc -l` | 4.4 |  91 | 21× |
| Write 1 KB file                   | 2.4 |  90 | 38× |
| Read 1 KB file                    | 2.8 |  90 | 32× |

The write gap is structural. `fast-mcp-ssh` writes via SFTP. `mcp-ssh-manager` has no inline write tool, so the bench uses `ssh_execute "cat > path <<EOF…"`, which costs a full shell exec round-trip.

### Token cost (from v0.1.1, OpenRouter `deepseek/deepseek-chat`)

| Scenario | `fast-mcp-ssh` | `mcp-ssh-manager` | fast / mgr |
|----------|---:|---:|---:|
| `exec` `echo ok`                |   35 |   49 | −29% |
| `exec` `uname …`                |   94 |  114 | −18% |
| `exec` `cat … \| wc -l`         |   35 |   58 | −40% |
| `exec` `ls -la /etc \| head`    | 2438 | 2413 | +1% |
| `exec` `seq 1 5000`             | 6513 | 5725 | +14% |
| `exec` `ls /nonexistent`        |   64 |   65 | 0% |
| Write 1 KB status               |   31 |  202 | −85% |
| Read 1 KB inline                |  167 |  186 | −10% |

`fast-mcp-ssh` is cheaper on small structured responses. On large raw stdout the savings disappear because the actual command output dominates the payload and TOON's per-call metadata costs a few percent.

In 0.1.2 the per-`tools/list` token cost dropped further — every tool's description was rewritten to 8-12 words and the global `instructions` blob is now a single line.

### Reproducing

```bash
# 1. Provision a benchmark host. Installs rust + npm + mcp-ssh-manager,
#    builds fast-mcp-ssh, sets up SSH keys to the target. Idempotent,
#    about 3 minutes on first run.
python benchmark/provision.py

# 2. Run the bench from the bench host. Set OPENROUTER_API_KEY for token
#    counting, otherwise that section is skipped.
ssh bench-host 'cd ~/bench && \
    FAST_BIN=$HOME/bench/fast-mcp-ssh/target/release/fast-mcp-ssh \
    MGR_BIN=$HOME/.npm-global/bin/mcp-ssh-manager \
    OPENROUTER_API_KEY=sk-or-... \
    python3 bench.py --iterations 50 --output results'
```

Results land in `<bench-host>:~/bench/results/`:
- `runs.csv`: every individual call (server, scenario, iter, ms, chars, error).
- `summary.md`: markdown tables (cold start, p50 and p95 latency, char counts, token counts).

A full N=50 run takes about 2.5 minutes wall time (140 seconds observed). Token sampling is 16 calls to the OpenRouter chat-completions endpoint with `max_tokens=1`. Total cost well under one US cent at current `deepseek/deepseek-chat` pricing. Override the model via `OPENROUTER_MODEL=<provider/model>`.

## License

MIT.
