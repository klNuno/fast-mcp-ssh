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
| `hosts` | none                                 | List configured hosts and their session state. |
| `ping`  | `host?`                              | Health check. With no arg, probes all hosts in parallel. |
| `exec`  | `host`, `cmd`, `timeout?`, `password?`, `confirm?` | One-shot command on a fresh exec channel. Stateless, parallel-safe. |
| `sh`    | same as `exec`                       | Same args, runs in a persistent PTY shell. `cd` and `export` survive between calls. |
| `kill`  | `host`                               | Close the persistent session. Reopens automatically next call. |
| `up`    | `host`, `local`, `remote`            | SFTP upload. |
| `dn`    | `host`, `remote`, `local?`           | SFTP download. With no `local`, returns content inline (text under 256 KB). |
| `ls`    | `host`, `path`                       | SFTP directory listing. |
| `wr`    | `host`, `remote`, `content`, `mode?` | Write a file inline. Optional octal mode applied at create time. |
| `tail`  | `host`, `path`, `lines?`, `follow?`, `seconds?` | `tail -n` (default) or streamed `tail -F`. |

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

Audit log at `~/.fast-mcp-ssh/audit.log`. Append-only NDJSON, one record per call, with timestamp, host, tool, command, exit code, duration, byte counts, blocking reason.

## Tests

```bash
cargo test                    # 22 unit tests
./scripts/test-sh.ps1         # end-to-end smoke against real hosts (Windows)
```

## Benchmark vs `mcp-ssh-manager`

50 iterations per scenario. Bench host: 16-core x86_64 box on Ubuntu 24.04. Target: an x86_64 Linux host reachable over gigabit LAN. Identical SSH key for both servers, identical target. Full data in [`benchmark/results/`](benchmark/results/), reproducible via [`benchmark/`](benchmark/).

### Summary

| Metric (median) | `fast-mcp-ssh` | `mcp-ssh-manager` | Ratio |
|---|---:|---:|---:|
| Cold start | 2 ms | 309 ms | 154× faster |
| Warm `exec` (typical) | 46 ms | 97 ms | 2.1× faster |
| Write 1 KB file | 4.5 ms | 98 ms | 22× faster |
| Read 1 KB file | 50 ms | 96 ms | 1.9× faster |
| Tokens, small command response | 35 | 49 | −29% |
| Tokens, write-status response | 31 | 202 | −85% |
| Tokens, large raw stdout | roughly equal (raw output dominates) | | |

### Cold start (process spawn to first response)

| Server | Median |
|---|---:|
| `fast-mcp-ssh` | 2 ms |
| `mcp-ssh-manager` (Node.js) | 309 ms |

### Warm latency, median ms (lower is better)

| Scenario | `fast-mcp-ssh` | `mcp-ssh-manager` | Ratio |
|----------|---:|---:|---:|
| `exec` `echo ok`                  |  46 |  97 | 2.1× |
| `exec` `uname -a; whoami; pwd`     |  48 |  98 | 2.0× |
| `exec` `seq 1 5000` (~12 KB)      |  46 |  98 | 2.1× |
| `exec` `ls -la /etc \| head -100` |  47 | 100 | 2.1× |
| `exec` `ls /nonexistent` (stderr) |  48 |  97 | 2.0× |
| `exec` `cat /etc/passwd \| wc -l` |  47 |  97 | 2.1× |
| Write 1 KB file                   | 4.5 |  98 | 22× |
| Read 1 KB file                    |  50 |  96 | 1.9× |

The write gap is structural. `fast-mcp-ssh` writes via SFTP. `mcp-ssh-manager` has no inline write tool, so the bench uses `ssh_execute "cat > path <<EOF…"`, which costs a full shell exec round-trip.

### Token cost, counted via OpenRouter (`deepseek/deepseek-chat`)

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
