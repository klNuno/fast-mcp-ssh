# Benchmark — fast-mcp-ssh vs mcp-ssh-manager (v0.1.2)

- iterations per scenario: **50**
- target host alias: target
- bench host: workstation (Windows 11, gigabit LAN to target)
- target: x86_64 Linux server, ~0 ms ICMP RTT (same /24)
- fast-mcp-ssh: **0.1.2** (release build, this repo)
- mcp-ssh-manager: 3.3.0 (npm)
- timing: `time.perf_counter()` (sub-µs resolution)

> ⚠️ **Env differs from v0.1.0.** v0.1.0 numbers were collected from a Linux bench host
> reaching a remote x86_64 LAN target. v0.1.2 was collected with the bench client running
> on the operator's Windows workstation against the same kind of target. Network RTT and
> client process overheads are different, so cross-version absolute numbers are not directly
> comparable. The `mcp-ssh-manager` baseline in both runs (~90 ms / op) is consistent enough
> that **per-server, scenario-relative comparisons are meaningful**.

## Cold start (process spawn → first response)

| server | min ms | median ms | max ms |
|---|---:|---:|---:|
| fast-mcp-ssh | 25 | 26 | 28 |
| mcp-ssh-manager | 208 | 217 | 218 |

`fast-mcp-ssh` is ~8× faster to first response in this env (was ~150× faster in v0.1.0's
Linux env — the Windows process spawn cost shifts the ratio, but the absolute startup time
is still dominated by mcp-ssh-manager's Node.js runtime warm-up).

## Latency per scenario

| scenario | server | n_ok | p50 ms | p95 ms | min ms | max ms | mean ms | stdev |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| exec_lsetc | fast-mcp-ssh | 50 | 7.1 | 9.4 | 6.1 | 10.6 | 7.2 | 0.9 |
| exec_lsetc | mcp-ssh-manager | 50 | 91.3 | 106.4 | 65.5 | 118.8 | 91.6 | 7.2 |
| exec_pipe | fast-mcp-ssh | 50 | 4.4 | 5.9 | 3.0 | 6.0 | 4.4 | 0.9 |
| exec_pipe | mcp-ssh-manager | 50 | 90.6 | 93.5 | 89.2 | 95.0 | 90.9 | 1.3 |
| exec_seq5000 | fast-mcp-ssh | 50 | 9.0 | 10.5 | 8.1 | 11.4 | 9.1 | 0.7 |
| exec_seq5000 | mcp-ssh-manager | 50 | 90.0 | 93.0 | 87.4 | 94.3 | 90.1 | 1.3 |
| exec_stderr | fast-mcp-ssh | 50 | 3.7 | 5.3 | 2.5 | 5.4 | 3.8 | 0.8 |
| exec_stderr | mcp-ssh-manager | 50 | 90.1 | 92.6 | 86.2 | 93.3 | 90.3 | 1.3 |
| exec_trivial | fast-mcp-ssh | 50 | 2.5 | 2.9 | 2.2 | 53.7 | 3.6 | 7.2 |
| exec_trivial | mcp-ssh-manager | 50 | 89.6 | 92.2 | 88.3 | 108.7 | 90.0 | 2.9 |
| exec_uname | fast-mcp-ssh | 50 | 4.0 | 4.6 | 3.4 | 5.4 | 4.0 | 0.4 |
| exec_uname | mcp-ssh-manager | 50 | 91.4 | 96.2 | 85.3 | 98.5 | 91.4 | 2.1 |
| read_1k | fast-mcp-ssh | 50 | 2.8 | 4.7 | 1.3 | 4.9 | 2.9 | 0.8 |
| read_1k | mcp-ssh-manager | 50 | 89.7 | 90.7 | 87.9 | 91.0 | 89.6 | 0.7 |
| write_1k | fast-mcp-ssh | 50 | 2.4 | 4.0 | 1.1 | 7.3 | 2.5 | 1.1 |
| write_1k | mcp-ssh-manager | 50 | 90.2 | 92.6 | 77.5 | 101.2 | 90.2 | 2.8 |

### Headline ratios (median)

| scenario | fast | mgr | mgr / fast |
|---|---:|---:|---:|
| exec_trivial | 2.5 ms | 89.6 ms | **36×** |
| exec_uname | 4.0 ms | 91.4 ms | 23× |
| exec_pipe | 4.4 ms | 90.6 ms | 21× |
| exec_seq5000 (~12 KB) | 9.0 ms | 90.0 ms | 10× |
| exec_lsetc (~6 KB) | 7.1 ms | 91.3 ms | 13× |
| exec_stderr | 3.7 ms | 90.1 ms | 24× |
| write_1k | 2.4 ms | 90.2 ms | 38× |
| read_1k | 2.8 ms | 89.7 ms | 32× |

The gap is much wider than v0.1.0 (which showed ~2× and ~22× for the same scenarios).
The big jumps come from:
- **`nodelay = true`** in the russh client config (TCP_NODELAY) — Nagle's algorithm was
  serializing round-trips on every small command.
- **Cached `Arc<russh::client::Config>`** + cached `KnownHostsStore` skip a TOML reparse and
  store re-open on every connect. (Cold-start improvement, mostly.)
- **Singleflight `get_or_connect`** kept the warm connection hot across calls without
  re-handshaking on a stale-detection race.
- **PTY split read/write** doesn't show up here (no `sh` scenarios) but unblocks the
  `interrupt` tool from a long-running `sh`.
- **Output cap during capture** doesn't show up either; it changes worst-case behavior.

## Response size (chars)

| scenario | server | p50 chars | p95 chars | max chars |
|---|---|---:|---:|---:|
| exec_lsetc | fast-mcp-ssh | 6066 | 6066 | 6066 |
| exec_lsetc | mcp-ssh-manager | 6024 | 6024 | 6024 |
| exec_pipe | fast-mcp-ssh | 75 | 75 | 75 |
| exec_pipe | mcp-ssh-manager | 135 | 135 | 135 |
| exec_seq5000 | fast-mcp-ssh | 12036 | 12036 | 12036 |
| exec_seq5000 | mcp-ssh-manager | 12375 | 12375 | 12375 |
| exec_stderr | fast-mcp-ssh | 180 | 180 | 180 |
| exec_stderr | mcp-ssh-manager | 185 | 185 | 185 |
| exec_trivial | fast-mcp-ssh | 75 | 75 | 76 |
| exec_trivial | mcp-ssh-manager | 119 | 119 | 119 |
| exec_uname | fast-mcp-ssh | 192 | 192 | 192 |
| exec_uname | mcp-ssh-manager | 246 | 246 | 246 |
| read_1k | fast-mcp-ssh | 1108 | 1108 | 1108 |
| read_1k | mcp-ssh-manager | 1168 | 1168 | 1168 |
| write_1k | fast-mcp-ssh | 70 | 70 | 70 |
| write_1k | mcp-ssh-manager | 1203 | 1203 | 1203 |

Slight char-count drop vs v0.1.0 on small responses (e.g. `exec_lsetc` 6066 vs 6067,
`exec_seq5000` 12036 vs 12099) thanks to the shorter truncation hint and tighter TOON
block emission, but the dominant payload is still the raw remote stdout.

## Notes

- The `--skip-tokens` flag was used (no `OPENROUTER_API_KEY` available in this env).
  Token counts are unchanged in shape from v0.1.0 since the TOON output format governs
  token cost — see `benchmark/results/v0.1.0/summary.md` for the per-payload breakdown.
- `tools/list` payload dropped meaningfully because of the tighter tool descriptions in
  0.1.2 (each description cut from ~25 words to ~10), but the bench scenarios don't
  exercise `tools/list` directly.
- `exec_batch` (new in 0.1.2) is not exercised by the existing scenarios — it pays off
  when the agent issues several commands in one round-trip.
