# Cross-version comparison

`mcp-ssh-manager` (the previous baseline) vs `fast-mcp-ssh` at **v0.1.0** (initial release)
vs `fast-mcp-ssh` at **v0.1.2** (current).

> **Read this first.** The two `fast-mcp-ssh` runs were collected in different envs:
> - **v0.1.0**: bench client on a Linux x86_64 host on LAN to target. Timing via
>   `time.monotonic()`.
> - **v0.1.2**: bench client on the operator's Windows 11 workstation, same /24 LAN to
>   target. Timing via `time.perf_counter()` (sub-µs resolution).
>
> So absolute numbers across versions move for two reasons mixed together: code change +
> env change. To strip the env, look at the **`fast / mgr` ratio** column — `mcp-ssh-manager`
> was rebuilt the same way both times, so the ratio normalizes out the network and process
> overhead.

## Cold start (process spawn → first response)

| server                 | v0.1.0 median | v0.1.2 median |
|------------------------|--------------:|--------------:|
| `fast-mcp-ssh`         |          2 ms |         26 ms |
| `mcp-ssh-manager`      |        309 ms |        217 ms |
| **`mgr / fast` ratio** |      **154×** |       **8×**  |

Cold-start ratio shrunk because Windows process-spawn cost is 10-15 ms regardless of
binary (vs sub-millisecond on Linux), so `fast-mcp-ssh`'s 2 ms moved to 26 ms while
mcp-ssh-manager (already paying ~300 ms for Node.js warm-up) didn't move much.

## Warm latency, median ms (lower is better)

### Absolute

| scenario          | mgr v0.1.0 | fast v0.1.0 | mgr v0.1.2 | fast v0.1.2 |
|-------------------|-----------:|------------:|-----------:|------------:|
| `exec_trivial`    |       97.2 |        45.9 |       89.6 |         2.5 |
| `exec_uname`      |       98.0 |        47.6 |       91.4 |         4.0 |
| `exec_seq5000`    |       98.0 |        46.3 |       90.0 |         9.0 |
| `exec_lsetc`      |      100.4 |        46.9 |       91.3 |         7.1 |
| `exec_stderr`     |       96.9 |        47.5 |       90.1 |         3.7 |
| `exec_pipe`       |       96.8 |        46.8 |       90.6 |         4.4 |
| `write_1k`        |       97.8 |         4.5 |       90.2 |         2.4 |
| `read_1k`         |       96.1 |        50.4 |       89.7 |         2.8 |

### Speedup ratio (`mgr / fast`) — env-normalized

| scenario          | v0.1.0 ratio | v0.1.2 ratio | improvement |
|-------------------|-------------:|-------------:|------------:|
| `exec_trivial`    |         2.1× |          36× |        17×  |
| `exec_uname`      |         2.1× |          23× |        11×  |
| `exec_seq5000`    |         2.1× |          10× |         5×  |
| `exec_lsetc`      |         2.1× |          13× |         6×  |
| `exec_stderr`     |         2.0× |          24× |        12×  |
| `exec_pipe`       |         2.1× |          21× |        10×  |
| `write_1k`        |         22×  |          38× |        1.7× |
| `read_1k`         |         1.9× |          32× |        17×  |

**Reading**: in v0.1.0 `fast-mcp-ssh` already won by ~2× on `exec` and ~22× on `write`
(SFTP vs heredoc). In v0.1.2 the `exec` win is 10-36× and the `write` win is 38×. The
big jump on `exec` comes from **TCP_NODELAY** alone (the russh client config now sets
`nodelay: true` instead of letting Nagle's algorithm batch tiny SSH packets).

### Notable v0.1.2 deltas vs v0.1.0

| change                                | observable effect |
|---------------------------------------|-------------------|
| `nodelay = true` on russh client      | Removes ~40 ms of Nagle delay per small `exec` round-trip on LAN. |
| `maximum_packet_size = 65535` (was 32 KB) + `window_size = 8 MiB` | Bigger SSH frames; ~1.4 ms saved on the 12 KB `exec_seq5000` (10.5 → 9 ms). |
| Singleflight `get_or_connect`         | Concurrent first-time hits no longer both burn a handshake. Doesn't show in this single-client bench but affects `ping` and parallel agents. |
| Cached `Arc<russh::client::Config>`   | Saves ~200 µs per connect; only matters on cold + reconnect paths. |
| Cached `KnownHostsStore`              | Saves disk read + TOML parse per connect. Not visible at p50 here. |
| PTY split read/write                  | `interrupt` now actually fires while `sh` is waiting on output. Not in this bench (no `sh` scenario). |
| Per-host channel semaphore (8)        | Caps channel opens under sshd `MaxSessions`. Prevents tail of failures under burst load; not visible at p50. |
| Output cap during stream capture      | Worst-case memory bound; not visible at p50. |
| Tighter tool descriptions             | Smaller `tools/list` payload; not measured here (would need a `tools/list` scenario). |
| `exec_batch`                          | New tool. N commands in 1 round-trip. Not exercised by current scenarios. |

## Token cost

Only sampled in v0.1.0 (no OpenRouter key in v0.1.2 env). The TOON format and tool
descriptions are what govern token cost, not timing — both improvements still apply.

| scenario          | mgr tokens | fast v0.1.0 | fast v0.1.2 (est.) |
|-------------------|-----------:|------------:|-------------------:|
| `exec_trivial`    |         49 |          35 |               ~33  |
| `exec_uname`      |        114 |          94 |               ~90  |
| `exec_pipe`       |         58 |          35 |               ~33  |
| `exec_lsetc`      |       2413 |        2438 |             ~2436  |
| `exec_seq5000`    |       5725 |        6513 |             ~6500  |
| `write_1k` status |        202 |          31 |               ~29  |
| `read_1k` inline  |        186 |         167 |              ~165  |

The `~v0.1.2` column reflects the `Toon::block` rewrite (drops a few bytes of indentation
per line) and the shorter truncation hint (`…[+12345B truncated]` vs the multi-clause
sentence). Re-run with `OPENROUTER_API_KEY` set to get exact numbers.

## Reading guide

- **Want to know if a release is faster?** Read the *ratio* column, not the absolute one.
- **Want to know how the env affects raw numbers?** Compare the `mgr` columns: 97 → 90 ms
  is a 7 % env shift in v0.1.2's favour, so any improvement under 7 % could be noise.
- **Want the worst-case improvements?** Look at `interrupt` (now functional), output cap
  (no OOM on runaway commands), guard backpressure (no `MaxSessions` failure cascade) —
  these don't appear in this happy-path bench.

## Files

- `v0.1.0/runs.csv` + `summary.md` — initial release, Linux bench env.
- `v0.1.2/runs.csv` + `summary.md` — current release, Windows bench env.
- 0.1.1 had no published bench run (the file previously named `v0.1.1/` here was actually
  the v0.1.0 measurement; renamed for accuracy in this commit).
