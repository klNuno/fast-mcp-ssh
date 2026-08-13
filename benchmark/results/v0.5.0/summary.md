# Benchmark

- iterations per scenario: **50**
- target: target (x86_64 Linux, gigabit LAN)
- bench client: workstation (Windows 11)

## Tool surface (paid once per session, before any work)

| server | tools | tools/list chars |
|---|---:|---:|
| fast-mcp-ssh | 26 | 21060 |
| mcp-ssh-manager | 37 | 39873 |
| ssh-mcp-server | 4 | 1743 |

## Cold start (process spawn to first response)

| server | min ms | median ms | max ms |
|---|---:|---:|---:|
| fast-mcp-ssh | 45 | 48 | 51 |
| mcp-ssh-manager | 263 | 280 | 298 |
| ssh-mcp-server | 258 | 260 | 264 |

## Latency per scenario

| scenario | server | n_ok | p50 ms | p95 ms | min ms | max ms | mean ms | stdev |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| exec_trivial | fast-mcp-ssh | 50 | 2.2 | 2.5 | 1.7 | 59.1 | 3.3 | 8.1 |
| exec_trivial | mcp-ssh-manager | 50 | 89.7 | 102.8 | 71.9 | 113.6 | 90.1 | 6.2 |
| exec_trivial | ssh-mcp-server | 50 | 46.7 | 77.1 | 6.7 | 123.1 | 44.6 | 20.1 |
| exec_uname | fast-mcp-ssh | 50 | 3.6 | 4.2 | 3.2 | 4.3 | 3.6 | 0.3 |
| exec_uname | mcp-ssh-manager | 50 | 90.9 | 93.1 | 87.9 | 95.2 | 91.1 | 1.6 |
| exec_uname | ssh-mcp-server | 50 | 50.6 | 58.2 | 47.3 | 60.0 | 51.9 | 3.9 |
| exec_seq5000 | fast-mcp-ssh | 50 | 19.6 | 20.5 | 18.3 | 21.0 | 19.5 | 0.5 |
| exec_seq5000 | mcp-ssh-manager | 50 | 90.4 | 95.6 | 84.9 | 96.5 | 90.4 | 2.4 |
| exec_seq5000 | ssh-mcp-server | 50 | 49.2 | 60.1 | 43.9 | 75.2 | 50.7 | 5.7 |
| exec_lsetc | fast-mcp-ssh | 50 | 7.0 | 7.5 | 6.1 | 7.6 | 7.0 | 0.3 |
| exec_lsetc | mcp-ssh-manager | 50 | 91.7 | 95.0 | 87.2 | 96.2 | 91.8 | 2.1 |
| exec_lsetc | ssh-mcp-server | 50 | 49.8 | 58.6 | 35.3 | 59.8 | 51.1 | 4.4 |
| exec_stderr | fast-mcp-ssh | 50 | 2.7 | 3.1 | 2.3 | 3.4 | 2.7 | 0.2 |
| exec_stderr | mcp-ssh-manager | 50 | 91.0 | 97.1 | 52.1 | 125.9 | 91.2 | 8.7 |
| exec_stderr | ssh-mcp-server | 50 | 48.7 | 57.8 | 44.9 | 59.2 | 50.5 | 4.0 |
| exec_pipe | fast-mcp-ssh | 50 | 3.4 | 3.7 | 2.8 | 3.8 | 3.4 | 0.2 |
| exec_pipe | mcp-ssh-manager | 50 | 91.1 | 105.0 | 69.1 | 116.5 | 91.3 | 6.2 |
| exec_pipe | ssh-mcp-server | 50 | 48.8 | 57.3 | 46.8 | 58.9 | 50.7 | 3.6 |
| write_1k | fast-mcp-ssh | 50 | 1.1 | 1.3 | 0.8 | 4.3 | 1.1 | 0.5 |
| write_1k | mcp-ssh-manager | 50 | 89.9 | 92.6 | 74.4 | 105.5 | 89.7 | 3.9 |
| write_1k | ssh-mcp-server | 50 | 47.9 | 54.4 | 46.5 | 59.5 | 48.9 | 2.7 |
| read_1k | fast-mcp-ssh | 50 | 1.7 | 1.9 | 1.4 | 2.2 | 1.7 | 0.1 |
| read_1k | mcp-ssh-manager | 50 | 90.3 | 95.7 | 76.2 | 108.1 | 90.9 | 3.9 |
| read_1k | ssh-mcp-server | 50 | 48.9 | 58.1 | 46.0 | 59.9 | 50.5 | 3.9 |

## Response size (chars)

| scenario | server | p50 chars | p95 chars | max chars |
|---|---|---:|---:|---:|
| exec_trivial | fast-mcp-ssh | 43 | 43 | 43 |
| exec_trivial | mcp-ssh-manager | 119 | 119 | 119 |
| exec_trivial | ssh-mcp-server | 2 | 2 | 2 |
| exec_uname | fast-mcp-ssh | 156 | 156 | 156 |
| exec_uname | mcp-ssh-manager | 244 | 244 | 244 |
| exec_uname | ssh-mcp-server | 113 | 113 | 113 |
| exec_seq5000 | fast-mcp-ssh | 33931 | 33931 | 33931 |
| exec_seq5000 | mcp-ssh-manager | 12375 | 12375 | 12375 |
| exec_seq5000 | ssh-mcp-server | 28891 | 28891 | 28891 |
| exec_lsetc | fast-mcp-ssh | 6093 | 6093 | 6093 |
| exec_lsetc | mcp-ssh-manager | 6086 | 6086 | 6086 |
| exec_lsetc | ssh-mcp-server | 5953 | 5953 | 5953 |
| exec_stderr | fast-mcp-ssh | 147 | 147 | 147 |
| exec_stderr | mcp-ssh-manager | 185 | 185 | 185 |
| exec_stderr | ssh-mcp-server | 152 | 152 | 152 |
| exec_pipe | fast-mcp-ssh | 43 | 43 | 43 |
| exec_pipe | mcp-ssh-manager | 135 | 135 | 135 |
| exec_pipe | ssh-mcp-server | 2 | 2 | 2 |
| write_1k | fast-mcp-ssh | 67 | 67 | 67 |
| write_1k | mcp-ssh-manager | 1203 | 1203 | 1203 |
| write_1k | ssh-mcp-server | 0 | 0 | 0 |
| read_1k | fast-mcp-ssh | 1105 | 1105 | 1105 |
| read_1k | mcp-ssh-manager | 1168 | 1168 | 1168 |
| read_1k | ssh-mcp-server | 1024 | 1024 | 1024 |

## Token counts on representative payloads

Counted via api.deepseek.com (deepseek-v4-flash).

| scenario | server | chars | tokens | chars/token |
|---|---|---:|---:|---:|
| exec_trivial | fast-mcp-ssh | 43 | 19 | 2.26 |
| exec_uname | fast-mcp-ssh | 156 | 78 | 2.00 |
| exec_seq5000 | fast-mcp-ssh | 33931 | 19017 | 1.78 |
| exec_lsetc | fast-mcp-ssh | 6093 | 2453 | 2.48 |
| exec_stderr | fast-mcp-ssh | 147 | 47 | 3.13 |
| exec_pipe | fast-mcp-ssh | 43 | 19 | 2.26 |
| write_1k | fast-mcp-ssh | 67 | 28 | 2.39 |
| read_1k | fast-mcp-ssh | 1105 | 163 | 6.78 |
| exec_trivial | mcp-ssh-manager | 119 | 47 | 2.53 |
| exec_uname | mcp-ssh-manager | 244 | 112 | 2.18 |
| exec_seq5000 | mcp-ssh-manager | 12375 | 5723 | 2.16 |
| exec_lsetc | mcp-ssh-manager | 6086 | 2443 | 2.49 |
| exec_stderr | mcp-ssh-manager | 185 | 63 | 2.94 |
| exec_pipe | mcp-ssh-manager | 135 | 56 | 2.41 |
| write_1k | mcp-ssh-manager | 1203 | 200 | 6.01 |
| read_1k | mcp-ssh-manager | 1168 | 184 | 6.35 |
| exec_trivial | ssh-mcp-server | 2 | 1 | 2.00 |
| exec_uname | ssh-mcp-server | 113 | 60 | 1.88 |
| exec_seq5000 | ssh-mcp-server | 28891 | 18999 | 1.52 |
| exec_lsetc | ssh-mcp-server | 5953 | 2439 | 2.44 |
| exec_stderr | ssh-mcp-server | 152 | 49 | 3.10 |
| exec_pipe | ssh-mcp-server | 2 | 1 | 2.00 |
| write_1k | ssh-mcp-server | 0 | 0 | 0.00 |
| read_1k | ssh-mcp-server | 1024 | 128 | 8.00 |
