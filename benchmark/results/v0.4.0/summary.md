# Benchmark

- iterations per scenario: **50**
- target host alias: target (x86_64 Linux, gigabit LAN)
- bench client: workstation (Windows 11)

## Tool surface (paid once per session, before any work)

| server | tools | tools/list chars |
|---|---:|---:|
| fast-mcp-ssh | 23 | 17645 |
| mcp-ssh-manager | 37 | 39873 |
| ssh-mcp-server | 4 | 1743 |

## Cold start (process spawn to first response)

| server | min ms | median ms | max ms |
|---|---:|---:|---:|
| fast-mcp-ssh | 39 | 41 | 42 |
| mcp-ssh-manager | 283 | 289 | 299 |
| ssh-mcp-server | 279 | 279 | 282 |

## Latency per scenario

| scenario | server | n_ok | p50 ms | p95 ms | min ms | max ms | mean ms | stdev |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| exec_trivial | fast-mcp-ssh | 50 | 1.5 | 1.6 | 1.3 | 77.8 | 3.0 | 10.8 |
| exec_trivial | mcp-ssh-manager | 50 | 89.9 | 91.3 | 86.3 | 157.7 | 90.8 | 9.8 |
| exec_trivial | ssh-mcp-server | 50 | 45.1 | 68.2 | 2.6 | 158.4 | 41.9 | 23.7 |
| exec_uname | fast-mcp-ssh | 50 | 2.4 | 2.6 | 2.2 | 2.7 | 2.5 | 0.1 |
| exec_uname | mcp-ssh-manager | 50 | 89.0 | 92.0 | 87.2 | 92.4 | 89.4 | 1.6 |
| exec_uname | ssh-mcp-server | 50 | 46.1 | 47.3 | 43.7 | 47.6 | 46.0 | 0.9 |
| exec_seq5000 | fast-mcp-ssh | 50 | 18.7 | 24.1 | 17.6 | 25.1 | 19.1 | 1.7 |
| exec_seq5000 | mcp-ssh-manager | 50 | 90.5 | 92.7 | 87.1 | 95.5 | 90.5 | 1.5 |
| exec_seq5000 | ssh-mcp-server | 50 | 46.3 | 50.3 | 39.5 | 63.0 | 46.7 | 3.2 |
| exec_lsetc | fast-mcp-ssh | 50 | 6.8 | 7.8 | 6.5 | 8.2 | 6.9 | 0.4 |
| exec_lsetc | mcp-ssh-manager | 50 | 91.3 | 93.1 | 88.1 | 93.7 | 91.2 | 1.4 |
| exec_lsetc | ssh-mcp-server | 50 | 45.5 | 48.0 | 33.9 | 48.9 | 45.6 | 2.0 |
| exec_stderr | fast-mcp-ssh | 50 | 2.0 | 2.1 | 1.7 | 2.4 | 2.0 | 0.1 |
| exec_stderr | mcp-ssh-manager | 50 | 90.6 | 91.9 | 87.2 | 92.1 | 90.4 | 1.1 |
| exec_stderr | ssh-mcp-server | 50 | 45.8 | 46.8 | 43.1 | 47.8 | 45.6 | 0.9 |
| exec_pipe | fast-mcp-ssh | 50 | 2.1 | 2.2 | 1.8 | 2.2 | 2.1 | 0.1 |
| exec_pipe | mcp-ssh-manager | 50 | 90.7 | 91.7 | 88.5 | 92.0 | 90.5 | 0.8 |
| exec_pipe | ssh-mcp-server | 50 | 45.6 | 46.6 | 43.5 | 46.9 | 45.3 | 1.0 |
| write_1k | fast-mcp-ssh | 50 | 1.4 | 1.6 | 1.3 | 3.9 | 1.5 | 0.4 |
| write_1k | mcp-ssh-manager | 50 | 90.9 | 91.7 | 88.2 | 92.1 | 90.8 | 0.8 |
| write_1k | ssh-mcp-server | 50 | 45.7 | 46.8 | 44.0 | 46.9 | 45.5 | 0.9 |
| read_1k | fast-mcp-ssh | 50 | 2.1 | 2.4 | 1.9 | 2.7 | 2.1 | 0.2 |
| read_1k | mcp-ssh-manager | 50 | 90.8 | 91.4 | 87.7 | 92.3 | 90.4 | 0.9 |
| read_1k | ssh-mcp-server | 50 | 45.8 | 46.8 | 43.9 | 46.9 | 45.7 | 0.7 |

## Response size (chars)

| scenario | server | p50 chars | p95 chars | max chars |
|---|---|---:|---:|---:|
| exec_trivial | fast-mcp-ssh | 43 | 43 | 43 |
| exec_trivial | mcp-ssh-manager | 116 | 116 | 116 |
| exec_trivial | ssh-mcp-server | 2 | 2 | 2 |
| exec_uname | fast-mcp-ssh | 195 | 195 | 195 |
| exec_uname | mcp-ssh-manager | 280 | 280 | 280 |
| exec_uname | ssh-mcp-server | 152 | 152 | 152 |
| exec_seq5000 | fast-mcp-ssh | 33931 | 33931 | 33931 |
| exec_seq5000 | mcp-ssh-manager | 12372 | 12372 | 12372 |
| exec_seq5000 | ssh-mcp-server | 28891 | 28891 | 28891 |
| exec_lsetc | fast-mcp-ssh | 8746 | 8746 | 8746 |
| exec_lsetc | mcp-ssh-manager | 8736 | 8736 | 8736 |
| exec_lsetc | ssh-mcp-server | 8606 | 8606 | 8606 |
| exec_stderr | fast-mcp-ssh | 147 | 147 | 147 |
| exec_stderr | mcp-ssh-manager | 182 | 182 | 182 |
| exec_stderr | ssh-mcp-server | 152 | 152 | 152 |
| exec_pipe | fast-mcp-ssh | 43 | 43 | 43 |
| exec_pipe | mcp-ssh-manager | 132 | 132 | 132 |
| exec_pipe | ssh-mcp-server | 2 | 2 | 2 |
| write_1k | fast-mcp-ssh | 67 | 67 | 67 |
| write_1k | mcp-ssh-manager | 1200 | 1200 | 1200 |
| write_1k | ssh-mcp-server | 0 | 0 | 0 |
| read_1k | fast-mcp-ssh | 1105 | 1105 | 1105 |
| read_1k | mcp-ssh-manager | 1165 | 1165 | 1165 |
| read_1k | ssh-mcp-server | 1024 | 1024 | 1024 |
