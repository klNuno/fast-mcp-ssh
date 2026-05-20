# Benchmark — fast-mcp-ssh vs mcp-ssh-manager

- iterations per scenario: **20**
- target host alias: mininist1
- bench host: 

## Cold start (process spawn → first response)

| server | min ms | median ms | max ms |
|---|---:|---:|---:|
| fast-mcp-ssh | 32 | 38 | 39 |
| mcp-ssh-manager | 267 | 300 | 328 |

## Latency per scenario

| scenario | server | n_ok | p50 ms | p95 ms | min ms | max ms | mean ms | stdev |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| exec_lsetc | fast-mcp-ssh | 20 | 7.4 | 9.0 | 6.3 | 9.0 | 7.3 | 0.6 |
| exec_lsetc | mcp-ssh-manager | 20 | 92.3 | 95.2 | 89.5 | 95.2 | 92.3 | 1.8 |
| exec_pipe | fast-mcp-ssh | 20 | 3.5 | 3.9 | 3.1 | 3.9 | 3.5 | 0.2 |
| exec_pipe | mcp-ssh-manager | 20 | 92.3 | 99.4 | 89.8 | 99.4 | 92.7 | 2.2 |
| exec_seq5000 | fast-mcp-ssh | 20 | 8.8 | 11.8 | 8.1 | 11.8 | 8.9 | 0.8 |
| exec_seq5000 | mcp-ssh-manager | 20 | 92.6 | 99.7 | 87.9 | 99.7 | 92.4 | 3.3 |
| exec_stderr | fast-mcp-ssh | 20 | 3.1 | 3.5 | 2.6 | 3.5 | 3.0 | 0.2 |
| exec_stderr | mcp-ssh-manager | 20 | 90.9 | 94.3 | 88.7 | 94.3 | 90.9 | 1.4 |
| exec_trivial | fast-mcp-ssh | 20 | 2.6 | 71.7 | 2.0 | 71.7 | 6.0 | 15.5 |
| exec_trivial | mcp-ssh-manager | 20 | 89.5 | 119.4 | 88.1 | 119.4 | 91.0 | 6.7 |
| exec_uname | fast-mcp-ssh | 20 | 3.9 | 4.7 | 3.2 | 4.7 | 3.9 | 0.3 |
| exec_uname | mcp-ssh-manager | 20 | 90.8 | 92.5 | 88.5 | 92.5 | 90.4 | 1.1 |
| read_1k | fast-mcp-ssh | 20 | 1.5 | 2.3 | 1.3 | 2.3 | 1.6 | 0.2 |
| read_1k | mcp-ssh-manager | 20 | 90.0 | 97.3 | 82.4 | 97.3 | 90.4 | 3.2 |
| write_1k | fast-mcp-ssh | 20 | 1.0 | 5.4 | 0.8 | 5.4 | 1.2 | 1.0 |
| write_1k | mcp-ssh-manager | 20 | 92.0 | 101.2 | 89.3 | 101.2 | 92.4 | 3.2 |

## Response size (chars)

| scenario | server | p50 chars | p95 chars | max chars |
|---|---|---:|---:|---:|
| exec_lsetc | fast-mcp-ssh | 6031 | 6031 | 6031 |
| exec_lsetc | mcp-ssh-manager | 6024 | 6024 | 6024 |
| exec_pipe | fast-mcp-ssh | 43 | 43 | 43 |
| exec_pipe | mcp-ssh-manager | 135 | 135 | 135 |
| exec_seq5000 | fast-mcp-ssh | 12020 | 12020 | 12020 |
| exec_seq5000 | mcp-ssh-manager | 12375 | 12375 | 12375 |
| exec_stderr | fast-mcp-ssh | 147 | 147 | 147 |
| exec_stderr | mcp-ssh-manager | 185 | 185 | 185 |
| exec_trivial | fast-mcp-ssh | 43 | 44 | 44 |
| exec_trivial | mcp-ssh-manager | 119 | 119 | 119 |
| exec_uname | fast-mcp-ssh | 158 | 158 | 158 |
| exec_uname | mcp-ssh-manager | 246 | 246 | 246 |
| read_1k | fast-mcp-ssh | 1108 | 1108 | 1108 |
| read_1k | mcp-ssh-manager | 1168 | 1168 | 1168 |
| write_1k | fast-mcp-ssh | 70 | 70 | 70 |
| write_1k | mcp-ssh-manager | 1203 | 1203 | 1203 |
