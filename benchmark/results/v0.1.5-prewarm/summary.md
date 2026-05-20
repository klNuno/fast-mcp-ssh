# Benchmark — fast-mcp-ssh vs mcp-ssh-manager

- iterations per scenario: **20**
- target host alias: target
- bench host: 

## Cold start (process spawn → first response)

| server | min ms | median ms | max ms |
|---|---:|---:|---:|
| fast-mcp-ssh | 27 | 27 | 29 |
| mcp-ssh-manager | 237 | 238 | 244 |

## Latency per scenario

| scenario | server | n_ok | p50 ms | p95 ms | min ms | max ms | mean ms | stdev |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| exec_lsetc | fast-mcp-ssh | 20 | 6.6 | 8.2 | 6.3 | 8.2 | 6.9 | 0.5 |
| exec_lsetc | mcp-ssh-manager | 20 | 91.3 | 94.9 | 88.5 | 94.9 | 91.6 | 1.7 |
| exec_pipe | fast-mcp-ssh | 20 | 3.6 | 4.4 | 3.2 | 4.4 | 3.5 | 0.3 |
| exec_pipe | mcp-ssh-manager | 20 | 90.7 | 94.8 | 89.0 | 94.8 | 91.2 | 1.7 |
| exec_seq5000 | fast-mcp-ssh | 20 | 8.4 | 11.1 | 7.9 | 11.1 | 8.9 | 1.0 |
| exec_seq5000 | mcp-ssh-manager | 20 | 89.6 | 99.6 | 87.8 | 99.6 | 90.4 | 2.6 |
| exec_stderr | fast-mcp-ssh | 20 | 3.0 | 3.5 | 2.5 | 3.5 | 3.0 | 0.2 |
| exec_stderr | mcp-ssh-manager | 20 | 90.3 | 93.4 | 87.9 | 93.4 | 90.5 | 1.4 |
| exec_trivial | fast-mcp-ssh | 20 | 2.3 | 230.6 | 1.8 | 230.6 | 13.6 | 51.1 |
| exec_trivial | mcp-ssh-manager | 20 | 90.5 | 114.7 | 86.9 | 114.7 | 91.6 | 5.7 |
| exec_uname | fast-mcp-ssh | 20 | 3.8 | 4.3 | 3.4 | 4.3 | 3.8 | 0.3 |
| exec_uname | mcp-ssh-manager | 20 | 91.6 | 97.4 | 88.9 | 97.4 | 91.8 | 2.0 |
| read_1k | fast-mcp-ssh | 20 | 1.3 | 1.5 | 1.1 | 1.5 | 1.3 | 0.1 |
| read_1k | mcp-ssh-manager | 20 | 89.4 | 93.4 | 87.3 | 93.4 | 89.9 | 1.7 |
| write_1k | fast-mcp-ssh | 20 | 0.9 | 4.3 | 0.8 | 4.3 | 1.0 | 0.8 |
| write_1k | mcp-ssh-manager | 20 | 90.0 | 92.0 | 88.4 | 92.0 | 90.1 | 1.0 |

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
| exec_trivial | fast-mcp-ssh | 43 | 45 | 45 |
| exec_trivial | mcp-ssh-manager | 119 | 119 | 119 |
| exec_uname | fast-mcp-ssh | 158 | 158 | 158 |
| exec_uname | mcp-ssh-manager | 246 | 246 | 246 |
| read_1k | fast-mcp-ssh | 1108 | 1108 | 1108 |
| read_1k | mcp-ssh-manager | 1168 | 1168 | 1168 |
| write_1k | fast-mcp-ssh | 70 | 70 | 70 |
| write_1k | mcp-ssh-manager | 1203 | 1203 | 1203 |
