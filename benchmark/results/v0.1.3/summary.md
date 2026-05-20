# Benchmark — fast-mcp-ssh vs mcp-ssh-manager

- iterations per scenario: **20**
- target host alias: mininist1
- bench host: 

## Cold start (process spawn → first response)

| server | min ms | median ms | max ms |
|---|---:|---:|---:|
| fast-mcp-ssh | 26 | 27 | 29 |
| mcp-ssh-manager | 214 | 228 | 233 |

## Latency per scenario

| scenario | server | n_ok | p50 ms | p95 ms | min ms | max ms | mean ms | stdev |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| exec_lsetc | fast-mcp-ssh | 20 | 7.3 | 7.9 | 6.4 | 7.9 | 7.2 | 0.4 |
| exec_lsetc | mcp-ssh-manager | 20 | 91.6 | 96.0 | 87.7 | 96.0 | 91.9 | 2.3 |
| exec_pipe | fast-mcp-ssh | 20 | 3.4 | 3.9 | 3.1 | 3.9 | 3.4 | 0.2 |
| exec_pipe | mcp-ssh-manager | 20 | 90.9 | 93.9 | 88.8 | 93.9 | 90.9 | 1.4 |
| exec_seq5000 | fast-mcp-ssh | 20 | 8.7 | 10.0 | 7.7 | 10.0 | 8.8 | 0.5 |
| exec_seq5000 | mcp-ssh-manager | 20 | 91.3 | 99.5 | 89.7 | 99.5 | 92.0 | 2.3 |
| exec_stderr | fast-mcp-ssh | 20 | 3.0 | 3.5 | 2.6 | 3.5 | 3.0 | 0.2 |
| exec_stderr | mcp-ssh-manager | 20 | 89.6 | 94.0 | 86.2 | 94.0 | 89.8 | 1.8 |
| exec_trivial | fast-mcp-ssh | 20 | 2.6 | 58.8 | 2.1 | 58.8 | 5.4 | 12.6 |
| exec_trivial | mcp-ssh-manager | 20 | 90.1 | 105.4 | 87.6 | 105.4 | 90.6 | 3.8 |
| exec_uname | fast-mcp-ssh | 20 | 3.9 | 4.3 | 3.2 | 4.3 | 3.9 | 0.3 |
| exec_uname | mcp-ssh-manager | 20 | 90.2 | 93.7 | 88.7 | 93.7 | 90.6 | 1.4 |
| read_1k | fast-mcp-ssh | 20 | 1.3 | 1.5 | 1.2 | 1.5 | 1.3 | 0.1 |
| read_1k | mcp-ssh-manager | 20 | 89.3 | 92.0 | 87.8 | 92.0 | 89.2 | 1.0 |
| write_1k | fast-mcp-ssh | 20 | 0.9 | 3.4 | 0.7 | 3.4 | 1.0 | 0.6 |
| write_1k | mcp-ssh-manager | 20 | 90.0 | 93.6 | 88.1 | 93.6 | 90.2 | 1.6 |

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
