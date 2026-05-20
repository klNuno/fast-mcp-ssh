# Benchmark — fast-mcp-ssh vs mcp-ssh-manager

- iterations per scenario: **20**
- target host alias: mininist1
- bench host: 

## Cold start (process spawn → first response)

| server | min ms | median ms | max ms |
|---|---:|---:|---:|
| fast-mcp-ssh | 28 | 29 | 29 |
| mcp-ssh-manager | 224 | 233 | 247 |

## Latency per scenario

| scenario | server | n_ok | p50 ms | p95 ms | min ms | max ms | mean ms | stdev |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| exec_lsetc | fast-mcp-ssh | 20 | 6.7 | 8.3 | 6.2 | 8.3 | 6.8 | 0.5 |
| exec_lsetc | mcp-ssh-manager | 20 | 91.4 | 96.0 | 88.6 | 96.0 | 91.4 | 1.6 |
| exec_pipe | fast-mcp-ssh | 20 | 3.6 | 3.9 | 3.1 | 3.9 | 3.5 | 0.3 |
| exec_pipe | mcp-ssh-manager | 20 | 90.6 | 95.8 | 88.5 | 95.8 | 91.1 | 2.0 |
| exec_seq5000 | fast-mcp-ssh | 20 | 8.5 | 10.4 | 8.2 | 10.4 | 8.6 | 0.5 |
| exec_seq5000 | mcp-ssh-manager | 20 | 90.4 | 93.9 | 87.3 | 93.9 | 90.6 | 1.7 |
| exec_stderr | fast-mcp-ssh | 20 | 2.9 | 3.4 | 2.5 | 3.4 | 2.9 | 0.2 |
| exec_stderr | mcp-ssh-manager | 20 | 90.4 | 97.5 | 86.9 | 97.5 | 91.3 | 2.7 |
| exec_trivial | fast-mcp-ssh | 20 | 2.5 | 235.9 | 1.9 | 235.9 | 14.2 | 52.2 |
| exec_trivial | mcp-ssh-manager | 20 | 91.0 | 123.5 | 87.3 | 123.5 | 92.0 | 7.5 |
| exec_uname | fast-mcp-ssh | 20 | 4.1 | 4.5 | 3.7 | 4.5 | 4.1 | 0.2 |
| exec_uname | mcp-ssh-manager | 20 | 91.0 | 92.9 | 89.6 | 92.9 | 91.1 | 1.0 |
| read_1k | fast-mcp-ssh | 20 | 1.3 | 1.5 | 1.2 | 1.5 | 1.3 | 0.1 |
| read_1k | mcp-ssh-manager | 20 | 90.0 | 94.0 | 88.4 | 94.0 | 90.5 | 1.6 |
| write_1k | fast-mcp-ssh | 20 | 0.8 | 4.6 | 0.7 | 4.6 | 1.0 | 0.8 |
| write_1k | mcp-ssh-manager | 20 | 90.9 | 94.7 | 87.8 | 94.7 | 91.0 | 2.1 |

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
