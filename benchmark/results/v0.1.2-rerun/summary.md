# Benchmark — fast-mcp-ssh vs mcp-ssh-manager

- iterations per scenario: **20**
- target host alias: target
- bench host: 

## Cold start (process spawn → first response)

| server | min ms | median ms | max ms |
|---|---:|---:|---:|
| fast-mcp-ssh | 25 | 27 | 31 |
| mcp-ssh-manager | 222 | 222 | 226 |

## Latency per scenario

| scenario | server | n_ok | p50 ms | p95 ms | min ms | max ms | mean ms | stdev |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| exec_lsetc | fast-mcp-ssh | 20 | 6.7 | 7.9 | 6.2 | 7.9 | 6.8 | 0.5 |
| exec_lsetc | mcp-ssh-manager | 20 | 90.9 | 93.7 | 88.3 | 93.7 | 91.1 | 1.5 |
| exec_pipe | fast-mcp-ssh | 20 | 3.8 | 4.3 | 3.3 | 4.3 | 3.8 | 0.3 |
| exec_pipe | mcp-ssh-manager | 20 | 90.6 | 92.9 | 89.0 | 92.9 | 90.7 | 1.1 |
| exec_seq5000 | fast-mcp-ssh | 20 | 8.3 | 9.7 | 7.8 | 9.7 | 8.4 | 0.6 |
| exec_seq5000 | mcp-ssh-manager | 20 | 90.7 | 96.7 | 88.6 | 96.7 | 91.0 | 2.3 |
| exec_stderr | fast-mcp-ssh | 20 | 3.0 | 3.3 | 2.6 | 3.3 | 3.0 | 0.2 |
| exec_stderr | mcp-ssh-manager | 20 | 90.3 | 95.0 | 88.4 | 95.0 | 90.8 | 1.6 |
| exec_trivial | fast-mcp-ssh | 20 | 2.4 | 57.8 | 1.9 | 57.8 | 5.1 | 12.4 |
| exec_trivial | mcp-ssh-manager | 20 | 89.3 | 105.4 | 87.7 | 105.4 | 90.3 | 3.8 |
| exec_uname | fast-mcp-ssh | 20 | 3.8 | 4.5 | 3.4 | 4.5 | 3.8 | 0.3 |
| exec_uname | mcp-ssh-manager | 20 | 91.0 | 93.8 | 89.3 | 93.8 | 91.3 | 1.2 |
| read_1k | fast-mcp-ssh | 20 | 1.3 | 1.8 | 1.2 | 1.8 | 1.4 | 0.1 |
| read_1k | mcp-ssh-manager | 20 | 90.0 | 93.0 | 87.3 | 93.0 | 89.9 | 1.4 |
| write_1k | fast-mcp-ssh | 20 | 0.9 | 3.5 | 0.8 | 3.5 | 1.0 | 0.6 |
| write_1k | mcp-ssh-manager | 20 | 90.0 | 94.5 | 87.6 | 94.5 | 89.9 | 1.6 |

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
| exec_trivial | fast-mcp-ssh | 75 | 76 | 76 |
| exec_trivial | mcp-ssh-manager | 119 | 119 | 119 |
| exec_uname | fast-mcp-ssh | 192 | 192 | 192 |
| exec_uname | mcp-ssh-manager | 246 | 246 | 246 |
| read_1k | fast-mcp-ssh | 1108 | 1108 | 1108 |
| read_1k | mcp-ssh-manager | 1168 | 1168 | 1168 |
| write_1k | fast-mcp-ssh | 70 | 70 | 70 |
| write_1k | mcp-ssh-manager | 1203 | 1203 | 1203 |
