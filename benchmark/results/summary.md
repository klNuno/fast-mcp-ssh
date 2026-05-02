# Benchmark — fast-mcp-ssh vs mcp-ssh-manager

- iterations per scenario: **50**
- target host alias: target
- bench host: bench-host

## Cold start (process spawn → first response)

| server | min ms | median ms | max ms |
|---|---:|---:|---:|
| fast-mcp-ssh | 2 | 2 | 3 |
| mcp-ssh-manager | 304 | 309 | 313 |

## Latency per scenario

| scenario | server | n_ok | p50 ms | p95 ms | min ms | max ms | mean ms | stdev |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| exec_lsetc | fast-mcp-ssh | 50 | 46.9 | 51.5 | 44.6 | 55.2 | 47.4 | 1.9 |
| exec_lsetc | mcp-ssh-manager | 50 | 100.4 | 105.6 | 90.7 | 109.9 | 99.5 | 4.5 |
| exec_pipe | fast-mcp-ssh | 50 | 46.8 | 52.1 | 45.2 | 54.8 | 47.9 | 2.4 |
| exec_pipe | mcp-ssh-manager | 50 | 96.8 | 106.6 | 90.1 | 112.7 | 97.6 | 5.3 |
| exec_seq5000 | fast-mcp-ssh | 50 | 46.3 | 52.3 | 44.0 | 54.3 | 47.5 | 2.8 |
| exec_seq5000 | mcp-ssh-manager | 50 | 98.0 | 105.2 | 91.5 | 110.5 | 97.8 | 4.7 |
| exec_stderr | fast-mcp-ssh | 50 | 47.5 | 52.6 | 44.3 | 54.0 | 48.0 | 2.6 |
| exec_stderr | mcp-ssh-manager | 50 | 96.9 | 105.9 | 90.7 | 107.8 | 97.1 | 4.8 |
| exec_trivial | fast-mcp-ssh | 50 | 45.9 | 52.0 | 43.2 | 148.7 | 48.8 | 14.6 |
| exec_trivial | mcp-ssh-manager | 50 | 97.2 | 108.0 | 90.2 | 127.5 | 97.7 | 6.9 |
| exec_uname | fast-mcp-ssh | 50 | 47.6 | 52.7 | 44.6 | 55.3 | 48.3 | 2.4 |
| exec_uname | mcp-ssh-manager | 50 | 98.0 | 104.6 | 91.7 | 106.4 | 98.1 | 4.3 |
| read_1k | fast-mcp-ssh | 50 | 50.4 | 66.7 | 5.7 | 73.4 | 42.7 | 20.6 |
| read_1k | mcp-ssh-manager | 50 | 96.1 | 106.7 | 91.0 | 108.1 | 97.2 | 5.1 |
| write_1k | fast-mcp-ssh | 50 | 4.5 | 61.1 | 3.9 | 62.9 | 16.1 | 20.9 |
| write_1k | mcp-ssh-manager | 50 | 97.8 | 106.2 | 91.5 | 107.1 | 98.0 | 4.7 |

## Response size (chars)

| scenario | server | p50 chars | p95 chars | max chars |
|---|---|---:|---:|---:|
| exec_lsetc | fast-mcp-ssh | 6067 | 6067 | 6067 |
| exec_lsetc | mcp-ssh-manager | 6017 | 6017 | 6017 |
| exec_pipe | fast-mcp-ssh | 76 | 76 | 76 |
| exec_pipe | mcp-ssh-manager | 128 | 128 | 128 |
| exec_seq5000 | fast-mcp-ssh | 12099 | 12099 | 12099 |
| exec_seq5000 | mcp-ssh-manager | 12368 | 12368 | 12368 |
| exec_stderr | fast-mcp-ssh | 181 | 181 | 181 |
| exec_stderr | mcp-ssh-manager | 178 | 178 | 178 |
| exec_trivial | fast-mcp-ssh | 76 | 76 | 76 |
| exec_trivial | mcp-ssh-manager | 112 | 112 | 112 |
| exec_uname | fast-mcp-ssh | 193 | 193 | 193 |
| exec_uname | mcp-ssh-manager | 239 | 239 | 239 |
| read_1k | fast-mcp-ssh | 1102 | 1102 | 1102 |
| read_1k | mcp-ssh-manager | 1161 | 1161 | 1161 |
| write_1k | fast-mcp-ssh | 63 | 64 | 64 |
| write_1k | mcp-ssh-manager | 1196 | 1196 | 1196 |

## Token counts on representative payloads

Counted via OpenRouter (deepseek/deepseek-chat).

| scenario | server | chars | tokens | chars/token |
|---|---|---:|---:|---:|
| exec_trivial | fast-mcp-ssh | 76 | 35 | 2.17 |
| exec_uname | fast-mcp-ssh | 193 | 94 | 2.05 |
| exec_seq5000 | fast-mcp-ssh | 12099 | 6513 | 1.86 |
| exec_lsetc | fast-mcp-ssh | 6067 | 2438 | 2.49 |
| exec_stderr | fast-mcp-ssh | 181 | 64 | 2.83 |
| exec_pipe | fast-mcp-ssh | 76 | 35 | 2.17 |
| write_1k | fast-mcp-ssh | 64 | 31 | 2.06 |
| read_1k | fast-mcp-ssh | 1102 | 167 | 6.60 |
| exec_trivial | mcp-ssh-manager | 112 | 49 | 2.29 |
| exec_uname | mcp-ssh-manager | 239 | 114 | 2.10 |
| exec_seq5000 | mcp-ssh-manager | 12368 | 5725 | 2.16 |
| exec_lsetc | mcp-ssh-manager | 6017 | 2413 | 2.49 |
| exec_stderr | mcp-ssh-manager | 178 | 65 | 2.74 |
| exec_pipe | mcp-ssh-manager | 128 | 58 | 2.21 |
| write_1k | mcp-ssh-manager | 1196 | 202 | 5.92 |
| read_1k | mcp-ssh-manager | 1161 | 186 | 6.24 |
