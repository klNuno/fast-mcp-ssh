# Benchmark results

One folder per published version, each holding the raw `runs.csv` from
`bench.py` and a `summary.md` with no host names, IPs or operator paths in it.
The headline table lives in the repo README and is taken from the newest run;
these folders are the receipts.

Runs before `v0.4.0` compare against `mcp-ssh-manager` only, and `v0.1.0` was
measured from a Linux bench client instead of Windows, so absolute numbers are
not comparable across folders. Compare within a single run.

`v0.5.0` is the first run on a build that also speaks MCP `2026-07-28`. The
bench client opens the classic `initialize` handshake, so these numbers are the
path a client takes today, not the stateless one. It is also the first run with
a token table: earlier folders have none.

Cold start is three process spawns and nothing else, so it is the one row that
reads the machine's load rather than the server's design. A run taken while the
workstation was busy doubled it for all three servers at once. Take that row on
an idle box or not at all.

## Reproducing

```bash
cd benchmark
python bench.py --servers servers.json --iterations 50 --output results/v<version>
```

The token table needs `BENCH_TOKEN_API_KEY` on top of that, pointed at any
OpenAI-shaped endpoint (`BENCH_TOKEN_BASE_URL`, `BENCH_TOKEN_MODEL`). Without
one the section is skipped rather than guessed.

`servers.json` is yours to write and is deliberately not committed: it holds
binary paths, a host address and a key path. See the docstring at the top of
`bench.py` for the schema, and give each server the same target host and the
same SSH key so the comparison means something.
