# Benchmark results

One folder per published version, each holding the raw `runs.csv` from
`bench.py` and a `summary.md` with no host names, IPs or operator paths in it.
The headline table lives in the repo README and is taken from the newest run;
these folders are the receipts.

Runs before `v0.4.0` compare against `mcp-ssh-manager` only, and `v0.1.0` was
measured from a Linux bench client instead of Windows, so absolute numbers are
not comparable across folders. Compare within a single run.

## Reproducing

```bash
cd benchmark
python bench.py --servers servers.json --iterations 50 --output results/v<version>
```

`servers.json` is yours to write and is deliberately not committed: it holds
binary paths, a host address and a key path. See the docstring at the top of
`bench.py` for the schema, and give each server the same target host and the
same SSH key so the comparison means something.
