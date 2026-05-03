# Benchmark results

One folder per published version. Each holds the unmodified `runs.csv` from
`bench.py` plus a sanitized `summary.md` (no host names, IPs, or operator paths).

## Layout

```
benchmark/results/
├── README.md          # this file
├── COMPARISON.md      # mgr vs fast v0.1.0 vs fast v0.1.2, normalized
├── v0.1.0/
│   ├── runs.csv
│   └── summary.md
└── v0.1.2/
    ├── runs.csv
    └── summary.md
```

> 0.1.1 had no published bench run. The folder previously named `v0.1.1/` was a
> measurement from v0.1.0 time, renamed in 0.1.2 for accuracy.

## Reproducing

See repo root `README.md` → "Reproducing" section. The bench needs:

- a `~/.fast-mcp-ssh/hosts.toml` with an alias the bench can reach by SSH key
- a `benchmark/.env` for `mcp-ssh-manager` (`SSH_SERVER_<NAME>_HOST`/`USER`/`PORT`/`KEYPATH`)
- both `FAST_BIN` and `MGR_BIN` env vars pointing at the binaries

Then:

```bash
cd benchmark
FAST_BIN=/path/to/fast-mcp-ssh \
MGR_BIN="node /path/to/mcp-ssh-manager/src/index.js" \
python bench.py --iterations 50 --output results/v<version> \
  --fast-target <alias> --mgr-target <alias> --skip-tokens
```

## Comparing versions

See [`COMPARISON.md`](COMPARISON.md) for the cross-version table. Normalizes the
env shift (Linux→Windows bench host) by reporting `mgr / fast` ratios per scenario.

> TODO when ≥ 3 published versions exist: publish a per-version benchmark
> history page on the GitHub wiki and link it from the top-level README,
> instead of letting `COMPARISON.md` grow another column each release.
