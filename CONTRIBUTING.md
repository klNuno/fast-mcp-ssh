# Contributing

## The invariant that breaks quietly

This is a stdio MCP server. Anything written to stdout that is not an rmcp
protocol frame corrupts the JSON-RPC stream and the client disconnects without
an error message. Never use `println!`, `print!`, `dbg!` or `std::io::stdout()`
in tool code. `tracing` macros are safe, they go to stderr.

## Before opening a pull request

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

CI runs the same three on Linux, macOS and Windows.

## Adding a configuration field

`examples/hosts.toml` and `README.md` are the only user-facing documentation for
configuration. A new field that lands in `src/config.rs` without appearing in
both is a bug.

## End-to-end testing

`scripts/smoke.ps1` and `scripts/smoke.sh` drive the built binary over JSON-RPC
stdio against a real SSH host. They default to a host alias named `target` and
take an override:

```bash
./scripts/smoke.sh --host myhost
```

Define that alias in `~/.fast-mcp-ssh/hosts.toml` first.
