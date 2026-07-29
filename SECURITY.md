# Security policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories on this repository
("Security" tab, "Report a vulnerability"). Do not open a public issue for a
vulnerability.

Expect an acknowledgement within a week.

## Threat model

fast-mcp-ssh hands an SSH connection to a large language model. Treat the model
as an untrusted, occasionally confused caller that is nonetheless allowed to run
commands you authorized it to run.

What the server does defend against:

- Command patterns matched before any SSH packet leaves the machine
  (`deny_patterns` refuse outright, `confirm_patterns` require a user
  confirmation through MCP elicitation, and a client that cannot elicit is
  denied).
- Host-key pinning, TOFU by default, with `strict` and per-host fingerprint
  modes.
- Path-based refusal of well-known credential files over SFTP.
- Per-host `read_only`, `allowed_tools` and rate limits.

What it does not defend against, by design:

- A determined model that wants to bypass a regex guard will succeed. Shell
  quoting, `$IFS`, base64, `bash -c` and shell functions defined earlier in a
  persistent PTY all defeat pattern matching. Guards are a speed bump against
  accidents, not a security boundary against an adversary. The boundary is the
  remote account's own permissions, `read_only`, and `allowed_tools`.
- Anything the remote account can already do. Give the server an account scoped
  to what the model should be able to reach.

## Deliberate omissions

SSH agent forwarding is not supported and will not be added. Forwarding an agent
into a machine an LLM is driving lets anyone with root on that machine sign with
your key for the duration of the connection.

## Known advisories in the dependency tree

`cargo audit` findings that ship knowingly are listed in `deny.toml` with the
reason. Re-check them before each release.
