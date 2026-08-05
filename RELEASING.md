# Releasing

Two workflows, two triggers, and a human between them.

`release.yml` fires on a `v*` tag: it checks the tag against the manifests,
builds five platform archives, checksums them into one `SHA256SUMS.txt`, and
opens the GitHub release **as a draft**. Nothing has shipped at that point:
`releases/latest` skips drafts.

`publish.yml` fires when that release is **published**. It uploads the crate to
crates.io, then registers the version with the MCP registry. crates.io goes
after the GitHub release on purpose: a crate version with no binary behind it
is one somebody installs and cannot update, or reads release notes for and
cannot download.

## One-time setup

crates.io publishes through trusted publishing, so no registry token is stored
in the repository secrets. This has to exist before the next release or the
run fails with `No Trusted Publishing config found for repository
klNuno/fast-mcp-ssh`, which reads like a workflow bug and is not:

crates.io → the crate → Settings → Trusted Publishing → Add, naming the
repository `klNuno/fast-mcp-ssh` and the workflow file name `publish.yml`.

Once that is in place, `secrets.CARGO_REGISTRY_TOKEN` is unused and can be
deleted from the repository secrets.

## Cutting a release

1. Bump the version in **three** places: `Cargo.toml`, both `version` fields of
   `server.json`, and the lockfile via `cargo update -p fast-mcp-ssh`. The
   `check` job refuses a tag that disagrees with any of them, and
   `cargo publish --locked` refuses a lockfile that disagrees with the manifest.
2. Commit, push, wait for CI to go green. The release workflow does not re-run
   the test suite.
3. `git tag -a vX.Y.Z -m "vX.Y.Z"` and push the tag. The draft release appears
   with its assets.
4. Read the draft. Every archive present, `SHA256SUMS.txt` there, notes say
   what changed.
5. Press Publish. The crate and the registry entry go up on their own.

## Re-running a failed publish

`publish.yml` also takes a `workflow_dispatch` with the tag as input, for the
case where crates.io or the registry failed after the release went out. Both
jobs check whether the version is already served before doing anything, so a
re-run over a release that already shipped ends as a green skip rather than a
failed upload. A crates.io version can be yanked, never replaced, so the guard
sits before the authentication step and not after it.
