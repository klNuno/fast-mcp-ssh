"""Provision a benchmark host for the fast-mcp-ssh vs mcp-ssh-manager bench.

The bench host runs both MCP servers as child processes and measures their behavior
when each opens an SSH connection to the same target host. This script does
everything required to make that work, given:

- a working fast-mcp-ssh on the operator's machine (see Cargo build)
- SSH access from the operator's machine to both BENCH_HOST and TARGET_HOST
- BENCH_HOST being a Linux machine with curl + apt available

What it does, in order, all driven over the local fast-mcp-ssh:

1. Authorize the bench host's pubkey on the target host (~/.ssh/bench_target),
   creating the key on the bench host first if missing.
2. Verify the bench-to-target SSH path with `ssh ... 'echo OK'`.
3. Install the rust toolchain on the bench host via rustup if missing.
4. Install npm on the bench host via apt if missing.
5. Push the fast-mcp-ssh source tree to BENCH_DIR/fast-mcp-ssh.
6. Push the bench scripts to BENCH_DIR.
7. Build fast-mcp-ssh in release mode on the bench host.
8. Install mcp-ssh-manager via npm globally on the bench host.
9. Drop both servers' configs (hosts.toml for fast-mcp-ssh, .env for mcp-ssh-manager).

CLI args parameterize host names, IPs, user, and port. No personal info hardcoded.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from client import McpStdio


REPO_ROOT = Path(__file__).resolve().parent.parent


def assert_ok(label: str, res, allow_nonzero: bool = False) -> str:
    if res.is_error:
        print(f"[FAIL] {label}: {res.text}")
        sys.exit(2)
    if not allow_nonzero and "exit_code:" in res.text and "exit_code: 0" not in res.text:
        print(f"[FAIL] {label} non-zero exit:\n{res.text}")
        sys.exit(2)
    print(f"[ OK ] {label}")
    return res.text


def step_generate_bench_key(mcp, args):
    cmd = (
        "test -f ~/.ssh/bench_target || "
        "ssh-keygen -t ed25519 -N '' -f ~/.ssh/bench_target -C 'fast-mcp-ssh-bench' -q; "
        "cat ~/.ssh/bench_target.pub"
    )
    res = mcp.call("exec", {"host": args.bench_alias, "cmd": cmd, "timeout": 10})
    if res.is_error:
        print(f"[FAIL] generate bench key: {res.text}")
        sys.exit(2)
    pubkey = ""
    for line in res.text.splitlines():
        line = line.strip()
        if line.startswith("ssh-"):
            pubkey = line
            break
    if not pubkey:
        print(f"[FAIL] could not extract pubkey:\n{res.text}")
        sys.exit(2)
    print(f"[ OK ] bench host key ready: {pubkey[:40]}...")
    return pubkey


def step_authorize_bench_on_target(mcp, args, pubkey):
    marker = "fast-mcp-ssh-bench"
    cmd = (
        f'mkdir -p /root/.ssh && touch /root/.ssh/authorized_keys && '
        f'grep -qF "{marker}" /root/.ssh/authorized_keys || '
        f'echo "{pubkey}" >> /root/.ssh/authorized_keys && '
        f'chmod 600 /root/.ssh/authorized_keys && echo done'
    )
    res = mcp.call("exec", {"host": args.target_alias, "cmd": cmd, "timeout": 10})
    assert_ok("authorize bench host on target", res)


def step_verify_bench_to_target(mcp, args):
    res = mcp.call(
        "exec",
        {
            "host": args.bench_alias,
            "cmd": (
                "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "
                f"-i ~/.ssh/bench_target -p {args.target_port} {args.target_user}@{args.target_addr} "
                "'echo BENCH_TO_TARGET_OK; uname -n'"
            ),
            "timeout": 15,
        },
    )
    if "BENCH_TO_TARGET_OK" not in res.text:
        print(f"[FAIL] bench -> target ssh check:\n{res.text}")
        sys.exit(2)
    print("[ OK ] bench -> target ssh verified")


def step_install_rust(mcp, args):
    res = mcp.call(
        "exec",
        {
            "host": args.bench_alias,
            "cmd": (
                "command -v cargo >/dev/null && cargo --version || "
                "(curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | "
                "sh -s -- -y --profile minimal --default-toolchain stable && "
                "$HOME/.cargo/bin/cargo --version)"
            ),
            "timeout": 600,
        },
        timeout_s=650,
    )
    assert_ok("rust toolchain on bench host", res)


def step_install_npm(mcp, args):
    res = mcp.call(
        "exec",
        {
            "host": args.bench_alias,
            "cmd": (
                "command -v npm >/dev/null && npm --version || "
                "(sudo -n apt-get install -y npm 2>&1 | tail -3 && npm --version)"
            ),
            "timeout": 300,
        },
        timeout_s=320,
    )
    if "exit_code: 0" not in res.text:
        print("[WARN] npm install may have failed (sudo without password?)")
        print(res.text)
    else:
        print("[ OK ] npm on bench host")


def step_push_repo(mcp, args):
    bench_dir = args.bench_dir
    res = mcp.call(
        "exec",
        {
            "host": args.bench_alias,
            "cmd": (
                f"mkdir -p {bench_dir}/fast-mcp-ssh/src/output "
                f"{bench_dir}/fast-mcp-ssh/src/session "
                f"{bench_dir}/fast-mcp-ssh/examples "
                f"{bench_dir}/results && echo done"
            ),
            "timeout": 5,
        },
    )
    assert_ok("create bench dirs", res)

    files_to_push = [
        ("Cargo.toml", "fast-mcp-ssh/Cargo.toml"),
        ("Cargo.lock", "fast-mcp-ssh/Cargo.lock"),
        ("src/main.rs", "fast-mcp-ssh/src/main.rs"),
        ("src/audit.rs", "fast-mcp-ssh/src/audit.rs"),
        ("src/config.rs", "fast-mcp-ssh/src/config.rs"),
        ("src/errors.rs", "fast-mcp-ssh/src/errors.rs"),
        ("src/guards.rs", "fast-mcp-ssh/src/guards.rs"),
        ("src/server.rs", "fast-mcp-ssh/src/server.rs"),
        ("src/sftp.rs", "fast-mcp-ssh/src/sftp.rs"),
        ("src/tail.rs", "fast-mcp-ssh/src/tail.rs"),
        ("src/output/mod.rs", "fast-mcp-ssh/src/output/mod.rs"),
        ("src/output/toon.rs", "fast-mcp-ssh/src/output/toon.rs"),
        ("src/output/truncate.rs", "fast-mcp-ssh/src/output/truncate.rs"),
        ("src/session/mod.rs", "fast-mcp-ssh/src/session/mod.rs"),
        ("src/session/connect.rs", "fast-mcp-ssh/src/session/connect.rs"),
        ("src/session/exec.rs", "fast-mcp-ssh/src/session/exec.rs"),
        ("src/session/pty.rs", "fast-mcp-ssh/src/session/pty.rs"),
    ]
    for src, dst in files_to_push:
        local = REPO_ROOT / src
        if not local.exists():
            continue
        content = local.read_text(encoding="utf-8")
        res = mcp.call(
            "wr",
            {"host": args.bench_alias, "remote": f"{bench_dir}/{dst}", "content": content, "mode": 0o644},
            timeout_s=15,
        )
        if res.is_error:
            print(f"[FAIL] push {src}: {res.text}")
            sys.exit(2)
    print(f"[ OK ] pushed {len(files_to_push)} source files")


def step_push_bench_scripts(mcp, args):
    bench_files = ["benchmark/client.py", "benchmark/bench.py", "benchmark/token_count.py"]
    for f in bench_files:
        path = REPO_ROOT / f
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8")
        res = mcp.call(
            "wr",
            {
                "host": args.bench_alias,
                "remote": f"{args.bench_dir}/{f.split('/')[-1]}",
                "content": content,
                "mode": 0o755,
            },
            timeout_s=10,
        )
        if res.is_error:
            print(f"[FAIL] push {f}: {res.text}")
            sys.exit(2)
    print("[ OK ] pushed bench scripts")


def step_push_hosts_toml(mcp, args):
    res = mcp.call(
        "exec",
        {
            "host": args.bench_alias,
            "cmd": f"mkdir -p {args.bench_home}/.fast-mcp-ssh && echo ok",
            "timeout": 5,
        },
    )
    assert_ok("mkdir bench .fast-mcp-ssh", res)
    hosts_toml = (
        "[defaults]\n"
        "import_ssh_config = false\n"
        'output = "toon"\n'
        "audit_log = false\n\n"
        "[host.target]\n"
        f'addr = "{args.target_addr}"\n'
        f'user = "{args.target_user}"\n'
        f"port = {args.target_port}\n"
        'auth = "key"\n'
        'key = "~/.ssh/bench_target"\n'
    )
    res = mcp.call(
        "wr",
        {
            "host": args.bench_alias,
            "remote": f"{args.bench_home}/.fast-mcp-ssh/hosts.toml",
            "content": hosts_toml,
            "mode": 0o600,
        },
        timeout_s=10,
    )
    assert_ok("push bench hosts.toml", res)


def step_build_fast_mcp_ssh(mcp, args):
    res = mcp.call(
        "exec",
        {
            "host": args.bench_alias,
            "cmd": (
                f"cd {args.bench_dir}/fast-mcp-ssh && "
                "$HOME/.cargo/bin/cargo build --release 2>&1 | tail -5 && "
                "ls -la target/release/fast-mcp-ssh"
            ),
            "timeout": 1200,
        },
        timeout_s=1300,
    )
    assert_ok("build fast-mcp-ssh on bench host", res)


def step_install_mcp_ssh_manager(mcp, args):
    res = mcp.call(
        "exec",
        {
            "host": args.bench_alias,
            "cmd": (
                "mkdir -p ~/.npm-global && npm config set prefix '~/.npm-global' && "
                "(command -v ~/.npm-global/bin/mcp-ssh-manager && "
                "~/.npm-global/bin/mcp-ssh-manager --version 2>/dev/null) || "
                "npm install -g mcp-ssh-manager 2>&1 | tail -3 && "
                "ls ~/.npm-global/bin/"
            ),
            "timeout": 600,
        },
        timeout_s=650,
    )
    assert_ok("install mcp-ssh-manager on bench host", res, allow_nonzero=True)


def step_setup_mcp_ssh_manager_env(mcp, args):
    res = mcp.call(
        "exec",
        {
            "host": args.bench_alias,
            "cmd": f"mkdir -p {args.bench_home}/.ssh-manager && echo ok",
            "timeout": 5,
        },
    )
    assert_ok("mkdir bench .ssh-manager", res)
    env = (
        f"SSH_SERVER_TARGET_HOST={args.target_addr}\n"
        f"SSH_SERVER_TARGET_PORT={args.target_port}\n"
        f"SSH_SERVER_TARGET_USER={args.target_user}\n"
        f"SSH_SERVER_TARGET_KEYPATH={args.bench_home}/.ssh/bench_target\n"
    )
    res = mcp.call(
        "wr",
        {
            "host": args.bench_alias,
            "remote": f"{args.bench_home}/.ssh-manager/.env",
            "content": env,
            "mode": 0o600,
        },
        timeout_s=5,
    )
    assert_ok("write mcp-ssh-manager .env", res)


def main():
    p = argparse.ArgumentParser(description="Provision a remote bench host for fast-mcp-ssh comparison")
    p.add_argument("--bench-alias", required=True,
                   help="hosts.toml alias for the bench host (where both servers will run)")
    p.add_argument("--target-alias", required=True,
                   help="hosts.toml alias for the target SSH host (what the servers connect to)")
    p.add_argument("--target-addr", required=True, help="Target host IP or DNS name")
    p.add_argument("--target-user", default="root", help="SSH user on the target host")
    p.add_argument("--target-port", type=int, default=22, help="SSH port on the target host")
    p.add_argument("--bench-home", default=os.environ.get("BENCH_HOME", "/home/user"),
                   help="Home directory of the bench-host login user (default /home/user)")
    p.add_argument("--bench-dir", default=None,
                   help="Working directory on the bench host (default <bench-home>/bench)")
    p.add_argument("--fast-bin", default=str(REPO_ROOT / "target" / "release" /
                                              ("fast-mcp-ssh.exe" if os.name == "nt" else "fast-mcp-ssh")),
                   help="Path to the local fast-mcp-ssh binary")
    args = p.parse_args()
    if args.bench_dir is None:
        args.bench_dir = f"{args.bench_home}/bench"

    if not Path(args.fast_bin).exists():
        print(f"missing fast-mcp-ssh binary: {args.fast_bin}")
        sys.exit(2)

    mcp = McpStdio([args.fast_bin])
    try:
        mcp.initialize(client_name="provision")
        pubkey = step_generate_bench_key(mcp, args)
        step_authorize_bench_on_target(mcp, args, pubkey)
        step_verify_bench_to_target(mcp, args)
        step_install_rust(mcp, args)
        step_install_npm(mcp, args)
        step_push_hosts_toml(mcp, args)
        step_setup_mcp_ssh_manager_env(mcp, args)
        step_push_repo(mcp, args)
        step_push_bench_scripts(mcp, args)
        step_build_fast_mcp_ssh(mcp, args)
        step_install_mcp_ssh_manager(mcp, args)
        print("\n[DONE] bench host provisioned.")
    finally:
        mcp.close()


if __name__ == "__main__":
    main()
