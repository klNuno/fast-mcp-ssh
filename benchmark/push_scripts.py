"""Push the latest benchmark scripts from local to the bench host's bench dir."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from client import McpStdio

REPO_ROOT = Path(__file__).resolve().parent.parent


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bench-alias", required=True)
    p.add_argument("--bench-dir", default="/home/user/bench")
    p.add_argument("--fast-bin", default=str(REPO_ROOT / "target" / "release" /
                                              ("fast-mcp-ssh.exe" if os.name == "nt" else "fast-mcp-ssh")))
    args = p.parse_args()

    files = ["client.py", "bench.py", "token_count.py"]
    mcp = McpStdio([args.fast_bin])
    try:
        mcp.initialize(client_name="push")
        for f in files:
            local = REPO_ROOT / "benchmark" / f
            if not local.exists():
                continue
            res = mcp.call(
                "wr",
                {
                    "host": args.bench_alias,
                    "remote": f"{args.bench_dir}/{f}",
                    "content": local.read_text(encoding="utf-8"),
                    "mode": 0o755,
                },
                timeout_s=10,
            )
            if res.is_error:
                print(f"FAIL {f}: {res.text}")
                sys.exit(2)
            print(f"  pushed {f} ({local.stat().st_size} B)")
    finally:
        mcp.close()


if __name__ == "__main__":
    main()
