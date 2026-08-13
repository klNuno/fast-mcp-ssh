"""End-to-end smoke for the MCP 2026-07-28 path, against a real host.

Covers the two things unit tests cannot reach: a confirmation that survives the
retry and then actually runs the command, and a task polled to completion. No
`initialize` handshake here, every request carries the `_meta` the stateless
core requires.

    python scripts/stateless-smoke.py --host target

The probe command is a plain `echo` that happens to match the default `reboot`
confirm pattern, so it needs no config change and does nothing on the host.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "stateless-smoke", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {
        "extensions": {"io.modelcontextprotocol/tasks": {}}
    },
}

PROBE = "echo reboot-probe"


class Server:
    """One server process, spoken to without a handshake."""

    def __init__(self, cmd: list[str]):
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self.next_id = 0

    def rpc(self, method: str, params: dict) -> dict:
        self.next_id += 1
        params = {**params, "_meta": META}
        frame = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        self.proc.stdin.write(json.dumps(frame) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def call(self, name: str, args: dict, answers: dict | None = None) -> dict:
        params = {"name": name, "arguments": args}
        if answers is not None:
            params["inputResponses"] = answers
        return self.rpc("tools/call", params)

    def close(self) -> None:
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def check(label: str, ok: bool, detail: str) -> bool:
    print(f"[{'PASS' if ok else 'FAIL'}] {label}: {detail[:150]}")
    return ok


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="target", help="host alias to drive")
    ap.add_argument("--config", default=None, help="hosts.toml (default: the server's own)")
    ap.add_argument(
        "--bin",
        default=str(root / "target" / "release" / ("fast-mcp-ssh.exe" if sys.platform == "win32" else "fast-mcp-ssh")),
    )
    args = ap.parse_args()

    cmd = [args.bin]
    if args.config:
        cmd += ["--config", args.config]
    server = Server(cmd)
    host = args.host
    passed = []

    # tools/list is cacheable and deterministically ordered for this peer.
    listed = server.rpc("tools/list", {}).get("result", {})
    names = [t["name"] for t in listed.get("tools", [])]
    passed.append(
        check(
            "tools/list is sorted and cacheable",
            names == sorted(names) and listed.get("ttlMs") and listed.get("cacheScope") == "public",
            f"{len(names)} tools, ttlMs={listed.get('ttlMs')}, scope={listed.get('cacheScope')}",
        )
    )

    # A guarded command defers instead of opening a server-side request.
    first = server.call("exec", {"host": host, "cmd": PROBE}).get("result", {})
    key = next(iter(first.get("inputRequests", {})), None)
    passed.append(
        check("a guarded call defers", first.get("resultType") == "input_required" and key is not None, str(first.get("resultType")))
    )

    # Answering and retrying runs the command for real.
    approved = server.call(
        "exec", {"host": host, "cmd": PROBE}, {key: {"action": "accept", "content": {"answer": "yes"}}}
    ).get("result", {})
    text = "".join(part.get("text", "") for part in approved.get("content", []))
    passed.append(check("the retry runs it on the host", "reboot-probe" in text, text.replace("\n", " | ")))

    # Anything that is not a yes fails closed. A second command, because the
    # approval above is remembered for `confirm_ttl` and would let the same one
    # straight through.
    other = PROBE + "-again"
    deferred = server.call("exec", {"host": host, "cmd": other}).get("result", {})
    other_key = next(iter(deferred.get("inputRequests", {})), None)
    declined = server.call("exec", {"host": host, "cmd": other}, {other_key: {"action": "decline"}})
    passed.append(check("a decline blocks", "error" in declined, json.dumps(declined.get("error", {}))))

    # Past the default timeout the call comes back as a task handle.
    started = server.call("exec", {"host": host, "cmd": "sleep 3; echo task-probe", "timeout": 61}).get("result", {})
    task_id = started.get("taskId")
    passed.append(check("a long exec is a task", started.get("resultType") == "task" and task_id is not None, str(started.get("resultType"))))

    status, task = None, {}
    if task_id:
        for _ in range(30):
            time.sleep(1)
            got = server.rpc("tasks/get", {"taskId": task_id})
            if "error" in got:
                task = got
                break
            task = got["result"]
            status = task.get("status")
            if status in ("completed", "failed", "cancelled"):
                break
    passed.append(check("the task completes", status == "completed", json.dumps(task)))

    # A completed task inlines the CallToolResult; there is no fetch-the-result
    # method to call afterwards.
    inlined = json.dumps(task.get("result", {}))
    passed.append(check("the task carries its output", "task-probe" in inlined, inlined))

    server.close()
    print(f"\n{sum(passed)}/{len(passed)} passed")
    return 0 if all(passed) else 1


if __name__ == "__main__":
    sys.exit(main())
