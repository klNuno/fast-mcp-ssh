"""MCP stdio client used by both the provisioning helper and bench.py."""
from __future__ import annotations

import json
import subprocess
import threading
import time
from dataclasses import dataclass
from queue import Queue, Empty
from typing import Any


@dataclass
class CallResult:
    request_id: int
    elapsed_ms: float
    response: dict[str, Any]
    chars: int

    @property
    def is_error(self) -> bool:
        return "error" in self.response

    @property
    def text(self) -> str:
        if self.is_error:
            return self.response["error"].get("message", "")
        contents = self.response.get("result", {}).get("content", [])
        for c in contents:
            if c.get("type") == "text":
                return c.get("text", "")
        return ""


class McpStdio:
    """Minimal MCP client speaking JSON-RPC over a child process' stdio."""

    def __init__(self, cmd: list[str], env: dict[str, str] | None = None):
        self.cmd = cmd
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0,
            env=env,
        )
        self._next_id = 0
        self._queue: Queue[dict[str, Any]] = Queue()
        self._stderr: list[bytes] = []
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._stderr_reader, daemon=True).start()

    def _reader(self):
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if "id" in msg:
                self._queue.put(msg)

    def _stderr_reader(self):
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self._stderr.append(line)

    def send(self, method: str, params: dict | None = None, notify: bool = False) -> int | None:
        if notify:
            payload = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                payload["params"] = params
            self.proc.stdin.write((json.dumps(payload) + "\n").encode())
            self.proc.stdin.flush()
            return None
        self._next_id += 1
        rid = self._next_id
        payload = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            payload["params"] = params
        self.proc.stdin.write((json.dumps(payload) + "\n").encode())
        self.proc.stdin.flush()
        return rid

    def recv(self, target_id: int, timeout_s: float = 60.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                msg = self._queue.get(timeout=0.5)
            except Empty:
                continue
            if msg.get("id") == target_id:
                return msg
            self._queue.put(msg)
        raise TimeoutError(f"id={target_id} after {timeout_s}s")

    def initialize(self, client_name: str = "bench") -> None:
        rid = self.send(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": client_name, "version": "1"},
            },
        )
        self.recv(rid, timeout_s=15)
        self.send("notifications/initialized", notify=True)

    def call(self, name: str, args: dict[str, Any], timeout_s: float = 60.0) -> CallResult:
        t0 = time.monotonic()
        rid = self.send("tools/call", {"name": name, "arguments": args})
        msg = self.recv(rid, timeout_s=timeout_s)
        elapsed = (time.monotonic() - t0) * 1000.0
        text = ""
        contents = msg.get("result", {}).get("content", [])
        for c in contents:
            if c.get("type") == "text":
                text = c.get("text", "")
                break
        return CallResult(rid, elapsed, msg, len(text))

    def stderr_text(self) -> str:
        return b"".join(self._stderr).decode(errors="replace")

    def close(self) -> None:
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
