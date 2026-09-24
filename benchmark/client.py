"""MCP stdio client used by both the provisioning helper and bench.py."""
from __future__ import annotations

import io
import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass
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
        # Overlay, never replace: handing Popen a bare dict drops PATH and
        # SystemRoot, and a node server then hangs before it ever speaks
        # JSON-RPC, which reads as "the server is slow" in the results.
        child_env = {**os.environ, **env} if env else None
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0,
            env=child_env,
        )
        self._next_id = 0
        # Responses keyed by id. A queue that `recv` drains and refills with
        # the ids it is not waiting for spins while holding the GIL as soon as
        # replies come back out of order, and starves the reader thread: a
        # burst of parallel calls then measured seconds the server never took.
        self._responses: dict[int, dict[str, Any]] = {}
        self._arrived = threading.Condition()
        self._stderr: list[bytes] = []
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._stderr_reader, daemon=True).start()

    def _reader(self):
        assert self.proc.stdout is not None
        # `bufsize=0` makes stdout a raw pipe, whose line iteration reads one
        # byte per syscall. Buffer the read side only; stdin stays unbuffered.
        for line in io.BufferedReader(self.proc.stdout):
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if "id" in msg:
                with self._arrived:
                    self._responses[msg["id"]] = msg
                    self._arrived.notify_all()

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
        with self._arrived:
            if not self._arrived.wait_for(lambda: target_id in self._responses, timeout_s):
                raise TimeoutError(f"id={target_id} after {timeout_s}s")
            return self._responses.pop(target_id)

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
        t0 = time.perf_counter()
        rid = self.send("tools/call", {"name": name, "arguments": args})
        msg = self.recv(rid, timeout_s=timeout_s)
        elapsed = (time.perf_counter() - t0) * 1000.0
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
