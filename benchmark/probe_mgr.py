"""Discover mcp-ssh-manager tool surface from the bench host.

Run after `provision.py` to confirm mcp-ssh-manager sees the configured server
and answers tools/list / tools/call. The probe runs entirely on the bench host;
this Windows-side helper only ships the probe and prints its output.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from client import McpStdio

REPO_ROOT = Path(__file__).resolve().parent.parent

PROBE = r"""
import json, subprocess, sys, time, os, threading
from queue import Queue, Empty

mgr_bin = os.path.expanduser('~/.npm-global/bin/mcp-ssh-manager')
print('[probe] mgr_bin =', mgr_bin)
print('[probe] exists  =', os.path.exists(mgr_bin))

p = subprocess.Popen([mgr_bin], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, text=False, bufsize=0)
q = Queue()

def reader():
    for line in p.stdout:
        try:
            q.put(json.loads(line))
        except Exception:
            pass

def stderr_reader():
    chunks = []
    for line in p.stderr:
        chunks.append(line)
    sys.__stderr__.write(b''.join(chunks).decode('utf-8', 'replace'))

threading.Thread(target=reader, daemon=True).start()
threading.Thread(target=stderr_reader, daemon=True).start()

def send(msg):
    p.stdin.write((json.dumps(msg) + '\n').encode())
    p.stdin.flush()

def recv(rid, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            m = q.get(timeout=0.5)
        except Empty:
            continue
        if m.get('id') == rid:
            return m
        q.put(m)
    return None

send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'probe','version':'1'}}})
init = recv(1, 15)
print('[probe] initialize ->', json.dumps(init, indent=2)[:500] if init else 'TIMEOUT')

send({'jsonrpc':'2.0','method':'notifications/initialized'})
send({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
tl = recv(2, 15)
if tl and 'result' in tl:
    for t in tl['result']['tools']:
        sch = t.get('inputSchema', {}).get('properties', {})
        print(f"[probe] {t['name']}({','.join(sch.keys())}): {t.get('description','')[:80]}")
else:
    print('[probe] tools/list FAILED:', tl)

send({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'ssh_execute','arguments':{'server':'target','command':'echo HELLO_FROM_MGR; uname -n'}}})
r = recv(3, 30)
print('[probe] ssh_execute target echo ->', json.dumps(r, indent=2)[:600])

send({'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'ssh_list_servers','arguments':{}}})
r = recv(4, 10)
print('[probe] ssh_list_servers ->', json.dumps(r, indent=2)[:400])

p.stdin.close()
try:
    p.wait(timeout=5)
except subprocess.TimeoutExpired:
    p.kill()
"""


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bench-alias", required=True)
    p.add_argument("--bench-dir", default="/home/user/bench")
    p.add_argument("--fast-bin", default=str(REPO_ROOT / "target" / "release" /
                                              ("fast-mcp-ssh.exe" if os.name == "nt" else "fast-mcp-ssh")))
    args = p.parse_args()

    mcp = McpStdio([args.fast_bin])
    try:
        mcp.initialize(client_name="probe-push")
        res = mcp.call(
            "wr",
            {
                "host": args.bench_alias,
                "remote": f"{args.bench_dir}/probe_mgr.py",
                "content": PROBE,
                "mode": 0o755,
            },
            timeout_s=10,
        )
        if res.is_error:
            print("push failed:", res.text)
            sys.exit(2)
        res = mcp.call(
            "exec",
            {
                "host": args.bench_alias,
                "cmd": f"cd {args.bench_dir} && python3 probe_mgr.py 2>&1",
                "timeout": 90,
            },
            timeout_s=120,
        )
        print(res.text)
    finally:
        mcp.close()


if __name__ == "__main__":
    main()
