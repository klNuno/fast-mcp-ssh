"""Benchmark fast-mcp-ssh against other stdio SSH MCP servers.

Runs a fixed set of scenarios against each server N times, measures wall-clock
latency and response payload size, and emits CSV + a markdown summary. Servers
are declared in a JSON file so no host, key path or binary location is baked
into the repo:

    [
      {"name": "fast-mcp-ssh", "adapter": "fast", "target": "target",
       "cmd": ["fast-mcp-ssh", "--config", "/path/to/bench-hosts.toml"]},
      {"name": "mcp-ssh-manager", "adapter": "mgr", "target": "target",
       "cmd": ["node", "/path/to/mcp-ssh-manager/src/index.js"],
       "env": {"SSH_ENV_PATH": "/path/to/mgr.env"}},
      {"name": "ssh-mcp-server", "adapter": "fangjunjie", "target": "",
       "cmd": ["node", "/path/to/build/index.js", "--host", "10.0.0.1", "..."]}
    ]

`adapter` picks how a scenario maps onto that server's tool surface; add one to
ADAPTERS to bench another server.

Usage:
    python bench.py --servers servers.json --iterations 30 --output results/

Environment:
    OPENROUTER_API_KEY  required for token counting; skipped when absent
    OPENROUTER_MODEL    default 'deepseek/deepseek-chat'
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).parent))
from client import McpStdio

HEREDOC = "__EOF_BENCH__"


@dataclass
class Adapter:
    """Maps the three scenario kinds onto one server's tool surface."""

    exec_call: Callable[[str, str, int], tuple[str, dict] | None]
    write_call: Callable[[str, str, str], tuple[str, dict] | None]
    read_call: Callable[[str, str], tuple[str, dict] | None]


@dataclass
class ServerSpec:
    name: str
    cmd: list[str]
    adapter: Adapter
    target: str
    env: dict[str, str] | None = None


# --- fast-mcp-ssh: purpose-built tools for each kind ------------------------


def fast_exec(host: str, cmd: str, timeout: int):
    return ("exec", {"host": host, "cmd": cmd, "timeout": timeout})


def fast_wr(host: str, remote: str, content: str):
    return ("wr", {"host": host, "remote": remote, "content": content})


def fast_dn(host: str, remote: str):
    return ("dn", {"host": host, "remote": remote})


# --- mcp-ssh-manager: one exec tool, no inline write ------------------------


def mgr_exec(server: str, cmd: str, timeout: int):
    return ("ssh_execute", {"server": server, "command": cmd, "timeout": timeout})


def mgr_wr(server: str, remote: str, content: str):
    # No inline write tool: ssh_upload takes a local path, so a write costs a
    # full shell round-trip through a heredoc.
    return (
        "ssh_execute",
        {
            "server": server,
            "command": f"cat > {remote} <<'{HEREDOC}'\n{content}\n{HEREDOC}",
            "timeout": 10,
        },
    )


def mgr_dn(server: str, remote: str):
    return ("ssh_execute", {"server": server, "command": f"cat {remote}", "timeout": 10})


# --- @fangjunjie/ssh-mcp-server: a single execute-command tool --------------


def fj_exec(_server: str, cmd: str, timeout: int):
    return ("execute-command", {"cmdString": cmd, "timeout": timeout * 1000})


def fj_wr(_server: str, remote: str, content: str):
    return (
        "execute-command",
        {"cmdString": f"cat > {remote} <<'{HEREDOC}'\n{content}\n{HEREDOC}", "timeout": 10000},
    )


def fj_dn(_server: str, remote: str):
    return ("execute-command", {"cmdString": f"cat {remote}", "timeout": 10000})


ADAPTERS: dict[str, Adapter] = {
    "fast": Adapter(fast_exec, fast_wr, fast_dn),
    "mgr": Adapter(mgr_exec, mgr_wr, mgr_dn),
    "fangjunjie": Adapter(fj_exec, fj_wr, fj_dn),
}


@dataclass
class ScenarioRun:
    server: str
    scenario: str
    iter: int
    ms: float
    chars: int
    error: str | None = None


@dataclass
class ScenarioStats:
    server: str
    scenario: str
    runs: list[ScenarioRun] = field(default_factory=list)

    def stats(self) -> dict[str, float]:
        ok = [r for r in self.runs if r.error is None]
        if not ok:
            return {
                "n_ok": 0,
                "n_err": len(self.runs),
                "ms_p50": -1,
                "ms_p95": -1,
                "ms_min": -1,
                "ms_max": -1,
                "ms_mean": -1,
                "ms_stdev": -1,
                "chars_p50": -1,
                "chars_p95": -1,
                "chars_max": -1,
            }
        ms = sorted(r.ms for r in ok)
        chars = sorted(r.chars for r in ok)
        return {
            "n_ok": len(ok),
            "n_err": len(self.runs) - len(ok),
            "ms_p50": ms[len(ms) // 2],
            "ms_p95": ms[min(len(ms) - 1, int(len(ms) * 0.95))],
            "ms_min": ms[0],
            "ms_max": ms[-1],
            "ms_mean": statistics.mean(ms),
            "ms_stdev": statistics.stdev(ms) if len(ms) > 1 else 0.0,
            "chars_p50": chars[len(chars) // 2],
            "chars_p95": chars[min(len(chars) - 1, int(len(chars) * 0.95))],
            "chars_max": chars[-1],
        }


SCENARIOS = [
    # (key, description, kind, args)
    ("exec_trivial", "exec 'echo ok'", "exec", ("echo ok", 5)),
    ("exec_uname", "exec 'uname -a; whoami; pwd'", "exec", ("uname -a; whoami; pwd", 5)),
    ("exec_seq5000", "exec 'seq 1 5000' (~28 KB)", "exec", ("seq 1 5000", 10)),
    ("exec_lsetc", "exec 'ls -la /etc | head -100'", "exec", ("ls -la /etc | head -100", 10)),
    ("exec_stderr", "exec 'ls /nonexistent'", "exec", ("ls /nonexistent", 5)),
    ("exec_pipe", "exec 'cat /etc/passwd | wc -l'", "exec", ("cat /etc/passwd | wc -l", 5)),
    ("write_1k", "write 1 KB file", "write", ("1k",)),
    ("read_1k", "read 1 KB file", "read", ("1k",)),
]


def bench_remote_path(spec: ServerSpec) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in spec.name)
    return f"/tmp/bench-{safe}.txt"


def scenario_call(spec: ServerSpec, key: str) -> tuple[str, dict, int] | None:
    """Build (tool, args, client_timeout_s) for one scenario against one server."""
    _, _, kind, args = next(s for s in SCENARIOS if s[0] == key)
    if kind == "exec":
        cmd, timeout = args
        built = spec.adapter.exec_call(spec.target, cmd, timeout)
        return (*built, timeout + 10) if built else None
    if kind == "write":
        content = "x" * (1024 if args[0] == "1k" else 8192)
        built = spec.adapter.write_call(spec.target, bench_remote_path(spec), content)
        return (*built, 15) if built else None
    if kind == "read":
        built = spec.adapter.read_call(spec.target, bench_remote_path(spec))
        return (*built, 15) if built else None
    raise ValueError(f"unknown scenario kind {kind}")


def invoke_scenario(spec: ServerSpec, mcp: McpStdio, key: str, iteration: int) -> ScenarioRun:
    built = scenario_call(spec, key)
    if built is None:
        return ScenarioRun(spec.name, key, iteration, -1.0, 0, error="unsupported")
    tool, tool_args, client_timeout = built
    res = mcp.call(tool, tool_args, timeout_s=client_timeout)
    return ScenarioRun(
        spec.name, key, iteration, res.elapsed_ms, res.chars, error=res.text if res.is_error else None
    )


def cold_start(spec: ServerSpec) -> dict:
    samples = []
    for _ in range(3):
        t0 = time.perf_counter()
        mcp = McpStdio(spec.cmd, env=spec.env)
        mcp.initialize(client_name="bench-cold")
        samples.append((time.perf_counter() - t0) * 1000.0)
        mcp.close()
    return {
        "server": spec.name,
        "cold_ms_min": min(samples),
        "cold_ms_med": sorted(samples)[len(samples) // 2],
        "cold_ms_max": max(samples),
    }


def tool_surface(spec: ServerSpec) -> dict:
    """Tool count and raw size of the tools/list payload.

    Every client pays this on each session, before any work happens, so it is
    part of the cost of choosing a server.
    """
    mcp = McpStdio(spec.cmd, env=spec.env)
    try:
        mcp.initialize(client_name="bench-discover")
        rid = mcp.send("tools/list", {})
        msg = mcp.recv(rid, timeout_s=15)
        tools = msg.get("result", {}).get("tools", [])
        return {
            "server": spec.name,
            "n_tools": len(tools),
            "chars": len(json.dumps(tools, separators=(",", ":"))),
            "names": [t["name"] for t in tools],
        }
    finally:
        mcp.close()


def write_csv(out_dir: Path, all_runs: list[ScenarioRun]):
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "runs.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["server", "scenario", "iter", "ms", "chars", "error"])
        for r in all_runs:
            w.writerow([r.server, r.scenario, r.iter, f"{r.ms:.2f}", r.chars, r.error or ""])
    print(f"  wrote {csv_path}")


def write_summary(
    out_dir: Path,
    cold: list[dict],
    surfaces: list[dict],
    stats_by_pair: dict[tuple[str, str], ScenarioStats],
    iterations: int,
    extra: dict | None = None,
):
    extra = extra or {}
    md = ["# Benchmark", ""]
    md.append(f"- iterations per scenario: **{iterations}**")
    md.append(f"- target: {extra.get('target', '?')}")
    md.append(f"- bench client: {extra.get('bench_host', 'localhost')}")
    md.append("")

    md.append("## Tool surface (paid once per session, before any work)")
    md.append("")
    md.append("| server | tools | tools/list chars |")
    md.append("|---|---:|---:|")
    for s in surfaces:
        md.append(f"| {s['server']} | {s['n_tools']} | {s['chars']} |")
    md.append("")

    md.append("## Cold start (process spawn to first response)")
    md.append("")
    md.append("| server | min ms | median ms | max ms |")
    md.append("|---|---:|---:|---:|")
    for c in cold:
        md.append(
            f"| {c['server']} | {c['cold_ms_min']:.0f} | {c['cold_ms_med']:.0f} | {c['cold_ms_max']:.0f} |"
        )
    md.append("")

    scenarios = [s[0] for s in SCENARIOS]
    servers = sorted({k[0] for k in stats_by_pair})

    md.append("## Latency per scenario")
    md.append("")
    md.append("| scenario | server | n_ok | p50 ms | p95 ms | min ms | max ms | mean ms | stdev |")
    md.append("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    for sc in scenarios:
        for sv in servers:
            st = stats_by_pair.get((sv, sc))
            if not st:
                continue
            s = st.stats()
            md.append(
                f"| {sc} | {sv} | {s['n_ok']} | {s['ms_p50']:.1f} | {s['ms_p95']:.1f} | "
                f"{s['ms_min']:.1f} | {s['ms_max']:.1f} | {s['ms_mean']:.1f} | {s['ms_stdev']:.1f} |"
            )
    md.append("")

    md.append("## Response size (chars)")
    md.append("")
    md.append("| scenario | server | p50 chars | p95 chars | max chars |")
    md.append("|---|---|---:|---:|---:|")
    for sc in scenarios:
        for sv in servers:
            st = stats_by_pair.get((sv, sc))
            if not st:
                continue
            s = st.stats()
            md.append(f"| {sc} | {sv} | {s['chars_p50']} | {s['chars_p95']} | {s['chars_max']} |")
    md.append("")

    if extra.get("token_samples"):
        md.append("## Token counts on representative payloads")
        md.append("")
        md.append(f"Counted via OpenRouter ({extra.get('token_model', '?')}).")
        md.append("")
        md.append("| scenario | server | chars | tokens | chars/token |")
        md.append("|---|---|---:|---:|---:|")
        for sample in extra["token_samples"]:
            md.append(
                f"| {sample['scenario']} | {sample['server']} | {sample['chars']} | "
                f"{sample['tokens']} | {sample['ratio']:.2f} |"
            )
        md.append("")

    summary = out_dir / "summary.md"
    summary.write_text("\n".join(md), encoding="utf-8")
    print(f"  wrote {summary}")


def load_specs(path: Path) -> list[ServerSpec]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    specs = []
    for entry in raw:
        adapter = ADAPTERS.get(entry["adapter"])
        if adapter is None:
            raise SystemExit(f"unknown adapter '{entry['adapter']}' for {entry['name']}")
        specs.append(
            ServerSpec(
                name=entry["name"],
                cmd=entry["cmd"],
                adapter=adapter,
                target=entry.get("target", ""),
                env=entry.get("env"),
            )
        )
    return specs


def sample_tokens(specs: list[ServerSpec], stats_by_pair, extra: dict):
    try:
        from token_count import count_tokens_for_payloads
    except Exception as e:  # noqa: BLE001 - optional dependency path
        print(f"  token_count import failed: {e}")
        return
    print("\n=== token sampling ===")
    sample_data = []
    for spec in specs:
        mcp = McpStdio(spec.cmd, env=spec.env)
        try:
            mcp.initialize(client_name="bench-tok")
            for key in (s[0] for s in SCENARIOS):
                if (spec.name, key) not in stats_by_pair:
                    continue
                built = scenario_call(spec, key)
                if built is None:
                    continue
                tool, tool_args, client_timeout = built
                res = mcp.call(tool, tool_args, timeout_s=client_timeout)
                sample_data.append({"server": spec.name, "scenario": key, "text": res.text})
        except Exception as e:  # noqa: BLE001 - one server failing must not kill the run
            print(f"  token sample failed for {spec.name}: {e}")
        finally:
            mcp.close()
    extra["token_samples"] = count_tokens_for_payloads(sample_data)
    extra["token_model"] = os.environ.get("OPENROUTER_MODEL", "deepseek/deepseek-chat")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--servers", type=Path, required=True, help="JSON file describing the servers to bench")
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--output", type=Path, default=Path("results"))
    parser.add_argument("--label", default="", help="Target description written into the summary")
    parser.add_argument("--skip-tokens", action="store_true")
    args = parser.parse_args()

    specs = load_specs(args.servers)
    args.output.mkdir(parents=True, exist_ok=True)

    print("=== tool surface ===")
    surfaces = []
    for spec in specs:
        try:
            s = tool_surface(spec)
            print(f"  {spec.name}: {s['n_tools']} tools, {s['chars']} chars")
            surfaces.append(s)
        except Exception as e:  # noqa: BLE001
            print(f"  {spec.name}: discovery FAILED - {e}")

    print("\n=== cold start ===")
    cold = []
    for spec in specs:
        try:
            c = cold_start(spec)
            print(
                f"  {spec.name}: median {c['cold_ms_med']:.0f} ms "
                f"(min {c['cold_ms_min']:.0f}, max {c['cold_ms_max']:.0f})"
            )
            cold.append(c)
        except Exception as e:  # noqa: BLE001
            print(f"  {spec.name}: cold start FAILED - {e}")
            cold.append({"server": spec.name, "cold_ms_min": -1, "cold_ms_med": -1, "cold_ms_max": -1})

    print(f"\n=== {args.iterations} iterations per scenario ===")
    all_runs: list[ScenarioRun] = []
    stats_by_pair: dict[tuple[str, str], ScenarioStats] = {}
    for spec in specs:
        print(f"\n--- {spec.name} (target={spec.target or 'from cmdline'}) ---")
        mcp = McpStdio(spec.cmd, env=spec.env)
        try:
            mcp.initialize(client_name="bench")
            for key in (s[0] for s in SCENARIOS):
                t0 = time.perf_counter()
                stats = ScenarioStats(server=spec.name, scenario=key)
                for i in range(args.iterations):
                    try:
                        stats.runs.append(invoke_scenario(spec, mcp, key, i))
                    except Exception as e:  # noqa: BLE001
                        stats.runs.append(ScenarioRun(spec.name, key, i, -1.0, 0, error=str(e)))
                elapsed = time.perf_counter() - t0
                all_runs.extend(stats.runs)
                stats_by_pair[(spec.name, key)] = stats
                s = stats.stats()
                print(
                    f"  {key:18s} n_ok={s['n_ok']:2d} n_err={s['n_err']:2d} "
                    f"p50={s['ms_p50']:7.1f} p95={s['ms_p95']:7.1f}  "
                    f"chars_p50={s['chars_p50']}  ({elapsed:.1f}s)"
                )
        finally:
            mcp.close()

    write_csv(args.output, all_runs)

    extra = {"target": args.label, "bench_host": os.environ.get("BENCH_HOST", "")}
    if not args.skip_tokens and os.environ.get("OPENROUTER_API_KEY"):
        sample_tokens(specs, stats_by_pair, extra)

    write_summary(args.output, cold, surfaces, stats_by_pair, args.iterations, extra)
    print("\n[DONE]")


if __name__ == "__main__":
    main()
