"""Benchmark fast-mcp-ssh vs mcp-ssh-manager.

Runs a fixed set of scenarios against each MCP server N times, measures wall-clock
latency and response payload size, and emits CSV + a markdown summary.

Token counting via OpenRouter (deepseek by default) is applied to a representative
sample of payloads at the end of the run, not per call (cost optimization).

Usage:
    python bench.py --iterations 30 --output results/

Environment:
    OPENROUTER_API_KEY  required for token counting; if absent, char-based estimate is used
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
from client import McpStdio, CallResult


@dataclass
class ServerSpec:
    name: str
    cmd: list[str]
    env: dict[str, str] | None = None
    # Tool name + args builder for each scenario. Returns None if unsupported.
    exec_call: Callable[[str, str, int], tuple[str, dict] | None] = None  # type: ignore
    write_call: Callable[[str, str, str], tuple[str, dict] | None] = None  # type: ignore
    read_call: Callable[[str, str], tuple[str, dict] | None] = None  # type: ignore
    list_tools_after_init: bool = True


def fast_exec(host: str, cmd: str, timeout: int):
    return ("exec", {"host": host, "cmd": cmd, "timeout": timeout})


def fast_wr(host: str, remote: str, content: str):
    return ("wr", {"host": host, "remote": remote, "content": content})


def fast_dn(host: str, remote: str):
    return ("dn", {"host": host, "remote": remote})


def mgr_exec(server: str, cmd: str, timeout: int):
    # mcp-ssh-manager schema (per Proxmox usage notes): ssh_execute(server, command, timeout)
    return ("ssh_execute", {"server": server, "command": cmd, "timeout": timeout})


def mgr_wr(server: str, remote: str, content: str):
    # mcp-ssh-manager has no inline write tool; we fall back to ssh_execute "echo ... > path".
    return (
        "ssh_execute",
        {
            "server": server,
            "command": f"cat > {remote} <<'__EOF_BENCH__'\n{content}\n__EOF_BENCH__",
            "timeout": 10,
        },
    )


def mgr_dn(server: str, remote: str):
    return ("ssh_execute", {"server": server, "command": f"cat {remote}", "timeout": 10})


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
                "chars_p50": -1,
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
    # (key, description, target_host_or_server, builder_kind, args)
    ("exec_trivial", "exec 'echo ok'", "exec", ("echo ok", 5)),
    ("exec_uname", "exec 'uname -a; whoami; pwd'", "exec", ("uname -a; whoami; pwd", 5)),
    ("exec_seq5000", "exec 'seq 1 5000' (~28 KB)", "exec", ("seq 1 5000", 10)),
    ("exec_lsetc", "exec 'ls -la /etc | head -100'", "exec", ("ls -la /etc | head -100", 10)),
    ("exec_stderr", "exec 'ls /nonexistent'", "exec", ("ls /nonexistent", 5)),
    ("exec_pipe", "exec 'cat /etc/passwd | wc -l'", "exec", ("cat /etc/passwd | wc -l", 5)),
    ("write_1k", "write 1 KB file", "write", ("1k",)),
    ("read_1k", "read 1 KB file", "read", ("1k",)),
]


def run_scenario_against(
    spec: ServerSpec,
    target: str,
    scenario_key: str,
    iterations: int,
) -> ScenarioStats:
    stats = ScenarioStats(server=spec.name, scenario=scenario_key)
    for i in range(iterations):
        try:
            result = invoke_scenario(spec, target, scenario_key, iteration=i)
            stats.runs.append(result)
        except Exception as e:
            stats.runs.append(
                ScenarioRun(
                    server=spec.name,
                    scenario=scenario_key,
                    iter=i,
                    ms=-1.0,
                    chars=0,
                    error=str(e),
                )
            )
    return stats


def invoke_scenario(spec: ServerSpec, target: str, key: str, iteration: int) -> ScenarioRun:
    sc = next(s for s in SCENARIOS if s[0] == key)
    _, _, kind, args = sc
    mcp: McpStdio = spec._mcp  # type: ignore[attr-defined]
    if kind == "exec":
        cmd, timeout = args
        builder_call = spec.exec_call(target, cmd, timeout)
        if builder_call is None:
            return ScenarioRun(spec.name, key, iteration, -1.0, 0, error="unsupported")
        tool, tool_args = builder_call
        res = mcp.call(tool, tool_args, timeout_s=timeout + 10)
    elif kind == "write":
        size = args[0]
        content = "x" * (1024 if size == "1k" else 8192)
        remote = f"/tmp/bench-{spec.name}.txt"
        builder_call = spec.write_call(target, remote, content)
        if builder_call is None:
            return ScenarioRun(spec.name, key, iteration, -1.0, 0, error="unsupported")
        tool, tool_args = builder_call
        res = mcp.call(tool, tool_args, timeout_s=15)
    elif kind == "read":
        remote = f"/tmp/bench-{spec.name}.txt"
        builder_call = spec.read_call(target, remote)
        if builder_call is None:
            return ScenarioRun(spec.name, key, iteration, -1.0, 0, error="unsupported")
        tool, tool_args = builder_call
        res = mcp.call(tool, tool_args, timeout_s=15)
    else:
        raise ValueError(f"unknown scenario kind {kind}")
    err = res.text if res.is_error else None
    return ScenarioRun(spec.name, key, iteration, res.elapsed_ms, res.chars, error=err)


def cold_start(spec: ServerSpec) -> dict:
    samples = []
    for _ in range(3):
        t0 = time.monotonic()
        mcp = McpStdio(spec.cmd, env=spec.env)
        mcp.initialize(client_name="bench-cold")
        elapsed = (time.monotonic() - t0) * 1000.0
        samples.append(elapsed)
        mcp.close()
    return {
        "server": spec.name,
        "cold_ms_min": min(samples),
        "cold_ms_med": sorted(samples)[len(samples) // 2],
        "cold_ms_max": max(samples),
    }


def list_tools(spec: ServerSpec) -> list[str]:
    mcp = McpStdio(spec.cmd, env=spec.env)
    try:
        mcp.initialize(client_name="bench-discover")
        rid = mcp.send("tools/list", {})
        msg = mcp.recv(rid, timeout_s=10)
        return [t["name"] for t in msg.get("result", {}).get("tools", [])]
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
    stats_by_pair: dict[tuple[str, str], ScenarioStats],
    iterations: int,
    extra: dict | None = None,
):
    md = ["# Benchmark — fast-mcp-ssh vs mcp-ssh-manager", ""]
    md.append(f"- iterations per scenario: **{iterations}**")
    md.append(f"- target host alias: {extra.get('target') if extra else 'target'}")
    md.append(f"- bench host: {extra.get('bench_host') if extra else 'localhost'}")
    md.append("")
    md.append("## Cold start (process spawn → first response)")
    md.append("")
    md.append("| server | min ms | median ms | max ms |")
    md.append("|---|---:|---:|---:|")
    for c in cold:
        md.append(f"| {c['server']} | {c['cold_ms_min']:.0f} | {c['cold_ms_med']:.0f} | {c['cold_ms_max']:.0f} |")
    md.append("")

    scenarios = sorted({k[1] for k in stats_by_pair.keys()})
    servers = sorted({k[0] for k in stats_by_pair.keys()})

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

    if extra and extra.get("token_samples"):
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


def representative_samples(stats_by_pair: dict[tuple[str, str], ScenarioStats]) -> list[dict]:
    """Pick one payload per (server, scenario) for token counting — the median-length one."""
    out = []
    for (server, scenario), st in stats_by_pair.items():
        ok = [r for r in st.runs if r.error is None and r.chars > 0]
        if not ok:
            continue
        ok.sort(key=lambda r: r.chars)
        med_run = ok[len(ok) // 2]
        out.append(
            {"server": server, "scenario": scenario, "iter": med_run.iter, "chars": med_run.chars}
        )
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--output", type=Path, default=Path("results"))
    parser.add_argument(
        "--fast-target",
        default="target",
        help="hosts.toml alias for fast-mcp-ssh that points at the target host",
    )
    parser.add_argument(
        "--mgr-target",
        default="target",
        help="server name in mcp-ssh-manager's .env that points at the target host",
    )
    parser.add_argument("--fast-bin", default=os.environ.get("FAST_BIN"))
    parser.add_argument("--mgr-bin", default=os.environ.get("MGR_BIN"))
    parser.add_argument("--skip-tokens", action="store_true")
    args = parser.parse_args()

    if not args.fast_bin or not args.mgr_bin:
        print("missing --fast-bin or --mgr-bin (or env FAST_BIN / MGR_BIN)")
        sys.exit(2)

    fast_spec = ServerSpec(
        name="fast-mcp-ssh",
        cmd=[args.fast_bin],
        exec_call=fast_exec,
        write_call=fast_wr,
        read_call=fast_dn,
    )
    mgr_spec = ServerSpec(
        name="mcp-ssh-manager",
        cmd=args.mgr_bin.split(),  # may be e.g. 'node /path/to/dist/index.js' or just one path
        exec_call=mgr_exec,
        write_call=mgr_wr,
        read_call=mgr_dn,
    )
    targets = {"fast-mcp-ssh": args.fast_target, "mcp-ssh-manager": args.mgr_target}

    args.output.mkdir(parents=True, exist_ok=True)

    print("=== tool discovery ===")
    for spec in (fast_spec, mgr_spec):
        try:
            tools = list_tools(spec)
            print(f"  {spec.name}: {tools}")
        except Exception as e:
            print(f"  {spec.name}: discovery FAILED — {e}")

    print("\n=== cold start ===")
    cold = []
    for spec in (fast_spec, mgr_spec):
        try:
            c = cold_start(spec)
            print(f"  {spec.name}: median {c['cold_ms_med']:.0f} ms (min {c['cold_ms_min']:.0f}, max {c['cold_ms_max']:.0f})")
            cold.append(c)
        except Exception as e:
            print(f"  {spec.name}: cold start FAILED — {e}")
            cold.append({"server": spec.name, "cold_ms_min": -1, "cold_ms_med": -1, "cold_ms_max": -1})

    print(f"\n=== {args.iterations} iterations per scenario ===")
    all_runs: list[ScenarioRun] = []
    stats_by_pair: dict[tuple[str, str], ScenarioStats] = {}
    for spec in (fast_spec, mgr_spec):
        target = targets[spec.name]
        print(f"\n--- {spec.name} (target={target}) ---")
        spec._mcp = McpStdio(spec.cmd, env=spec.env)  # type: ignore[attr-defined]
        try:
            spec._mcp.initialize(client_name="bench")  # type: ignore[attr-defined]
            for sc in SCENARIOS:
                key = sc[0]
                t0 = time.monotonic()
                stats = run_scenario_against(spec, target, key, args.iterations)
                elapsed = time.monotonic() - t0
                all_runs.extend(stats.runs)
                stats_by_pair[(spec.name, key)] = stats
                s = stats.stats()
                print(
                    f"  {key:18s} n_ok={s['n_ok']:2d} n_err={s['n_err']:2d} "
                    f"p50={s['ms_p50']:7.1f} p95={s['ms_p95']:7.1f}  chars_p50={s['chars_p50']}  ({elapsed:.1f}s)"
                )
        finally:
            spec._mcp.close()  # type: ignore[attr-defined]

    write_csv(args.output, all_runs)

    extra = {"target": args.fast_target, "bench_host": os.environ.get("BENCH_HOST", "")}

    if not args.skip_tokens and os.environ.get("OPENROUTER_API_KEY"):
        try:
            from token_count import count_tokens_for_payloads
        except Exception as e:
            print(f"  token_count import failed: {e}")
            count_tokens_for_payloads = None  # type: ignore
        if count_tokens_for_payloads:
            samples = representative_samples(stats_by_pair)
            # we only have lengths recorded, not the actual payloads — recall once
            print("\n=== token sampling ===")
            sample_data = []
            for s in samples:
                spec = fast_spec if s["server"] == "fast-mcp-ssh" else mgr_spec
                target = targets[spec.name]
                spec._mcp = McpStdio(spec.cmd, env=spec.env)  # type: ignore[attr-defined]
                try:
                    spec._mcp.initialize(client_name="bench-tok")  # type: ignore[attr-defined]
                    res_run = invoke_scenario(spec, target, s["scenario"], iteration=999)
                    # we need actual text — re-invoke and grab .text; use the call helper:
                    sc = next(x for x in SCENARIOS if x[0] == s["scenario"])
                    _, _, kind, ar = sc
                    if kind == "exec":
                        cmd, timeout = ar
                        tool, ta = spec.exec_call(target, cmd, timeout)
                    elif kind == "write":
                        content = "x" * 1024
                        tool, ta = spec.write_call(target, f"/tmp/bench-{spec.name}.txt", content)
                    else:
                        tool, ta = spec.read_call(target, f"/tmp/bench-{spec.name}.txt")
                    res = spec._mcp.call(tool, ta, timeout_s=20)  # type: ignore[attr-defined]
                    sample_data.append({"server": s["server"], "scenario": s["scenario"], "text": res.text})
                except Exception as e:
                    print(f"  token sample fetch failed for {s}: {e}")
                finally:
                    spec._mcp.close()  # type: ignore[attr-defined]
            tok = count_tokens_for_payloads(sample_data)
            extra["token_samples"] = tok
            extra["token_model"] = os.environ.get("OPENROUTER_MODEL", "deepseek/deepseek-chat")

    write_summary(args.output, cold, stats_by_pair, args.iterations, extra)
    print("\n[DONE]")


if __name__ == "__main__":
    main()
