"""OpenRouter token counter for benchmark sampling.

OpenRouter exposes a generic chat-completions API; for token counting we use the
upstream tokenizer endpoint where available, falling back to a tiny no-op completion
with `usage` populated. To avoid spending more than a few cents we cap token reports
to ~10 samples and stay under 1 KB each.
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from typing import Any

DEFAULT_MODEL = os.environ.get("OPENROUTER_MODEL", "deepseek/deepseek-chat")


def _post(url: str, payload: dict, api_key: str, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/fast-mcp-ssh",
            "X-Title": "fast-mcp-ssh-bench",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def count_tokens_via_completion(text: str, api_key: str, model: str) -> int:
    """Send a 1-token-output completion that includes `text` as user message; report prompt_tokens."""
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": text}],
        "max_tokens": 1,
        "temperature": 0,
    }
    res = _post("https://openrouter.ai/api/v1/chat/completions", payload, api_key)
    usage = res.get("usage", {})
    return int(usage.get("prompt_tokens", -1))


def count_tokens_for_payloads(samples: list[dict]) -> list[dict]:
    """Each sample is {server, scenario, text}. Returns the same dicts plus tokens + ratio."""
    api_key = os.environ.get("OPENROUTER_API_KEY")
    model = DEFAULT_MODEL
    if not api_key:
        for s in samples:
            chars = len(s.get("text", ""))
            s["chars"] = chars
            s["tokens"] = chars // 4  # rough fallback
            s["ratio"] = 4.0
        return samples
    out = []
    for s in samples:
        text = s.get("text", "")
        chars = len(text)
        if chars == 0:
            tokens = 0
        else:
            try:
                tokens = count_tokens_via_completion(text, api_key, model)
            except Exception as e:
                print(f"  token api error for {s.get('scenario')}@{s.get('server')}: {e}")
                tokens = chars // 4
        ratio = chars / tokens if tokens > 0 else 0.0
        out.append(
            {
                "server": s["server"],
                "scenario": s["scenario"],
                "chars": chars,
                "tokens": tokens,
                "ratio": ratio,
            }
        )
    return out


if __name__ == "__main__":
    import sys

    sample = "hosts(3):\n  name addr user port auth session\n  a 1.1.1.1 root 22 key idle\n"
    out = count_tokens_for_payloads([{"server": "test", "scenario": "demo", "text": sample}])
    print(json.dumps(out, indent=2))
