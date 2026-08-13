"""Token counter for benchmark sampling, against any OpenAI-shaped endpoint.

Response size in characters is what the harness measures for free; what a model
actually pays for is tokens, and only a tokenizer knows the ratio. There is no
portable count-only endpoint, so this sends the payload as a prompt with a
one-token cap and reads `prompt_tokens` back out of `usage`. The completion is
discarded, which keeps the bill to the prompt side.

Point it anywhere with three environment variables:

    BENCH_TOKEN_API_KEY   required; without it the caller falls back to chars/4
    BENCH_TOKEN_BASE_URL  default https://api.deepseek.com
    BENCH_TOKEN_MODEL     default deepseek-v4-flash

`OPENROUTER_API_KEY` and `OPENROUTER_MODEL` are still read as fallbacks, since
that is what earlier runs used.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-flash"


def api_key() -> str | None:
    return os.environ.get("BENCH_TOKEN_API_KEY") or os.environ.get("OPENROUTER_API_KEY")


def base_url() -> str:
    url = os.environ.get("BENCH_TOKEN_BASE_URL")
    if url:
        return url.rstrip("/")
    # An OpenRouter key with no explicit base still reaches OpenRouter.
    if not os.environ.get("BENCH_TOKEN_API_KEY") and os.environ.get("OPENROUTER_API_KEY"):
        return "https://openrouter.ai/api/v1"
    return DEFAULT_BASE_URL


def model() -> str:
    return (
        os.environ.get("BENCH_TOKEN_MODEL")
        or os.environ.get("OPENROUTER_MODEL")
        or DEFAULT_MODEL
    )


def provider() -> str:
    """What to name in the summary, derived from the endpoint rather than guessed."""
    host = base_url().split("//", 1)[-1].split("/", 1)[0]
    return f"{host} ({model()})"


def _post(url: str, payload: dict, key: str, timeout: int = 60) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _prompt_tokens(text: str, key: str, model_id: str) -> int:
    """`prompt_tokens` for one request carrying `text` as the user message.

    The completion is capped at one token and thrown away. A reasoning model
    spends that budget on hidden tokens and returns empty content, which does
    not matter here: the prompt side is what is being read.
    """
    payload = {
        "model": model_id,
        "messages": [{"role": "user", "content": text}],
        "max_tokens": 1,
        "temperature": 0,
    }
    res = _post(f"{base_url()}/chat/completions", payload, key)
    return int(res.get("usage", {}).get("prompt_tokens", -1))


_overhead_cache: dict[tuple[str, str], int] = {}


def chat_overhead(key: str, model_id: str) -> int:
    """Tokens a request costs before any payload: the provider's chat template.

    DeepSeek bills ~85 of them, so a 74-character payload came back as 112
    "prompt tokens" and a ratio below 1. Measure the floor once and subtract it,
    otherwise every small response looks like it tokenizes worse than it does.
    """
    cached = _overhead_cache.get((base_url(), model_id))
    if cached is not None:
        return cached
    try:
        overhead = max(_prompt_tokens("", key, model_id), 0)
    except Exception:  # noqa: BLE001 - an endpoint may refuse an empty message
        overhead = 0
    _overhead_cache[(base_url(), model_id)] = overhead
    return overhead


def count_tokens_via_completion(text: str, key: str, model_id: str) -> int:
    """Tokens the payload itself costs, with the chat template subtracted."""
    total = _prompt_tokens(text, key, model_id)
    if total < 0:
        return -1
    return max(total - chat_overhead(key, model_id), 0)


def count_tokens_for_payloads(samples: list[dict]) -> list[dict]:
    """Each sample is {server, scenario, text}. Returns the same dicts plus tokens + ratio."""
    key = api_key()
    model_id = model()
    if not key:
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
                tokens = count_tokens_via_completion(text, key, model_id)
            except Exception as e:  # noqa: BLE001 - one sample must not kill the run
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
    sample = "hosts(3):\n  name addr user port auth session\n  a 1.1.1.1 root 22 key idle\n"
    print(f"endpoint: {provider()}")
    print(json.dumps(count_tokens_for_payloads([{"server": "test", "scenario": "demo", "text": sample}]), indent=2))
