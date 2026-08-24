"""A single HTTP client for any OpenAI-compatible /v1/chat/completions
endpoint. The bundled local llama-server and a real remote OpenAI account
look identical from here — just a different base_url and api_key. Nothing
else in this codebase should know or care which one it's talking to.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


class LLMError(RuntimeError):
    pass


def chat_completion(
    base_url: str,
    messages: list[dict],
    *,
    model: str = "default",
    api_key: str | None = None,
    response_format: dict | None = None,
    timeout: float = 180.0,
) -> str:
    """Returns the assistant's reply text.

    180s default: a grammar-constrained structured completion from the
    bundled 3B model on CPU-only hardware can genuinely take over a minute
    once the model is already resident — measured directly, not guessed.
    Remote OpenAI-compatible calls finish far sooner in practice, so this
    errs toward "local mode never times out on a slow home server" rather
    than "remote mode fails fast."
    """
    payload: dict = {"model": model, "messages": messages}
    if response_format is not None:
        payload["response_format"] = response_format

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    request = urllib.request.Request(
        url=base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError) as exc:
        raise LLMError(f"could not reach LLM endpoint at {base_url}: {exc}") from exc

    try:
        return body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError(f"unexpected response shape from LLM endpoint: {body}") from exc


def test_connection(base_url: str, api_key: str | None = None, model: str = "default") -> bool:
    try:
        chat_completion(base_url, [{"role": "user", "content": "ping"}], model=model, api_key=api_key, timeout=10)
        return True
    except LLMError:
        return False
