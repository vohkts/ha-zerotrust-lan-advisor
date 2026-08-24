"""Starts the bundled llama-server, bound to loopback only — it's never
reachable from outside the container, only from this add-on's own web/
analysis process.

When the user has switched to a remote OpenAI-compatible endpoint, running
a local model would just burn RAM and CPU for nothing, so this idles
instead of exec'ing the server. s6 treats that as "still running", which is
correct — the service is deliberately doing nothing, not crash-looping.

Model selection: `-hf <repo>:<quant>` hands the download entirely to
llama-server's own Hugging Face resolver rather than this script guessing
at exact filenames, which drift between quantization releases. `LLAMA_CACHE`
redirects that download into /data so it survives container recreation
instead of being re-fetched on every restart.
"""
from __future__ import annotations

import os
import time

from app.config import load_config

_DEFAULT_HF_MODEL = "Qwen/Qwen2.5-3B-Instruct-GGUF:Q4_K_M"
_PORT = 8080

_running = True


def main() -> None:
    config = load_config()

    if config.llm_mode == "remote":
        while _running:
            time.sleep(3600)
        return

    config.models_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = config.models_dir / "hf-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    os.environ["LLAMA_CACHE"] = str(cache_dir)

    argv = [
        "llama-server",
        "--host", "127.0.0.1",
        "--port", str(_PORT),
        "-c", "4096",
        "-ngl", "0",
    ]

    if config.llm_model_path:
        argv += ["-m", str(config.models_dir / config.llm_model_path)]
    else:
        argv += ["-hf", _DEFAULT_HF_MODEL]

    os.execvp("llama-server", argv)


if __name__ == "__main__":
    main()
