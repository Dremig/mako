from __future__ import annotations

import json
import math
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

_EMBED_MODEL_CACHE: dict[str, str] = {}


def load_dotenv(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def _env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _tls_mode() -> str:
    if _env_truthy("OPENAI_INSECURE_TLS"):
        return "insecure"
    mode = os.getenv("OPENAI_TLS_MODE", "auto").strip().lower()
    return mode if mode in {"auto", "strict", "insecure"} else "auto"


def _is_official_openai_host(base_url: str) -> bool:
    host = (urllib.parse.urlparse(base_url).hostname or "").lower()
    return host in {"api.openai.com", "openai.com"}


def _ssl_context_for(base_url: str, allow_insecure_fallback: bool = False) -> ssl.SSLContext | None:
    mode = _tls_mode()
    if mode == "insecure":
        return ssl._create_unverified_context()
    if allow_insecure_fallback and mode == "auto" and not _is_official_openai_host(base_url):
        print(f"[warn] TLS certificate verification failed for {base_url}; retrying with insecure TLS")
        return ssl._create_unverified_context()
    return None


def post_json(base_url: str, path: str, api_key: str, payload: dict[str, Any], timeout: int = 120) -> dict[str, Any]:
    url = base_url.rstrip("/") + path
    req = urllib.request.Request(
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        context = _ssl_context_for(base_url)
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {detail[:1000]}") from exc
    except urllib.error.URLError as exc:
        if "CERTIFICATE_VERIFY_FAILED" in str(exc) and _tls_mode() == "auto":
            try:
                context = _ssl_context_for(base_url, allow_insecure_fallback=True)
                with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as retry_exc:
                detail = retry_exc.read().decode("utf-8", errors="ignore")
                raise RuntimeError(f"HTTP {retry_exc.code} from {url}: {detail[:1000]}") from retry_exc
            except urllib.error.URLError as retry_exc:
                raise RuntimeError(f"Network error for {url}: {retry_exc}") from retry_exc
        raise RuntimeError(f"Network error for {url}: {exc}") from exc


def _is_unsupported_embedding_error(message: str) -> bool:
    text = message.lower()
    return "operationnotsupported" in text or "does not work with the specified model" in text


def _embedding_fallback_models(requested_model: str) -> list[str]:
    ordered = [requested_model, "text-embedding-3-small", "text-embedding-3-large", "text-embedding-ada-002"]
    seen: set[str] = set()
    out: list[str] = []
    for model in ordered:
        model = model.strip()
        if model and model not in seen:
            seen.add(model)
            out.append(model)
    return out


def embed_texts(base_url: str, api_key: str, model: str, texts: list[str]) -> list[list[float]]:
    cache_key = f"{base_url.rstrip('/')}::{model}"
    candidates = _embedding_fallback_models(_EMBED_MODEL_CACHE.get(cache_key, model))
    last_error: RuntimeError | None = None

    for candidate in candidates:
        payload = {
            "model": candidate,
            "input": texts,
        }
        try:
            data = post_json(base_url, "/embeddings", api_key, payload)
            _EMBED_MODEL_CACHE[cache_key] = candidate
            if candidate != model:
                print(f"[embed] fallback model selected: {candidate}")
            return [item["embedding"] for item in data["data"]]
        except RuntimeError as exc:
            last_error = exc
            if candidate == candidates[-1] or not _is_unsupported_embedding_error(str(exc)):
                raise
            continue

    if last_error is not None:
        raise last_error
    raise RuntimeError("Embedding request failed without a specific error")


def chat_completion(
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict[str, str]],
    temperature: float = 0.2,
) -> str:
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    data = post_json(base_url, "/chat/completions", api_key, payload)
    return data["choices"][0]["message"]["content"]


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return -1.0
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for i in range(len(a)):
        ai = a[i]
        bi = b[i]
        dot += ai * bi
        norm_a += ai * ai
        norm_b += bi * bi
    if norm_a <= 0.0 or norm_b <= 0.0:
        return -1.0
    return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))
