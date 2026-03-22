from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from common import chat_completion, cosine_similarity, embed_texts, load_dotenv, require_env


TOKEN_RE = re.compile(r"[A-Za-z0-9_./:%?=&+-]+|[\u4e00-\u9fff]")
FLAG_RE = re.compile(r"(flag|ctf)\{[^{}\n]{1,200}\}", re.IGNORECASE)
DEFAULT_WORDLISTS = {
    "path-small": "repos/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt",
    "param-names": "repos/SecLists/Discovery/Web-Content/url-params_from-top-55-most-popular-apps.txt",
    "ssti": "repos/SecLists/Fuzzing/template-engines-expression.txt",
    "xss": "repos/SecLists/Fuzzing/URI-XSS.fuzzdb.txt",
    "cmdi": "repos/SecLists/Fuzzing/command-injection-commix.txt",
}


def tokenize(text: str) -> list[str]:
    return [m.group(0).lower() for m in TOKEN_RE.finditer(text)]


def normalize_minmax(scores: list[float]) -> list[float]:
    if not scores:
        return []
    lo = min(scores)
    hi = max(scores)
    if hi <= lo:
        return [0.0 for _ in scores]
    return [(x - lo) / (hi - lo) for x in scores]


def bm25_scores(query: str, docs: list[dict[str, Any]], k1: float = 1.5, b: float = 0.75) -> list[float]:
    q_terms = tokenize(query)
    if not q_terms:
        return [0.0 for _ in docs]
    qf = Counter(q_terms)

    tf_list: list[Counter[str]] = []
    df: Counter[str] = Counter()
    dl_list: list[int] = []
    for d in docs:
        terms = tokenize(d["text"])
        tf = Counter(terms)
        tf_list.append(tf)
        dl = sum(tf.values())
        dl_list.append(dl)
        for t in tf:
            df[t] += 1

    n = len(docs)
    avgdl = (sum(dl_list) / n) if n > 0 else 1.0
    if avgdl <= 0:
        avgdl = 1.0

    scores: list[float] = []
    for tf, dl in zip(tf_list, dl_list):
        norm = k1 * (1 - b + b * (dl / avgdl))
        s = 0.0
        for term, term_qf in qf.items():
            freq = tf.get(term, 0)
            if freq <= 0:
                continue
            term_df = df.get(term, 0)
            idf = max(0.0, (n - term_df + 0.5) / (term_df + 0.5))
            idf = 0.0 if idf <= 0 else __import__("math").log(1 + idf)
            s += term_qf * (idf * ((freq * (k1 + 1)) / (freq + norm)))
        scores.append(s)
    return scores


def load_index(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def hybrid_retrieve(
    query: str,
    docs: list[dict[str, Any]],
    top_k: int,
    mode: str,
    alpha: float,
    base_url: str,
    api_key: str,
    embed_model: str,
) -> list[dict[str, Any]]:
    if not docs:
        return []

    alpha = max(0.0, min(1.0, alpha))
    dense_raw = [0.0 for _ in docs]
    if mode in {"dense", "hybrid"}:
        q_vec = embed_texts(base_url=base_url, api_key=api_key, model=embed_model, texts=[query])[0]
        dense_raw = [cosine_similarity(q_vec, d["embedding"]) for d in docs]

    bm25_raw = [0.0 for _ in docs]
    if mode in {"bm25", "hybrid"}:
        bm25_raw = bm25_scores(query, docs)

    dense_norm = normalize_minmax(dense_raw)
    bm25_norm = normalize_minmax(bm25_raw)

    scored: list[dict[str, Any]] = []
    for i, d in enumerate(docs):
        if mode == "dense":
            final_score = dense_raw[i]
        elif mode == "bm25":
            final_score = bm25_raw[i]
        else:
            final_score = alpha * dense_norm[i] + (1.0 - alpha) * bm25_norm[i]
        scored.append(
            {
                "score": final_score,
                "dense_score": dense_raw[i],
                "bm25_score": bm25_raw[i],
                **d,
            }
        )
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[: max(1, top_k)]


class SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "a" and attr.get("href"):
            self.links.append(attr["href"])
        elif tag == "form":
            self._current_form = {
                "method": (attr.get("method") or "GET").upper(),
                "action": attr.get("action") or "",
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag in {"input", "textarea", "select"}:
            if self._current_form is not None:
                name = attr.get("name", "")
                if name:
                    self._current_form["inputs"].append(name)
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


@dataclass
class HttpResult:
    method: str
    url: str
    status: int
    content_type: str
    body_len: int
    body_preview: str
    headers: dict[str, str]
    title: str
    flag_matches: list[str]
    error: str = ""


def http_request(
    method: str,
    url: str,
    params: dict[str, str] | None,
    headers: dict[str, str] | None,
    body: str | None,
    content_type: str,
    timeout: int,
) -> HttpResult:
    method = method.upper()
    params = params or {}
    headers = headers or {}
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    qs.extend(list(params.items()))
    query = urllib.parse.urlencode(qs)
    final_url = urllib.parse.urlunparse(parsed._replace(query=query))

    data_bytes: bytes | None = None
    send_headers = {"User-Agent": "ctf-rag-agent/0.1", **headers}
    if method in {"POST", "PUT", "PATCH"}:
        if content_type == "json":
            send_headers["Content-Type"] = "application/json"
            data_bytes = (body or "{}").encode("utf-8")
        elif content_type == "form":
            send_headers["Content-Type"] = "application/x-www-form-urlencoded"
            if body and "=" in body:
                data_bytes = body.encode("utf-8")
            else:
                data_bytes = urllib.parse.urlencode(params).encode("utf-8")
        else:
            send_headers["Content-Type"] = "text/plain"
            data_bytes = (body or "").encode("utf-8")

    req = urllib.request.Request(final_url, data=data_bytes, headers=send_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.getcode()
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
    except Exception as exc:
        return HttpResult(
            method=method,
            url=final_url,
            status=0,
            content_type="",
            body_len=0,
            body_preview="",
            headers={},
            title="",
            flag_matches=[],
            error=str(exc),
        )

    text = raw.decode("utf-8", errors="ignore")
    preview = text[:1800]
    content_type_resp = resp_headers.get("content-type", "")
    parser = SurfaceParser()
    if "html" in content_type_resp.lower() or "<html" in preview.lower():
        try:
            parser.feed(text[:200000])
        except Exception:
            pass
    flags = FLAG_RE.findall(text)
    expanded_flags = [m.group(0) for m in FLAG_RE.finditer(text)]

    return HttpResult(
        method=method,
        url=final_url,
        status=status,
        content_type=content_type_resp,
        body_len=len(text),
        body_preview=preview,
        headers={
            "server": resp_headers.get("server", ""),
            "content-type": content_type_resp,
            "location": resp_headers.get("location", ""),
            "set-cookie": resp_headers.get("set-cookie", "")[:300],
        },
        title=parser.title[:160],
        flag_matches=expanded_flags if expanded_flags else [],
    )


def curl_request(
    method: str,
    url: str,
    params: dict[str, str] | None,
    headers: dict[str, str] | None,
    body: str | None,
    content_type: str,
    timeout: int,
) -> HttpResult:
    method = method.upper()
    params = params or {}
    headers = headers or {}
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    qs.extend(list(params.items()))
    final_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))

    cmd = [
        "curl",
        "-sS",
        "--max-time",
        str(timeout),
        "-X",
        method,
        final_url,
        "-w",
        "\n__CURL_META__%{http_code}\t%{content_type}\t%{url_effective}",
    ]
    merged_headers = {"User-Agent": "ctf-rag-agent/0.1", **headers}
    for k, v in merged_headers.items():
        cmd.extend(["-H", f"{k}: {v}"])

    if method in {"POST", "PUT", "PATCH"}:
        if content_type == "json":
            cmd.extend(["-H", "Content-Type: application/json"])
            cmd.extend(["--data-raw", body or "{}"])
        elif content_type == "form":
            cmd.extend(["-H", "Content-Type: application/x-www-form-urlencoded"])
            if body and "=" in body:
                cmd.extend(["--data-raw", body])
            else:
                cmd.extend(["--data-raw", urllib.parse.urlencode(params)])
        elif content_type == "text":
            cmd.extend(["-H", "Content-Type: text/plain"])
            cmd.extend(["--data-raw", body or ""])

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 3, check=False)
    except Exception as exc:
        return HttpResult(
            method=method,
            url=final_url,
            status=0,
            content_type="",
            body_len=0,
            body_preview="",
            headers={},
            title="",
            flag_matches=[],
            error=str(exc),
        )

    out = proc.stdout.decode("utf-8", errors="ignore")
    marker = "\n__CURL_META__"
    idx = out.rfind(marker)
    if idx >= 0:
        body_text = out[:idx]
        meta = out[idx + len(marker) :].strip().split("\t")
    else:
        body_text = out
        meta = []

    status = 0
    ctype = ""
    effective_url = final_url
    if len(meta) >= 1:
        try:
            status = int(meta[0])
        except ValueError:
            status = 0
    if len(meta) >= 2:
        ctype = meta[1]
    if len(meta) >= 3:
        effective_url = meta[2]

    parser = SurfaceParser()
    preview = body_text[:1800]
    if "html" in ctype.lower() or "<html" in preview.lower():
        try:
            parser.feed(body_text[:200000])
        except Exception:
            pass
    expanded_flags = [m.group(0) for m in FLAG_RE.finditer(body_text)]
    err = ""
    if proc.returncode != 0 and status == 0:
        err = proc.stderr.decode("utf-8", errors="ignore")[:200]

    return HttpResult(
        method=method,
        url=effective_url,
        status=status,
        content_type=ctype,
        body_len=len(body_text),
        body_preview=preview,
        headers={
            "server": "",
            "content-type": ctype,
            "location": "",
            "set-cookie": "",
        },
        title=parser.title[:160],
        flag_matches=expanded_flags if expanded_flags else [],
        error=err,
    )


def execute_request(
    tool: str,
    method: str,
    url: str,
    params: dict[str, str] | None,
    headers: dict[str, str] | None,
    body: str | None,
    content_type: str,
    timeout: int,
) -> HttpResult:
    tool = tool.lower().strip()
    if tool == "auto":
        # Prefer curl for better parity with real pentest workflows.
        tool = "curl"
    if tool == "curl":
        return curl_request(method, url, params, headers, body, content_type, timeout)
    return http_request(method, url, params, headers, body, content_type, timeout)


def resolve_url(target: str, candidate_url: str) -> str:
    candidate_url = candidate_url.strip()
    if not candidate_url:
        return target
    if candidate_url.startswith("/"):
        return urllib.parse.urljoin(target, candidate_url)
    if candidate_url.startswith(("http://", "https://")):
        return candidate_url
    return urllib.parse.urljoin(target + ("" if target.endswith("/") else "/"), candidate_url)


def resolve_wordlist(root: Path, wordlist_spec: str) -> Path:
    spec = (wordlist_spec or "").strip()
    if not spec:
        spec = "path-small"
    if spec in DEFAULT_WORDLISTS:
        return (root / DEFAULT_WORDLISTS[spec]).resolve()
    p = Path(spec)
    if not p.is_absolute():
        p = (root / p).resolve()
    return p


def load_wordlist(path: Path, max_candidates: int) -> list[str]:
    if not path.exists():
        return []
    items: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if len(s) > 200:
            continue
        items.append(s)
        if len(items) >= max(1, max_candidates):
            break
    return items


def fuzz_execute(
    root: Path,
    tool: str,
    target: str,
    baseline: HttpResult,
    fuzz_obj: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    kind = str(fuzz_obj.get("kind", "path")).strip().lower()
    wordlist_name = str(fuzz_obj.get("wordlist", "path-small")).strip() or "path-small"
    max_candidates = int(fuzz_obj.get("max_candidates", 40))
    max_candidates = max(1, min(500, max_candidates))
    method = str(fuzz_obj.get("method", "GET")).upper()
    url = resolve_url(target, str(fuzz_obj.get("url", target)))
    target_param = str(fuzz_obj.get("param", "q")).strip() or "q"
    static_params_obj = fuzz_obj.get("static_params", {})
    static_params = {str(k): str(v) for k, v in static_params_obj.items()} if isinstance(static_params_obj, dict) else {}

    wordlist_path = resolve_wordlist(root, wordlist_name)
    payloads = load_wordlist(wordlist_path, max_candidates=max_candidates)
    if not payloads:
        payloads = ["admin", "login", "debug", "test", "backup", "index", "..%2f", "{{7*7}}", "' OR '1'='1"]
        payloads = payloads[:max_candidates]

    results: list[dict[str, Any]] = []
    found_flag = ""
    for payload in payloads:
        params = dict(static_params)
        req_url = url
        body = ""
        content_type = "none"
        if kind == "path":
            frag = payload.strip().lstrip("/")
            req_url = urllib.parse.urljoin(url.rstrip("/") + "/", urllib.parse.quote(frag, safe="/%"))
        elif kind == "param-name":
            params[payload] = "1"
        else:
            params[target_param] = payload

        resp = execute_request(
            tool=tool,
            method=method,
            url=req_url,
            params=params,
            headers={},
            body=body,
            content_type=content_type,
            timeout=timeout,
        )
        signal_score = 0
        signals: list[str] = []
        if resp.status != baseline.status:
            signal_score += 2
            signals.append(f"status:{baseline.status}->{resp.status}")
        dlen = resp.body_len - baseline.body_len
        if abs(dlen) > 60:
            signal_score += 1
            signals.append(f"len:{dlen:+d}")
        if resp.title and resp.title != baseline.title:
            signal_score += 1
            signals.append("title-change")
        if resp.flag_matches:
            signal_score += 10
            found_flag = resp.flag_matches[0]
            signals.append(f"flag:{found_flag}")

        results.append(
            {
                "payload": payload,
                "url": resp.url,
                "status": resp.status,
                "body_len": resp.body_len,
                "title": resp.title,
                "signal_score": signal_score,
                "signal": ";".join(signals) if signals else "none",
            }
        )
        if found_flag:
            break

    results.sort(key=lambda x: (x["signal_score"], abs(x["body_len"] - baseline.body_len)), reverse=True)
    top = results[: min(8, len(results))]
    return {
        "kind": kind,
        "tool": tool,
        "wordlist": str(wordlist_path),
        "tested": len(results),
        "top_results": top,
        "found_flag": found_flag,
    }


def request_fingerprint(
    tool: str,
    method: str,
    url: str,
    params: dict[str, str],
    body: str,
    content_type: str,
) -> str:
    key_obj = {
        "action": "request",
        "tool": tool,
        "method": method,
        "url": url,
        "params": params,
        "body": body[:120],
        "content_type": content_type,
    }
    return json.dumps(key_obj, ensure_ascii=False, sort_keys=True)


def fuzz_fingerprint(tool: str, fuzz_obj: dict[str, Any]) -> str:
    key_obj = {
        "action": "fuzz",
        "tool": tool,
        "kind": str(fuzz_obj.get("kind", "path")),
        "url": str(fuzz_obj.get("url", "")),
        "method": str(fuzz_obj.get("method", "GET")),
        "param": str(fuzz_obj.get("param", "")),
        "wordlist": str(fuzz_obj.get("wordlist", "")),
        "max_candidates": int(fuzz_obj.get("max_candidates", 40)),
        "static_params": fuzz_obj.get("static_params", {}),
    }
    return json.dumps(key_obj, ensure_ascii=False, sort_keys=True)


def short_history(history: list[dict[str, Any]], limit: int = 8) -> str:
    if not history:
        return "none"
    rows = []
    for h in history[-limit:]:
        if h.get("action") == "fuzz":
            rows.append(
                f"step={h['step']} phase={h.get('phase','')} action=fuzz tested={h.get('tested',0)} "
                f"best={h.get('best_signal','none')[:80]}"
            )
            continue
        rows.append(
            f"step={h['step']} phase={h.get('phase','')} status={h.get('status',0)} "
            f"url={h.get('url','')} signal={h.get('signal','')[:120]}"
        )
    return "\n".join(rows)


def extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise RuntimeError(f"Model output is not valid JSON: {text[:400]}")
    return json.loads(match.group(0))


def ensure_same_host(base_url: str, candidate_url: str) -> None:
    base_host = urllib.parse.urlparse(base_url).hostname or ""
    cand_host = urllib.parse.urlparse(candidate_url).hostname or ""
    if base_host and cand_host and base_host.lower() != cand_host.lower():
        raise RuntimeError(f"Blocked cross-host request: {cand_host} != {base_host}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Blackbox web CTF agent with RAG + iterative solving")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--env", type=Path, default=Path(".env"))
    parser.add_argument("--index", type=Path, default=Path("rag_data/index.jsonl"))
    parser.add_argument("--target", type=str, required=True, help="target URL")
    parser.add_argument("--objective", type=str, default="Find exploitable web vuln and retrieve flag")
    parser.add_argument("--hint", type=str, default="blackbox web CTF")
    parser.add_argument("--max-steps", type=int, default=12)
    parser.add_argument("--top-k", type=int, default=8)
    parser.add_argument("--mode", type=str, default="hybrid", choices=["dense", "bm25", "hybrid"])
    parser.add_argument("--alpha", type=float, default=0.65)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--request-tool", type=str, default="auto", choices=["auto", "http", "curl"])
    parser.add_argument("--allow-external-host", action="store_true")
    parser.add_argument("--out", type=Path, default=Path("rag_data/agent_last_run.json"))
    args = parser.parse_args()

    root = args.root.resolve()
    load_dotenv((root / args.env).resolve())

    api_key = require_env("OPENAI_API_KEY")
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").strip()
    chat_model = os.getenv("OPENAI_AGENT_MODEL", os.getenv("OPENAI_CHAT_MODEL", "gpt-5.2")).strip()
    embed_model = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small").strip()

    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    index_path = (root / args.index).resolve()
    docs = load_index(index_path)

    print(f"[agent] target={target}")
    print(f"[agent] model={chat_model} retrieval={args.mode} docs={len(docs)}")

    baseline = execute_request(
        tool=args.request_tool,
        method="GET",
        url=target,
        params={},
        headers={},
        body=None,
        content_type="none",
        timeout=args.timeout,
    )
    if baseline.error:
        raise RuntimeError(f"Baseline request failed: {baseline.error}")

    parser_surface = SurfaceParser()
    try:
        parser_surface.feed(baseline.body_preview)
    except Exception:
        pass
    parsed_target = urllib.parse.urlparse(target)
    initial_params = dict(urllib.parse.parse_qsl(parsed_target.query, keep_blank_values=True))

    history: list[dict[str, Any]] = []
    action_seen: dict[str, int] = {}
    done = False
    final_report = ""
    found_flag = ""

    for step in range(1, max(1, args.max_steps) + 1):
        retrieval_query = (
            f"{args.objective}\n{args.hint}\n"
            f"title:{baseline.title}\n"
            f"history:{short_history(history)}\n"
        )
        try:
            hits = hybrid_retrieve(
                query=retrieval_query,
                docs=docs,
                top_k=args.top_k,
                mode=args.mode,
                alpha=args.alpha,
                base_url=base_url,
                api_key=api_key,
                embed_model=embed_model,
            ) if docs else []
        except Exception as exc:
            print(f"[warn] retrieval degraded to empty context: {exc}")
            hits = []

        context = "\n\n".join(
            [
                f"[score={h['score']:.4f}] {h['path']}#chunk{h['chunk_index']}\n{h['text'][:900]}"
                for h in hits
            ]
        )
        if not context:
            context = "no retrieval context"

        planner_prompt = (
            "You are a Codex-style CTF blackbox web agent.\n"
            "Be direct and execution-first: short plan, one concrete action each step, then observe and iterate.\n"
            "Workflow: recon -> hypothesis -> probe -> exploit -> verify.\n"
            "Never repeat an action that already failed unless you explicitly changed a key variable.\n"
            f"Available tools: http, curl, fuzz (default request tool: {args.request_tool}).\n"
            "Return ONLY valid JSON with this schema:\n"
            "{"
            "\"analysis\":\"1-2 short sentences\","
            "\"confidence\":0.0,"
            "\"decision\":\"request|fuzz|done\","
            "\"phase\":\"recon|hypothesis|probe|exploit|verify|done\","
            "\"hypothesis\":\"...\","
            "\"request\":{"
            "\"tool\":\"auto|http|curl\","
            "\"method\":\"GET|POST\","
            "\"url\":\"absolute-or-relative-url\","
            "\"params\":{\"k\":\"v\"},"
            "\"headers\":{\"k\":\"v\"},"
            "\"content_type\":\"none|form|json|text\","
            "\"body\":\"optional-body-string\""
            "},"
            "\"fuzz\":{"
            "\"kind\":\"path|param-value|param-name\","
            "\"tool\":\"auto|http|curl\","
            "\"url\":\"absolute-or-relative-url\","
            "\"method\":\"GET|POST\","
            "\"param\":\"parameter-name-if-needed\","
            "\"wordlist\":\"path-small|param-names|ssti|xss|cmdi|relative/path.txt\","
            "\"max_candidates\":40,"
            "\"static_params\":{\"k\":\"v\"}"
            "},"
            "\"success_signal\":\"what indicates success\","
            "\"next_if_fail\":\"what to try next\""
            "}\n"
            "If solved, set decision=done and put concise final finding in hypothesis."
        )
        user_prompt = (
            f"Target: {target}\n"
            f"Objective: {args.objective}\n"
            f"Hint: {args.hint}\n"
            f"Step: {step}/{args.max_steps}\n"
            f"Baseline: status={baseline.status} title={baseline.title} len={baseline.body_len}\n"
            f"Initial query params: {json.dumps(initial_params, ensure_ascii=False)}\n"
            f"Surface links(sample): {json.dumps(parser_surface.links[:20], ensure_ascii=False)}\n"
            f"Surface forms(sample): {json.dumps(parser_surface.forms[:10], ensure_ascii=False)}\n"
            f"Recent history:\n{short_history(history)}\n\n"
            f"Retrieved context:\n{context}\n"
        )

        raw_plan = chat_completion(
            base_url=base_url,
            api_key=api_key,
            model=chat_model,
            messages=[
                {"role": "system", "content": planner_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
        )
        plan = extract_json(raw_plan)

        analysis = str(plan.get("analysis", "")).strip()
        confidence = float(plan.get("confidence", 0.0) or 0.0)
        decision = str(plan.get("decision", "request")).lower()
        phase = str(plan.get("phase", "probe"))
        hypothesis = str(plan.get("hypothesis", ""))
        if analysis:
            print(f"[step {step}] plan: {analysis[:180]} (conf={confidence:.2f})")
        if decision == "done":
            done = True
            final_report = hypothesis or "Agent decided done."
            break

        success_signal = str(plan.get("success_signal", ""))
        next_if_fail = str(plan.get("next_if_fail", ""))
        if decision == "fuzz":
            fuzz_obj = plan.get("fuzz") or {}
            fuzz_tool = str(fuzz_obj.get("tool", args.request_tool)).strip().lower() or args.request_tool
            fuzz_url = resolve_url(target, str(fuzz_obj.get("url", target)))
            if not args.allow_external_host:
                ensure_same_host(target, fuzz_url)
            fuzz_obj["url"] = fuzz_url
            fuzz_key = fuzz_fingerprint(fuzz_tool, fuzz_obj)
            action_seen[fuzz_key] = action_seen.get(fuzz_key, 0) + 1
            if action_seen[fuzz_key] > 2:
                item = {
                    "step": step,
                    "phase": phase,
                    "action": "fuzz",
                    "hypothesis": hypothesis,
                    "analysis": analysis,
                    "confidence": confidence,
                    "tool": fuzz_tool,
                    "signal": "skipped-duplicate-fuzz-action",
                }
                history.append(item)
                print(f"[step {step}] {phase} FUZZ skipped duplicate action")
                time.sleep(0.2)
                continue

            fuzz_summary = fuzz_execute(
                root=root,
                tool=fuzz_tool,
                target=target,
                baseline=baseline,
                fuzz_obj=fuzz_obj,
                timeout=args.timeout,
            )
            best_signal = fuzz_summary["top_results"][0]["signal"] if fuzz_summary["top_results"] else "none"
            item = {
                "step": step,
                "phase": phase,
                "action": "fuzz",
                "hypothesis": hypothesis,
                "analysis": analysis,
                "confidence": confidence,
                "success_signal": success_signal,
                "next_if_fail": next_if_fail,
                "tool": fuzz_summary["tool"],
                "fuzz_kind": fuzz_summary["kind"],
                "wordlist": fuzz_summary["wordlist"],
                "tested": fuzz_summary["tested"],
                "best_signal": best_signal,
                "top_results": fuzz_summary["top_results"],
            }
            history.append(item)
            print(
                f"[step {step}] {phase} FUZZ tool={fuzz_summary['tool']} "
                f"kind={fuzz_summary['kind']} tested={fuzz_summary['tested']} best={best_signal}"
            )
            if fuzz_summary["found_flag"]:
                found_flag = fuzz_summary["found_flag"]
                done = True
                final_report = f"Flag pattern found during fuzz: {found_flag}"
            if done:
                break
            time.sleep(0.2)
            continue

        req = plan.get("request") or {}
        req_tool = str(req.get("tool", args.request_tool)).strip().lower() or args.request_tool
        method = str(req.get("method", "GET")).upper()
        candidate_url = resolve_url(target, str(req.get("url", target)).strip() or target)
        if not args.allow_external_host:
            ensure_same_host(target, candidate_url)

        params_obj = req.get("params", {})
        params = {str(k): str(v) for k, v in params_obj.items()} if isinstance(params_obj, dict) else {}
        headers_obj = req.get("headers", {})
        headers = {str(k): str(v) for k, v in headers_obj.items()} if isinstance(headers_obj, dict) else {}
        body = str(req.get("body", "")) if req.get("body") is not None else ""
        content_type = str(req.get("content_type", "none"))
        req_key = request_fingerprint(req_tool, method, candidate_url, params, body, content_type)
        action_seen[req_key] = action_seen.get(req_key, 0) + 1
        if action_seen[req_key] > 2:
            item = {
                "step": step,
                "phase": phase,
                "hypothesis": hypothesis,
                "analysis": analysis,
                "confidence": confidence,
                "tool": req_tool,
                "method": method,
                "url": candidate_url,
                "signal": "skipped-duplicate-request-action",
            }
            history.append(item)
            print(f"[step {step}] {phase} {req_tool.upper()} {method} skipped duplicate action")
            time.sleep(0.2)
            continue

        result = execute_request(
            tool=req_tool,
            method=method,
            url=candidate_url,
            params=params,
            headers=headers,
            body=body,
            content_type=content_type,
            timeout=args.timeout,
        )

        signal_parts = []
        if result.status != baseline.status:
            signal_parts.append(f"status-diff {baseline.status}->{result.status}")
        delta_len = result.body_len - baseline.body_len
        if abs(delta_len) > 40:
            signal_parts.append(f"len-diff {delta_len:+d}")
        if result.title and result.title != baseline.title:
            signal_parts.append(f"title-changed '{result.title[:80]}'")
        if result.flag_matches:
            found_flag = result.flag_matches[0]
            signal_parts.append(f"flag-found {found_flag}")
            done = True
            final_report = f"Flag pattern found in response: {found_flag}"

        if result.error:
            signal_parts.append(f"error {result.error[:120]}")

        item = {
            "step": step,
            "phase": phase,
            "hypothesis": hypothesis,
            "analysis": analysis,
            "confidence": confidence,
            "success_signal": success_signal,
            "next_if_fail": next_if_fail,
            "tool": req_tool,
            "method": method,
            "url": result.url,
            "params": params,
            "status": result.status,
            "body_len": result.body_len,
            "title": result.title,
            "signal": "; ".join(signal_parts) if signal_parts else "no-strong-signal",
            "response_preview": result.body_preview[:1200],
        }
        history.append(item)
        print(f"[step {step}] {phase} {req_tool.upper()} {method} {result.url} -> {result.status} | {item['signal']}")

        if done:
            break
        time.sleep(0.2)

    if not final_report:
        summary_prompt = (
            "Summarize current progress as a CTF solver report.\n"
            "Return concise markdown with: findings, failed hypotheses, next best step.\n"
        )
        report_input = (
            f"Objective: {args.objective}\n"
            f"Target: {target}\n"
            f"History JSON:\n{json.dumps(history, ensure_ascii=False)}\n"
            f"Flag found: {found_flag or 'none'}\n"
        )
        final_report = chat_completion(
            base_url=base_url,
            api_key=api_key,
            model=chat_model,
            messages=[
                {"role": "system", "content": summary_prompt},
                {"role": "user", "content": report_input},
            ],
            temperature=0.1,
        )

    out_path = (root / args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    run_obj = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "target": target,
        "objective": args.objective,
        "hint": args.hint,
        "model": chat_model,
        "retrieval_mode": args.mode,
        "request_tool": args.request_tool,
        "steps": history,
        "done": done,
        "final_report": final_report,
        "flag": found_flag,
    }
    out_path.write_text(json.dumps(run_obj, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n=== Final Report ===")
    print(final_report)
    print(f"\n[agent] run log saved: {out_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        raise
