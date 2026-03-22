from __future__ import annotations

import json
import re
from typing import Any

from agent import hybrid_retrieve, short_history
from common import chat_completion
from solver_shared import MemoryStore, extract_json, recent_observations, task_prior_map


FAMILY_KEYWORDS = {
    "web": ["web", "http", "sql", "xss", "ssrf", "ssti", "php", "flask", "express", "nginx"],
    "misc": ["misc", "forensics", "stego", "pcap"],
    "pwn": ["pwn", "heap", "stack", "elf", "glibc"],
    "rev": ["reverse", "rev", "ida", "ghidra"],
    "crypto": ["crypto", "rsa", "aes", "hash"],
}
VULN_KEYWORDS = {
    "sqli": ["sql injection", "sqli", "mysql", "postgres", "sqlite", "query error"],
    "ssrf": ["ssrf", "metadata", "169.254.169.254", "internal fetch"],
    "ssti": ["ssti", "template injection", "jinja", "twig", "freemarker", "velocity"],
    "xss": ["xss", "cross site scripting", "<script", "onerror"],
    "lfi": ["lfi", "file inclusion", "/etc/passwd", "php://filter"],
    "rce": ["rce", "command injection", "remote code execution", "uid="],
}
TECH_STACK_PATTERNS = {
    "nodejs": [r"express", r"node\.js"],
    "php": [r"php", r"\$_get", r"\$_post"],
    "python": [r"flask", r"django", r"werkzeug", r"jinja"],
    "java": [r"spring", r"jsp", r"tomcat"],
    "nginx": [r"nginx"],
    "mysql": [r"mysql"],
}


def _normalize_vuln_label(text: str) -> str:
    lower = text.strip().lower()
    for label, keywords in VULN_KEYWORDS.items():
        if label == lower or any(keyword in lower for keyword in keywords):
            return label
    return lower.replace(" ", "_")[:40]


def _normalize_family(text: str) -> str:
    lower = text.strip().lower()
    for family in FAMILY_KEYWORDS:
        if family == lower or family in lower:
            return family
    return "web" if "http" in lower else "unknown"


def _normalize_str_list(values: list[Any], normalizer) -> list[str]:
    out: list[str] = []
    for item in values:
        val = normalizer(str(item))
        if val and val not in out:
            out.append(val)
    return out


def _keyword_hits(text: str, mapping: dict[str, list[str]]) -> list[str]:
    lower = text.lower()
    hits: list[str] = []
    for label, keywords in mapping.items():
        if any(keyword in lower for keyword in keywords):
            hits.append(label)
    return hits


def _tech_hits(text: str) -> list[str]:
    lower = text.lower()
    hits: list[str] = []
    for label, patterns in TECH_STACK_PATTERNS.items():
        if any(re.search(pattern, lower, re.IGNORECASE) for pattern in patterns):
            hits.append(label)
    return hits


def heuristic_prior(objective: str, hint: str, observation_text: str) -> dict[str, Any]:
    merged = "\n".join([objective, hint, observation_text])
    families = _keyword_hits(merged, FAMILY_KEYWORDS)
    vulns = _keyword_hits(merged, VULN_KEYWORDS)
    techs = _tech_hits(merged)

    family = families[0] if families else "web"
    primary = vulns[:2]
    secondary = [v for v in ["sqli", "ssrf", "ssti", "xss", "lfi", "rce"] if v not in primary][:2]
    deprioritized = [v for v in ["sqli", "ssrf", "ssti", "xss", "lfi", "rce"] if v not in primary and v not in secondary][:3]

    if "sqli" in primary:
        secondary = [v for v in secondary if v != "sqli"]
        deprioritized = [v for v in deprioritized if v != "sqli"]

    exploit_chain = primary[:]
    if "ssti" in primary and "rce" not in exploit_chain:
        exploit_chain.append("rce")
    if "ssrf" in primary and "rce" not in exploit_chain:
        exploit_chain.append("rce")

    return {
        "challenge_family": family,
        "tech_stack": techs[:4],
        "primary_hypotheses": primary[:3],
        "secondary_hypotheses": secondary[:3],
        "deprioritized": deprioritized[:4],
        "exploit_chain": exploit_chain[:4],
        "recommended_first_steps": ["baseline_request", "controllability_probe", "minimal_diff_probe"],
        "confidence": 0.70 if primary else 0.45,
        "rationale": "heuristic prior from description, hint, and current observations",
    }


def write_task_prior(memory: MemoryStore, step: int, prior: dict[str, Any]) -> None:
    family = _normalize_family(str(prior.get("challenge_family", "")).strip())
    if family:
        memory.upsert_fact("task_prior.family", family, float(prior.get("confidence", 0.6) or 0.6), step)
    rationale = str(prior.get("rationale", "")).strip()
    if rationale:
        memory.upsert_fact("task_prior.rationale", rationale[:280], 0.9, step)

    for idx, item in enumerate(_normalize_str_list(prior.get("tech_stack", [])[:5], lambda x: x.strip().lower()[:40]), start=1):
        val = str(item).strip().lower()
        if val:
            memory.upsert_fact(f"task_prior.tech.{idx}", val, 0.82, step)
    for idx, item in enumerate(_normalize_str_list(prior.get("primary_hypotheses", [])[:4], _normalize_vuln_label), start=1):
        val = str(item).strip().lower()
        if val:
            memory.upsert_fact(f"task_prior.primary.{idx}", val, 0.93, step)
    for idx, item in enumerate(_normalize_str_list(prior.get("secondary_hypotheses", [])[:4], _normalize_vuln_label), start=1):
        val = str(item).strip().lower()
        if val:
            memory.upsert_fact(f"task_prior.secondary.{idx}", val, 0.74, step)
    for idx, item in enumerate(_normalize_str_list(prior.get("deprioritized", [])[:5], _normalize_vuln_label), start=1):
        val = str(item).strip().lower()
        if val:
            memory.upsert_fact(f"task_prior.deprioritized.{idx}", val, 0.82, step)
    for idx, item in enumerate(_normalize_str_list(prior.get("exploit_chain", [])[:5], _normalize_vuln_label), start=1):
        val = str(item).strip().lower()
        if val:
            memory.upsert_fact(f"task_prior.chain.{idx}", val, 0.86, step)
    for idx, item in enumerate(prior.get("recommended_first_steps", [])[:5], start=1):
        val = str(item).strip()
        if val:
            memory.upsert_fact(f"task_prior.recommendation.{idx}", val, 0.72, step)


def should_refresh_interpretation(step: int, memory: MemoryStore, history: list[dict[str, Any]]) -> bool:
    if step == 1 or not memory.has_prefix("task_prior."):
        return True
    if step % 4 == 0:
        return True
    reason = memory.get_fact("reflect.last_failure_reason") or ""
    if reason in {"timeout_on_valid_path", "repeated_low_gain_pattern", "no_new_signal"}:
        return True
    if history and "flag=" in str(history[-1].get("signal", "")):
        return True
    return False


def run_task_interpreter(
    *,
    step: int,
    base_url: str,
    api_key: str,
    model: str,
    docs: list[dict[str, Any]],
    top_k: int,
    mode: str,
    alpha: float,
    embed_model: str,
    target: str,
    objective: str,
    hint: str,
    available_tools: list[str],
    history: list[dict[str, Any]],
    memory: MemoryStore,
) -> dict[str, Any]:
    observation_text = recent_observations(history, limit=6)
    heuristic = heuristic_prior(objective, hint, observation_text)
    retrieval_query = f"task interpretation\n{objective}\n{hint}\n{short_history(history)}"
    try:
        hits = hybrid_retrieve(
            query=retrieval_query,
            docs=docs,
            top_k=max(4, min(8, top_k)),
            mode=mode,
            alpha=alpha,
            base_url=base_url,
            api_key=api_key,
            embed_model=embed_model,
        ) if docs else []
    except Exception:
        hits = []
    context = "\n\n".join(
        [f"[score={h['score']:.4f}] {h['path']}#chunk{h['chunk_index']}\n{h['text'][:500]}" for h in hits[:6]]
    ) or "no retrieval context"

    planner_prompt = (
        "You are a task interpreter for a blackbox CTF solving system.\n"
        "Infer the most likely challenge family, initial vulnerability routes, and drift controls.\n"
        "Use description/hint as strong priors, but allow runtime evidence to refine secondary routes.\n"
        "Return ONLY JSON schema:\n"
        "{"
        "\"challenge_family\":\"web|misc|pwn|rev|crypto|unknown\","
        "\"tech_stack\":[\"...\"],"
        "\"primary_hypotheses\":[\"sqli\"],"
        "\"secondary_hypotheses\":[\"...\"],"
        "\"deprioritized\":[\"...\"],"
        "\"exploit_chain\":[\"...\"],"
        "\"recommended_first_steps\":[\"...\"],"
        "\"confidence\":0.0,"
        "\"rationale\":\"short text\""
        "}"
    )
    user_prompt = (
        f"Target: {target}\n"
        f"Objective: {objective}\n"
        f"Hint: {hint}\n"
        f"Available tools: {json.dumps(available_tools, ensure_ascii=False)}\n"
        f"Existing task prior: {json.dumps(task_prior_map(memory), ensure_ascii=False)}\n"
        f"Recent observations:\n{observation_text}\n\n"
        f"Retrieved context:\n{context}\n\n"
        f"Heuristic prior:\n{json.dumps(heuristic, ensure_ascii=False)}\n"
    )
    try:
        raw = chat_completion(
            base_url=base_url,
            api_key=api_key,
            model=model,
            messages=[{"role": "system", "content": planner_prompt}, {"role": "user", "content": user_prompt}],
            temperature=0.1,
        )
        prior = extract_json(raw)
    except Exception:
        prior = heuristic

    if not prior.get("primary_hypotheses"):
        prior["primary_hypotheses"] = heuristic.get("primary_hypotheses", [])
    if not prior.get("challenge_family"):
        prior["challenge_family"] = heuristic.get("challenge_family", "web")
    if not prior.get("deprioritized"):
        prior["deprioritized"] = heuristic.get("deprioritized", [])
    if not prior.get("recommended_first_steps"):
        prior["recommended_first_steps"] = heuristic.get("recommended_first_steps", [])
    if "confidence" not in prior:
        prior["confidence"] = heuristic.get("confidence", 0.6)
    if not prior.get("rationale"):
        prior["rationale"] = heuristic.get("rationale", "fallback heuristic prior")

    prior["challenge_family"] = _normalize_family(str(prior.get("challenge_family", "web")))
    prior["primary_hypotheses"] = _normalize_str_list(prior.get("primary_hypotheses", []), _normalize_vuln_label)
    prior["secondary_hypotheses"] = _normalize_str_list(prior.get("secondary_hypotheses", []), _normalize_vuln_label)
    prior["deprioritized"] = _normalize_str_list(prior.get("deprioritized", []), _normalize_vuln_label)
    prior["exploit_chain"] = _normalize_str_list(prior.get("exploit_chain", []), _normalize_vuln_label)
    prior["tech_stack"] = _normalize_str_list(prior.get("tech_stack", []), lambda x: x.strip().lower()[:40])

    write_task_prior(memory, step, prior)
    memory.add_event(step, "task_interpretation", json.dumps(prior, ensure_ascii=False))
    return prior
