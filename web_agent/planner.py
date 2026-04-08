from __future__ import annotations

import json
from typing import Any

from rag.common import chat_completion
from web_agent.solver_shared import MemoryStore, extract_json

STRICT_JSON_RULES = (
    "CRITICAL OUTPUT RULES:\n"
    "Return exactly one valid JSON object only.\n"
    "Do not output markdown, code fences, comments, or any text before/after JSON.\n"
    "Use double quotes for all keys/strings.\n"
    "If uncertain, keep schema fields with safe defaults instead of adding prose.\n"
)

PHASES = {"recon", "probe", "exploit", "extract", "verify"}


def _normalize_plan_subtask(raw: dict[str, Any], idx: int) -> dict[str, Any]:
    phase = str(raw.get("phase", "probe")).strip().lower()
    if phase not in PHASES:
        phase = "probe"
    return {
        "id": str(raw.get("id", f"st-{idx}")).strip() or f"st-{idx}",
        "title": str(raw.get("title", f"Subtask {idx}")).strip()[:180] or f"Subtask {idx}",
        "phase": phase,
        "goal": str(raw.get("goal", "")).strip()[:240],
        "success_signal": str(raw.get("success_signal", "")).strip()[:200],
        "suggested_action": str(raw.get("suggested_action", "")).strip()[:80],
        "status": str(raw.get("status", "pending")).strip().lower() or "pending",
    }


def fallback_plan(memory: MemoryStore) -> dict[str, Any]:
    target = memory.get_fact("target") or "$TARGET_URL"
    has_html = memory.get_fact("http.last_status") == "200"
    has_empty_reply = memory.get_fact("service.http.empty_reply") == "true"
    endpoint_focus = memory.get_fact("endpoint.focus") or ""
    subtasks: list[dict[str, Any]] = [
        {
            "id": "baseline-fetch",
            "title": "Fetch baseline landing page and headers",
            "phase": "recon",
            "goal": f"Collect one stable baseline response from {target}",
            "success_signal": "status line, headers, and body saved under artifact dir",
            "suggested_action": "http_probe_with_baseline",
            "status": "pending",
        }
    ]
    if has_empty_reply:
        subtasks.append(
            {
                "id": "service-recovery",
                "title": "Recover abnormal root service behavior",
                "phase": "probe",
                "goal": "Determine whether the target is not-ready, non-HTTP, or protocol-mismatched",
                "success_signal": "service classification and readiness facts recorded",
                "suggested_action": "service_recovery_probe",
                "status": "pending",
            }
        )
    if has_html or (memory.get_fact("artifact.html_file") or ""):
        subtasks.append(
            {
                "id": "html-surface",
                "title": "Extract routes, forms, and filenames from the downloaded HTML",
                "phase": "extract",
                "goal": "Turn the landing page into concrete follow-up endpoints and input names",
                "success_signal": "endpoint.focus or form/input facts appear in memory",
                "suggested_action": "extract_html_attack_surface",
                "status": "pending",
            }
        )
    if endpoint_focus:
        subtasks.append(
            {
                "id": "focused-probe",
                "title": f"Probe focused endpoint {endpoint_focus}",
                "phase": "probe",
                "goal": f"Validate controllability of {endpoint_focus}",
                "success_signal": "new status, params, methods, or form fields discovered on focused endpoint",
                "suggested_action": "",
                "status": "pending",
            }
        )
    subtasks.append(
        {
            "id": "hypothesis-probe",
            "title": "Run one hypothesis-driven probe with the best current evidence",
            "phase": "probe",
            "goal": "Move from generic discovery into a concrete exploit route",
            "success_signal": "new auth/token/parameter/vulnerability signal appears",
            "suggested_action": "",
            "status": "pending",
        }
    )
    norm = [_normalize_plan_subtask(item, idx + 1) for idx, item in enumerate(subtasks)]
    return {
        "rationale": "fallback planner generated from current memory facts",
        "subtasks": norm[:5],
    }


def run_plan_worker(
    *,
    base_url: str,
    api_key: str,
    model: str,
    target: str,
    objective: str,
    hint: str,
    task_priors: str,
    endpoints_text: str,
    memory_summary: str,
    hypotheses_text: str,
    actions_text: str,
    reflection_text: str,
    controller_reflection: dict[str, Any],
    history_text: str,
    recent_obs: str,
    memory: MemoryStore,
) -> dict[str, Any]:
    system_prompt = (
        "You are a planning layer for a command-driven CTF agent.\n"
        "Produce a short ordered plan of subtasks before command execution.\n"
        "The plan should be explicit enough that a solver can execute one subtask at a time.\n"
        "Prefer structured actions when they directly match the subtask goal.\n"
        "Use `extract_html_attack_surface` for parsing downloaded HTML into routes/forms/files.\n"
        "Use `service_recovery_probe` when HTTP responses are empty, protocol-mismatched, or unstable.\n"
        f"{STRICT_JSON_RULES}"
        "Return ONLY JSON with schema:\n"
        "{"
        "\"rationale\":\"short text\","
        "\"subtasks\":["
        "{\"title\":\"...\",\"phase\":\"recon|probe|exploit|extract|verify\",\"goal\":\"...\",\"success_signal\":\"...\",\"suggested_action\":\"\"}"
        "]"
        "}"
    )
    user_prompt = (
        f"Target: {target}\n"
        f"Objective: {objective}\n"
        f"Hint: {hint}\n"
        f"Task priors:\n{task_priors}\n\n"
        f"Endpoint candidates:\n{endpoints_text}\n\n"
        f"Memory summary:\n{memory_summary}\n\n"
        f"Hypotheses:\n{hypotheses_text}\n\n"
        f"Structured actions:\n{actions_text}\n\n"
        f"Reflection summary:\n{reflection_text}\n\n"
        f"Controller reflection:\n{json.dumps(controller_reflection, ensure_ascii=False)}\n\n"
        f"Recent history:\n{history_text}\n\n"
        f"Recent observations:\n{recent_obs}\n"
    )
    parsed: dict[str, Any] | None = None
    for attempt in range(1, 4):
        raw = chat_completion(
            base_url=base_url,
            api_key=api_key,
            model=model,
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
            temperature=0.1,
        )
        try:
            parsed = extract_json(raw)
            break
        except Exception:
            if attempt >= 3:
                return fallback_plan(memory)
            user_prompt = user_prompt + "\n\nYour previous output was not valid JSON. " + STRICT_JSON_RULES
    if not isinstance(parsed, dict):
        return fallback_plan(memory)
    subtasks = parsed.get("subtasks", [])
    if not isinstance(subtasks, list) or not subtasks:
        return fallback_plan(memory)
    norm = [_normalize_plan_subtask(item if isinstance(item, dict) else {}, idx + 1) for idx, item in enumerate(subtasks[:5])]
    return {
        "rationale": str(parsed.get("rationale", "")).strip()[:240] or "planner_generated_subtasks",
        "subtasks": norm,
    }


def plan_summary(plan: dict[str, Any]) -> str:
    rows: list[str] = []
    for idx, subtask in enumerate(plan.get("subtasks", []), start=1):
        if not isinstance(subtask, dict):
            continue
        rows.append(
            f"{idx}. [{subtask.get('status', 'pending')}] {subtask.get('phase', 'probe')} | "
            f"{subtask.get('title', '')} | action={subtask.get('suggested_action', '') or 'none'}"
        )
    return "\n".join(rows) if rows else "none"


def current_subtask(plan: dict[str, Any]) -> dict[str, Any]:
    for item in plan.get("subtasks", []):
        if isinstance(item, dict) and str(item.get("status", "pending")).lower() in {"pending", "running"}:
            return item
    return {}


def persist_plan(memory: MemoryStore, plan: dict[str, Any], step: int) -> None:
    payload = json.dumps(plan, ensure_ascii=False)
    memory.upsert_fact("plan.current", payload[:3500], 0.92, step)
    active = current_subtask(plan)
    if active:
        memory.upsert_fact("plan.active.title", str(active.get("title", ""))[:180], 0.92, step)
        memory.upsert_fact("plan.active.phase", str(active.get("phase", "probe"))[:20], 0.92, step)
        action = str(active.get("suggested_action", "")).strip()
        if action:
            memory.upsert_fact("plan.active.suggested_action", action[:80], 0.90, step)


def build_plan_patch(
    *,
    current: dict[str, Any],
    reflection: dict[str, Any],
    controller_reflection: dict[str, Any],
    facts: list[tuple[str, str, float]],
    result: dict[str, Any],
    gain: float,
) -> dict[str, Any]:
    patch: dict[str, Any] = {"mark_current": "completed", "insert_after": []}
    failure_reason = str(reflection.get("failure_reason", "none")).strip().lower()
    cluster = str(controller_reflection.get("failure_cluster", "none")).strip().lower()
    if int(result.get("returncode", 0)) != 0 and gain < 0.15:
        patch["mark_current"] = "failed"
    elif gain < 0.05 and failure_reason not in {"needs_followup", "none"}:
        patch["mark_current"] = "failed"

    fact_map = {key: value for key, value, _ in facts}
    endpoint_focus = fact_map.get("endpoint.focus") or ""
    if endpoint_focus:
        patch["insert_after"].append(
            {
                "title": f"Probe focused endpoint {endpoint_focus}",
                "phase": "probe",
                "goal": "Validate the most promising newly extracted route before wider exploration",
                "success_signal": "new method, parameter, auth, or response-diff signal appears",
                "suggested_action": "",
            }
        )
    if any(key.startswith("entrypoint.candidate.") for key in fact_map):
        patch["insert_after"].append(
            {
                "title": "Submit a benign request to the observed input surface",
                "phase": "probe",
                "goal": "Turn discovered input names into a controllable request surface",
                "success_signal": "server returns parameter validation, next stage, or parser error",
                "suggested_action": "",
            }
        )
    if fact_map.get("service.http.empty_reply") == "true" or fact_map.get("service.recovery.classification") == "service_not_ready_or_non_http":
        patch["insert_after"].append(
            {
                "title": "Recover abnormal service behavior before more probing",
                "phase": "probe",
                "goal": "Classify the service and recover a stable HTTP response path",
                "success_signal": "service classification or ready HTTP response recorded",
                "suggested_action": "service_recovery_probe",
            }
        )
    if cluster in {"timeout_spiral", "low_gain_loop"}:
        patch["insert_after"].append(
            {
                "title": "Run one focused low-risk command with fresh evidence",
                "phase": str(current.get("phase", "probe")).strip().lower() or "probe",
                "goal": "Break repetition by changing command style or narrowing scope",
                "success_signal": "new signal appears without repeating the previous command family",
                "suggested_action": "",
            }
        )
    return patch


def apply_plan_patch(plan: dict[str, Any], current_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    subtasks: list[dict[str, Any]] = []
    mark_current = str(patch.get("mark_current", "completed")).strip().lower() or "completed"
    inserted = False
    for idx, item in enumerate(plan.get("subtasks", []), start=1):
        if not isinstance(item, dict):
            continue
        normalized = _normalize_plan_subtask(item, idx)
        if normalized["id"] == current_id:
            normalized["status"] = "completed" if mark_current not in {"failed", "skipped"} else mark_current
            subtasks.append(normalized)
            extra = patch.get("insert_after", [])
            if isinstance(extra, list):
                for raw in extra:
                    if isinstance(raw, dict):
                        subtasks.append(_normalize_plan_subtask(raw, len(subtasks) + 1))
            inserted = True
            continue
        subtasks.append(normalized)
    if not inserted:
        extra = patch.get("insert_after", [])
        if isinstance(extra, list):
            for raw in extra:
                if isinstance(raw, dict):
                    subtasks.append(_normalize_plan_subtask(raw, len(subtasks) + 1))
    seen_titles: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for idx, item in enumerate(subtasks, start=1):
        key = f"{item.get('phase', 'probe')}::{item.get('title', '')}".strip().lower()
        if not key or key in seen_titles:
            continue
        seen_titles.add(key)
        item["id"] = item.get("id") or f"st-{idx}"
        deduped.append(item)
    return {
        "rationale": str(plan.get("rationale", "")).strip(),
        "subtasks": deduped[:7],
    }
