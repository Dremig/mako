from __future__ import annotations

import json
from typing import Any

from rag.common import chat_completion
from web_agent.solver_shared import FAILURE_CLUSTERS, MemoryStore, extract_json, normalize_failure_reason

STRICT_JSON_RULES = (
    "CRITICAL OUTPUT RULES:\n"
    "Return exactly one valid JSON object only.\n"
    "Do not output markdown, code fences, comments, or any text before/after JSON.\n"
    "Use double quotes for all keys/strings.\n"
    "If uncertain, keep schema fields with safe defaults instead of adding prose.\n"
)


def run_reflector_policy(
    *,
    base_url: str,
    api_key: str,
    model: str,
    step: int,
    target: str,
    objective: str,
    expected_phase: str,
    task_priors: str,
    reflection_state: str,
    recent_obs: str,
    history_text: str,
) -> dict[str, Any]:
    system_prompt = (
        "You are a policy reflector for a CTF web agent.\n"
        "You do NOT output shell commands.\n"
        "Your job is to diagnose drift/failure and emit strict controller constraints.\n"
        f"{STRICT_JSON_RULES}"
        "Return ONLY JSON with schema:\n"
        "{"
        "\"phase_override\":\"recon|probe|exploit|extract|verify|\","
        "\"failure_cluster\":\"none|drift|low_gain_loop|tool_mismatch|timeout_spiral|hypothesis_stale|execution_error\","
        "\"must_do\":[\"short constraint\"],"
        "\"must_avoid\":[\"short constraint\"],"
        "\"rationale\":\"short reason\""
        "}"
    )
    user_prompt = (
        f"Step: {step}\n"
        f"Target: {target}\n"
        f"Objective: {objective}\n"
        f"Expected phase: {expected_phase}\n\n"
        f"Task priors:\n{task_priors}\n\n"
        f"Reflection state:\n{reflection_state}\n\n"
        f"Recent observations:\n{recent_obs}\n\n"
        f"Recent history:\n{history_text}\n"
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
                parsed = {
                    "phase_override": "",
                    "failure_cluster": "none",
                    "must_do": [],
                    "must_avoid": [],
                    "rationale": "fallback_after_json_parse_failure",
                }
            else:
                user_prompt = user_prompt + "\n\nYour previous output was not valid JSON. " + STRICT_JSON_RULES
    out = {
        "phase_override": str(parsed.get("phase_override", "")).strip().lower(),
        "failure_cluster": str(parsed.get("failure_cluster", "none")).strip().lower() or "none",
        "must_do": [],
        "must_avoid": [],
        "rationale": str(parsed.get("rationale", "")).strip(),
    }
    if out["failure_cluster"] not in FAILURE_CLUSTERS:
        out["failure_cluster"] = "none"
    must_do = parsed.get("must_do", [])
    if isinstance(must_do, list):
        out["must_do"] = [str(item).strip()[:220] for item in must_do if str(item).strip()]
    must_avoid = parsed.get("must_avoid", [])
    if isinstance(must_avoid, list):
        out["must_avoid"] = [str(item).strip()[:220] for item in must_avoid if str(item).strip()]
    return out


def _count_recent_timeouts(history: list[dict[str, Any]], limit: int = 4) -> int:
    count = 0
    for item in reversed(history[-limit:]):
        if int(item.get("returncode", 0)) == 124:
            count += 1
    return count


def _normalize_constraints(values: list[str], limit: int = 4) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        val = str(raw).strip()
        if not val or val in seen:
            continue
        seen.add(val)
        out.append(val[:220])
        if len(out) >= limit:
            break
    return out


def _count_recent_policy_blocks(history: list[dict[str, Any]], limit: int = 4) -> int:
    count = 0
    for item in reversed(history[-limit:]):
        sig = str(item.get("signal", "")).lower()
        if "blocked-by-controller" in sig or "blocked-by-validator" in sig:
            count += 1
    return count


def repair_controller_policy(
    *,
    expected_phase: str,
    controller_reflection: dict[str, Any],
    memory: MemoryStore,
    history: list[dict[str, Any]],
) -> dict[str, Any]:
    out = {
        "phase_override": str(controller_reflection.get("phase_override", "")).strip().lower(),
        "failure_cluster": str(controller_reflection.get("failure_cluster", "none")).strip().lower() or "none",
        "must_do": [str(item).strip() for item in controller_reflection.get("must_do", []) if str(item).strip()],
        "must_avoid": [str(item).strip() for item in controller_reflection.get("must_avoid", []) if str(item).strip()],
        "rationale": str(controller_reflection.get("rationale", "")).strip(),
        "requirements": {
            "change_command_family": False,
            "require_explicit_success_signal": False,
        },
    }

    last_failure_reason = (memory.get_fact("reflect.last_failure_reason") or "").strip().lower()
    normalized_failure_reason = normalize_failure_reason(last_failure_reason)
    recent_timeouts = _count_recent_timeouts(history)
    recent_policy_blocks = _count_recent_policy_blocks(history, limit=4)
    has_entry = memory.has_prefix("entrypoint.confirmed.") or memory.has_prefix("entrypoint.candidate.")
    has_vuln = memory.has_prefix("vuln.signal.") or memory.get_fact("injection.parameter") is not None

    if normalized_failure_reason in {"timeout_on_valid_path", "timeout_without_signal"} or recent_timeouts >= 2:
        out["failure_cluster"] = "timeout_spiral"
        out["must_avoid"].append("Avoid another broad long-running command; reduce scope before retry.")
        out["must_do"].append("Use a short command that validates one focused hypothesis.")
        out["requirements"]["change_command_family"] = True
        out["requirements"]["require_explicit_success_signal"] = True
    elif normalized_failure_reason in {"repeated_low_gain_pattern", "no_new_signal", "redundant_recon"}:
        out["failure_cluster"] = "low_gain_loop"
        out["must_avoid"].append("Do not repeat low-information commands on the same surface.")
        out["must_do"].append("Change action style and target a different observable signal.")
        out["requirements"]["change_command_family"] = True
        out["requirements"]["require_explicit_success_signal"] = True
    elif normalized_failure_reason == "tool_unavailable":
        out["failure_cluster"] = "tool_mismatch"
        out["must_avoid"].append("Do not call unavailable tools again.")
        out["must_do"].append("Select only discovered available tools.")
    elif normalized_failure_reason == "missing_required_parameter":
        out["failure_cluster"] = "hypothesis_stale"
        out["must_avoid"].append("Do not continue broad route discovery while required-parameter errors persist.")
        out["must_do"].append("Keep endpoint constant and recover required parameter names/schema from response and source.")
        out["requirements"]["require_explicit_success_signal"] = True
    elif normalized_failure_reason == "method_not_allowed":
        out["failure_cluster"] = "execution_error"
        out["must_avoid"].append("Do not switch to unrelated endpoints before recovering allowed methods.")
        out["must_do"].append("Recover allowed HTTP method(s) and retry with minimal request-body variants.")
        out["requirements"]["require_explicit_success_signal"] = True
    elif normalized_failure_reason == "auth_required":
        out["failure_cluster"] = "tool_mismatch"
        out["must_avoid"].append("Avoid unauthenticated brute-force endpoint discovery under an auth gate.")
        out["must_do"].append("Focus on token/session/auth acquisition and preserve session context across requests.")
        out["requirements"]["require_explicit_success_signal"] = True
    elif normalized_failure_reason == "invalid_parameter_format":
        out["failure_cluster"] = "execution_error"
        out["must_avoid"].append("Do not add new attack surfaces before format recovery succeeds.")
        out["must_do"].append("Keep endpoint fixed and vary one parameter format dimension until error-class changes.")
        out["requirements"]["require_explicit_success_signal"] = True
    elif normalized_failure_reason == "command_failed":
        out["failure_cluster"] = "execution_error"
        out["must_do"].append("Reduce command complexity and isolate one variable.")
        out["requirements"]["require_explicit_success_signal"] = True

    phase_override = out["phase_override"]
    if phase_override not in {"", "recon", "probe", "exploit", "extract", "verify"}:
        phase_override = ""
    if phase_override == "recon" and (has_entry or has_vuln):
        phase_override = "probe"
        out["must_avoid"].append("Do not regress to recon when entrypoint/vuln signals already exist.")
    if phase_override in {"exploit", "extract"} and not (has_entry or has_vuln):
        phase_override = expected_phase
        out["must_do"].append("Gather controllability evidence before exploit/extract escalation.")
    if out["failure_cluster"] == "timeout_spiral" and phase_override == "exploit" and not has_vuln:
        phase_override = "probe"
    out["phase_override"] = phase_override

    if recent_policy_blocks >= 2:
        out["requirements"]["change_command_family"] = False
        out["requirements"]["require_explicit_success_signal"] = False
        out["must_do"].append("Policy relaxation: pick any valid low-risk command that can produce fresh evidence.")
        out["must_avoid"] = [x for x in out["must_avoid"] if "command family" not in x.lower()]
        if out["failure_cluster"] in {"low_gain_loop", "execution_error"}:
            out["failure_cluster"] = "none"

    out["must_do"] = _normalize_constraints(out["must_do"], limit=4)
    out["must_avoid"] = _normalize_constraints(out["must_avoid"], limit=4)
    if not out["rationale"]:
        out["rationale"] = f"repaired_by_rules:{out['failure_cluster']}"
    return out


def run_reflector_worker(
    *,
    step: int,
    base_url: str,
    api_key: str,
    model: str,
    target: str,
    objective: str,
    expected_phase: str,
    task_priors: str,
    reflection_state: str,
    recent_obs: str,
    history_text: str,
    memory: MemoryStore,
    history: list[dict[str, Any]],
) -> dict[str, Any]:
    raw = run_reflector_policy(
        base_url=base_url,
        api_key=api_key,
        model=model,
        step=step,
        target=target,
        objective=objective,
        expected_phase=expected_phase,
        task_priors=task_priors,
        reflection_state=reflection_state,
        recent_obs=recent_obs,
        history_text=history_text,
    )
    repaired = repair_controller_policy(
        expected_phase=expected_phase,
        controller_reflection=raw,
        memory=memory,
        history=history,
    )
    memory.add_event(step, "worker_reflector", json.dumps(repaired, ensure_ascii=False)[:3000])
    return repaired
