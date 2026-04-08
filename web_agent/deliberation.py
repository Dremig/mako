from __future__ import annotations

from typing import Any

from rag.common import chat_completion
from web_agent.solver_shared import extract_json

STRICT_JSON_RULES = (
    "CRITICAL OUTPUT RULES:\n"
    "Return exactly one valid JSON object only.\n"
    "Do not output markdown, code fences, comments, or any text before/after JSON.\n"
    "Use double quotes for all keys/strings.\n"
    "If uncertain, keep schema fields with safe defaults instead of adding prose.\n"
)


def _fallback_proposal() -> dict[str, Any]:
    return {
        "analysis": "Fallback proposal after repeated JSON parse failures.",
        "confidence": 0.05,
        "decision": "command",
        "phase": "recon",
        "command": "curl -si $TARGET_URL/robots.txt",
        "action": {},
        "success_signal": "HTTP response with status and body collected",
        "next_if_fail": "curl -si $TARGET_URL/",
    }


def _run_json_model(*, base_url: str, api_key: str, model: str, system_prompt: str, user_prompt: str, temperature: float) -> dict[str, Any]:
    local_user_prompt = user_prompt
    strict_system = system_prompt + "\n" + STRICT_JSON_RULES
    for attempt in range(1, 4):
        raw = chat_completion(
            base_url=base_url,
            api_key=api_key,
            model=model,
            messages=[{"role": "system", "content": strict_system}, {"role": "user", "content": local_user_prompt}],
            temperature=temperature,
        )
        try:
            parsed = extract_json(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            if attempt >= 3:
                return {}
            local_user_prompt = user_prompt + "\n\nYour previous output was not valid JSON. " + STRICT_JSON_RULES
    return {}


def run_recommender(
    *,
    base_url: str,
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> dict[str, Any]:
    parsed = _run_json_model(
        base_url=base_url,
        api_key=api_key,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=0.2,
    )
    return parsed or _fallback_proposal()


def run_corrector(
    *,
    base_url: str,
    api_key: str,
    model: str,
    target: str,
    step: int,
    active_title: str,
    active_goal: str,
    active_signal: str,
    active_action: str,
    controller_reflection: dict[str, Any],
    recommender: dict[str, Any],
    available_actions_text: str,
    memory_summary: str,
    recent_history: str,
) -> dict[str, Any]:
    system_prompt = (
        "You are a sabotager-style corrector for a CTF execution agent.\n"
        "Your job is to aggressively find flaws in the recommender proposal, then produce the smallest corrected executable proposal.\n"
        "Do not brainstorm a completely new strategy unless the proposal is clearly misaligned.\n"
        "You may return a corrected command or a corrected structured action.\n"
        "Prefer the planner-suggested structured action when it fits the current subtask.\n"
        "Mark proposals that depend on optional libraries or unverified assumptions as fragile.\n"
        "Return ONLY JSON with schema:\n"
        "{"
        "\"verdict\":\"accept|fragile|misaligned|replace\","
        "\"issues\":[\"short issue\"],"
        "\"corrected\":{"
        "\"analysis\":\"...\","
        "\"confidence\":0.0,"
        "\"decision\":\"command|action|done\","
        "\"phase\":\"recon|probe|exploit|extract|verify|done\","
        "\"command\":\"...\","
        "\"action\":{\"name\":\"\",\"args\":{}},"
        "\"success_signal\":\"...\","
        "\"next_if_fail\":\"...\""
        "}"
        "}"
    )
    user_prompt = (
        f"Step: {step}\n"
        f"Target: {target}\n"
        f"Current subtask: {active_title}\n"
        f"Current goal: {active_goal}\n"
        f"Current success signal: {active_signal}\n"
        f"Current suggested action: {active_action or 'none'}\n"
        f"Controller reflection: {controller_reflection}\n"
        f"Available actions:\n{available_actions_text}\n\n"
        f"Memory summary:\n{memory_summary}\n\n"
        f"Recent history:\n{recent_history}\n\n"
        f"Recommender proposal:\n{recommender}\n"
    )
    parsed = _run_json_model(
        base_url=base_url,
        api_key=api_key,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=0.1,
    )
    verdict = str(parsed.get("verdict", "accept")).strip().lower() or "accept"
    corrected = parsed.get("corrected", recommender)
    if not isinstance(corrected, dict):
        corrected = recommender
    issues = parsed.get("issues", [])
    if not isinstance(issues, list):
        issues = []
    return {
        "verdict": verdict,
        "issues": [str(item).strip()[:220] for item in issues if str(item).strip()][:6],
        "corrected": corrected,
    }


def choose_final_proposal(
    *,
    recommender: dict[str, Any],
    corrector: dict[str, Any],
    active_action: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    verdict = str(corrector.get("verdict", "accept")).strip().lower()
    corrected = corrector.get("corrected", recommender)
    if not isinstance(corrected, dict):
        corrected = recommender

    chosen = recommender
    judge = {
        "decision": "accept_recommender",
        "reason": "corrector found no blocking issue",
    }
    if verdict in {"fragile", "misaligned", "replace"}:
        chosen = corrected
        judge = {
            "decision": "accept_corrected",
            "reason": f"corrector verdict={verdict}",
        }
    if active_action:
        payload = chosen.get("action", {})
        action_name = ""
        if isinstance(payload, dict):
            action_name = str(payload.get("name", "")).strip()
        if not action_name and str(chosen.get("decision", "command")).strip().lower() != "done":
            chosen = dict(chosen)
            chosen["decision"] = "action"
            chosen["action"] = {"name": active_action, "args": {}}
            judge = {
                "decision": "force_planner_action",
                "reason": f"planner suggested structured action {active_action}",
            }
    return chosen, judge
