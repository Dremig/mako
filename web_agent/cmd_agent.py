from __future__ import annotations

import argparse
import json
import os
from queue import Empty, Queue
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rag.agent import hybrid_retrieve, load_index, short_history
from rag.common import chat_completion, load_dotenv, require_env
from web_agent.solver_shared import (
    available_actions_summary,
    cluster_for_failure_reason,
    compile_action_command,
    FLAG_RE,
    FAILURE_CLUSTERS,
    MemoryStore,
    derive_phase_state,
    discover_tools,
    extract_facts,
    extract_json,
    endpoint_summary,
    hypothesis_summary,
    hint_summary,
    info_gain_score,
    normalize_failure_reason,
    normalize_command,
    repair_helper_command,
    recent_observations,
    reflection_summary,
    reflect_step,
    run_shell_command,
    strip_noise,
    task_prior_summary,
    update_hypotheses,
    validate_action,
    validate_action_spec,
    validate_command,
)
from web_agent.task_interpreter import run_task_interpreter, should_refresh_interpretation


def utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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
                user_prompt = (
                    user_prompt
                    + "\n\nYour previous output was not valid JSON. "
                    + STRICT_JSON_RULES
                )
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
    last_family = (memory.get_fact("reflect.last_command_family") or "").strip().lower()
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
    # Guard against unsafe phase drift: don't allow recon regression after strong signals.
    if phase_override == "recon" and (has_entry or has_vuln):
        phase_override = "probe"
        out["must_avoid"].append("Do not regress to recon when entrypoint/vuln signals already exist.")
    # Guard against unsupported escalation without evidence.
    if phase_override in {"exploit", "extract"} and not (has_entry or has_vuln):
        phase_override = expected_phase
        out["must_do"].append("Gather controllability evidence before exploit/extract escalation.")
    # If cluster indicates timeout spiral, avoid forcing exploit unless route is clearly valid.
    if out["failure_cluster"] == "timeout_spiral" and phase_override == "exploit" and not has_vuln:
        phase_override = "probe"
    out["phase_override"] = phase_override

    # Avoid lock-up: if policy keeps blocking, temporarily relax hard requirements.
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


def summarize_run(
    base_url: str,
    api_key: str,
    model: str,
    target: str,
    objective: str,
    history: list[dict[str, Any]],
    found_flag: str,
) -> str:
    prompt = (
        "Summarize this command-driven CTF run.\n"
        "Use concise markdown with: findings, failed attempts, strongest next step.\n"
    )
    content = (
        f"Target: {target}\n"
        f"Objective: {objective}\n"
        f"Flag: {found_flag or 'none'}\n"
        f"History JSON:\n{json.dumps(history, ensure_ascii=False)}\n"
    )
    return chat_completion(
        base_url=base_url,
        api_key=api_key,
        model=model,
        messages=[{"role": "system", "content": prompt}, {"role": "user", "content": content}],
        temperature=0.1,
    )


def run_interpreter_worker(
    *,
    enabled: bool,
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
    if not enabled:
        return {}
    prior = run_task_interpreter(
        step=step,
        base_url=base_url,
        api_key=api_key,
        model=model,
        docs=docs,
        top_k=top_k,
        mode=mode,
        alpha=alpha,
        embed_model=embed_model,
        target=target,
        objective=objective,
        hint=hint,
        available_tools=available_tools,
        history=history,
        memory=memory,
    )
    memory.add_event(step, "worker_interpreter", json.dumps(prior, ensure_ascii=False)[:3000])
    return prior


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


def run_solver_worker(
    *,
    base_url: str,
    api_key: str,
    model: str,
    planner_prompt: str,
    user_prompt: str,
) -> dict[str, Any]:
    strict_planner_prompt = planner_prompt + "\n" + STRICT_JSON_RULES
    local_user_prompt = user_prompt
    for attempt in range(1, 4):
        raw = chat_completion(
            base_url=base_url,
            api_key=api_key,
            model=model,
            messages=[{"role": "system", "content": strict_planner_prompt}, {"role": "user", "content": local_user_prompt}],
            temperature=0.2,
        )
        try:
            return extract_json(raw)
        except Exception:
            if attempt >= 3:
                return {
                    "analysis": "Fallback plan after repeated JSON parse failures.",
                    "confidence": 0.05,
                    "decision": "command",
                    "phase": "recon",
                    "command": "curl -si $TARGET_URL/robots.txt",
                    "action": {},
                    "success_signal": "HTTP response with status and body collected",
                    "next_if_fail": "curl -si $TARGET_URL/",
                }
            local_user_prompt = (
                user_prompt
                + "\n\nYour previous output was not valid JSON. "
                + STRICT_JSON_RULES
            )
    return {
        "analysis": "Fallback plan after unexpected retry path.",
        "confidence": 0.01,
        "decision": "command",
        "phase": "recon",
        "command": "curl -si $TARGET_URL/",
        "action": {},
        "success_signal": "HTTP response observed",
        "next_if_fail": "curl -si $TARGET_URL/robots.txt",
    }


class QueueWorkerOrchestrator:
    def __init__(self, *, max_workers: int = 2) -> None:
        self._jobs: Queue[tuple[int, str, dict[str, Any]] | None] = Queue()
        self._results: Queue[tuple[int, bool, Any, str]] = Queue()
        self._next_id = 1
        self._threads: list[threading.Thread] = []
        for idx in range(max(1, int(max_workers))):
            t = threading.Thread(target=self._worker_loop, name=f"cmd-worker-{idx + 1}", daemon=True)
            t.start()
            self._threads.append(t)

    def _worker_loop(self) -> None:
        while True:
            item = self._jobs.get()
            if item is None:
                self._jobs.task_done()
                break
            job_id, job_name, kwargs = item
            try:
                if job_name == "interpreter":
                    payload = run_interpreter_worker(**kwargs)
                elif job_name == "reflector":
                    payload = run_reflector_worker(**kwargs)
                else:
                    raise ValueError(f"unknown job: {job_name}")
                self._results.put((job_id, True, payload, ""))
            except Exception as exc:  # pragma: no cover - defensive worker guard
                self._results.put((job_id, False, None, str(exc)))
            finally:
                self._jobs.task_done()

    def submit(self, job_name: str, **kwargs: Any) -> int:
        job_id = self._next_id
        self._next_id += 1
        self._jobs.put((job_id, job_name, kwargs))
        return job_id

    def collect(self, job_ids: list[int], timeout_sec: float = 180.0) -> dict[int, Any]:
        pending = set(job_ids)
        outputs: dict[int, Any] = {}
        deadline = time.time() + max(1.0, float(timeout_sec))
        while pending:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(f"worker jobs timed out: {sorted(pending)}")
            try:
                job_id, ok, payload, err = self._results.get(timeout=min(1.0, remaining))
            except Empty:
                continue
            if job_id not in pending:
                continue
            pending.remove(job_id)
            if not ok:
                raise RuntimeError(f"worker job {job_id} failed: {err}")
            outputs[job_id] = payload
        return outputs

    def close(self) -> None:
        for _ in self._threads:
            self._jobs.put(None)
        self._jobs.join()
        for t in self._threads:
            t.join(timeout=1.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Codex-style command agent for blackbox CTF web challenges")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--env", type=Path, default=Path(".env"))
    parser.add_argument("--index", type=Path, default=Path("rag_data/index.jsonl"))
    parser.add_argument("--target", type=str, required=True)
    parser.add_argument("--objective", type=str, default="Find SQL injection and retrieve flag")
    parser.add_argument("--hint", type=str, default="blackbox web SQL injection challenge")
    parser.add_argument("--max-steps", type=int, default=12)
    parser.add_argument("--cmd-timeout", type=int, default=25)
    parser.add_argument("--top-k", type=int, default=8)
    parser.add_argument("--mode", type=str, default="hybrid", choices=["dense", "bm25", "hybrid"])
    parser.add_argument("--alpha", type=float, default=0.65)
    parser.add_argument("--memory-db", type=Path, default=Path("logs/agent_memory.sqlite"))
    parser.add_argument("--run-id", type=str, default="")
    parser.add_argument("--out", type=Path, default=Path("logs/cmd_agent_last_run.json"))
    parser.add_argument("--artifact-dir", type=Path, default=Path("artifacts/cmd_agent"))
    parser.add_argument("--worker-mode", type=str, default="threaded", choices=["threaded", "sync"])
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

    run_id = args.run_id.strip() or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    artifact_dir = (root / args.artifact_dir / run_id).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)

    memory_db_path = (root / args.memory_db).resolve()
    if not args.memory_db.is_absolute() and str(args.memory_db).startswith("logs/"):
        memory_db_path = (artifact_dir / args.memory_db.name).resolve()
    out_path = (root / args.out).resolve()
    if not args.out.is_absolute() and str(args.out).startswith("logs/"):
        out_path = (artifact_dir / args.out.name).resolve()

    memory = MemoryStore(memory_db_path, run_id=run_id)
    memory.upsert_fact("target", target, 1.0, 0)
    memory.upsert_fact("objective", args.objective, 1.0, 0)
    memory.upsert_fact("hint", args.hint, 0.9, 0)
    memory.upsert_fact("artifact.dir", str(artifact_dir), 0.95, 0)
    memory.upsert_fact("project.root", str(root), 0.95, 0)
    memory.ensure_flow(target=target, objective=args.objective, hint=args.hint, status="running")
    task_state_id = memory.create_task_state(title=args.objective, step_start=1, status="running")

    tools = discover_tools()
    docs = load_index((root / args.index).resolve())
    available_tools = sorted(tools.keys())
    memory.upsert_fact("tools.available", ",".join(available_tools), 0.95, 0)

    print(f"[cmd-agent] target={target}")
    print(f"[cmd-agent] run_id={run_id} model={chat_model} tools={','.join(available_tools) if available_tools else 'none'} docs={len(docs)}")

    history: list[dict[str, Any]] = []
    command_seen: dict[str, int] = {}
    found_flag = ""
    done = False
    final_report = ""
    orchestrator = QueueWorkerOrchestrator(max_workers=2) if args.worker_mode == "threaded" else None

    env = os.environ.copy()
    env["TARGET_URL"] = target
    env["AGENT_ARTIFACT_DIR"] = str(artifact_dir)
    env["PROJECT_ROOT"] = str(root)
    env.pop("http_proxy", None)
    env.pop("https_proxy", None)
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)

    try:
        for step in range(1, max(1, args.max_steps) + 1):
            refresh_interpreter = should_refresh_interpretation(step, memory, history)
            if args.worker_mode == "threaded":
                assert orchestrator is not None
                expected_phase_local, _ = derive_phase_state(memory, history)
                task_priors_text = task_prior_summary(memory, max_items=20)
                reflection_state_text = reflection_summary(memory, max_items=8)
                recent_obs_text = recent_observations(history)
                history_text = short_history(history)
                job_ids: list[int] = []
                prior_job_id = -1
                if refresh_interpreter:
                    prior_job_id = orchestrator.submit(
                        "interpreter",
                        enabled=True,
                        step=step,
                        base_url=base_url,
                        api_key=api_key,
                        model=chat_model,
                        docs=docs,
                        top_k=args.top_k,
                        mode=args.mode,
                        alpha=args.alpha,
                        embed_model=embed_model,
                        target=target,
                        objective=args.objective,
                        hint=args.hint,
                        available_tools=available_tools,
                        history=history,
                        memory=memory,
                    )
                    job_ids.append(prior_job_id)
                reflector_job_id = orchestrator.submit(
                    "reflector",
                    step=step,
                    base_url=base_url,
                    api_key=api_key,
                    model=chat_model,
                    target=target,
                    objective=args.objective,
                    expected_phase=expected_phase_local,
                    task_priors=task_priors_text,
                    reflection_state=reflection_state_text,
                    recent_obs=recent_obs_text,
                    history_text=history_text,
                    memory=memory,
                    history=history,
                )
                job_ids.append(reflector_job_id)
                try:
                    worker_outputs = orchestrator.collect(job_ids, timeout_sec=180.0)
                    prior = worker_outputs.get(prior_job_id, {}) if refresh_interpreter else {}
                    controller_reflection = worker_outputs[reflector_job_id]
                except Exception as exc:
                    memory.add_event(step, "worker_collect_error", str(exc)[:1200])
                    print(f"[step {step}] threaded worker degraded to sync: {exc}")
                    prior = run_interpreter_worker(
                        enabled=refresh_interpreter,
                        step=step,
                        base_url=base_url,
                        api_key=api_key,
                        model=chat_model,
                        docs=docs,
                        top_k=args.top_k,
                        mode=args.mode,
                        alpha=args.alpha,
                        embed_model=embed_model,
                        target=target,
                        objective=args.objective,
                        hint=args.hint,
                        available_tools=available_tools,
                        history=history,
                        memory=memory,
                    )
                    controller_reflection = run_reflector_worker(
                        step=step,
                        base_url=base_url,
                        api_key=api_key,
                        model=chat_model,
                        target=target,
                        objective=args.objective,
                        expected_phase=expected_phase_local,
                        task_priors=task_priors_text,
                        reflection_state=reflection_state_text,
                        recent_obs=recent_obs_text,
                        history_text=history_text,
                        memory=memory,
                        history=history,
                    )
            else:
                prior = run_interpreter_worker(
                    enabled=refresh_interpreter,
                    step=step,
                    base_url=base_url,
                    api_key=api_key,
                    model=chat_model,
                    docs=docs,
                    top_k=args.top_k,
                    mode=args.mode,
                    alpha=args.alpha,
                    embed_model=embed_model,
                    target=target,
                    objective=args.objective,
                    hint=args.hint,
                    available_tools=available_tools,
                    history=history,
                    memory=memory,
                )
                controller_reflection = run_reflector_worker(
                    step=step,
                    base_url=base_url,
                    api_key=api_key,
                    model=chat_model,
                    target=target,
                    objective=args.objective,
                    expected_phase=derive_phase_state(memory, history)[0],
                    task_priors=task_prior_summary(memory, max_items=20),
                    reflection_state=reflection_summary(memory, max_items=8),
                    recent_obs=recent_observations(history),
                    history_text=short_history(history),
                    memory=memory,
                    history=history,
                )
            if refresh_interpreter:
                print(f"[step {step}] interpreter primary={','.join(prior.get('primary_hypotheses', [])[:3]) or 'none'} family={prior.get('challenge_family', 'unknown')}")

            retrieval_query = (
                f"{args.objective}\n{args.hint}\n"
                f"task_prior:\n{task_prior_summary(memory)}\n"
                f"history:\n{short_history(history)}"
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
                print(f"[warn] retrieval degraded: {exc}")
                hits = []

            context = "\n\n".join(
                [f"[score={h['score']:.4f}] {h['path']}#chunk{h['chunk_index']}\n{h['text'][:700]}" for h in hits]
            ) or "no retrieval context"
            memory_summary = memory.summary(max_items=30)
            prior_summary = task_prior_summary(memory, max_items=20)
            endpoints_text = endpoint_summary(memory, max_items=10)
            hints_text = hint_summary(memory, max_items=8)
            reflect_summary = reflection_summary(memory, max_items=8)
            hypo_summary = hypothesis_summary(memory, max_items=12)
            actions_text = available_actions_summary()
            expected_phase, constraints = derive_phase_state(memory, history)
            # Rebind expected phase based on latest local derivation and reflector override.
            phase_override = str(controller_reflection.get("phase_override", "")).strip().lower()
            if phase_override in {"recon", "probe", "exploit", "extract", "verify"}:
                expected_phase = phase_override
            controller_do = [str(item).strip() for item in controller_reflection.get("must_do", []) if str(item).strip()]
            controller_avoid = [str(item).strip() for item in controller_reflection.get("must_avoid", []) if str(item).strip()]
            for item in controller_do[:3]:
                constraints.append(f"Controller must-do: {item}")
            for item in controller_avoid[:3]:
                constraints.append(f"Controller avoid: {item}")
            memory.upsert_fact(
                "controller.reflect.last_failure_cluster",
                str(controller_reflection.get("failure_cluster", "none"))[:80],
                0.92,
                step,
            )
            for i, item in enumerate(controller_do[:3], start=1):
                memory.upsert_fact(f"controller.reflect.must_do.{i}", item, 0.90, step)
            for i, item in enumerate(controller_avoid[:3], start=1):
                memory.upsert_fact(f"controller.reflect.must_avoid.{i}", item, 0.90, step)
            memory.upsert_fact(
                "controller.reflect.policy_source",
                "llm+rule_repair",
                0.95,
                step,
            )
            memory.add_event(step, "controller_reflection", json.dumps(controller_reflection, ensure_ascii=False))
            constraint_text = "\n".join(f"- {item}" for item in constraints) if constraints else "- none"

            planner_prompt = (
                "You are a Codex-style CTF command agent.\n"
                "A separate interpreter has already produced task priors. Treat those priors as strong guidance unless runtime evidence is overwhelming.\n"
                "Output one concrete shell command per step, then iterate from observed output.\n"
                "Use persistent memory facts, hypotheses, and reflection constraints as hard constraints.\n"
                "Minimize recon once actionable entrypoints exist. Prefer commands with the highest expected information gain.\n"
                "Only treat actual request inputs as attack surfaces: query parameters, form input names, headers, cookies, request bodies, or confirmed API fields.\n"
                "Do not treat HTML meta tags, author tags, renderer hints, or other static markup labels as controllable parameters unless they are proven to be sent in a request.\n"
                "For frontend/source-inspection challenges, treat HTML comments, href/src links, and hinted backup filenames as candidate endpoints to fetch directly.\n"
                "When a new endpoint candidate is known, fetch that endpoint before retrying the current page or switching to speculative exploit classes.\n"
                "When a page exposes a POST form with known input names, submit a benign value first to observe the next stage before speculative exploit payloads.\n"
                "When a POST form exposes hidden default inputs, submit those defaults as-is before inventing alternative parameters or attack classes.\n"
                "When a form field's sample value is JSON text, consider a minimal malformed JSON probe to test for parser-error information leakage.\n"
                "If a Werkzeug or traceback debug page appears, inspect it directly for leaked source comments, secrets, and flags.\n"
                "If Tomcat Manager Basic Auth is detected, try a small Tomcat default-credential set first (for example tomcat:tomcat, tomcat:s3cret, admin:admin, manager:manager).\n"
                "If Tomcat Manager GUI access succeeds, use one cookie jar, fetch /manager/html, parse the exact HTML upload action (including jsessionid and CSRF nonce), build a minimal WAR with a JSP reader, upload it through that exact HTML manager action, then fetch the deployed JSP to read the target file.\n"
                "When generating helper artifacts such as WAR files or cookie jars, write them under $AGENT_ARTIFACT_DIR or the current working directory with stable names, then reuse those paths instead of mktemp-only paths.\n"
                "For Tomcat WAR generation, prefer the local helper script $PROJECT_ROOT/scripts/build_jsp_war.py over fragile shell heredocs.\n"
                "For the full Tomcat Manager HTML upload chain, prefer the helper $PROJECT_ROOT/scripts/tomcat_manager_read_file.py when the goal is to read a server file through a deployed JSP.\n"
                "Return ONLY JSON schema:\n"
                "{"
                "\"analysis\":\"1-2 short sentences\","
                "\"confidence\":0.0,"
                "\"decision\":\"command|action|done\","
                "\"phase\":\"recon|probe|exploit|extract|verify|done\","
                "\"command\":\"shell command string, may use $TARGET_URL\","
                "\"action\":{\"name\":\"optional structured action name\",\"args\":{\"key\":\"value\"}},"
                "\"success_signal\":\"what confirms progress\","
                "\"next_if_fail\":\"fallback command idea\""
                "}"
            )
            user_prompt = (
                f"Target: {target}\n"
                f"Objective: {args.objective}\n"
                f"Hint: {args.hint}\n"
                f"Step: {step}/{args.max_steps}\n"
                f"Expected phase: {expected_phase}\n"
                f"Available tools: {json.dumps(available_tools, ensure_ascii=False)}\n"
                f"Active constraints:\n{constraint_text}\n\n"
                f"Task priors:\n{prior_summary}\n\n"
                f"Endpoint candidates:\n{endpoints_text}\n\n"
                f"Comment hints:\n{hints_text}\n\n"
                f"Persistent memory facts:\n{memory_summary}\n\n"
                f"Hypotheses:\n{hypo_summary}\n\n"
                f"Structured actions:\n{actions_text}\n\n"
                f"Reflection constraints:\n{reflect_summary}\n\n"
                f"Controller reflection:\n{json.dumps(controller_reflection, ensure_ascii=False)}\n\n"
                f"Recent history:\n{short_history(history)}\n\n"
                f"Recent observations:\n{recent_observations(history)}\n\n"
                f"Retrieved context:\n{context}\n"
            )

            plan = run_solver_worker(
                base_url=base_url,
                api_key=api_key,
                model=chat_model,
                planner_prompt=planner_prompt,
                user_prompt=user_prompt,
            )
            analysis = str(plan.get("analysis", "")).strip()
            confidence = float(plan.get("confidence", 0.0) or 0.0)
            decision = str(plan.get("decision", "command")).strip().lower()
            phase = str(plan.get("phase", "probe")).strip()
            success_signal = str(plan.get("success_signal", "")).strip()
            next_if_fail = str(plan.get("next_if_fail", "")).strip()
            req = controller_reflection.get("requirements", {}) if isinstance(controller_reflection, dict) else {}
            require_signal = bool(req.get("require_explicit_success_signal", False))
            subtask_title = analysis if analysis else f"{phase} step {step}"
            subtask_state_id = memory.create_subtask_state(
            task_id=task_state_id,
            step=step,
            phase=phase,
            title=subtask_title,
            status="running",
        )

            if analysis:
                print(f"[step {step}] plan: {analysis[:180]} (conf={confidence:.2f})")

            if decision == "done":
                done = True
                final_report = "Model decided challenge solved."
                memory.finish_subtask_state(
                subtask_state_id,
                status="finished",
                command="__model_done__",
                return_code=0,
                info_gain=0.0,
            )
                break

            raw_cmd = str(plan.get("command", "")).replace("{target}", target).strip()
            action_obj = plan.get("action", {})
            if decision == "action":
                action_spec = validate_action_spec(action_obj if isinstance(action_obj, dict) else {}, memory)
                raw_cmd = compile_action_command(action_spec, memory)
            cmd = validate_command(repair_helper_command(raw_cmd, memory))
            if require_signal and not success_signal:
                history.append(
                {
                    "step": step,
                    "phase": phase,
                    "analysis": analysis,
                    "confidence": confidence,
                    "command": cmd,
                    "signal": "blocked-by-controller: missing success_signal",
                }
            )
                memory.add_event(step, "controller_block", "missing success_signal while controller requires explicit signal")
                memory.finish_subtask_state(
                subtask_state_id,
                status="failed",
                command=cmd,
                return_code=1,
                info_gain=0.0,
                error="blocked-by-controller: missing success_signal",
            )
                print(f"[step {step}] controller blocked action: missing success_signal")
                time.sleep(0.2)
                continue
            ok, reason = validate_action(
            phase=phase,
            expected_phase=expected_phase,
            command=cmd,
            memory=memory,
            history=history,
                controller_reflection=controller_reflection,
            )
            if not ok:
                history.append(
                {
                    "step": step,
                    "phase": phase,
                    "analysis": analysis,
                    "confidence": confidence,
                    "command": cmd,
                    "signal": f"blocked-by-validator: {reason}",
                }
            )
                memory.add_event(step, "validator_block", reason)
                memory.finish_subtask_state(
                subtask_state_id,
                status="failed",
                command=cmd,
                return_code=1,
                info_gain=0.0,
                error=f"blocked-by-validator: {reason}",
            )
                print(f"[step {step}] validator blocked action: {reason}")
                time.sleep(0.2)
                continue

            cmd_key = normalize_command(cmd)
            command_seen[cmd_key] = command_seen.get(cmd_key, 0) + 1
            if command_seen[cmd_key] > 2:
                history.append(
                {
                    "step": step,
                    "phase": phase,
                    "analysis": analysis,
                    "confidence": confidence,
                    "command": cmd,
                    "signal": "skipped-duplicate-command",
                }
            )
                memory.add_event(step, "duplicate_skip", cmd_key)
                memory.finish_subtask_state(
                subtask_state_id,
                status="skipped",
                command=cmd,
                return_code=0,
                info_gain=0.0,
                error="skipped-duplicate-command",
            )
                print(f"[step {step}] skipped duplicate command")
                time.sleep(0.2)
                continue

            memory.add_tool_event(
            step=step,
            phase=phase,
            tool_name="call",
            payload={"command": cmd, "timeout_sec": args.cmd_timeout},
        )
            result = run_shell_command(cmd, timeout=args.cmd_timeout, env=env, cwd=artifact_dir)
            stdout_clean = strip_noise(result["stdout"])
            stderr_clean = strip_noise(result["stderr"])
            merged = (stdout_clean + "\n" + stderr_clean)[:120000]
            flag_matches = [m.group(0) for m in FLAG_RE.finditer(merged)]
            signal = f"rc={result['returncode']}"
            if flag_matches:
                found_flag = flag_matches[0]
                signal += f"; flag={found_flag}"
                done = True
                final_report = f"Flag found in command output: {found_flag}"

            facts = extract_facts(cmd, stdout_clean, stderr_clean)
            gain = info_gain_score(memory, facts)
            for key, value, conf in facts:
                memory.upsert_fact(key, value, conf, step)

            reflection = reflect_step(
            step=step,
            phase=phase,
            command=cmd,
            result=result,
            facts=facts,
            gain=gain,
            memory=memory,
            history=history,
            success_signal=success_signal,
        )
            hypothesis_updates = update_hypotheses(
            step=step,
            memory=memory,
            phase=phase,
            facts=facts,
            reflection=reflection,
            result=result,
        )

            memory.add_event(step, "command", cmd)
            memory.add_event(step, "signal", signal)
            memory.add_event(step, "info_gain", str(gain))
            memory.add_tool_event(
            step=step,
            phase=phase,
            tool_name="result",
            payload={
                "command": cmd,
                "returncode": result["returncode"],
                "elapsed_sec": result["elapsed_sec"],
                "signal": signal,
                "info_gain": gain,
            },
        )
            if result["returncode"] != 0:
                memory.add_event(step, "failure_reason", str(reflection.get("failure_reason", "command_failed")))
            memory.finish_subtask_state(
            subtask_state_id,
            status="finished" if result["returncode"] == 0 else "failed",
            command=cmd,
            return_code=int(result["returncode"]),
            info_gain=float(gain),
            error="" if result["returncode"] == 0 else str(reflection.get("failure_reason", "command_failed")),
        )

            entry = {
            "step": step,
            "phase": phase,
            "expected_phase": expected_phase,
            "analysis": analysis,
            "confidence": confidence,
            "command": cmd,
            "action": action_obj if isinstance(action_obj, dict) else {},
            "success_signal": success_signal,
            "next_if_fail": next_if_fail,
            "returncode": result["returncode"],
            "elapsed_sec": result["elapsed_sec"],
            "signal": signal,
            "info_gain": gain,
            "reflection": reflection,
            "hypothesis_updates": hypothesis_updates,
            "controller_reflection": controller_reflection,
            "stdout_head": stdout_clean[:2000],
            "stderr_head": stderr_clean[:1200],
        }
            history.append(entry)
            print(f"[step {step}] {phase} rc={result['returncode']} cmd={cmd[:120]}")

            if done:
                break
            time.sleep(0.2)
    finally:
        if orchestrator is not None:
            orchestrator.close()

    if not final_report:
        final_report = summarize_run(
            base_url=base_url,
            api_key=api_key,
            model=chat_model,
            target=target,
            objective=args.objective,
            history=history,
            found_flag=found_flag,
        )

    run_success = bool(found_flag)
    memory.set_task_state_status(
        task_state_id,
        status="finished" if run_success else "failed",
        step_end=max(0, len(history)),
    )
    memory.set_flow_status("finished" if run_success else "failed")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    run_obj = {
        "timestamp": utc_now_z(),
        "run_id": run_id,
        "target": target,
        "objective": args.objective,
        "hint": args.hint,
        "model": chat_model,
        "memory_db": str(memory_db_path),
        "artifact_dir": str(artifact_dir),
        "tools": tools,
        "memory_facts": memory.export_facts(),
        "execution_state": memory.export_execution_state(),
        "steps": history,
        "done": done,
        "flag": found_flag,
        "final_report": final_report,
    }
    out_path.write_text(json.dumps(run_obj, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n=== Final Report ===")
    print(final_report)
    print(f"\n[cmd-agent] run log saved: {out_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        raise
    # Keep cluster aligned with canonical reason->cluster mapping whenever reason is known.
    mapped_cluster = cluster_for_failure_reason(normalized_failure_reason)
    if mapped_cluster != "none" and out["failure_cluster"] == "none":
        out["failure_cluster"] = mapped_cluster
