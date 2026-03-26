from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from agent import hybrid_retrieve, load_index, short_history
from common import chat_completion, load_dotenv, require_env
from solver_shared import (
    FLAG_RE,
    MemoryStore,
    derive_phase_state,
    discover_tools,
    extract_facts,
    extract_json,
    endpoint_summary,
    hypothesis_summary,
    hint_summary,
    info_gain_score,
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
    validate_command,
)
from task_interpreter import run_task_interpreter, should_refresh_interpretation


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

    run_id = args.run_id.strip() or datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
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

    env = os.environ.copy()
    env["TARGET_URL"] = target
    env["AGENT_ARTIFACT_DIR"] = str(artifact_dir)
    env["PROJECT_ROOT"] = str(root)
    env.pop("http_proxy", None)
    env.pop("https_proxy", None)
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)

    for step in range(1, max(1, args.max_steps) + 1):
        if should_refresh_interpretation(step, memory, history):
            prior = run_task_interpreter(
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
        expected_phase, constraints = derive_phase_state(memory, history)
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
            "\"decision\":\"command|done\","
            "\"phase\":\"recon|probe|exploit|extract|verify|done\","
            "\"command\":\"shell command string, may use $TARGET_URL\","
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
            f"Reflection constraints:\n{reflect_summary}\n\n"
            f"Recent history:\n{short_history(history)}\n\n"
            f"Recent observations:\n{recent_observations(history)}\n\n"
            f"Retrieved context:\n{context}\n"
        )

        raw = chat_completion(
            base_url=base_url,
            api_key=api_key,
            model=chat_model,
            messages=[{"role": "system", "content": planner_prompt}, {"role": "user", "content": user_prompt}],
            temperature=0.2,
        )
        plan = extract_json(raw)
        analysis = str(plan.get("analysis", "")).strip()
        confidence = float(plan.get("confidence", 0.0) or 0.0)
        decision = str(plan.get("decision", "command")).strip().lower()
        phase = str(plan.get("phase", "probe")).strip()
        success_signal = str(plan.get("success_signal", "")).strip()
        next_if_fail = str(plan.get("next_if_fail", "")).strip()

        if analysis:
            print(f"[step {step}] plan: {analysis[:180]} (conf={confidence:.2f})")

        if decision == "done":
            done = True
            final_report = "Model decided challenge solved."
            break

        raw_cmd = str(plan.get("command", "")).replace("{target}", target).strip()
        cmd = validate_command(repair_helper_command(raw_cmd, memory))
        ok, reason = validate_action(phase=phase, expected_phase=expected_phase, command=cmd, memory=memory, history=history)
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
            print(f"[step {step}] skipped duplicate command")
            time.sleep(0.2)
            continue

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

        entry = {
            "step": step,
            "phase": phase,
            "expected_phase": expected_phase,
            "analysis": analysis,
            "confidence": confidence,
            "command": cmd,
            "success_signal": success_signal,
            "next_if_fail": next_if_fail,
            "returncode": result["returncode"],
            "elapsed_sec": result["elapsed_sec"],
            "signal": signal,
            "info_gain": gain,
            "reflection": reflection,
            "hypothesis_updates": hypothesis_updates,
            "stdout_head": stdout_clean[:2000],
            "stderr_head": stderr_clean[:1200],
        }
        history.append(entry)
        print(f"[step {step}] {phase} rc={result['returncode']} cmd={cmd[:120]}")

        if done:
            break
        time.sleep(0.2)

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

    out_path.parent.mkdir(parents=True, exist_ok=True)
    run_obj = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "run_id": run_id,
        "target": target,
        "objective": args.objective,
        "hint": args.hint,
        "model": chat_model,
        "memory_db": str(memory_db_path),
        "artifact_dir": str(artifact_dir),
        "tools": tools,
        "memory_facts": memory.export_facts(),
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
