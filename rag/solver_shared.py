from __future__ import annotations

import hashlib
import json
import re
import shlex
import sqlite3
import subprocess
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any


FLAG_RE = re.compile(r"(flag|ctf)\{[^{}\n]{1,200}\}", re.IGNORECASE)
VULN_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "sqli": [
        re.compile(r"sql syntax|query error|mysql|postgres|sqlite|odbc", re.IGNORECASE),
        re.compile(r"sqlmap resumed", re.IGNORECASE),
    ],
    "ssrf": [
        re.compile(r"169\.254\.169\.254|metadata|latest/meta-data", re.IGNORECASE),
        re.compile(r"127\.0\.0\.1|localhost|internal", re.IGNORECASE),
    ],
    "ssti": [
        re.compile(r"jinja|template|twig|freemarker|velocity|mustache", re.IGNORECASE),
        re.compile(r"\{\{.*\}\}|\$\{.*\}", re.IGNORECASE),
    ],
    "xss": [
        re.compile(r"<script|onerror=|onload=|xss", re.IGNORECASE),
    ],
    "lfi": [
        re.compile(r"/etc/passwd|php://filter|php://input|file inclusion", re.IGNORECASE),
    ],
    "rce": [
        re.compile(r"uid=\d+\(.*\)|command not found|bin/sh", re.IGNORECASE),
    ],
}
BANNED_TOKENS = {
    "rm -rf /",
    "shutdown",
    "reboot",
    "mkfs",
    ":(){:|:&};:",
}
NOISE_PATTERNS = [
    re.compile(r"^Error while loading conda entry point:", re.IGNORECASE),
    re.compile(r"typing_extensions", re.IGNORECASE),
]


class MemoryStore:
    def __init__(self, db_path: Path, run_id: str) -> None:
        self.db_path = db_path
        self.run_id = run_id
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS facts (
              run_id TEXT NOT NULL,
              key TEXT NOT NULL,
              value TEXT NOT NULL,
              confidence REAL NOT NULL DEFAULT 0.5,
              source_step INTEGER NOT NULL DEFAULT 0,
              updated_at TEXT NOT NULL,
              PRIMARY KEY (run_id, key)
            );
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              run_id TEXT NOT NULL,
              step INTEGER NOT NULL,
              kind TEXT NOT NULL,
              content TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def upsert_fact(self, key: str, value: str, confidence: float, step: int) -> None:
        now = datetime.utcnow().isoformat() + "Z"
        old = self.conn.execute("SELECT confidence FROM facts WHERE run_id=? AND key=?", (self.run_id, key)).fetchone()
        if old is not None and float(old[0]) > confidence:
            return
        self.conn.execute(
            """
            INSERT INTO facts(run_id,key,value,confidence,source_step,updated_at)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(run_id,key) DO UPDATE SET
              value=excluded.value,
              confidence=excluded.confidence,
              source_step=excluded.source_step,
              updated_at=excluded.updated_at
            """,
            (self.run_id, key, value, confidence, step, now),
        )
        self.conn.commit()

    def add_event(self, step: int, kind: str, content: str) -> None:
        now = datetime.utcnow().isoformat() + "Z"
        self.conn.execute(
            "INSERT INTO events(run_id,step,kind,content,created_at) VALUES(?,?,?,?,?)",
            (self.run_id, step, kind, content[:4000], now),
        )
        self.conn.commit()

    def summary(self, max_items: int = 30) -> str:
        rows = self.conn.execute(
            """
            SELECT key, value, confidence, source_step
            FROM facts WHERE run_id=?
            ORDER BY confidence DESC, source_step DESC
            LIMIT ?
            """,
            (self.run_id, max_items),
        ).fetchall()
        if not rows:
            return "none"
        return "\n".join([f"{k}={v} (conf={c:.2f}, step={s})" for k, v, c, s in rows])

    def export_facts(self) -> dict[str, Any]:
        rows = self.conn.execute(
            "SELECT key, value, confidence, source_step, updated_at FROM facts WHERE run_id=?",
            (self.run_id,),
        ).fetchall()
        out: dict[str, Any] = {}
        for key, value, conf, step, updated_at in rows:
            out[key] = {
                "value": value,
                "confidence": conf,
                "source_step": step,
                "updated_at": updated_at,
            }
        return out

    def get_fact(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM facts WHERE run_id=? AND key=?", (self.run_id, key)).fetchone()
        return None if row is None else str(row[0])

    def has_prefix(self, prefix: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM facts WHERE run_id=? AND key LIKE ? LIMIT 1",
            (self.run_id, f"{prefix}%"),
        ).fetchone()
        return row is not None

    def prefix_rows(self, prefix: str, max_items: int = 20) -> list[tuple[str, str, float, int]]:
        rows = self.conn.execute(
            """
            SELECT key, value, confidence, source_step
            FROM facts
            WHERE run_id=? AND key LIKE ?
            ORDER BY source_step DESC, confidence DESC
            LIMIT ?
            """,
            (self.run_id, f"{prefix}%", max_items),
        ).fetchall()
        return [(str(k), str(v), float(c), int(s)) for k, v, c, s in rows]


def discover_tools() -> dict[str, str]:
    candidates = [
        "curl",
        "ffuf",
        "sqlmap",
        "python3",
        "python",
        "bash",
        "sh",
        "nc",
        "ncat",
        "nmap",
        "wget",
        "awk",
        "sed",
        "rg",
    ]
    found: dict[str, str] = {}
    for tool in candidates:
        proc = subprocess.run(["bash", "-lc", f"command -v {shlex.quote(tool)}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode == 0:
            path = proc.stdout.decode("utf-8", errors="ignore").strip()
            if path:
                found[tool] = path
    return found


def validate_command(cmd: str) -> str:
    command = cmd.strip()
    if not command:
        raise RuntimeError("Empty command")
    lower = command.lower()
    for token in BANNED_TOKENS:
        if token in lower:
            raise RuntimeError(f"Blocked potentially destructive command token: {token}")
    return command


def strip_noise(text: str) -> str:
    out_lines: list[str] = []
    for line in text.splitlines():
        if any(p.search(line) for p in NOISE_PATTERNS):
            continue
        out_lines.append(line)
    return "\n".join(out_lines).strip()


def normalize_command(command: str) -> str:
    cmd = command.strip()
    cmd = re.sub(r"\s+", " ", cmd)
    cmd = cmd.replace("http://", "URL://").replace("https://", "URL://")
    cmd = re.sub(r"URL://[^/\s]+", "URL://HOST", cmd)
    return cmd


def detect_vuln_signals(text: str) -> list[str]:
    hits: list[str] = []
    for vuln, patterns in VULN_PATTERNS.items():
        if any(p.search(text) for p in patterns):
            hits.append(vuln)
    return hits


def extract_form_input_names(html: str) -> list[str]:
    names: list[str] = []
    for form_match in re.finditer(r"<form\b.*?</form>", html, re.IGNORECASE | re.DOTALL):
        block = form_match.group(0)
        for name_match in re.finditer(
            r"<(?:input|textarea|select)\b[^>]*\bname=\"([a-zA-Z0-9_\-]{1,40})\"",
            block,
            re.IGNORECASE,
        ):
            names.append(name_match.group(1))
    return names


def extract_query_params_from_command(command: str) -> list[str]:
    params: list[str] = []
    for url_match in re.finditer(r"https?://[^\s\"']+", command):
        url = url_match.group(0)
        try:
            parsed = urllib.parse.urlparse(url)
            for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
                if re.fullmatch(r"[a-zA-Z0-9_\-]{1,40}", key):
                    params.append(key)
        except ValueError:
            continue
    return params


def extract_facts(command: str, stdout: str, stderr: str) -> list[tuple[str, str, float]]:
    facts: list[tuple[str, str, float]] = []
    merged = f"{stdout}\n{stderr}"

    for name in extract_form_input_names(stdout):
        facts.append((f"entrypoint.candidate.{name}", "form-input", 0.80))
    for name in extract_query_params_from_command(command):
        facts.append((f"entrypoint.candidate.{name}", "query-param", 0.82))
    for m in re.finditer(r"<form[^>]*method=\"([A-Za-z]+)\"", stdout, re.IGNORECASE):
        facts.append(("form.method", m.group(1).upper(), 0.65))
    for m in re.finditer(r"(https?://[^\s\"']+)", merged):
        u = m.group(1)[:300]
        facts.append((f"url.seen.{hashlib.md5(u.encode()).hexdigest()[:8]}", u, 0.55))

    dbms_match = re.search(r"back-end DBMS:\s*([^\n\r]+)", merged, re.IGNORECASE)
    if dbms_match:
        facts.append(("dbms", dbms_match.group(1).strip(), 0.90))
    db_match = re.search(r"current database:\s*'([^']+)'", merged, re.IGNORECASE)
    if db_match:
        facts.append(("current_database", db_match.group(1).strip(), 0.92))
    inj_match = re.search(r"Parameter:\s*([a-zA-Z0-9_\-]+)\s*\((GET|POST)\)", merged, re.IGNORECASE)
    if inj_match:
        facts.append(("injection.parameter", inj_match.group(1), 0.92))
        facts.append(("injection.method", inj_match.group(2).upper(), 0.92))
        facts.append((f"entrypoint.confirmed.{inj_match.group(1)}", inj_match.group(2).upper(), 0.95))
    if re.search(r"union", merged, re.IGNORECASE) and re.search(r"block|禁止|不要用", merged, re.IGNORECASE):
        facts.append(("technique.union_blocked", "true", 0.85))
    if re.search(r"time-based blind|sleep\(", merged, re.IGNORECASE):
        facts.append(("technique.time_based", "true", 0.88))

    for vuln in detect_vuln_signals(merged):
        facts.append((f"vuln.signal.{vuln}", "true", 0.78))

    return facts


def _task_prior_values(memory: MemoryStore, prefix: str, max_items: int = 8) -> list[str]:
    rows = memory.prefix_rows(prefix, max_items=max_items)
    out: list[str] = []
    for _, value, _, _ in rows:
        val = value.strip().lower()
        if val and val not in out:
            out.append(val)
    return out


def task_prior_map(memory: MemoryStore) -> dict[str, list[str]]:
    return {
        "primary": _task_prior_values(memory, "task_prior.primary."),
        "secondary": _task_prior_values(memory, "task_prior.secondary."),
        "deprioritized": _task_prior_values(memory, "task_prior.deprioritized."),
        "chain": _task_prior_values(memory, "task_prior.chain."),
    }


def task_prior_summary(memory: MemoryStore, max_items: int = 18) -> str:
    rows = memory.prefix_rows("task_prior.", max_items=max_items)
    if not rows:
        return "none"
    return "\n".join([f"{k}={v} (conf={c:.2f}, step={s})" for k, v, c, s in rows])


def derive_phase_state(memory: MemoryStore, history: list[dict[str, Any]]) -> tuple[str, list[str]]:
    constraints: list[str] = []
    priors = task_prior_map(memory)
    has_candidate_entrypoints = memory.has_prefix("entrypoint.candidate.")
    has_confirmed_entrypoints = memory.has_prefix("entrypoint.confirmed.")
    has_vuln = memory.has_prefix("vuln.signal.")
    has_injection = memory.get_fact("injection.parameter") is not None
    has_dbms = memory.get_fact("dbms") is not None
    has_flag = memory.has_prefix("flag.")

    if has_flag:
        phase = "verify"
    elif has_dbms or has_injection:
        phase = "extract"
        constraints.append("Do not return to broad recon; focus on extraction and verification.")
    elif has_vuln:
        phase = "exploit"
        constraints.append("A vulnerability signal already exists; prefer exploitation over more discovery.")
    elif has_confirmed_entrypoints or has_candidate_entrypoints:
        phase = "probe"
        constraints.append("At least one entrypoint candidate is known; probe hypotheses instead of rereading the homepage.")
    else:
        phase = "recon"
        constraints.append("No confirmed entrypoint yet; recon should discover parameters, methods, or endpoints.")

    if priors["primary"]:
        constraints.append(f"Primary route(s) from task interpretation: {', '.join(priors['primary'][:3])}.")
    if priors["deprioritized"]:
        constraints.append(f"Do not drift into weak alternative routes without strong evidence: {', '.join(priors['deprioritized'][:4])}.")

    recent_same = 0
    if history:
        tail_phase = history[-1].get("phase", "")
        for item in reversed(history):
            if item.get("phase") == tail_phase:
                recent_same += 1
            else:
                break
        if recent_same >= 3 and tail_phase == phase:
            constraints.append(f"The last {recent_same} steps stayed in {phase} without enough progress; force a different action style.")

    return phase, constraints


def info_gain_score(memory: MemoryStore, new_facts: list[tuple[str, str, float]]) -> int:
    score = 0
    for key, value, conf in new_facts:
        prev = memory.get_fact(key)
        if prev is None:
            score += 3 if conf >= 0.85 else 2
        elif prev != value:
            score += 2
    return score


def validate_action(
    phase: str,
    expected_phase: str,
    command: str,
    memory: MemoryStore,
    history: list[dict[str, Any]],
) -> tuple[bool, str]:
    cmd = command.lower()
    if expected_phase == "probe" and phase == "recon" and memory.has_prefix("entrypoint.candidate."):
        return False, "Known entrypoint candidates exist; recon should not continue."
    if expected_phase in {"exploit", "extract"} and phase == "recon":
        return False, "A stronger signal exists; recon is no longer the best action."
    if memory.has_prefix("entrypoint.candidate.") and "sed -n" in cmd and "/tmp/index.html" in cmd:
        return False, "Re-reading the same page is low information gain after parameters are known."
    if phase in {"exploit", "extract"} and not (memory.has_prefix("entrypoint.confirmed.") or memory.has_prefix("vuln.signal.")):
        return False, "Exploit/extract requires a confirmed entrypoint or vulnerability signal."
    if history and "skipped-duplicate-command" in str(history[-1].get("signal", "")):
        return False, "Previous action was duplicate-like; choose a materially different command."
    return True, ""


def reflection_summary(memory: MemoryStore, max_items: int = 8) -> str:
    rows = memory.prefix_rows("reflect.", max_items=max_items)
    if not rows:
        return "none"
    return "\n".join([f"{k}={v} (conf={c:.2f}, step={s})" for k, v, c, s in rows])


def hypothesis_summary(memory: MemoryStore, max_items: int = 12) -> str:
    rows = memory.prefix_rows("hypothesis.state.", max_items=max_items)
    if not rows:
        return "none"
    return "\n".join([f"{k}={v} (conf={c:.2f}, step={s})" for k, v, c, s in rows])


def hypothesis_state(memory: MemoryStore, label: str) -> str | None:
    return memory.get_fact(f"hypothesis.state.{label}")


def upsert_hypothesis(memory: MemoryStore, step: int, state: str, label: str, confidence: float, evidence: str) -> None:
    state = state.strip().lower()
    if state not in {"candidate", "confirmed", "rejected", "weak_candidate"}:
        return
    memory.upsert_fact(f"hypothesis.state.{label}", state, confidence, step)
    memory.upsert_fact(f"hypothesis.evidence.{label}", evidence[:240], confidence, step)


def _command_family(command: str) -> str:
    lower = command.lower()
    if "sqlmap" in lower:
        return "sqlmap"
    if "ffuf" in lower:
        return "ffuf"
    if "curl" in lower:
        return "curl"
    if "nmap" in lower:
        return "nmap"
    return shlex.split(command)[0] if command.strip() else "unknown"


def reflect_step(
    step: int,
    phase: str,
    command: str,
    result: dict[str, Any],
    facts: list[tuple[str, str, float]],
    gain: int,
    memory: MemoryStore,
    history: list[dict[str, Any]],
    success_signal: str,
) -> dict[str, Any]:
    merged = f"{strip_noise(result.get('stdout', ''))}\n{strip_noise(result.get('stderr', ''))}".lower()
    rc = int(result.get("returncode", 1))
    family = _command_family(command)
    found_flag = bool(FLAG_RE.search(merged))
    has_progress_fact = any(k in {"dbms", "current_database", "injection.parameter"} or k.startswith("entrypoint.confirmed.") for k, _, _ in facts)
    repeated_timeouts = 0
    repeated_family = 0
    for item in reversed(history):
        if item.get("returncode") == 124:
            repeated_timeouts += 1
        else:
            break
    for item in reversed(history):
        if _command_family(str(item.get("command", ""))) == family:
            repeated_family += 1
        else:
            break

    judgment = "partial_success"
    failure_reason = "needs_followup"
    strategy_update = "Use the new facts to narrow the next action."
    next_constraints: list[str] = []

    if found_flag:
        judgment = "success"
        failure_reason = "none"
        strategy_update = "Flag found. Move to verification and final reporting."
        next_constraints.append("Do not continue exploitation after a candidate flag is found; verify and stop.")
    elif rc == 124 and (phase in {"exploit", "extract"} or has_progress_fact):
        judgment = "failure"
        failure_reason = "timeout_on_valid_path"
        strategy_update = "The route is likely correct but too expensive. Reduce search space and avoid broad enumeration."
        next_constraints.extend([
            "Do not repeat broad extraction after a timeout on a valid path.",
            "Prefer targeted search, narrower scope, or lighter probes over full enumeration.",
        ])
    elif rc == 124:
        judgment = "failure"
        failure_reason = "timeout_without_signal"
        strategy_update = "The command timed out without enough evidence. Switch to a cheaper probe before retrying."
        next_constraints.extend([
            "After timeout without signal, downgrade cost and verify the route with a smaller command.",
            "Avoid repeating the same timeout-prone action pattern immediately.",
        ])
    elif rc != 0 and ("not found" in merged or "no such file" in merged):
        judgment = "failure"
        failure_reason = "tool_unavailable"
        strategy_update = "The selected tool path is invalid or missing. Verify availability and choose an alternative tool."
        next_constraints.extend([
            "Do not retry the same missing tool command.",
            "Choose a command only from discovered available tools.",
        ])
    elif rc != 0:
        judgment = "failure"
        failure_reason = "command_failed"
        strategy_update = "The command failed operationally. Simplify the command and isolate the failing component."
        next_constraints.extend([
            "Use a simpler command that isolates a single hypothesis.",
            "Do not add more moving parts after an operational failure.",
        ])
    elif gain <= 0 and phase == "recon" and memory.has_prefix("entrypoint.candidate."):
        judgment = "failure"
        failure_reason = "redundant_recon"
        strategy_update = "Recon has stopped producing value. Move to controllability checks on known inputs."
        next_constraints.extend([
            "Do not keep rereading the same pages once candidate entrypoints exist.",
            "Next action must test controllability or produce a measurable diff.",
        ])
    elif gain <= 0 and repeated_family >= 2:
        judgment = "failure"
        failure_reason = "repeated_low_gain_pattern"
        strategy_update = "The same tool family is producing little new information. Change action style or hypothesis."
        next_constraints.extend([
            "Do not repeat the same low-gain tool family without narrowing scope.",
            "The next command must materially differ in hypothesis or observability.",
        ])
    elif gain <= 0:
        judgment = "failure"
        failure_reason = "no_new_signal"
        strategy_update = "No new facts were gained. Change one variable and choose a command with clearer expected evidence."
        next_constraints.extend([
            "The next command must have an explicit expected signal.",
            "Avoid cosmetic command changes that test the same thing.",
        ])
    elif has_progress_fact or gain >= 3:
        judgment = "partial_success"
        failure_reason = "none"
        strategy_update = "Progress is real. Stay on the current route, but narrow scope based on confirmed facts."
        next_constraints.extend([
            "Preserve the strongest confirmed hypothesis.",
            "Use newly confirmed facts to reduce search space before escalating cost.",
        ])

    if repeated_timeouts >= 2:
        next_constraints.append("Multiple recent timeouts detected; impose a stricter budget and prefer targeted extraction.")
    if success_signal:
        next_constraints.append(f"Prefer commands that can directly validate this signal: {success_signal[:180]}")

    unique_constraints: list[str] = []
    seen: set[str] = set()
    for item in next_constraints:
        val = item.strip()
        if val and val not in seen:
            seen.add(val)
            unique_constraints.append(val)

    payload = {
        "judgment": judgment,
        "failure_reason": failure_reason,
        "strategy_update": strategy_update,
        "next_action_constraints": unique_constraints[:4],
        "command_family": family,
    }

    memory.upsert_fact("reflect.last_judgment", judgment, 0.96, step)
    memory.upsert_fact("reflect.last_failure_reason", failure_reason, 0.96, step)
    memory.upsert_fact("reflect.last_strategy_update", strategy_update, 0.94, step)
    memory.upsert_fact("reflect.last_command_family", family, 0.90, step)
    for index, item in enumerate(unique_constraints[:4], start=1):
        memory.upsert_fact(f"reflect.constraint.{index}", item, 0.93, step)
    memory.add_event(step, "reflection", json.dumps(payload, ensure_ascii=False))
    return payload


def update_hypotheses(
    step: int,
    memory: MemoryStore,
    phase: str,
    facts: list[tuple[str, str, float]],
    reflection: dict[str, Any],
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = []
    merged = f"{strip_noise(result.get('stdout', ''))}\n{strip_noise(result.get('stderr', ''))}".lower()
    failure_reason = str(reflection.get("failure_reason", "")).strip()
    judgment = str(reflection.get("judgment", "")).strip()
    priors = task_prior_map(memory)
    primary = set(priors["primary"])
    secondary = set(priors["secondary"])
    deprioritized = set(priors["deprioritized"])

    entry_candidates = [k.split("entrypoint.candidate.", 1)[1] for k, _, _ in facts if k.startswith("entrypoint.candidate.")]
    entry_confirmed = [k.split("entrypoint.confirmed.", 1)[1] for k, _, _ in facts if k.startswith("entrypoint.confirmed.")]
    for name in entry_candidates:
        label = f"entrypoint:{name}"
        if hypothesis_state(memory, label) is None:
            upsert_hypothesis(memory, step, "candidate", label, 0.76, "discovered request input")
            updates.append({"label": label, "state": "candidate", "why": "discovered request input"})
    for name in entry_confirmed:
        label = f"entrypoint:{name}"
        upsert_hypothesis(memory, step, "confirmed", label, 0.94, "confirmed controllable request input")
        updates.append({"label": label, "state": "confirmed", "why": "confirmed controllable request input"})

    vuln_hits = [k.split("vuln.signal.", 1)[1] for k, _, _ in facts if k.startswith("vuln.signal.")]
    for vuln in vuln_hits:
        label = f"vuln:{vuln}"
        if vuln in primary:
            target_state = "candidate"
            conf = 0.84
            why = "matches primary task prior and runtime signal"
        elif vuln in secondary:
            target_state = "candidate"
            conf = 0.72
            why = "matches secondary task prior and runtime signal"
        elif vuln in deprioritized:
            target_state = "weak_candidate"
            conf = 0.56
            why = "runtime signal exists but task prior deprioritizes this route"
        else:
            target_state = "candidate"
            conf = 0.68
            why = "runtime signal observed"

        if vuln == "sqli" and (memory.get_fact("dbms") or memory.get_fact("injection.parameter")):
            target_state = "confirmed"
            conf = 0.95
            why = "dbms or injection facts confirm SQLi route"

        upsert_hypothesis(memory, step, target_state, label, conf, why)
        updates.append({"label": label, "state": target_state, "why": why})

    if memory.get_fact("injection.parameter"):
        label = "vuln:sqli"
        upsert_hypothesis(memory, step, "confirmed", label, 0.96, "confirmed injectable parameter")
        updates.append({"label": label, "state": "confirmed", "why": "confirmed injectable parameter"})

    if failure_reason in {"timeout_on_valid_path", "repeated_low_gain_pattern"} and phase in {"exploit", "extract"}:
        for key, value, _, _ in memory.prefix_rows("hypothesis.state.", max_items=20):
            label = key.split("hypothesis.state.", 1)[1]
            if label.startswith("vuln:") and value == "confirmed":
                upsert_hypothesis(memory, step, "confirmed", label, 0.90, "route remains valid but requires narrower extraction")
                updates.append({"label": label, "state": "confirmed", "why": "route valid, extraction too expensive"})

    if failure_reason in {"timeout_without_signal", "no_new_signal", "command_failed"} and phase == "probe":
        for key, value, _, _ in memory.prefix_rows("hypothesis.state.", max_items=20):
            label = key.split("hypothesis.state.", 1)[1]
            if label.startswith("vuln:") and value == "candidate" and label.split("vuln:", 1)[1] not in primary:
                upsert_hypothesis(memory, step, "rejected", label, 0.88, f"probe failed with {failure_reason}")
                updates.append({"label": label, "state": "rejected", "why": f"probe failed with {failure_reason}"})

    if failure_reason == "redundant_recon":
        for key, value, _, _ in memory.prefix_rows("hypothesis.state.", max_items=20):
            label = key.split("hypothesis.state.", 1)[1]
            if label.startswith("entrypoint:") and value == "candidate":
                upsert_hypothesis(memory, step, "candidate", label, 0.80, "existing entrypoint candidate should be probed next")
                updates.append({"label": label, "state": "candidate", "why": "existing entrypoint candidate should be probed next"})

    if judgment == "success" and FLAG_RE.search(merged):
        upsert_hypothesis(memory, step, "confirmed", "goal:flag", 0.99, "flag observed in output")
        updates.append({"label": "goal:flag", "state": "confirmed", "why": "flag observed in output"})

    memory.add_event(step, "hypothesis_update", json.dumps(updates[:20], ensure_ascii=False))
    return updates


def run_shell_command(command: str, timeout: int, env: dict[str, str], cwd: Path) -> dict[str, Any]:
    start = time.time()
    try:
        proc = subprocess.run(
            ["bash", "-lc", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
            cwd=str(cwd),
        )
        elapsed = time.time() - start
        out = proc.stdout.decode("utf-8", errors="ignore")
        err = proc.stderr.decode("utf-8", errors="ignore")
        return {
            "returncode": proc.returncode,
            "stdout": out,
            "stderr": err,
            "elapsed_sec": round(elapsed, 3),
        }
    except subprocess.TimeoutExpired as exc:
        elapsed = time.time() - start
        out = (exc.stdout or b"").decode("utf-8", errors="ignore")
        err = (exc.stderr or b"").decode("utf-8", errors="ignore")
        return {
            "returncode": 124,
            "stdout": out,
            "stderr": (err + "\n[timeout] command exceeded limit").strip(),
            "elapsed_sec": round(elapsed, 3),
        }


def recent_observations(history: list[dict[str, Any]], limit: int = 5) -> str:
    if not history:
        return "none"
    rows: list[str] = []
    for h in history[-limit:]:
        cmd = str(h.get("command", ""))[:140]
        rc = h.get("returncode", "")
        sig = str(h.get("signal", ""))[:120]
        out = str(h.get("stdout_head", "")).replace("\n", "\\n")[:260]
        err = str(h.get("stderr_head", "")).replace("\n", "\\n")[:180]
        rows.append(f"cmd={cmd} rc={rc} signal={sig} out={out} err={err}")
    return "\n".join(rows)


def extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise RuntimeError(f"Model output is not valid JSON: {text[:500]}")
    return json.loads(match.group(0))
