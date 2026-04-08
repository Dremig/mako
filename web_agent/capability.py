from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

from web_agent.solver_shared import ACTION_SCHEMAS, MemoryStore

SHELL_BUILTINS = {
    "alias",
    "bg",
    "cd",
    "echo",
    "eval",
    "exec",
    "exit",
    "export",
    "fg",
    "pwd",
    "read",
    "set",
    "shift",
    "source",
    "test",
    "time",
    "trap",
    "true",
    "type",
    "ulimit",
    "umask",
    "unset",
}


def _extract_command(proposal: dict[str, Any]) -> str:
    return str(proposal.get("command", "")).strip()


def detect_capability_gap(proposal: dict[str, Any], available_tools: dict[str, str]) -> dict[str, Any]:
    decision = str(proposal.get("decision", "command")).strip().lower()
    if decision == "action":
        return {"kind": "none", "reason": "structured_action"}
    command = _extract_command(proposal)
    lower = command.lower()
    if "beautifulsoup" in lower or "bs4" in lower:
        return {
            "kind": "optional_python_dependency",
            "dependency": "beautifulsoup4",
            "reason": "proposal depends on BeautifulSoup/bs4 which may be absent",
        }
    try:
        tokens = shlex.split(command)
    except Exception:
        tokens = command.split()
    if not tokens:
        return {"kind": "none", "reason": "empty_command"}
    first = tokens[0]
    if "/" in first or first.startswith("."):
        return {"kind": "none", "reason": "path_command"}
    if first in SHELL_BUILTINS:
        return {"kind": "none", "reason": "shell_builtin"}
    if first in available_tools:
        return {"kind": "none", "reason": "tool_available"}
    return {
        "kind": "missing_tool",
        "tool": first,
        "reason": f"tool `{first}` is not currently available",
    }


def _html_helper_path(artifact_dir: Path) -> Path:
    return artifact_dir / "capability_helpers" / "html_surface_helper.py"


def _write_html_surface_helper(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = """from __future__ import annotations

import argparse
import json
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path


class SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links = []
        self.forms = []
        self.filenames = []
        self.comments = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        attr_map = {k: v or "" for k, v in attrs}
        if tag == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(href)
        elif tag == "form":
            self._form = {
                "action": attr_map.get("action", "").strip(),
                "method": (attr_map.get("method", "GET") or "GET").upper(),
                "inputs": [],
                "hidden": {},
            }
        elif tag == "input" and isinstance(self._form, dict):
            name = attr_map.get("name", "").strip()
            kind = attr_map.get("type", "").strip().lower()
            value = attr_map.get("value", "")
            if name:
                self._form["inputs"].append(name)
                if kind == "hidden":
                    self._form["hidden"][name] = value
        elif tag in {"script", "img", "source"}:
            raw = attr_map.get("src", "").strip()
            if raw:
                self.links.append(raw)

    def handle_endtag(self, tag):
        if tag == "form" and isinstance(self._form, dict):
            self.forms.append(self._form)
            self._form = None

    def handle_comment(self, data):
        text = (data or "").strip()
        if text:
            self.comments.append(text[:300])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--html-file", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    html = Path(args.html_file).read_text(encoding="utf-8", errors="ignore")
    p = SurfaceParser()
    p.feed(html)
    candidate_paths = []
    for raw in p.links:
        if raw.startswith(("javascript:", "mailto:", "#")):
            continue
        normalized = urllib.parse.urljoin(args.base_url, raw)
        candidate_paths.append(normalized)
        tail = Path(urllib.parse.urlparse(normalized).path).name
        if "." in tail:
            p.filenames.append(tail)

    payload = {
        "candidate_paths": sorted(set(candidate_paths))[:80],
        "forms": p.forms[:20],
        "filenames": sorted(set(x for x in p.filenames if x))[:40],
        "comments": p.comments[:20],
    }
    text = json.dumps(payload, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
"""
    path.write_text(content, encoding="utf-8")


def score_capability_options(
    *,
    proposal: dict[str, Any],
    gap: dict[str, Any],
    active_action: str,
    memory: MemoryStore,
) -> list[dict[str, Any]]:
    options: list[dict[str, Any]] = []
    if gap.get("kind") == "none":
        return [{"name": "keep_current", "score": 1.0, "reason": "no capability gap detected"}]
    if active_action and active_action in ACTION_SCHEMAS:
        options.append(
            {
                "name": "reuse_existing_action",
                "score": 0.92,
                "reason": f"planner already suggested stable action `{active_action}`",
            }
        )
    if gap.get("kind") == "optional_python_dependency":
        html_file = memory.get_fact("artifact.html_file") or ""
        if not html_file:
            artifact_dir = memory.get_fact("artifact.dir") or ""
            if artifact_dir:
                html_file = str(Path(artifact_dir) / "root.body")
        if html_file:
            options.append(
                {
                    "name": "write_helper_script",
                    "score": 0.78,
                    "reason": "HTML parsing can be handled with a small stdlib helper script",
                }
            )
        options.append(
            {
                "name": "install_dependency",
                "score": 0.36,
                "reason": "installing the missing Python package may unblock the proposal but changes the environment",
            }
        )
    options.append(
        {
            "name": "replan",
            "score": 0.15,
            "reason": "drop the current route and ask for a different proposal",
        }
    )
    return sorted(options, key=lambda item: float(item.get("score", 0.0)), reverse=True)


def resolve_capability_gap(
    *,
    proposal: dict[str, Any],
    active_action: str,
    available_tools: dict[str, str],
    memory: MemoryStore,
    artifact_dir: Path,
) -> dict[str, Any]:
    gap = detect_capability_gap(proposal, available_tools)
    scores = score_capability_options(proposal=proposal, gap=gap, active_action=active_action, memory=memory)
    selected = scores[0] if scores else {"name": "keep_current", "score": 1.0, "reason": "no scores"}
    out: dict[str, Any] = {
        "gap": gap,
        "scores": scores,
        "selected": selected["name"],
        "selected_score": float(selected.get("score", 0.0)),
        "reason": str(selected.get("reason", "")),
        "proposal": proposal,
        "performed": False,
        "acquisition_command": "",
    }
    if selected["name"] == "reuse_existing_action":
        revised = dict(proposal)
        revised["decision"] = "action"
        revised["action"] = {"name": active_action, "args": {}}
        revised["command"] = ""
        revised["analysis"] = (
            str(revised.get("analysis", "")).strip() + f" Corrected by capability manager to use `{active_action}`."
        ).strip()
        out["proposal"] = revised
        return out
    if selected["name"] == "write_helper_script":
        helper_path = _html_helper_path(artifact_dir)
        _write_html_surface_helper(helper_path)
        html_file = memory.get_fact("artifact.html_file") or str(artifact_dir / "root.body")
        base_url = memory.get_fact("target") or "$TARGET_URL"
        out_file = str(artifact_dir / "html_attack_surface_helper.json")
        revised = dict(proposal)
        revised["decision"] = "command"
        revised["phase"] = "extract"
        revised["command"] = (
            f"python3 {shlex.quote(str(helper_path))} "
            f"--html-file {shlex.quote(html_file)} "
            f"--base-url {shlex.quote(base_url)} "
            f"--out {shlex.quote(out_file)}"
        )
        revised["success_signal"] = revised.get("success_signal") or "candidate paths or form fields extracted from HTML"
        revised["analysis"] = (
            str(revised.get("analysis", "")).strip() + " Capability manager wrote a stdlib helper to avoid missing bs4."
        ).strip()
        out["proposal"] = revised
        out["performed"] = True
        out["artifact"] = str(helper_path)
        return out
    if selected["name"] == "install_dependency":
        out["acquisition_command"] = "python3 -m pip install beautifulsoup4"
        return out
    return out

