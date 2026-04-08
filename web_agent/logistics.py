from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from web_agent.solver_shared import strip_noise


def classify_tool_family(name: str) -> str:
    tool = name.strip().lower()
    if tool in {"bs4", "beautifulsoup4", "pillow", "numpy", "requests"}:
        return "python_package"
    if tool in {"zsteg", "binwalk", "exiftool", "steghide", "foremost", "strings", "file"}:
        return "cli_tool"
    if tool in {"stegsolve"}:
        return "gui_tool"
    return "unknown"


def build_logistics_request(capability: dict[str, Any]) -> dict[str, Any]:
    gap = capability.get("gap", {}) if isinstance(capability.get("gap"), dict) else {}
    selected = str(capability.get("selected", "")).strip()
    if selected == "write_helper_script":
        return {
            "kind": "helper_generation",
            "goal": "generate_small_helper",
            "tool_family": "builtin_script",
            "command": "",
        }
    if selected == "install_dependency":
        dependency = str(gap.get("dependency") or gap.get("tool") or "").strip()
        family = classify_tool_family(dependency)
        command = ""
        if family == "python_package" and dependency:
            command = f"python3 -m pip install {shlex.quote(dependency)}"
        return {
            "kind": "environment_setup",
            "goal": "install_missing_dependency",
            "dependency": dependency,
            "tool_family": family,
            "command": command,
        }
    return {
        "kind": "none",
        "goal": "no_logistics_needed",
        "tool_family": "none",
        "command": "",
    }


def perform_logistics_request(
    *,
    request: dict[str, Any],
    run_shell_command: Any,
    env: dict[str, str],
    artifact_dir: Path,
    timeout: int,
) -> dict[str, Any]:
    command = str(request.get("command", "")).strip()
    result = {
        "performed": False,
        "returncode": 0,
        "stdout_head": "",
        "stderr_head": "",
        "command": command,
    }
    if not command:
        return result
    proc = run_shell_command(command, timeout=timeout, env=env, cwd=artifact_dir)
    result["performed"] = True
    result["returncode"] = int(proc.get("returncode", 1))
    result["stdout_head"] = strip_noise(str(proc.get("stdout", "")))[:1000]
    result["stderr_head"] = strip_noise(str(proc.get("stderr", "")))[:800]
    return result

