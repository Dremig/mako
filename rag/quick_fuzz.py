from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent import execute_request, fuzz_execute, load_dotenv


def main() -> None:
    parser = argparse.ArgumentParser(description="Quick fuzz runner for blackbox web target")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--env", type=Path, default=Path(".env"))
    parser.add_argument("--target", type=str, required=True)
    parser.add_argument("--tool", type=str, default="curl", choices=["auto", "http", "curl"])
    parser.add_argument("--kind", type=str, default="path", choices=["path", "param-value", "param-name"])
    parser.add_argument("--wordlist", type=str, default="path-small")
    parser.add_argument("--param", type=str, default="q")
    parser.add_argument("--max-candidates", type=int, default=80)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--out", type=Path, default=Path("rag_data/quick_fuzz_last.json"))
    args = parser.parse_args()

    root = args.root.resolve()
    load_dotenv((root / args.env).resolve())

    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    baseline = execute_request(
        tool=args.tool,
        method="GET",
        url=target,
        params={},
        headers={},
        body="",
        content_type="none",
        timeout=args.timeout,
    )
    if baseline.error:
        raise RuntimeError(f"Baseline request failed: {baseline.error}")

    summary = fuzz_execute(
        root=root,
        tool=args.tool,
        target=target,
        baseline=baseline,
        fuzz_obj={
            "kind": args.kind,
            "url": target,
            "method": "GET",
            "param": args.param,
            "wordlist": args.wordlist,
            "max_candidates": args.max_candidates,
        },
        timeout=args.timeout,
    )

    out_path = (root / args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[quick-fuzz] target={target} tool={args.tool} kind={args.kind} tested={summary['tested']}")
    if summary["found_flag"]:
        print(f"[quick-fuzz] flag={summary['found_flag']}")
    print("[quick-fuzz] top results:")
    for i, r in enumerate(summary["top_results"], start=1):
        print(
            f"{i}. score={r['signal_score']} status={r['status']} len={r['body_len']} "
            f"payload={r['payload']} signal={r['signal']}"
        )
    print(f"[quick-fuzz] saved: {out_path}")


if __name__ == "__main__":
    main()
