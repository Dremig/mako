#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target_url> [objective] [hint]"
  echo "Example: $0 'http://127.0.0.1:8080/' 'Find SQL injection and get flag' 'GET parameter id, SQLi challenge'"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$1"
OBJECTIVE="${2:-Find SQL injection and retrieve flag}"
HINT="${3:-blackbox web SQL injection challenge}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-artifacts/cmd_agent}"

PYTHONUNBUFFERED=1 python3 -u "$ROOT_DIR/rag/cmd_agent.py" \
  --root "$ROOT_DIR" \
  --env ".env" \
  --index "rag_data/index.jsonl" \
  --target "$TARGET" \
  --objective "$OBJECTIVE" \
  --hint "$HINT" \
  --cmd-timeout 120 \
  --mode hybrid \
  --alpha 0.65 \
  --top-k 8 \
  --max-steps 16 \
  --artifact-dir "$ARTIFACT_ROOT"
