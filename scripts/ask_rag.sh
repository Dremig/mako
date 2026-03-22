#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 \"your question\" [--mode hybrid|dense|bm25] [--top-k 8] [--alpha 0.65]"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUESTION="$1"
shift || true

python3 "$ROOT_DIR/rag/query.py" \
  "$QUESTION" \
  --root "$ROOT_DIR" \
  --env ".env" \
  --index "rag_data/index.jsonl" \
  "$@"
