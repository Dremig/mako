#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAX_CHUNKS="${RAG_MAX_CHUNKS:-600}"
BATCH_SIZE="${RAG_BATCH_SIZE:-24}"

env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
PYTHONUNBUFFERED=1 python3 -u "$ROOT_DIR/rag/index.py" \
  --root "$ROOT_DIR" \
  --env ".env" \
  --config "rag/config.json" \
  --out "rag_data/index.jsonl" \
  --cache "rag_data/embed_cache.jsonl" \
  --max-chunks "$MAX_CHUNKS" \
  --batch-size "$BATCH_SIZE"
