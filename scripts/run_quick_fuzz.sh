#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target_url> [kind] [wordlist]"
  echo "Example: $0 'http://127.0.0.1:8080/' path path-small"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$1"
KIND="${2:-path}"
WORDLIST="${3:-path-small}"

python3 "$ROOT_DIR/rag/quick_fuzz.py" \
  --root "$ROOT_DIR" \
  --env ".env" \
  --target "$TARGET" \
  --tool curl \
  --kind "$KIND" \
  --wordlist "$WORDLIST" \
  --max-candidates 80
