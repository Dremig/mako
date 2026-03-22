#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPOS_DIR="$ROOT_DIR/repos"

mkdir -p "$REPOS_DIR"

clone_or_update() {
  local name="$1"
  local url="$2"
  local target="$REPOS_DIR/$name"

  if [[ -d "$target/.git" ]]; then
    echo "[*] Updating $name"
    git -C "$target" pull --ff-only
  else
    echo "[*] Cloning $name"
    git clone --depth 1 "$url" "$target"
  fi
}

clone_or_update_sparse_seclists() {
  local name="SecLists"
  local url="https://github.com/danielmiessler/SecLists.git"
  local target="$REPOS_DIR/$name"

  if [[ -d "$target/.git" ]]; then
    echo "[*] Updating $name (sparse)"
    git -C "$target" pull --ff-only
  else
    echo "[*] Cloning $name (sparse)"
    git clone --depth 1 --filter=blob:none --sparse "$url" "$target"
  fi

  git -C "$target" sparse-checkout set \
    Discovery/Web-Content \
    Fuzzing \
    Payloads \
    Passwords/Common-Credentials \
    Usernames
}

clone_or_update "PayloadsAllTheThings" "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
clone_or_update "hacktricks" "https://github.com/HackTricks-wiki/hacktricks.git"
clone_or_update "nuclei-templates" "https://github.com/projectdiscovery/nuclei-templates.git"
clone_or_update "OWASP-CheatSheetSeries" "https://github.com/OWASP/CheatSheetSeries.git"
clone_or_update "fuzzdb" "https://github.com/fuzzdb-project/fuzzdb.git"
clone_or_update_sparse_seclists

echo "[+] Sync complete."
