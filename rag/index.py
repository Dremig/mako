from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from common import embed_texts, load_dotenv, require_env


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build local RAG index for blackbox CTF KB.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="blackbox-kb root")
    parser.add_argument("--env", type=Path, default=Path(".env"), help=".env file path")
    parser.add_argument("--config", type=Path, default=Path("rag/config.json"), help="config json path")
    parser.add_argument("--out", type=Path, default=Path("rag_data/index.jsonl"), help="output index file")
    parser.add_argument("--cache", type=Path, default=Path("rag_data/embed_cache.jsonl"), help="embedding cache file")
    parser.add_argument("--batch-size", type=int, default=32, help="embedding batch size")
    parser.add_argument("--max-chunks", type=int, default=0, help="override max chunks (0 = use config)")
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def is_probably_text(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            sample = f.read(2048)
        return b"\x00" not in sample
    except OSError:
        return False


def chunk_text(text: str, chunk_chars: int, overlap: int) -> list[str]:
    cleaned = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not cleaned:
        return []
    if chunk_chars <= overlap:
        overlap = max(0, chunk_chars // 5)
    chunks: list[str] = []
    step = max(1, chunk_chars - overlap)
    start = 0
    while start < len(cleaned):
        end = min(len(cleaned), start + chunk_chars)
        chunk = cleaned[start:end].strip()
        if len(chunk) >= 80:
            chunks.append(chunk)
        start += step
    return chunks


def iter_candidate_files(root: Path, config: dict[str, Any]) -> list[Path]:
    repos_root = root / config["repos_root"]
    extensions = set(config["include_extensions"])
    max_file_size = int(config["max_file_size_kb"]) * 1024
    files: list[Path] = []

    for source in config["sources"]:
        repo = source["repo"]
        base = repos_root / repo
        if not base.exists():
            continue
        paths = source.get("paths", [])
        targets = [base] if not paths else [base / p for p in paths]
        for target in targets:
            if not target.exists():
                continue
            if target.is_file():
                if target.suffix.lower() in extensions and target.stat().st_size <= max_file_size and is_probably_text(target):
                    files.append(target)
                continue
            for p in target.rglob("*"):
                if not p.is_file():
                    continue
                if p.suffix.lower() not in extensions:
                    continue
                try:
                    if p.stat().st_size > max_file_size:
                        continue
                except OSError:
                    continue
                if not is_probably_text(p):
                    continue
                files.append(p)

    # keep deterministic order + deduplicate
    unique = sorted(set(files))
    return unique


def load_embed_cache(cache_path: Path) -> dict[str, list[float]]:
    cache: dict[str, list[float]] = {}
    if not cache_path.exists():
        return cache
    with cache_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            cache[obj["hash"]] = obj["embedding"]
    return cache


def save_embed_cache(cache_path: Path, cache: dict[str, list[float]]) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with cache_path.open("w", encoding="utf-8") as f:
        for key, vec in cache.items():
            f.write(json.dumps({"hash": key, "embedding": vec}, ensure_ascii=False) + "\n")


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    load_dotenv((root / args.env).resolve())
    config = read_json((root / args.config).resolve())

    api_key = require_env("OPENAI_API_KEY")
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").strip()
    embed_model = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small").strip()

    out_path = (root / args.out).resolve()
    cache_path = (root / args.cache).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    candidate_files = iter_candidate_files(root, config)
    chunk_chars = int(config["chunk_chars"])
    chunk_overlap = int(config["chunk_overlap"])
    max_chunks = int(config.get("max_chunks", 0))
    if args.max_chunks > 0:
        max_chunks = args.max_chunks

    chunks: list[dict[str, Any]] = []
    for file_path in candidate_files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        repo_name = file_path.relative_to(root / config["repos_root"]).parts[0]
        rel_path = str(file_path.relative_to(root))
        parts = chunk_text(text, chunk_chars=chunk_chars, overlap=chunk_overlap)
        for idx, piece in enumerate(parts):
            chunks.append(
                {
                    "id": len(chunks),
                    "repo": repo_name,
                    "path": rel_path,
                    "chunk_index": idx,
                    "text": piece,
                }
            )
            if max_chunks > 0 and len(chunks) >= max_chunks:
                break
        if max_chunks > 0 and len(chunks) >= max_chunks:
            break

    if not chunks:
        raise RuntimeError("No chunks generated. Check config paths and file extensions.")

    embed_cache = load_embed_cache(cache_path)
    to_embed_texts: list[str] = []
    to_embed_hashes: list[str] = []

    for item in chunks:
        key = hashlib.sha256((embed_model + "\n" + item["text"]).encode("utf-8")).hexdigest()
        item["hash"] = key
        if key not in embed_cache:
            to_embed_hashes.append(key)
            to_embed_texts.append(item["text"])

    if to_embed_texts:
        batch_size = max(1, args.batch_size)
        for i in range(0, len(to_embed_texts), batch_size):
            batch_texts = to_embed_texts[i : i + batch_size]
            batch_hashes = to_embed_hashes[i : i + batch_size]
            vectors = embed_texts(base_url=base_url, api_key=api_key, model=embed_model, texts=batch_texts)
            for h, vec in zip(batch_hashes, vectors):
                embed_cache[h] = vec
            print(f"[embed] {min(i + batch_size, len(to_embed_texts))}/{len(to_embed_texts)}")
        save_embed_cache(cache_path, embed_cache)

    with out_path.open("w", encoding="utf-8") as f:
        for item in chunks:
            output_obj = {
                "id": item["id"],
                "repo": item["repo"],
                "path": item["path"],
                "chunk_index": item["chunk_index"],
                "text": item["text"],
                "embedding": embed_cache[item["hash"]],
            }
            f.write(json.dumps(output_obj, ensure_ascii=False) + "\n")

    print(f"[done] chunks={len(chunks)} out={out_path}")


if __name__ == "__main__":
    main()
