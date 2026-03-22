from __future__ import annotations

import argparse
import math
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from common import chat_completion, cosine_similarity, embed_texts, load_dotenv, require_env


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ask local blackbox CTF RAG index.")
    parser.add_argument("question", type=str, help="question to ask")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="blackbox-kb root")
    parser.add_argument("--env", type=Path, default=Path(".env"), help=".env file path")
    parser.add_argument("--index", type=Path, default=Path("rag_data/index.jsonl"), help="index file path")
    parser.add_argument("--top-k", type=int, default=6, help="retrieval top-k")
    parser.add_argument("--mode", type=str, default="hybrid", choices=["dense", "bm25", "hybrid"], help="retrieval mode")
    parser.add_argument("--alpha", type=float, default=0.65, help="hybrid weight for dense score")
    parser.add_argument("--bm25-k1", type=float, default=1.5, help="BM25 k1")
    parser.add_argument("--bm25-b", type=float, default=0.75, help="BM25 b")
    parser.add_argument("--max-context-chars", type=int, default=9000, help="max chars for retrieved context")
    return parser.parse_args()


def load_index(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+|[\u4e00-\u9fff]")


def tokenize(text: str) -> list[str]:
    return [m.group(0).lower() for m in TOKEN_RE.finditer(text)]


def normalize_minmax(scores: list[float]) -> list[float]:
    if not scores:
        return []
    lo = min(scores)
    hi = max(scores)
    if hi <= lo:
        return [0.0 for _ in scores]
    return [(x - lo) / (hi - lo) for x in scores]


def dense_scores(question_embedding: list[float], docs: list[dict[str, Any]]) -> list[float]:
    return [cosine_similarity(question_embedding, doc["embedding"]) for doc in docs]


def bm25_scores(
    question: str,
    docs: list[dict[str, Any]],
    k1: float = 1.5,
    b: float = 0.75,
) -> list[float]:
    query_terms = tokenize(question)
    if not query_terms:
        return [0.0 for _ in docs]

    tf_list: list[Counter[str]] = []
    df: Counter[str] = Counter()
    doc_lens: list[int] = []

    for doc in docs:
        terms = tokenize(doc["text"])
        tf = Counter(terms)
        tf_list.append(tf)
        dl = sum(tf.values())
        doc_lens.append(dl)
        for term in tf:
            df[term] += 1

    n_docs = len(docs)
    avgdl = (sum(doc_lens) / n_docs) if n_docs > 0 else 1.0
    if avgdl <= 0:
        avgdl = 1.0

    qf = Counter(query_terms)
    scores: list[float] = []
    for tf, dl in zip(tf_list, doc_lens):
        score = 0.0
        norm = k1 * (1 - b + b * (dl / avgdl))
        for term, term_qf in qf.items():
            term_tf = tf.get(term, 0)
            if term_tf <= 0:
                continue
            term_df = df.get(term, 0)
            idf = math.log(1 + ((n_docs - term_df + 0.5) / (term_df + 0.5)))
            score += term_qf * (idf * ((term_tf * (k1 + 1)) / (term_tf + norm)))
        scores.append(score)
    return scores


def retrieve(
    question: str,
    docs: list[dict[str, Any]],
    top_k: int,
    mode: str,
    alpha: float,
    question_embedding: list[float] | None,
    bm25_k1: float,
    bm25_b: float,
) -> list[dict[str, Any]]:
    if mode in {"dense", "hybrid"}:
        if question_embedding is None:
            raise RuntimeError("question_embedding is required for dense/hybrid mode")
        dense_raw = dense_scores(question_embedding, docs)
    else:
        dense_raw = [0.0 for _ in docs]

    if mode in {"bm25", "hybrid"}:
        bm25_raw = bm25_scores(question, docs, k1=bm25_k1, b=bm25_b)
    else:
        bm25_raw = [0.0 for _ in docs]

    dense_norm = normalize_minmax(dense_raw)
    bm25_norm = normalize_minmax(bm25_raw)
    alpha = max(0.0, min(1.0, alpha))

    scored: list[dict[str, Any]] = []
    for i, doc in enumerate(docs):
        if mode == "dense":
            final_score = dense_raw[i]
        elif mode == "bm25":
            final_score = bm25_raw[i]
        else:
            final_score = alpha * dense_norm[i] + (1.0 - alpha) * bm25_norm[i]
        scored.append(
            {
                "score": final_score,
                "dense_score": dense_raw[i],
                "bm25_score": bm25_raw[i],
                "dense_norm": dense_norm[i],
                "bm25_norm": bm25_norm[i],
                **doc,
            }
        )
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:top_k]


def build_context(hits: list[dict[str, Any]], max_context_chars: int) -> str:
    sections: list[str] = []
    used = 0
    for h in hits:
        header = (
            f"[score={h['score']:.4f} dense={h['dense_score']:.4f} bm25={h['bm25_score']:.4f}] "
            f"{h['path']}#chunk{h['chunk_index']}\n"
        )
        body = h["text"].strip()
        block = header + body + "\n"
        if used + len(block) > max_context_chars:
            remain = max(0, max_context_chars - used - len(header) - 10)
            if remain > 120:
                block = header + body[:remain] + "\n"
            else:
                break
        sections.append(block)
        used += len(block)
    return "\n".join(sections)


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    load_dotenv((root / args.env).resolve())

    api_key = require_env("OPENAI_API_KEY")
    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").strip()
    embed_model = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small").strip()
    chat_model = os.getenv("OPENAI_CHAT_MODEL", "gpt-4.1-mini").strip()

    index_path = (root / args.index).resolve()
    if not index_path.exists():
        raise RuntimeError(f"Index file not found: {index_path}")

    docs = load_index(index_path)
    if not docs:
        raise RuntimeError("Index is empty.")

    q_embedding: list[float] | None = None
    if args.mode in {"dense", "hybrid"}:
        q_embedding = embed_texts(base_url=base_url, api_key=api_key, model=embed_model, texts=[args.question])[0]

    hits = retrieve(
        question=args.question,
        docs=docs,
        top_k=max(1, args.top_k),
        mode=args.mode,
        alpha=args.alpha,
        question_embedding=q_embedding,
        bm25_k1=args.bm25_k1,
        bm25_b=args.bm25_b,
    )
    context = build_context(hits, max_context_chars=max(500, args.max_context_chars))

    system_prompt = (
        "You are a blackbox CTF web exploitation assistant. "
        "Use retrieved context first, then infer cautiously. "
        "If context is insufficient, say what to test next."
    )
    user_prompt = (
        f"Question:\n{args.question}\n\n"
        f"Retrieved Context:\n{context}\n\n"
        "Output format:\n"
        "1) concise answer\n"
        "2) concrete test steps/commands\n"
        "3) risk or uncertainty"
    )

    answer = chat_completion(
        base_url=base_url,
        api_key=api_key,
        model=chat_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )

    print("=== Retrieved ===")
    for i, h in enumerate(hits, start=1):
        print(
            f"{i}. score={h['score']:.4f} dense={h['dense_score']:.4f} "
            f"bm25={h['bm25_score']:.4f} {h['path']}#chunk{h['chunk_index']}"
        )
    print("\n=== Answer ===")
    print(answer)


if __name__ == "__main__":
    main()
