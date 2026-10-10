#!/usr/bin/env python3
import os
import re
import csv
import json
import math
import time
import hashlib
from pathlib import Path
from collections import Counter

import boto3
from botocore.exceptions import ClientError

CORPUS = Path("data/master_e2e_rag_v2/corpus.jsonl")
QUERIES = Path("data/master_e2e_rag_v2/queries.jsonl")

OUT_CSV = Path("tables/table_retrieval_sensitivity_dense_hybrid_v1.csv")
OUT_DETAIL = Path("data/master_e2e_rag_v2/retrieval_sensitivity_dense_hybrid_v1_detail.jsonl")
OUT_SUMMARY = Path("summaries/retrieval_sensitivity_dense_hybrid_v1_summary.md")
EMBED_CACHE = Path("data/master_e2e_rag_v2/titan_embedding_cache_v1.json")

REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
EMBED_MODEL_ID = os.environ.get("BEDROCK_EMBED_MODEL_ID", "amazon.titan-embed-text-v2:0")

K_VALUES = [1, 3, 5]
HYBRID_ALPHA = 0.5  # 0.5 dense + 0.5 BM25 after per-query min-max normalization

def load_jsonl(path):
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows

def save_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def text_of_doc(d):
    parts = []
    for k in [
        "title", "service", "aws_service", "category", "iam_category",
        "trusted_task", "task", "content", "text", "body", "document"
    ]:
        v = d.get(k)
        if v:
            parts.append(str(v))
    if not parts:
        parts.append(json.dumps(d, ensure_ascii=False))
    return "\n".join(parts)

def text_of_query(q):
    for k in [
        "query", "retrieval_query", "task", "trusted_task",
        "task_request", "user_task", "control_query", "prompt"
    ]:
        v = q.get(k)
        if v:
            return str(v)
    # fallback: compact whole row except metadata
    return json.dumps(q, ensure_ascii=False)

def doc_id(d):
    return d.get("doc_id") or d.get("id") or d.get("document_id")

def case_id(q):
    return q.get("case_id") or q.get("pair_id") or q.get("id")

def is_poison_doc(d):
    did = doc_id(d) or ""
    kind = str(d.get("kind", "")).lower()
    return (
        "poison" in did.lower()
        or "poi" in did.lower()
        or "poison" in kind
        or "retrieval_competitive" in did.lower()
    )

def tokenize(s):
    return re.findall(r"[a-zA-Z0-9:_./*#=-]+", s.lower())

class BM25:
    def __init__(self, docs):
        self.docs = docs
        self.doc_tokens = [tokenize(text_of_doc(d)) for d in docs]
        self.N = len(docs)
        self.avgdl = sum(len(t) for t in self.doc_tokens) / max(1, self.N)
        self.df = Counter()
        for toks in self.doc_tokens:
            self.df.update(set(toks))
        self.idf = {
            term: math.log(1 + (self.N - df + 0.5) / (df + 0.5))
            for term, df in self.df.items()
        }

    def scores(self, query, k1=1.5, b=0.75):
        q = tokenize(query)
        out = []
        for idx, toks in enumerate(self.doc_tokens):
            tf = Counter(toks)
            dl = len(toks)
            score = 0.0
            for term in q:
                if term not in tf:
                    continue
                idf = self.idf.get(term, 0.0)
                freq = tf[term]
                denom = freq + k1 * (1 - b + b * dl / max(1e-9, self.avgdl))
                score += idf * (freq * (k1 + 1)) / denom
            out.append(score)
        return out

def minmax(xs):
    if not xs:
        return []
    mn, mx = min(xs), max(xs)
    if abs(mx - mn) < 1e-12:
        return [0.0 for _ in xs]
    return [(x - mn) / (mx - mn) for x in xs]

def dot(a, b):
    return sum(x*y for x, y in zip(a, b))

def norm(a):
    return math.sqrt(sum(x*x for x in a))

def cosine(a, b):
    na, nb = norm(a), norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return dot(a, b) / (na * nb)

def hash_text(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def load_cache():
    if EMBED_CACHE.exists():
        return json.loads(EMBED_CACHE.read_text(encoding="utf-8"))
    return {}

def save_cache(cache):
    EMBED_CACHE.parent.mkdir(parents=True, exist_ok=True)
    EMBED_CACHE.write_text(json.dumps(cache), encoding="utf-8")

def embed_text(client, text, cache):
    # Titan V2 supports 8K tokens; keep this conservative for benchmark docs.
    text = text[:12000]
    h = hash_text(EMBED_MODEL_ID + "\n" + text)
    if h in cache:
        return cache[h]

    body = {
        "inputText": text,
        "dimensions": 1024,
        "normalize": True
    }

    for attempt in range(5):
        try:
            resp = client.invoke_model(
                modelId=EMBED_MODEL_ID,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json",
            )
            obj = json.loads(resp["body"].read())
            emb = obj.get("embedding")
            if not emb:
                raise RuntimeError(f"No embedding in response keys={list(obj.keys())}")
            cache[h] = emb
            if len(cache) % 25 == 0:
                save_cache(cache)
            return emb
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in {"ThrottlingException", "TooManyRequestsException", "ServiceUnavailableException"}:
                time.sleep(2 ** attempt)
                continue
            raise
        except Exception:
            if attempt == 4:
                raise
            time.sleep(2 ** attempt)

def dense_scores(query_emb, doc_embs):
    return [cosine(query_emb, e) for e in doc_embs]

def rank_docs(docs, scores):
    return sorted(
        [{"doc_id": doc_id(d), "score": float(s), "kind": d.get("kind", ""), "case_id": d.get("case_id", "")}
         for d, s in zip(docs, scores)],
        key=lambda x: x["score"],
        reverse=True
    )

def find_expected_ids(case, docs):
    clean = None
    poison = None

    exact_clean = f"{case}::clean"
    if any(doc_id(d) == exact_clean for d in docs):
        clean = exact_clean

    poison_candidates = []
    clean_candidates = []
    for d in docs:
        did = doc_id(d) or ""
        if did.startswith(f"{case}::"):
            if is_poison_doc(d):
                poison_candidates.append(did)
            elif "clean" in did.lower():
                clean_candidates.append(did)

    if clean is None and clean_candidates:
        clean = sorted(clean_candidates)[0]
    if poison_candidates:
        poison = sorted(poison_candidates)[0]

    return clean, poison

def rank_of(target_id, ranking):
    if not target_id:
        return None
    for i, r in enumerate(ranking, start=1):
        if r["doc_id"] == target_id:
            return i
    return None

def at_k(rank, k):
    return rank is not None and rank <= k

def evaluate_retriever(name, queries, docs, bm25_ctrl, bm25_poi, doc_embs_by_id, query_embs_by_case):
    details = []
    rows = []

    ctrl_docs = [d for d in docs if not is_poison_doc(d)]
    poi_docs = docs

    ctrl_id_to_emb = [doc_embs_by_id[doc_id(d)] for d in ctrl_docs]
    poi_id_to_emb = [doc_embs_by_id[doc_id(d)] for d in poi_docs]

    for q in queries:
        cid = case_id(q)
        qtext = text_of_query(q)
        clean_id, poison_id = find_expected_ids(cid, docs)

        if name == "bm25":
            ctrl_scores = bm25_ctrl.scores(qtext)
            poi_scores = bm25_poi.scores(qtext)

        elif name == "dense":
            qemb = query_embs_by_case[cid]
            ctrl_scores = dense_scores(qemb, ctrl_id_to_emb)
            poi_scores = dense_scores(qemb, poi_id_to_emb)

        elif name == "hybrid":
            qemb = query_embs_by_case[cid]

            ctrl_bm25 = bm25_ctrl.scores(qtext)
            poi_bm25 = bm25_poi.scores(qtext)

            ctrl_dense = dense_scores(qemb, ctrl_id_to_emb)
            poi_dense = dense_scores(qemb, poi_id_to_emb)

            ctrl_scores = [
                HYBRID_ALPHA * d + (1 - HYBRID_ALPHA) * b
                for d, b in zip(minmax(ctrl_dense), minmax(ctrl_bm25))
            ]
            poi_scores = [
                HYBRID_ALPHA * d + (1 - HYBRID_ALPHA) * b
                for d, b in zip(minmax(poi_dense), minmax(poi_bm25))
            ]

        else:
            raise ValueError(name)

        ctrl_ranked = rank_docs(ctrl_docs, ctrl_scores)
        poi_ranked = rank_docs(poi_docs, poi_scores)

        clean_ctrl_rank = rank_of(clean_id, ctrl_ranked)
        clean_poi_rank = rank_of(clean_id, poi_ranked)
        poison_rank = rank_of(poison_id, poi_ranked)

        drow = {
            "retriever": name,
            "case_id": cid,
            "clean_doc_id": clean_id,
            "poison_doc_id": poison_id,
            "clean_ctrl_rank": clean_ctrl_rank,
            "clean_poi_rank": clean_poi_rank,
            "poison_rank": poison_rank,
            "ctrl_top5": ctrl_ranked[:5],
            "poi_top5": poi_ranked[:5],
        }
        details.append(drow)

    n = len(details)
    poison_ranks = [d["poison_rank"] for d in details if d["poison_rank"] is not None]
    poison_ranks_sorted = sorted(poison_ranks)
    median_poison_rank = poison_ranks_sorted[len(poison_ranks_sorted)//2] if poison_ranks_sorted else None

    summary = {
        "retriever": name,
        "cases": n,
        "poison_at_1": sum(at_k(d["poison_rank"], 1) for d in details),
        "poison_at_3": sum(at_k(d["poison_rank"], 3) for d in details),
        "poison_at_5": sum(at_k(d["poison_rank"], 5) for d in details),
        "clean_ctrl_at_5": sum(at_k(d["clean_ctrl_rank"], 5) for d in details),
        "clean_poi_at_5": sum(at_k(d["clean_poi_rank"], 5) for d in details),
        "median_poison_rank": median_poison_rank,
        "mean_poison_rank": round(sum(poison_ranks)/len(poison_ranks), 2) if poison_ranks else None,
    }

    return summary, details

def main():
    docs = load_jsonl(CORPUS)
    queries = load_jsonl(QUERIES)

    print(f"Loaded docs={len(docs)} queries={len(queries)}")
    print(f"Embedding model: {EMBED_MODEL_ID}")

    ctrl_docs = [d for d in docs if not is_poison_doc(d)]
    poi_docs = docs

    bm25_ctrl = BM25(ctrl_docs)
    bm25_poi = BM25(poi_docs)

    cache = load_cache()
    client = boto3.client("bedrock-runtime", region_name=REGION)

    # Embed docs and queries once.
    doc_embs_by_id = {}
    for i, d in enumerate(docs, start=1):
        did = doc_id(d)
        if not did:
            raise ValueError(f"Document missing doc_id/id: {d}")
        if did not in doc_embs_by_id:
            doc_embs_by_id[did] = embed_text(client, text_of_doc(d), cache)
        if i % 50 == 0:
            print(f"embedded docs {i}/{len(docs)} cache={len(cache)}")
            save_cache(cache)

    query_embs_by_case = {}
    for i, q in enumerate(queries, start=1):
        cid = case_id(q)
        if not cid:
            raise ValueError(f"Query missing case_id/pair_id/id: {q}")
        query_embs_by_case[cid] = embed_text(client, text_of_query(q), cache)
        if i % 20 == 0:
            print(f"embedded queries {i}/{len(queries)} cache={len(cache)}")
            save_cache(cache)

    save_cache(cache)

    all_summaries = []
    all_details = []

    for retriever in ["bm25", "dense", "hybrid"]:
        summary, details = evaluate_retriever(
            retriever,
            queries,
            docs,
            bm25_ctrl,
            bm25_poi,
            doc_embs_by_id,
            query_embs_by_case,
        )
        all_summaries.append(summary)
        all_details.extend(details)

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "retriever", "cases", "poison_at_1", "poison_at_3", "poison_at_5",
            "clean_ctrl_at_5", "clean_poi_at_5", "median_poison_rank", "mean_poison_rank"
        ]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(all_summaries)

    save_jsonl(OUT_DETAIL, all_details)

    lines = ["# Retrieval sensitivity: BM25 vs dense vs hybrid", ""]
    lines.append("| Retriever | Poison@1 | Poison@3 | Poison@5 | Clean@5 ctrl | Clean@5 poi | Median poison rank |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for s in all_summaries:
        lines.append(
            f"| {s['retriever']} | {s['poison_at_1']}/60 | {s['poison_at_3']}/60 | {s['poison_at_5']}/60 | "
            f"{s['clean_ctrl_at_5']}/60 | {s['clean_poi_at_5']}/60 | {s['median_poison_rank']} |"
        )
    lines.append("")
    lines.append(f"Embedding model: `{EMBED_MODEL_ID}`")
    lines.append(f"Detail JSONL: `{OUT_DETAIL}`")
    lines.append(f"CSV: `{OUT_CSV}`")
    OUT_SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    OUT_SUMMARY.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("")
    print("---- retrieval sensitivity summary ----")
    print(OUT_SUMMARY.read_text(encoding="utf-8"))

if __name__ == "__main__":
    main()
