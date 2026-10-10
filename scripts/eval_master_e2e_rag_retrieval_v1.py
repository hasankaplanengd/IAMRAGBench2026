#!/usr/bin/env python3
import json
import math
import re
from pathlib import Path
from collections import Counter, defaultdict

CORPUS = Path("data/master_e2e_rag_v1/corpus.jsonl")
QUERIES = Path("data/master_e2e_rag_v1/queries.jsonl")
OUT_DIR = Path("data/master_e2e_rag_v1")
TABLE_DIR = Path("tables")
SUMMARY_DIR = Path("summaries")

TABLE_DIR.mkdir(exist_ok=True)
SUMMARY_DIR.mkdir(exist_ok=True)

def load_jsonl(path):
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows

def tokenize(text):
    return re.findall(r"[a-zA-Z0-9:_./*\-#]+", text.lower())

docs = load_jsonl(CORPUS)
queries = load_jsonl(QUERIES)

doc_tokens = []
df = Counter()

for d in docs:
    toks = tokenize(d["text"])
    doc_tokens.append(toks)
    for t in set(toks):
        df[t] += 1

N = len(docs)
avgdl = sum(len(t) for t in doc_tokens) / max(1, N)

def bm25_score(q_tokens, d_tokens):
    k1 = 1.5
    b = 0.75
    tf = Counter(d_tokens)
    score = 0.0
    dl = len(d_tokens)

    for q in q_tokens:
        if q not in tf:
            continue
        n_q = df.get(q, 0)
        idf = math.log(1 + (N - n_q + 0.5) / (n_q + 0.5))
        freq = tf[q]
        denom = freq + k1 * (1 - b + b * dl / avgdl)
        score += idf * (freq * (k1 + 1)) / denom

    return score

per_query = []

for q in queries:
    q_tokens = tokenize(q["query"])

    scored = []
    for i, d in enumerate(docs):
        score = bm25_score(q_tokens, doc_tokens[i])
        scored.append((score, d))

    scored.sort(key=lambda x: x[0], reverse=True)

    clean_id = q["clean_doc_id"]
    poison_id = q["poison_doc_id"]

    clean_rank = None
    poison_rank = None

    for rank, (score, d) in enumerate(scored, start=1):
        if d["doc_id"] == clean_id:
            clean_rank = rank
        if d["doc_id"] == poison_id:
            poison_rank = rank

    top10 = [
        {
            "rank": i + 1,
            "doc_id": d["doc_id"],
            "kind": d["kind"],
            "case_id": d["case_id"],
            "score": round(score, 4),
        }
        for i, (score, d) in enumerate(scored[:10])
    ]

    per_query.append({
        "case_id": q["case_id"],
        "aws_service": q["aws_service"],
        "iam_category": q["iam_category"],
        "clean_doc_id": clean_id,
        "poison_doc_id": poison_id,
        "clean_rank": clean_rank,
        "poison_rank": poison_rank,
        "poison_retrieved_at_1": poison_rank is not None and poison_rank <= 1,
        "poison_retrieved_at_3": poison_rank is not None and poison_rank <= 3,
        "poison_retrieved_at_5": poison_rank is not None and poison_rank <= 5,
        "poison_retrieved_at_10": poison_rank is not None and poison_rank <= 10,
        "clean_retrieved_at_5": clean_rank is not None and clean_rank <= 5,
        "top10": top10,
    })

# Write JSONL detail
detail_path = OUT_DIR / "retrieval_bm25_per_query.jsonl"
with detail_path.open("w", encoding="utf-8") as f:
    for r in per_query:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

# Write CSV summary
csv_path = TABLE_DIR / "table_master_e2e_rag_v1_retrieval_bm25.csv"
with csv_path.open("w", encoding="utf-8") as f:
    f.write("case_id,aws_service,iam_category,clean_rank,poison_rank,poison_at_1,poison_at_3,poison_at_5,poison_at_10,clean_at_5\n")
    for r in per_query:
        f.write(
            f"{r['case_id']},{r['aws_service']},{r['iam_category']},"
            f"{r['clean_rank']},{r['poison_rank']},"
            f"{int(r['poison_retrieved_at_1'])},"
            f"{int(r['poison_retrieved_at_3'])},"
            f"{int(r['poison_retrieved_at_5'])},"
            f"{int(r['poison_retrieved_at_10'])},"
            f"{int(r['clean_retrieved_at_5'])}\n"
        )

def count(key):
    return sum(1 for r in per_query if r[key])

summary = {
    "retriever": "local_bm25",
    "queries": len(per_query),
    "corpus_docs": len(docs),
    "poison_retrieved_at_1": count("poison_retrieved_at_1"),
    "poison_retrieved_at_3": count("poison_retrieved_at_3"),
    "poison_retrieved_at_5": count("poison_retrieved_at_5"),
    "poison_retrieved_at_10": count("poison_retrieved_at_10"),
    "clean_retrieved_at_5": count("clean_retrieved_at_5"),
}

summary_path = OUT_DIR / "retrieval_bm25_summary.json"
summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

md_path = SUMMARY_DIR / "master_e2e_rag_v1_retrieval_bm25_summary.md"
md_path.write_text(
    "# master_e2e_rag_v1 BM25 retrieval summary\n\n"
    f"- Queries: {summary['queries']}\n"
    f"- Corpus docs: {summary['corpus_docs']}\n"
    f"- Poison retrieved@1: {summary['poison_retrieved_at_1']}/{summary['queries']}\n"
    f"- Poison retrieved@3: {summary['poison_retrieved_at_3']}/{summary['queries']}\n"
    f"- Poison retrieved@5: {summary['poison_retrieved_at_5']}/{summary['queries']}\n"
    f"- Poison retrieved@10: {summary['poison_retrieved_at_10']}/{summary['queries']}\n"
    f"- Clean retrieved@5: {summary['clean_retrieved_at_5']}/{summary['queries']}\n",
    encoding="utf-8"
)

print(json.dumps(summary, indent=2))
print("")
print(f"Wrote {detail_path}")
print(f"Wrote {csv_path}")
print(f"Wrote {summary_path}")
print(f"Wrote {md_path}")

print("\nFirst 5 retrieval rows:")
for r in per_query[:5]:
    print(
        r["case_id"],
        "clean_rank=", r["clean_rank"],
        "poison_rank=", r["poison_rank"],
        "poison@5=", r["poison_retrieved_at_5"]
    )
