#!/usr/bin/env python3
import json
import math
import re
import statistics
from pathlib import Path
from collections import Counter, defaultdict

CORPUS = Path("data/master_e2e_rag_v2/corpus.jsonl")
QUERIES = Path("data/master_e2e_rag_v2/queries.jsonl")
OUT_CSV = Path("tables/table_retrieval_overlap_bias_v1.csv")
OUT_DETAIL = Path("data/master_e2e_rag_v2/retrieval_overlap_bias_v1_detail.jsonl")
OUT_MD = Path("summaries/retrieval_overlap_bias_v1_summary.md")

STOP = {
    "the","a","an","and","or","to","for","of","in","on","with","only","must",
    "that","this","is","are","be","by","as","from","into","it","its","use",
    "using","generate","policy","iam","aws","json","least","privilege",
    "trusted","task","request","allowed","resources","actions","condition",
    "conditions","guardrails","document","retrieved","context"
}

def load_jsonl(path):
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows

def doc_id(d):
    return d.get("doc_id") or d.get("id") or d.get("document_id")

def case_id(x):
    return x.get("case_id") or x.get("pair_id") or x.get("id")

def is_poison_doc(d):
    did = (doc_id(d) or "").lower()
    kind = str(d.get("kind", "")).lower()
    return "poison" in did or "poi" in did or "poison" in kind or "retrieval_competitive" in did

def text_of_doc(d):
    fields = [
        "title", "service", "aws_service", "category", "iam_category",
        "trusted_task", "task", "content", "text", "body", "document",
        "approved_guidance", "safe_policy", "poisoned_guidance"
    ]
    parts = []
    for k in fields:
        v = d.get(k)
        if v:
            if isinstance(v, (list, dict)):
                parts.append(json.dumps(v, ensure_ascii=False))
            else:
                parts.append(str(v))
    if not parts:
        parts.append(json.dumps(d, ensure_ascii=False))
    return "\n".join(parts)

def text_of_query(q):
    fields = [
        "query", "retrieval_query", "task", "trusted_task",
        "task_request", "user_task", "control_query", "prompt"
    ]
    for k in fields:
        v = q.get(k)
        if v:
            return str(v)
    return json.dumps(q, ensure_ascii=False)

def toks(s):
    raw = re.findall(r"[a-zA-Z0-9:_./#*\-=]+", s.lower())
    return [t for t in raw if len(t) > 1 and t not in STOP]

def jaccard(a, b):
    A, B = set(a), set(b)
    if not A and not B:
        return 0.0
    return len(A & B) / max(1, len(A | B))

def build_tfidf(texts):
    tokenized = [toks(t) for t in texts]
    N = len(tokenized)
    df = Counter()
    for ts in tokenized:
        df.update(set(ts))
    idf = {t: math.log((N + 1) / (c + 1)) + 1 for t, c in df.items()}

    vecs = []
    for ts in tokenized:
        tf = Counter(ts)
        v = {t: tf[t] * idf[t] for t in tf}
        norm = math.sqrt(sum(x*x for x in v.values()))
        if norm:
            v = {t: x / norm for t, x in v.items()}
        vecs.append(v)
    return vecs

def cosine(v1, v2):
    if len(v1) > len(v2):
        v1, v2 = v2, v1
    return sum(v * v2.get(k, 0.0) for k, v in v1.items())

def mean(xs):
    return sum(xs) / len(xs) if xs else 0.0

def med(xs):
    return statistics.median(xs) if xs else 0.0

def pct(x):
    return f"{100*x:.1f}%"

def main():
    docs = load_jsonl(CORPUS)
    queries = load_jsonl(QUERIES)

    docs_by_id = {doc_id(d): d for d in docs}
    query_by_case = {case_id(q): q for q in queries}

    all_texts = [text_of_doc(d) for d in docs] + [text_of_query(q) for q in queries]
    all_vecs = build_tfidf(all_texts)
    doc_vec_by_id = {doc_id(d): all_vecs[i] for i, d in enumerate(docs)}
    query_vec_by_case = {case_id(q): all_vecs[len(docs)+i] for i, q in enumerate(queries)}

    detail = []

    for cid, q in query_by_case.items():
        clean = docs_by_id.get(f"{cid}::clean")
        poison = None
        for d in docs:
            if (doc_id(d) or "").startswith(f"{cid}::") and is_poison_doc(d):
                poison = d
                break

        if clean is None or poison is None:
            continue

        q_text = text_of_query(q)
        clean_text = text_of_doc(clean)
        poison_text = text_of_doc(poison)

        q_t = toks(q_text)
        c_t = toks(clean_text)
        p_t = toks(poison_text)

        same_case_ids = {doc_id(clean), doc_id(poison)}
        distractors = [d for d in docs if doc_id(d) not in same_case_ids]

        q_vec = query_vec_by_case[cid]
        c_vec = doc_vec_by_id[doc_id(clean)]
        p_vec = doc_vec_by_id[doc_id(poison)]

        best_dist_j = -1.0
        best_dist_id_j = None
        best_dist_cos = -1.0
        best_dist_id_cos = None

        for d in distractors:
            d_id = doc_id(d)
            d_t = toks(text_of_doc(d))
            j = jaccard(q_t, d_t)
            co = cosine(q_vec, doc_vec_by_id[d_id])
            if j > best_dist_j:
                best_dist_j = j
                best_dist_id_j = d_id
            if co > best_dist_cos:
                best_dist_cos = co
                best_dist_id_cos = d_id

        row = {
            "case_id": cid,
            "query_clean_jaccard": round(jaccard(q_t, c_t), 4),
            "query_poison_jaccard": round(jaccard(q_t, p_t), 4),
            "clean_poison_jaccard": round(jaccard(c_t, p_t), 4),
            "query_best_distractor_jaccard": round(best_dist_j, 4),
            "best_distractor_jaccard_doc": best_dist_id_j,
            "query_clean_tfidf_cos": round(cosine(q_vec, c_vec), 4),
            "query_poison_tfidf_cos": round(cosine(q_vec, p_vec), 4),
            "clean_poison_tfidf_cos": round(cosine(c_vec, p_vec), 4),
            "query_best_distractor_tfidf_cos": round(best_dist_cos, 4),
            "best_distractor_tfidf_doc": best_dist_id_cos,
            "poison_more_similar_than_clean_jaccard": jaccard(q_t, p_t) > jaccard(q_t, c_t),
            "poison_more_similar_than_clean_tfidf": cosine(q_vec, p_vec) > cosine(q_vec, c_vec),
            "clean_poison_near_duplicate_jaccard_ge_080": jaccard(c_t, p_t) >= 0.80,
            "clean_poison_near_duplicate_tfidf_ge_090": cosine(c_vec, p_vec) >= 0.90,
        }
        detail.append(row)

    OUT_DETAIL.parent.mkdir(parents=True, exist_ok=True)
    with OUT_DETAIL.open("w", encoding="utf-8") as f:
        for r in detail:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    import csv
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        fieldnames = list(detail[0].keys())
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(detail)

    vals = defaultdict(list)
    for r in detail:
        for k, v in r.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                vals[k].append(float(v))

    n = len(detail)
    poison_gt_clean_j = sum(r["poison_more_similar_than_clean_jaccard"] for r in detail)
    poison_gt_clean_t = sum(r["poison_more_similar_than_clean_tfidf"] for r in detail)
    near_j = sum(r["clean_poison_near_duplicate_jaccard_ge_080"] for r in detail)
    near_t = sum(r["clean_poison_near_duplicate_tfidf_ge_090"] for r in detail)

    lines = []
    lines.append("# Retrieval-overlap / synthetic-corpus bias analysis")
    lines.append("")
    lines.append(f"Cases analyzed: **{n}**")
    lines.append("")
    lines.append("| Similarity measure | Query-clean | Query-poison | Clean-poison | Query-best distractor |")
    lines.append("|---|---:|---:|---:|---:|")
    lines.append(
        f"| Jaccard median | {med(vals['query_clean_jaccard']):.3f} | "
        f"{med(vals['query_poison_jaccard']):.3f} | "
        f"{med(vals['clean_poison_jaccard']):.3f} | "
        f"{med(vals['query_best_distractor_jaccard']):.3f} |"
    )
    lines.append(
        f"| TF-IDF cosine median | {med(vals['query_clean_tfidf_cos']):.3f} | "
        f"{med(vals['query_poison_tfidf_cos']):.3f} | "
        f"{med(vals['clean_poison_tfidf_cos']):.3f} | "
        f"{med(vals['query_best_distractor_tfidf_cos']):.3f} |"
    )
    lines.append("")
    lines.append(f"- Poison document more similar to query than clean document by Jaccard: **{poison_gt_clean_j}/{n}**")
    lines.append(f"- Poison document more similar to query than clean document by TF-IDF cosine: **{poison_gt_clean_t}/{n}**")
    lines.append(f"- Clean/poison near-duplicates by Jaccard >= 0.80: **{near_j}/{n}**")
    lines.append(f"- Clean/poison near-duplicates by TF-IDF cosine >= 0.90: **{near_t}/{n}**")
    lines.append("")
    lines.append(f"CSV: `{OUT_CSV}`")
    lines.append(f"Detail JSONL: `{OUT_DETAIL}`")

    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(OUT_MD.read_text(encoding="utf-8"))

if __name__ == "__main__":
    main()
