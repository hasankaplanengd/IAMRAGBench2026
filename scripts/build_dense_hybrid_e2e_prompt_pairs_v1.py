#!/usr/bin/env python3
import json
from pathlib import Path

CORPUS = Path("data/master_e2e_rag_v2/corpus.jsonl")
BASE = Path("data/master_e2e_rag_v2/rag_pairs_e2e_k5_standard_run_eval.jsonl")
DETAIL = Path("data/master_e2e_rag_v2/retrieval_sensitivity_dense_hybrid_v1_detail.jsonl")
OUT_DIR = Path("data/master_e2e_rag_v2")

RETRIEVERS = ["dense", "hybrid"]

START = "Retrieved enterprise context:\n"
END = "\n\nReturn exactly one valid AWS IAM policy JSON object."

def load_jsonl(path):
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows

def doc_id(d):
    return d.get("doc_id") or d.get("id") or d.get("document_id")

def get_prompt(row, keys):
    for k in keys:
        if k in row and row[k]:
            return row[k]
    raise KeyError(f"missing prompt key in row keys={list(row.keys())}")

def set_prompt(row, keys, value):
    for k in keys:
        if k in row:
            row[k] = value
            return
    row[keys[0]] = value

def format_value(v):
    if v is None:
        return ""
    if isinstance(v, list):
        return "; ".join(str(x) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False)
    return str(v)

def format_doc(d, rank, score):
    did = doc_id(d)
    kind = d.get("kind", "")
    service = d.get("service") or d.get("aws_service") or ""
    lines = [f"[Document {rank} | {did} | kind={kind} | service={service} | score={score:.4f}]"]

    skip = {"doc_id", "id", "document_id", "case_id", "kind", "score"}
    preferred = [
        "title", "service", "aws_service", "category", "iam_category",
        "trusted_task", "task", "allowed_actions", "expected_actions",
        "allowed_resources", "resource_hint", "required_conditions",
        "conditions_or_guardrails", "content", "text", "body", "document",
        "approved_guidance", "safe_policy", "poisoned_guidance"
    ]

    seen = set()
    for k in preferred:
        if k in d and d[k] not in (None, "", []):
            lines.append(f"{k}: {format_value(d[k])}")
            seen.add(k)

    for k, v in d.items():
        if k in skip or k in seen or v in (None, "", []):
            continue
        if isinstance(v, (str, int, float, list, dict, bool)):
            lines.append(f"{k}: {format_value(v)}")

    return "\n".join(lines)

def replace_context(prompt, docs_text):
    if START not in prompt:
        raise ValueError("prompt missing START marker")
    before, rest = prompt.split(START, 1)
    if END not in rest:
        raise ValueError("prompt missing END marker")
    _, after = rest.split(END, 1)
    return before + START + docs_text.strip() + END + after

def main():
    corpus = {doc_id(d): d for d in load_jsonl(CORPUS)}
    base_rows = load_jsonl(BASE)

    details_by = {}
    for d in load_jsonl(DETAIL):
        if d["retriever"] in RETRIEVERS:
            details_by[(d["retriever"], d["case_id"])] = d

    for retriever in RETRIEVERS:
        out_rows = []

        for row in base_rows:
            cid = row.get("pair_id") or row.get("case_id")
            detail = details_by[(retriever, cid)]

            new_row = dict(row)
            new_row["retriever"] = retriever
            new_row["retrieval_sensitivity_source"] = str(DETAIL)

            for prompt_side, topk_key, id_key in [
                ("ctrl", "ctrl_top5", "ctrl_retrieved_doc_ids"),
                ("poi", "poi_top5", "poi_retrieved_doc_ids"),
            ]:
                docs_texts = []
                doc_ids = []
                for i, item in enumerate(detail[topk_key], start=1):
                    did = item["doc_id"]
                    doc_ids.append(did)
                    docs_texts.append(format_doc(corpus[did], i, float(item["score"])))

                docs_text = "\n\n".join(docs_texts)

                if prompt_side == "ctrl":
                    old_prompt = get_prompt(new_row, ["ctrl_prompt", "prompt_control"])
                    set_prompt(new_row, ["ctrl_prompt", "prompt_control"], replace_context(old_prompt, docs_text))
                    new_row[id_key] = doc_ids
                else:
                    old_prompt = get_prompt(new_row, ["poi_prompt", "prompt_poisoned"])
                    set_prompt(new_row, ["poi_prompt", "prompt_poisoned"], replace_context(old_prompt, docs_text))
                    new_row[id_key] = doc_ids

            out_rows.append(new_row)

        out = OUT_DIR / f"rag_pairs_e2e_k5_{retriever}_standard_run_eval.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for r in out_rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

        print(f"Wrote {out} rows={len(out_rows)}")

if __name__ == "__main__":
    main()
