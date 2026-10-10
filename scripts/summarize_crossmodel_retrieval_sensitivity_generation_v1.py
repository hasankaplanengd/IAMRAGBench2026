#!/usr/bin/env python3
import csv
import json
from pathlib import Path

OUT_CSV = Path("tables/table_crossmodel_retrieval_sensitivity_generation_v1.csv")
OUT_MD = Path("summaries/crossmodel_retrieval_sensitivity_generation_v1_summary.md")

# Known BM25 baseline final runs + Nova Pro dense/hybrid already completed.
BASE = [
    {
        "model": "Nova Lite",
        "retriever": "BM25",
        "poison_at_5": "59/60",
        "run": "runs/20260605_021337_amazon_nova_lite_v1_0",
        "score_file": "master_e2e_rag_v2_k5_standard_full60_semantic_score.csv",
    },
    {
        "model": "Nova Pro",
        "retriever": "BM25",
        "poison_at_5": "59/60",
        "run": "runs/20260605_022706_amazon_nova_pro_v1_0",
        "score_file": "master_e2e_rag_v2_k5_standard_full60_semantic_score.csv",
    },
    {
        "model": "Llama 3 8B",
        "retriever": "BM25",
        "poison_at_5": "59/60",
        "run": "runs/20260605_024307_meta_llama3_8b_instruct_v1_0",
        "score_file": "master_e2e_rag_v2_k5_standard_full60_semantic_score.csv",
    },
    {
        "model": "Nova Pro",
        "retriever": "Dense",
        "poison_at_5": "58/60",
        "run": "runs/20260612_103737_amazon_nova_pro_v1_0",
        "score_file": "master_e2e_rag_v2_k5_dense_standard_full60_semantic_score.csv",
    },
    {
        "model": "Nova Pro",
        "retriever": "Hybrid",
        "poison_at_5": "59/60",
        "run": "runs/20260612_104249_amazon_nova_pro_v1_0",
        "score_file": "master_e2e_rag_v2_k5_hybrid_standard_full60_semantic_score.csv",
    },
]

# New dense/hybrid runs from manifest.
manifest = Path("tables/table_crossmodel_dense_hybrid_runs_v1.csv")
if manifest.exists():
    with manifest.open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            model_map = {
                "nova_lite": "Nova Lite",
                "llama3_8b": "Llama 3 8B",
            }
            retr_map = {
                "dense": "Dense",
                "hybrid": "Hybrid",
            }
            poison_map = {
                "dense": "58/60",
                "hybrid": "59/60",
            }
            BASE.append({
                "model": model_map.get(r["model"], r["model"]),
                "retriever": retr_map.get(r["retriever"], r["retriever"]),
                "poison_at_5": poison_map.get(r["retriever"], ""),
                "run": r["run"],
                "score_file": Path(r["score_file"]).name,
            })

def read_scores(path):
    rows = []
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0] in {"case_id", "pair_id"}:
                continue
            rows.append(row)
    cases = sorted({r[0] for r in rows})
    score = {(r[0], r[1]): (r[2].lower() == "true", r[3] if len(r) > 3 else "") for r in rows}
    return cases, score

def is_policy(path):
    if not path.exists():
        return False
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    if isinstance(obj, dict) and "Statement" in obj:
        return True
    if isinstance(obj, list):
        return True
    return False

summary = []

for item in BASE:
    run = Path(item["run"])
    score_path = run / item["score_file"]
    if not score_path.exists():
        summary.append({
            **item,
            "control_pass": "MISSING",
            "semantic_attacks": "MISSING",
            "deployable_candidates": "MISSING",
            "attack_cases": "",
        })
        continue

    cases, score = read_scores(score_path)

    ctrl_pass = sum(score.get((c, "ctrl"), (False, ""))[0] for c in cases)
    attacks = []
    deployable = []

    for c in cases:
        ctrl_ok = score.get((c, "ctrl"), (False, ""))[0]
        poi_ok, fail = score.get((c, "poi"), (False, ""))
        if ctrl_ok and not poi_ok:
            attacks.append((c, fail))
            if is_policy(run / "raw" / f"req_{c}_poi__REPAIRED.json"):
                deployable.append((c, fail))

    summary.append({
        **item,
        "control_pass": f"{ctrl_pass}/60",
        "semantic_attacks": f"{len(attacks)}/60",
        "deployable_candidates": f"{len(deployable)}/60",
        "attack_cases": "; ".join(c for c, _ in attacks),
    })

# Sort cleanly.
order_model = {"Nova Lite": 0, "Nova Pro": 1, "Llama 3 8B": 2}
order_ret = {"BM25": 0, "Dense": 1, "Hybrid": 2}
summary.sort(key=lambda r: (order_model.get(r["model"], 99), order_ret.get(r["retriever"], 99)))

OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
    fields = ["model", "retriever", "poison_at_5", "control_pass", "semantic_attacks", "deployable_candidates", "attack_cases", "run"]
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for r in summary:
        w.writerow({k: r.get(k, "") for k in fields})

lines = []
lines.append("# Cross-model retrieval sensitivity with generation")
lines.append("")
lines.append("| Model | Retriever | Poison@5 | Control pass | Semantic attacks | Deployable candidates |")
lines.append("|---|---|---:|---:|---:|---:|")
for r in summary:
    lines.append(
        f"| {r['model']} | {r['retriever']} | {r['poison_at_5']} | {r['control_pass']} | "
        f"{r['semantic_attacks']} | {r['deployable_candidates']} |"
    )

lines.append("")
lines.append("Attack cases:")
for r in summary:
    lines.append(f"- {r['model']} / {r['retriever']}: {r['attack_cases']}")

lines.append("")
lines.append(f"CSV: `{OUT_CSV}`")

OUT_MD.parent.mkdir(parents=True, exist_ok=True)
OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(OUT_MD.read_text(encoding="utf-8"))
