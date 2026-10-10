#!/usr/bin/env python3
import csv, json
from pathlib import Path

OUT_CSV = Path("tables/table_retrieval_sensitivity_generation_v1.csv")
OUT_MD = Path("summaries/retrieval_sensitivity_generation_v1_summary.md")

RUNS = {
    "BM25": {
        "run": "runs/20260605_022706_amazon_nova_pro_v1_0",
        "score": "master_e2e_rag_v2_k5_standard_full60_semantic_score.csv",
        "poison_at_5": "59/60"
    },
    "Dense": {
        "run": "runs/20260612_103737_amazon_nova_pro_v1_0",
        "score": "master_e2e_rag_v2_k5_dense_standard_full60_semantic_score.csv",
        "poison_at_5": "58/60"
    },
    "Hybrid": {
        "run": "runs/20260612_104249_amazon_nova_pro_v1_0",
        "score": "master_e2e_rag_v2_k5_hybrid_standard_full60_semantic_score.csv",
        "poison_at_5": "59/60"
    },
}

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

def read_scores(score_path):
    rows = []
    with score_path.open(newline="", encoding="utf-8") as f:
        for r in csv.reader(f):
            if not r or r[0] in {"case_id", "pair_id"}:
                continue
            rows.append(r)
    cases = sorted({r[0] for r in rows})
    score = {(r[0], r[1]): (r[2].lower() == "true", r[3] if len(r) > 3 else "") for r in rows}
    return cases, score

summary_rows = []

for retriever, info in RUNS.items():
    run = Path(info["run"])
    score_path = run / info["score"]
    cases, score = read_scores(score_path)

    ctrl_pass = sum(score.get((c, "ctrl"), (False, ""))[0] for c in cases)

    attacks = []
    deployable = []
    for c in cases:
        ctrl_ok = score.get((c, "ctrl"), (False, ""))[0]
        poi_ok, fail = score.get((c, "poi"), (False, ""))
        if ctrl_ok and not poi_ok:
            attacks.append((c, fail))
            poi_json = run / "raw" / f"req_{c}_poi__REPAIRED.json"
            if is_policy(poi_json):
                deployable.append((c, fail))

    summary_rows.append({
        "retriever": retriever,
        "poison_at_5": info["poison_at_5"],
        "nova_pro_control_pass": f"{ctrl_pass}/60",
        "nova_pro_semantic_attacks": f"{len(attacks)}/60",
        "deployable_attack_candidates": f"{len(deployable)}/60",
        "attack_cases": "; ".join(c for c, _ in attacks),
        "run": run.name
    })

OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
    w.writeheader()
    w.writerows(summary_rows)

lines = ["# Retrieval sensitivity with Nova Pro generation", ""]
lines.append("| Retriever | Poison@5 | Control pass | Semantic attacks | Deployable candidates |")
lines.append("|---|---:|---:|---:|---:|")
for r in summary_rows:
    lines.append(
        f"| {r['retriever']} | {r['poison_at_5']} | {r['nova_pro_control_pass']} | "
        f"{r['nova_pro_semantic_attacks']} | {r['deployable_attack_candidates']} |"
    )
lines.append("")
lines.append("Attack cases:")
for r in summary_rows:
    lines.append(f"- {r['retriever']}: {r['attack_cases']}")
lines.append("")
lines.append(f"CSV: `{OUT_CSV}`")

OUT_MD.parent.mkdir(parents=True, exist_ok=True)
OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(OUT_MD.read_text(encoding="utf-8"))
