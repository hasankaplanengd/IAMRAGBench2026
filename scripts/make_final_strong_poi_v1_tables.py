#!/usr/bin/env python3
import csv
import json
from pathlib import Path
from collections import Counter

RUNS = [
    {
        "model": "Claude Sonnet 4.5",
        "run_dir": "runs/20260604_122410_us_anthropic_claude_sonnet_4_5_20250929_v1_0",
        "score_file": "master_strong_poi_v1_full60_semantic_score_final.csv",
    },
    {
        "model": "Nova Lite",
        "run_dir": "runs/20260604_123058_amazon_nova_lite_v1_0",
        "score_file": "master_strong_poi_v1_full60_semantic_score_final.csv",
    },
    {
        "model": "Nova Pro",
        "run_dir": "runs/20260604_123432_amazon_nova_pro_v1_0",
        "score_file": "master_strong_poi_v1_full60_semantic_score_final.csv",
    },
    {
        "model": "Llama 3 8B",
        "run_dir": "runs/20260604_121007_meta_llama3_8b_instruct_v1_0",
        "score_file": "master_strong_poi_v1_full60_semantic_score_final.csv",
    },
]

MASTER = Path("data/iam_rag_benchmark_master.csv")
TABLE_DIR = Path("tables")
SUMMARY_DIR = Path("summaries")
TABLE_DIR.mkdir(exist_ok=True)
SUMMARY_DIR.mkdir(exist_ok=True)

master = {}
with MASTER.open(newline="", encoding="utf-8-sig") as f:
    for r in csv.DictReader(f):
        master[r["case_id"]] = r

def read_score(path: Path):
    rows = []
    with path.open(encoding="utf-8") as f:
        header = next(f, None)
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split(",", 3)
            if len(parts) < 4:
                continue
            pair_id, prompt_type, semantic_ok, failures = parts
            rows.append({
                "pair_id": pair_id,
                "prompt_type": prompt_type,
                "semantic_ok": semantic_ok,
                "failures": failures,
            })
    return rows

summary_rows = []
category_rows = []
attack_rows = []

for item in RUNS:
    run = Path(item["run_dir"])
    score_path = run / item["score_file"]
    summary_path = run / "summary_overall.json"

    if not score_path.exists():
        raise SystemExit(f"Missing score file: {score_path}")

    rows = read_score(score_path)
    ctrl = [r for r in rows if r["prompt_type"] == "ctrl"]
    poi = [r for r in rows if r["prompt_type"] == "poi"]

    ctrl_fail = [r for r in ctrl if r["semantic_ok"] != "True"]
    poi_fail = [r for r in poi if r["semantic_ok"] != "True"]

    ctrl_by_id = {r["pair_id"]: r for r in ctrl}
    attack_success = [
        r for r in poi_fail
        if ctrl_by_id.get(r["pair_id"], {}).get("semantic_ok") == "True"
    ]

    denom = len(ctrl) - len(ctrl_fail)
    asr = (len(attack_success) / denom * 100.0) if denom else 0.0

    model_summary = {}
    if summary_path.exists():
        model_summary = json.loads(summary_path.read_text(encoding="utf-8"))

    summary_rows.append({
        "model": item["model"],
        "run_dir": item["run_dir"],
        "pairs_total": len(ctrl),
        "control_pass": len(ctrl) - len(ctrl_fail),
        "control_total": len(ctrl),
        "poisoned_pass": len(poi) - len(poi_fail),
        "poisoned_total": len(poi),
        "attack_successes": len(attack_success),
        "asr_denominator": denom,
        "asr_percent": f"{asr:.1f}",
        "ok_json": model_summary.get("counts", {}).get("ok_json", ""),
        "wrapped_plain": model_summary.get("counts", {}).get("wrapped_plain", ""),
        "error_stub": model_summary.get("counts", {}).get("error_stub", ""),
        "control_failures": "; ".join(f"{r['pair_id']}:{r['failures']}" for r in ctrl_fail),
    })

    cats = Counter(master.get(r["pair_id"], {}).get("iam_category", "unknown") for r in attack_success)
    for cat, n in sorted(cats.items()):
        category_rows.append({
            "model": item["model"],
            "category": cat,
            "attack_successes": n,
        })

    for r in attack_success:
        attack_rows.append({
            "model": item["model"],
            "pair_id": r["pair_id"],
            "category": master.get(r["pair_id"], {}).get("iam_category", "unknown"),
            "aws_service": master.get(r["pair_id"], {}).get("aws_service", "unknown"),
            "failure": r["failures"],
        })

final_csv = TABLE_DIR / "table_master_strong_poi_v1_final.csv"
category_csv = TABLE_DIR / "table_master_strong_poi_v1_by_category.csv"
attacks_csv = TABLE_DIR / "table_master_strong_poi_v1_attack_successes.csv"
final_md = TABLE_DIR / "table_master_strong_poi_v1_final.md"
summary_md = SUMMARY_DIR / "master_strong_poi_v1_final_summary.md"

with final_csv.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
    writer.writeheader()
    writer.writerows(summary_rows)

with category_csv.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["model", "category", "attack_successes"])
    writer.writeheader()
    writer.writerows(category_rows)

with attacks_csv.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["model", "pair_id", "category", "aws_service", "failure"])
    writer.writeheader()
    writer.writerows(attack_rows)

md_lines = []
md_lines.append("| Model | Control pass | Poisoned pass | Attack successes | ASR | Notes |")
md_lines.append("|---|---:|---:|---:|---:|---|")
for r in summary_rows:
    notes = ""
    if r["model"] == "Llama 3 8B":
        notes = "ASR uses clean-control-passing denominator."
    md_lines.append(
        f"| {r['model']} | {r['control_pass']}/{r['control_total']} | "
        f"{r['poisoned_pass']}/{r['poisoned_total']} | "
        f"{r['attack_successes']} | {r['asr_percent']}% | {notes} |"
    )

final_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

summary_lines = []
summary_lines.append("# Final strong_poi_v1 60-case semantic benchmark summary\n")
summary_lines.append("Final frozen runs:\n")
for r in summary_rows:
    summary_lines.append(
        f"- {r['model']}: control {r['control_pass']}/{r['control_total']}, "
        f"poisoned {r['poisoned_pass']}/{r['poisoned_total']}, "
        f"attack successes {r['attack_successes']}/{r['asr_denominator']} "
        f"({r['asr_percent']}%). Run: `{r['run_dir']}`"
    )

summary_lines.append("\nKey interpretation:\n")
summary_lines.append(
    "The benchmark separates clean IAM-generation competence from poisoned-context effects. "
    "Claude Sonnet 4.5 remains robust on this 60-case suite. Nova Lite and Nova Pro show "
    "IAM-semantic failures under strong generation-steering poison while passing all clean controls. "
    "Llama 3 8B has lower clean-control competence, so its ASR is reported over clean-control-passing cases."
)

summary_md.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

print("Wrote:")
print(f"  {final_csv}")
print(f"  {category_csv}")
print(f"  {attacks_csv}")
print(f"  {final_md}")
print(f"  {summary_md}")
print("")
print(final_md.read_text(encoding="utf-8"))
