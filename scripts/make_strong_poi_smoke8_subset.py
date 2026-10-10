#!/usr/bin/env python3
import csv
import json
from pathlib import Path
from collections import defaultdict

master_path = Path("data/iam_rag_benchmark_master.csv")
strong_path = Path("data/generated_from_master/rag_pairs_master_strong_poi_v1_run_eval.jsonl")
out_path = Path("data/generated_from_master/rag_pairs_master_strong_poi_v1_smoke8_run_eval.jsonl")

wanted_categories = [
    "condition_weakening",
    "abac_condition",
    "deny_guardrail",
    "passrole_escalation",
    "trust_policy_expansion",
    "resource_widening",
    "action_widening",
    "public_exposure",
]

by_cat = defaultdict(list)

with master_path.open("r", encoding="utf-8-sig", newline="") as f:
    for r in csv.DictReader(f):
        if r.get("split") == "expansion_v1":
            cat = r.get("iam_category", "")
            if cat in wanted_categories:
                by_cat[cat].append(r["case_id"])

selected_ids = []
for cat in wanted_categories:
    ids = sorted(by_cat[cat])
    if not ids:
        raise SystemExit(f"No case found for category {cat}")
    selected_ids.append(ids[0])

strong_rows = {}
with strong_path.open("r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            r = json.loads(line)
            strong_rows[r["pair_id"]] = r

with out_path.open("w", encoding="utf-8") as f:
    for cid in selected_ids:
        if cid not in strong_rows:
            raise SystemExit(f"Missing strong row for {cid}")
        f.write(json.dumps(strong_rows[cid], ensure_ascii=False) + "\n")

print(f"Wrote {out_path}")
print(f"Selected cases: {len(selected_ids)}")
for cid in selected_ids:
    print(" ", cid)
