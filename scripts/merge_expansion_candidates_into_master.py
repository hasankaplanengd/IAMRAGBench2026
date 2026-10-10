#!/usr/bin/env python3
import csv
from pathlib import Path
from collections import Counter

master_path = Path("data/iam_rag_benchmark_master.csv")
cand_path = Path("data/iam_rag_benchmark_expansion_candidates_v1.csv")

with master_path.open("r", encoding="utf-8-sig", newline="") as f:
    master_reader = csv.DictReader(f)
    fieldnames = master_reader.fieldnames
    master_rows = list(master_reader)

if not fieldnames:
    raise SystemExit("Could not read master header.")

with cand_path.open("r", encoding="utf-8-sig", newline="") as f:
    cand_reader = csv.DictReader(f)
    cand_rows = list(cand_reader)

existing_ids = {r["case_id"] for r in master_rows if r.get("case_id")}
added = []
skipped = []

for r in cand_rows:
    cid = r.get("case_id", "").strip()
    if not cid:
        continue
    if cid in existing_ids:
        skipped.append(cid)
        continue

    clean = {k: r.get(k, "") for k in fieldnames}
    added.append(clean)
    existing_ids.add(cid)

merged = master_rows + added

with master_path.open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(merged)

print(f"Original master rows: {len(master_rows)}")
print(f"Candidate rows: {len(cand_rows)}")
print(f"Added rows: {len(added)}")
print(f"Skipped duplicate rows: {len(skipped)}")
print(f"New master rows: {len(merged)}")

print("")
print("By split:")
for k, v in sorted(Counter(r.get("split", "") for r in merged).items()):
    print(f"  {k}: {v}")

print("")
print("By category:")
for k, v in sorted(Counter(r.get("iam_category", "") for r in merged).items()):
    print(f"  {k}: {v}")
