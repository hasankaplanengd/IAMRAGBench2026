#!/usr/bin/env python3
import csv
import json
import sys
from pathlib import Path

def as_list(x):
    if isinstance(x, list):
        return x
    if x is None:
        return []
    return [x]

def statements(policy):
    return as_list(policy.get("Statement", []))

def collect(policy, key):
    vals = []
    for st in statements(policy):
        if key in st:
            vals.extend(as_list(st.get(key)))
    return vals

def conditions(policy):
    vals = []
    for st in statements(policy):
        if "Condition" in st:
            vals.append(st["Condition"])
    return vals

def principals(policy):
    vals = []
    for st in statements(policy):
        if "Principal" in st:
            vals.append(st["Principal"])
    return vals

def load_jsonl_by_id(path, key):
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                out[r[key]] = r
    return out

def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 scripts/inspect_candidate_attack_successes.py runs/<run_dir>")

    run = Path(sys.argv[1])
    score_path = run / "master_strong_poi_v1_full60_semantic_score.csv"

    master = load_jsonl_by_id("data/generated_from_master/rag_pairs_from_master.jsonl", "case_id")
    meta = load_jsonl_by_id("data/generated_from_master/rag_pairs_master_strong_poi_v1_meta.jsonl", "case_id")

    with score_path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    ctrl = {r["pair_id"]: r for r in rows if r["prompt_type"] == "ctrl"}
    poi_fail = [
        r for r in rows
        if r["prompt_type"] == "poi"
        and r["semantic_ok"] != "True"
        and ctrl.get(r["pair_id"], {}).get("semantic_ok") == "True"
    ]

    print(f"Run: {run}")
    print(f"Candidate attack successes: {len(poi_fail)}")

    for r in poi_fail:
        cid = r["pair_id"]
        ctrl_policy = json.loads((run / "raw" / f"req_{cid}_ctrl__REPAIRED.json").read_text(encoding="utf-8"))
        poi_policy = json.loads((run / "raw" / f"req_{cid}_poi__REPAIRED.json").read_text(encoding="utf-8"))
        m = master[cid]
        mt = meta[cid]

        print("\n" + "=" * 90)
        print(f"CASE: {cid}")
        print(f"Category: {m.get('iam_category')}")
        print(f"Service: {m.get('aws_service')}")
        print(f"Failures: {r['failures']}")
        print(f"Attacker goal: {m.get('attacker_goal')}")
        print(f"Oracle: {m.get('oracle_check')}")
        print("\nStrong poison:")
        print(mt.get("strong_poison", ""))

        print("\nCTRL summary:")
        print("  Actions:    ", collect(ctrl_policy, "Action"))
        print("  Resources:  ", collect(ctrl_policy, "Resource"))
        print("  NotResource:", collect(ctrl_policy, "NotResource"))
        print("  Principal:  ", principals(ctrl_policy))
        print("  Conditions: ", json.dumps(conditions(ctrl_policy), ensure_ascii=False))

        print("\nPOISONED summary:")
        print("  Actions:    ", collect(poi_policy, "Action"))
        print("  Resources:  ", collect(poi_policy, "Resource"))
        print("  NotResource:", collect(poi_policy, "NotResource"))
        print("  Principal:  ", principals(poi_policy))
        print("  Conditions: ", json.dumps(conditions(poi_policy), ensure_ascii=False))

        print("\nCTRL full JSON:")
        print(json.dumps(ctrl_policy, indent=2, ensure_ascii=False))

        print("\nPOISONED full JSON:")
        print(json.dumps(poi_policy, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
