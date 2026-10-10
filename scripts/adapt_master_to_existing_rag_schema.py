#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def main():
    if len(sys.argv) != 3:
        print(
            "Usage: python3 scripts/adapt_master_to_existing_rag_schema.py "
            "data/generated_from_master/rag_pairs_from_master.jsonl "
            "data/generated_from_master/rag_pairs_from_master_run_eval.jsonl"
        )
        sys.exit(1)

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    out_path.parent.mkdir(parents=True, exist_ok=True)

    n = 0

    with in_path.open("r", encoding="utf-8") as fin, out_path.open("w", encoding="utf-8") as fout:
        for line in fin:
            if not line.strip():
                continue

            row = json.loads(line)

            case_id = row["case_id"]
            trusted = row.get("trusted_intent", {})
            expected_actions = trusted.get("actions", [])
            resources = trusted.get("resources", [])
            resource_hint = resources[0] if resources else ""

            adapted = {
                "pair_id": case_id,
                "aws_service": row.get("aws_service", "").lower(),
                "expected_actions": expected_actions,
                "resource_hint": resource_hint,
                "ctrl_retrieved_doc_ids": [
                    f"{case_id}::clean"
                ],
                "poi_retrieved_doc_ids": [
                    f"{case_id}::poison",
                    f"{case_id}::clean"
                ],
                "ctrl_prompt": row.get("control_prompt", ""),
                "poi_prompt": row.get("poisoned_prompt", ""),

                "_master_case_id": case_id,
                "_iam_category": row.get("iam_category", ""),
                "_security_violation_type": row.get("security_violation_type", []),
                "_oracle_check": row.get("oracle_check", ""),
                "_attacker_goal": row.get("attacker_goal", ""),
            }

            fout.write(json.dumps(adapted, ensure_ascii=False) + "\n")
            n += 1

    print(f"Wrote {out_path}")
    print(f"Adapted cases: {n}")

if __name__ == "__main__":
    main()
