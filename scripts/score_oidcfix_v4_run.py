#!/usr/bin/env python3
import csv
import json
import sys
from pathlib import Path

from oidc_oracle_v4 import (
    load_policy_file,
    score_policy,
)

QUERIES = Path(
    "data/master_e2e_rag_v4_oidcfix/queries.jsonl"
)

EXPECTED_CASES = [
    f"sts_oidc_trust_{index:03d}"
    for index in range(1, 7)
]


def load_queries():
    rows = {}

    for line in QUERIES.read_text(
        encoding="utf-8"
    ).splitlines():
        if not line.strip():
            continue

        row = json.loads(line)
        case_id = row.get("case_id")

        if case_id in EXPECTED_CASES:
            rows[case_id] = row

    missing = set(EXPECTED_CASES) - set(rows)

    if missing:
        raise RuntimeError(
            "Missing query metadata: "
            + ", ".join(sorted(missing))
        )

    return rows


def main():
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: score_oidcfix_v4_run.py RUN_DIR"
        )

    run = Path(sys.argv[1])

    if not run.exists():
        raise FileNotFoundError(run)

    queries = load_queries()

    writer = csv.DictWriter(
        sys.stdout,
        fieldnames=[
            "pair_id",
            "prompt_type",
            "semantic_ok",
            "deployable",
            "failures",
            "local_error",
            "policy_file",
        ],
    )

    writer.writeheader()

    for case_id in EXPECTED_CASES:
        oracle = queries[case_id]["oracle_check"]

        for prompt_type in ["ctrl", "poi"]:
            policy_file = (
                run
                / "raw"
                / (
                    f"req_{case_id}_{prompt_type}"
                    "__REPAIRED.json"
                )
            )

            policy, local_error = load_policy_file(
                policy_file
            )

            if policy is None:
                failures = [
                    "nondeployable",
                    local_error,
                ]
                deployable = False
            else:
                failures = score_policy(
                    policy,
                    oracle,
                )
                deployable = True

            writer.writerow({
                "pair_id": case_id,
                "prompt_type": prompt_type,
                "semantic_ok": not failures,
                "deployable": deployable,
                "failures": " | ".join(
                    failure
                    for failure in failures
                    if failure
                ),
                "local_error": local_error,
                "policy_file": str(policy_file),
            })


if __name__ == "__main__":
    main()
