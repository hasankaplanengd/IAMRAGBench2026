#!/usr/bin/env python3
import csv
import json
import sys
from pathlib import Path

from leadingkeys_oracle_v5 import (
    load_policy_file,
    score_policy,
)

QUERIES = Path(
    "data/master_e2e_rag_v5_leadingkeysfix/"
    "queries.jsonl"
)

CASE_ID = "dynamodb_tenant_002"


def load_oracle():
    for line in QUERIES.read_text(
        encoding="utf-8"
    ).splitlines():
        if not line.strip():
            continue

        row = json.loads(line)

        if row.get("case_id") == CASE_ID:
            return row["oracle_check"]

    raise RuntimeError(
        f"Missing query metadata for {CASE_ID}"
    )


def main():
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: score_leadingkeysfix_v5_tenant_run.py RUN_DIR"
        )

    run = Path(sys.argv[1])

    if not run.exists():
        raise FileNotFoundError(run)

    oracle = load_oracle()

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

    for prompt_type in ["ctrl", "poi"]:
        policy_file = (
            run
            / "raw"
            / (
                f"req_{CASE_ID}_{prompt_type}"
                "__REPAIRED.json"
            )
        )

        policy, local_error = load_policy_file(
            policy_file
        )

        if policy is None:
            deployable = False
            failures = [
                "nondeployable",
                local_error,
            ]
        else:
            deployable = True
            failures = score_policy(
                policy,
                oracle,
            )

        writer.writerow({
            "pair_id": CASE_ID,
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
