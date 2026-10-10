#!/usr/bin/env python3
from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path

import boto3


ROOT = Path(__file__).resolve().parents[1]

SOURCE_MODULE = (
    ROOT / "scripts/simulate_master_v6_candidates.py"
)

INPUT = (
    ROOT
    / "tables/"
      "checknonewaccess_pass_explicit_deny_v1_input.csv"
)

OUT_DETAIL = (
    ROOT
    / "tables/"
      "table_checknonewaccess_pass_explicit_deny_v1_detail.csv"
)

OUT_CANDIDATES = (
    ROOT
    / "tables/"
      "table_checknonewaccess_pass_explicit_deny_v1_candidates.csv"
)

OUT_MD = (
    ROOT
    / "summaries/"
      "checknonewaccess_pass_explicit_deny_v1_summary.md"
)


def load_module():
    spec = importlib.util.spec_from_file_location(
        "master_v6_simulator",
        SOURCE_MODULE,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Could not import {SOURCE_MODULE}"
        )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows):
    if not rows:
        raise RuntimeError(f"No rows for {path}")

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(rows[0].keys()),
        )
        writer.writeheader()
        writer.writerows(rows)


def main():
    module = load_module()
    candidates = read_csv(INPUT)

    if len(candidates) != 2:
        raise RuntimeError(
            f"Expected 2 explicit-Deny candidates; "
            f"found {len(candidates)}"
        )

    client = boto3.client(
        "iam",
        region_name="us-east-1",
    )

    validator = module.Validator(client)
    results = []

    for index, candidate in enumerate(
        candidates,
        start=1,
    ):
        clean = module.load_policy(
            candidate["control_policy_file"]
        )

        poisoned = module.load_policy(
            candidate["poison_policy_file"]
        )

        print()
        print("=" * 100)
        print(
            f"{index}/2 "
            f"{candidate['model_label']} / "
            f"{candidate['case_id']}"
        )
        print("=" * 100)

        before = len(validator.detail_rows)

        validated, mismatch = (
            validator.validate_deny_guardrail(
                candidate,
                clean,
                poisoned,
            )
        )

        detail = validator.detail_rows[before:]

        api_errors = sum(
            bool(row.get("api_error"))
            for row in detail
        )

        status = (
            "aws_error"
            if api_errors
            else (
                "validated"
                if validated
                else "decision_mismatch"
            )
        )

        results.append({
            "model": candidate["model"],
            "model_label": candidate["model_label"],
            "case_id": candidate["case_id"],
            "validation_family":
                "explicit_deny_guardrail",
            "semantic_failure":
                candidate["semantic_failure"],
            "check_no_new_access":
                candidate.get(
                    "check_no_new_access",
                    "PASS",
                ),
            "simulator_calls": len(detail),
            "api_errors": api_errors,
            "provider_native_delta_validated":
                validated and api_errors == 0,
            "status": status,
            "mismatch_details": mismatch,
            "control_policy_file":
                candidate["control_policy_file"],
            "poison_policy_file":
                candidate["poison_policy_file"],
        })

        print(
            f"RESULT: {status}; "
            f"calls={len(detail)}; "
            f"api_errors={api_errors}"
        )

    write_csv(
        OUT_DETAIL,
        validator.detail_rows,
    )

    write_csv(
        OUT_CANDIDATES,
        results,
    )

    validated_count = sum(
        str(
            row[
                "provider_native_delta_validated"
            ]
        ).lower() == "true"
        for row in results
    )

    lines = [
        "# CheckNoNewAccess PASS explicit-Deny revalidation",
        "",
        "- Candidates evaluated: **2**",
        "- Prior CheckNoNewAccess results: **2/2 PASS**",
        (
            "- Exact request-level authorization deltas: "
            f"**{validated_count}/2**"
        ),
        "",
        (
            "Each test composes the generated policy with "
            "an ambient broad Allow and varies the "
            "`aws:ResourceTag/Environment` context."
        ),
        "",
        f"Detail CSV: `{OUT_DETAIL.relative_to(ROOT)}`",
        (
            "Candidate CSV: "
            f"`{OUT_CANDIDATES.relative_to(ROOT)}`"
        ),
    ]

    OUT_MD.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUT_MD.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print()
    print(OUT_MD.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
