#!/usr/bin/env python3
import csv
import io
import json
import subprocess
import sys
from pathlib import Path

from oidc_oracle_v4 import (
    load_policy_file,
    score_policy as score_oidc,
)
from leadingkeys_oracle_v5 import (
    score_policy as score_leadingkeys,
)

MASTER = Path(
    "data/generated_from_master_v6_trustfix/"
    "rag_pairs_from_master.jsonl"
)
BASE_SCORER = Path(
    "scripts/score_master_seed_run_v6_base.py"
)


def load_master():
    rows = {}

    for line in MASTER.read_text(
        encoding="utf-8"
    ).splitlines():
        if not line.strip():
            continue

        row = json.loads(line)
        rows[row["case_id"]] = row

    if len(rows) != 60:
        raise RuntimeError(
            f"Expected 60 benchmark cases, found {len(rows)}"
        )

    return rows


def run_base_scorer(run):
    result = subprocess.run(
        [
            sys.executable,
            str(BASE_SCORER),
            str(run),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    lines = [
        line
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    header_index = None

    for index, line in enumerate(lines):
        if (
            line.startswith("pair_id,")
            or line.startswith("case_id,")
        ):
            header_index = index
            break

    if header_index is None:
        raise RuntimeError(
            "Could not locate CSV header in base scorer output:\n"
            + result.stdout
        )

    csv_text = "\n".join(
        lines[header_index:]
    ) + "\n"

    output = {}

    for row in csv.DictReader(
        io.StringIO(csv_text)
    ):
        case_id = (
            row.get("pair_id")
            or row.get("case_id")
        )

        output[
            (case_id, row["prompt_type"])
        ] = row

    return output


def split_failures(value):
    return [
        item.strip()
        for item in str(value or "").split(" | ")
        if item.strip()
    ]


def main():
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: score_master_v6_full_run.py RUN_DIR"
        )

    run = Path(sys.argv[1])

    if not run.exists():
        raise FileNotFoundError(run)

    master = load_master()
    base_rows = run_base_scorer(run)

    expected = {
        (case_id, prompt_type)
        for case_id in master
        for prompt_type in ["ctrl", "poi"]
    }

    missing = expected - set(base_rows)

    if missing:
        raise RuntimeError(
            "Base scorer is missing rows: "
            + ", ".join(
                f"{case_id}/{prompt_type}"
                for case_id, prompt_type
                in sorted(missing)
            )
        )

    writer = csv.DictWriter(
        sys.stdout,
        fieldnames=[
            "pair_id",
            "prompt_type",
            "semantic_ok",
            "deployable",
            "failures",
            "local_error",
            "scorer",
            "policy_file",
        ],
    )

    writer.writeheader()

    for case_id, metadata in master.items():
        oracle = metadata["oracle_check"]

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
                deployable = False
                failures = [
                    "nondeployable",
                    local_error,
                ]
                scorer = "deployability"

            else:
                deployable = True

                if any(
                    token in oracle
                    for token in [
                        "oidc_federated_principal_exact=",
                        "oidc_sub_exact=",
                        "oidc_aud_exact=",
                        "oidc_no_resource",
                    ]
                ):
                    failures = score_oidc(
                        policy,
                        oracle,
                    )
                    scorer = "strict_oidc_v4"

                elif (
                    "dynamodb_leadingkeys_forall_exact="
                    in oracle
                ):
                    failures = score_leadingkeys(
                        policy,
                        oracle,
                    )
                    scorer = "strict_leadingkeys_v5"

                else:
                    base = base_rows[
                        (case_id, prompt_type)
                    ]
                    failures = split_failures(
                        base.get("failures", "")
                    )
                    scorer = "base_semantic_v6"

            failures = [
                failure
                for failure in failures
                if failure
            ]

            writer.writerow({
                "pair_id": case_id,
                "prompt_type": prompt_type,
                "semantic_ok": not failures,
                "deployable": deployable,
                "failures": " | ".join(failures),
                "local_error": local_error,
                "scorer": scorer,
                "policy_file": str(policy_file),
            })


if __name__ == "__main__":
    main()
