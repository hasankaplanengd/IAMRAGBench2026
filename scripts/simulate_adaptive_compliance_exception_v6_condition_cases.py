#!/usr/bin/env python3
import csv
import importlib.util
from collections import Counter, defaultdict
from pathlib import Path

BASE_PATH = Path(
    "scripts/simulate_master_v6_candidates.py"
)

INPUT = Path(
    "tables/"
    "table_adaptive_compliance_exception_v6_"
    "survivor_families.csv"
)

OUT_DETAIL = Path(
    "tables/"
    "table_adaptive_compliance_exception_v6_"
    "condition_leadingkeys_request_detail.csv"
)

OUT_CANDIDATES = Path(
    "tables/"
    "table_adaptive_compliance_exception_v6_"
    "condition_leadingkeys_request_candidates.csv"
)

OUT_MD = Path(
    "summaries/"
    "adaptive_compliance_exception_v6_"
    "condition_leadingkeys_request_summary.md"
)

if not BASE_PATH.exists():
    raise FileNotFoundError(BASE_PATH)

spec = importlib.util.spec_from_file_location(
    "base_sim",
    BASE_PATH,
)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def stronger_forbidden_value(key, intended):
    intended = str(intended)

    options = {
        "aws:RequestedRegion": [
            "us-west-2",
            "eu-west-1",
        ],
        "aws:SourceVpce": [
            "vpce-0ddd4444",
            "vpce-0eee5555",
        ],
        "s3:ExistingObjectTag/Tenant": [
            "beta",
            "tenant-beta",
        ],
        "aws:ResourceTag/Project": [
            "billing",
            "analytics",
        ],
        "aws:ResourceTag/Team": [
            "security",
            "analytics",
        ],
        "aws:ResourceTag/Environment": [
            "dev",
            "staging",
        ],
        "aws:ResourceTag/Env": [
            "dev",
            "staging",
        ],
        "kms:ViaService": [
            "ec2.us-east-1.amazonaws.com",
            "s3.us-east-1.amazonaws.com",
        ],
    }

    for candidate in options.get(
        key,
        ["forbidden-value"],
    ):
        if candidate != intended:
            return candidate

    return intended + "-different"


# Validator methods resolve this function from their module.
base.forbidden_value = stronger_forbidden_value


def main():
    if not INPUT.exists():
        raise FileNotFoundError(INPUT)

    with INPUT.open(
        newline="",
        encoding="utf-8",
    ) as f:
        rows = list(csv.DictReader(f))

    candidates = [
        row
        for row in rows
        if row["validation_family"] in {
            "allow_condition_removal",
            "dynamodb_leadingkeys",
        }
    ]

    counts = Counter(
        row["validation_family"]
        for row in candidates
    )

    expected = {
        "allow_condition_removal": 19,
        "dynamodb_leadingkeys": 4,
    }

    if dict(counts) != expected:
        raise RuntimeError(
            f"Expected {expected}, observed {dict(counts)}"
        )

    validator = base.Validator(
        base.boto3.client(
            "iam",
            region_name="us-east-1",
        )
    )

    results = []

    for index, candidate in enumerate(
        candidates,
        start=1,
    ):
        clean = base.load_policy(
            candidate["control_policy_file"]
        )
        poisoned = base.load_policy(
            candidate["poison_policy_file"]
        )

        family = candidate[
            "validation_family"
        ]

        print("")
        print("=" * 100)
        print(
            f"{index}/22 "
            f"{candidate['model_label']} / "
            f"{candidate['case_id']} / {family}"
        )
        print("=" * 100)

        before = len(
            validator.detail_rows
        )

        if family == "dynamodb_leadingkeys":
            validated, mismatch = (
                validator.validate_leadingkeys(
                    candidate,
                    clean,
                    poisoned,
                )
            )
        else:
            validated, mismatch = (
                validator.validate_condition_removal(
                    candidate,
                    clean,
                    poisoned,
                )
            )

        detail = validator.detail_rows[
            before:
        ]

        api_errors = sum(
            bool(row["api_error"])
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
            "model_label":
                candidate["model_label"],
            "case_id": candidate["case_id"],
            "validation_family": family,
            "semantic_failure":
                candidate["semantic_failure"],
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

        if mismatch:
            print(f"MISMATCH: {mismatch}")

    OUT_DETAIL.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    detail_fields = [
        "model",
        "model_label",
        "case_id",
        "validation_family",
        "policy_variant",
        "request_class",
        "action",
        "resource",
        "context_key",
        "context_values",
        "context_type",
        "ambient_allow",
        "decision",
        "missing_context",
        "api_error",
    ]

    with OUT_DETAIL.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=detail_fields,
        )
        writer.writeheader()
        writer.writerows(
            validator.detail_rows
        )

    result_fields = [
        "model",
        "model_label",
        "case_id",
        "validation_family",
        "semantic_failure",
        "simulator_calls",
        "api_errors",
        "provider_native_delta_validated",
        "status",
        "mismatch_details",
        "control_policy_file",
        "poison_policy_file",
    ]

    with OUT_CANDIDATES.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=result_fields,
        )
        writer.writeheader()
        writer.writerows(results)

    by_family = defaultdict(Counter)

    for row in results:
        by_family[
            row["validation_family"]
        ][row["status"]] += 1

    total_errors = sum(
        row["api_errors"]
        for row in results
    )

    total_validated = sum(
        row[
            "provider_native_delta_validated"
        ]
        for row in results
    )

    lines = [
        "# Adaptive compliance-exception v6 condition/LeadingKeys request validation",
        "",
        "- Candidates tested: **23**",
        (
            "- Provider-native authorization deltas: "
            f"**{total_validated}/23**"
        ),
        f"- AWS/API errors: **{total_errors}**",
        "",
        "## By family",
        "",
        "| Family | Candidates | Validated | Mismatch | AWS errors |",
        "|---|---:|---:|---:|---:|",
    ]

    for family, total in expected.items():
        values = by_family[family]

        lines.append(
            f"| {family} | "
            f"{total} | "
            f"{values['validated']} | "
            f"{values['decision_mismatch']} | "
            f"{values['aws_error']} |"
        )

    lines.extend([
        "",
        "## Candidate outcomes",
        "",
        "| Model | Case | Family | Status | Calls |",
        "|---|---|---|---|---:|",
    ])

    for row in results:
        lines.append(
            f"| {row['model_label']} | "
            f"{row['case_id']} | "
            f"{row['validation_family']} | "
            f"{row['status']} | "
            f"{row['simulator_calls']} |"
        )

    lines.extend([
        "",
        f"Detail CSV: `{OUT_DETAIL}`",
        f"Candidate CSV: `{OUT_CANDIDATES}`",
    ])

    OUT_MD.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUT_MD.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print("")
    print(
        OUT_MD.read_text(
            encoding="utf-8"
        )
    )

    if total_errors:
        raise SystemExit(
            "FAIL: one or more simulator calls failed."
        )

    print(
        "PASS: all 23 condition/LeadingKeys "
        "survivors were request-tested."
    )


if __name__ == "__main__":
    main()
