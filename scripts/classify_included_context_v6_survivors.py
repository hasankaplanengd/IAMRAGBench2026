#!/usr/bin/env python3
import csv
from collections import Counter, defaultdict
from pathlib import Path

INPUT = Path(
    "tables/"
    "table_included_context_v6_unguarded_strong_"
    "new_access_survivors.csv"
)

OUT_CSV = Path(
    "tables/"
    "table_included_context_v6_unguarded_strong_"
    "survivor_families.csv"
)

OUT_MD = Path(
    "summaries/"
    "included_context_v6_unguarded_strong_"
    "survivor_families_summary.md"
)

MODEL_ORDER = {
    "mistral_small": 0,
    "nova_lite": 1,
    "nova_pro": 2,
    "llama3_8b": 3,
}


def classify(row):
    case_id = row["case_id"]
    policy_type = row["policy_type"]
    failure = row["semantic_failure"]

    if policy_type == "RESOURCE_POLICY":
        if case_id.startswith("sqs_sourcearn_"):
            return "sqs_sourcearn_resource"

        if (
            case_id == "sts_trust_001"
            or case_id.startswith("sts_oidc_trust_")
        ):
            return "oidc_or_role_trust"

        return "resource_policy_other"

    if case_id == "iam_passrole_001":
        return "passrole_scope"

    if case_id == "dynamodb_abac_001":
        return "dynamodb_leadingkeys"

    if case_id == "kms_condition_001":
        return "kms_multi_condition"

    if "missing_deny_condition:" in failure:
        return "explicit_deny_guardrail"

    if (
        "missing_allow_condition:" in failure
        or "missing_condition:" in failure
    ):
        return "allow_condition_removal"

    return "unclassified"


def main():
    if not INPUT.exists():
        raise FileNotFoundError(INPUT)

    with INPUT.open(
        newline="",
        encoding="utf-8",
    ) as f:
        rows = list(csv.DictReader(f))

    if len(rows) != 54:
        raise RuntimeError(
            f"Expected 54 AWS new-access survivors, "
            f"found {len(rows)}"
        )

    output = []

    for row in rows:
        row = dict(row)
        row["validation_family"] = classify(row)
        output.append(row)

    unclassified = [
        row
        for row in output
        if row["validation_family"] in {
            "unclassified",
            "resource_policy_other",
        }
    ]

    if unclassified:
        for row in unclassified:
            print(
                "UNCLASSIFIED:",
                row["model"],
                row["case_id"],
                row["policy_type"],
                row["semantic_failure"],
            )

        raise SystemExit(
            "FAIL: one or more survivors were not classified."
        )

    family_counts = Counter(
        row["validation_family"]
        for row in output
    )

    expected_counts = {
        "allow_condition_removal": 20,
        "oidc_or_role_trust": 17,
        "explicit_deny_guardrail": 6,
        "passrole_scope": 4,
        "kms_multi_condition": 3,
        "dynamodb_leadingkeys": 2,
        "sqs_sourcearn_resource": 2,
    }

    if dict(family_counts) != expected_counts:
        print("Observed:", dict(family_counts))
        print("Expected:", expected_counts)

        raise SystemExit(
            "FAIL: survivor-family counts differ from expected."
        )

    fieldnames = list(output[0].keys())

    with OUT_CSV.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(output)

    by_family = defaultdict(list)
    by_model = defaultdict(Counter)

    for row in output:
        by_family[
            row["validation_family"]
        ].append(row)

        by_model[
            row["model"]
        ][row["validation_family"]] += 1

    lines = [
        "# Included-context v6 survivor families",
        "",
        f"- AWS new-access survivors: **{len(output)}**",
        "",
        "## Family counts",
        "",
        "| Validation family | Candidates |",
        "|---|---:|",
    ]

    for family, count in expected_counts.items():
        lines.append(
            f"| {family} | {count} |"
        )

    lines.extend([
        "",
        "## By model",
        "",
        (
            "| Model | Allow-condition | PassRole | "
            "LeadingKeys | KMS multi-condition | "
            "Explicit Deny | Trust/OIDC | SQS SourceArn |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ])

    for model in sorted(
        by_model,
        key=lambda value: MODEL_ORDER.get(
            value,
            99,
        ),
    ):
        counts = by_model[model]

        lines.append(
            f"| {model} | "
            f"{counts['allow_condition_removal']} | "
            f"{counts['passrole_scope']} | "
            f"{counts['dynamodb_leadingkeys']} | "
            f"{counts['kms_multi_condition']} | "
            f"{counts['explicit_deny_guardrail']} | "
            f"{counts['oidc_or_role_trust']} | "
            f"{counts['sqs_sourcearn_resource']} |"
        )

    lines.extend([
        "",
        "## Candidate details",
        "",
    ])

    for family in expected_counts:
        lines.append(f"### {family}")
        lines.append("")

        for row in by_family[family]:
            lines.append(
                f"- `{row['model']}` / "
                f"`{row['case_id']}`: "
                f"{row['semantic_failure']}"
            )

        lines.append("")

    lines.append(f"CSV: `{OUT_CSV}`")

    OUT_MD.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUT_MD.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(OUT_MD.read_text(encoding="utf-8"))
    print(
        "PASS: all 54 AWS new-access survivors "
        "were assigned to request-validation families."
    )


if __name__ == "__main__":
    main()
