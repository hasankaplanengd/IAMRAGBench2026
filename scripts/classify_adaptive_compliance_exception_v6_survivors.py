#!/usr/bin/env python3
import csv
from collections import Counter, defaultdict
from pathlib import Path


INPUT = Path(
    "tables/"
    "table_adaptive_compliance_exception_v6_"
    "new_access_survivors.csv"
)

OUT_CSV = Path(
    "tables/"
    "table_adaptive_compliance_exception_v6_"
    "survivor_families.csv"
)

OUT_MD = Path(
    "summaries/"
    "adaptive_compliance_exception_v6_"
    "survivor_families_summary.md"
)


ACTION_CASES = {
    "cloudwatch_logs_001",
    "ddb_action_002",
    "ec2_action_002",
    "kms_action_002",
    "lambda_action_002",
    "logs_action_002",
    "s3_action_002",
}

RESOURCE_CASES = {
    "ddb_resource_002",
    "lambda_resource_002",
    "logs_resource_002",
    "s3_resource_002",
    "secrets_resource_001",
    "secrets_resource_002",
    "sqs_resource_002",
}

PUBLIC_CASES = {
    "ecr_public_002",
    "lambda_public_002",
    "s3_public_002",
    "s3_public_policy_001",
}

LEADINGKEYS_CASES = {
    "dynamodb_abac_001",
    "dynamodb_tenant_002",
}

DENY_CASES = {
    "ec2_mfa_deny_002",
    "iam_mfa_deny_002",
    "kms_tls_deny_002",
    "s3_tls_deny_002",
    "secrets_tls_deny_002",
    "sqs_tls_deny_002",
}

CONDITION_CASES = {
    "ec2_region_002",
    "ec2_tag_002",
    "kms_tag_002",
    "kms_viaservice_002",
    "logs_vpce_002",
    "s3_condition_001",
    "s3_tag_002",
    "s3_vpce_002",
    "secrets_tag_002",
    "secrets_vpce_002",
    "ssm_tag_002",
}

EXPECTED_FAMILY_COUNTS = {
    "action_scope_widening": 8,
    "resource_scope_widening": 9,
    "public_or_principal_scope": 4,
    "dynamodb_leadingkeys": 4,
    "explicit_deny_guardrail": 7,
    "allow_condition_removal": 19,
    "kms_multi_condition": 2,
    "passrole_scope": 14,
    "oidc_or_role_trust": 13,
    "sqs_sourcearn_resource": 2,
}

EXPECTED_MODEL_COUNTS = {
    "nova_pro": 46,
    "llama3_8b": 36,
}


def read_csv(path):
    if not path.exists():
        raise FileNotFoundError(path)

    with path.open(
        newline="",
        encoding="utf-8",
    ) as f:
        return list(csv.DictReader(f))


def classify(case_id):
    if (
        case_id.startswith("sts_oidc_trust_")
        or case_id == "sts_trust_001"
    ):
        return "oidc_or_role_trust"

    if case_id.startswith("sqs_sourcearn_"):
        return "sqs_sourcearn_resource"

    if case_id.startswith("iam_passrole"):
        return "passrole_scope"

    if case_id == "kms_condition_001":
        return "kms_multi_condition"

    if case_id in LEADINGKEYS_CASES:
        return "dynamodb_leadingkeys"

    if case_id in DENY_CASES:
        return "explicit_deny_guardrail"

    if case_id in PUBLIC_CASES:
        return "public_or_principal_scope"

    if case_id in ACTION_CASES:
        return "action_scope_widening"

    if case_id in RESOURCE_CASES:
        return "resource_scope_widening"

    if case_id in CONDITION_CASES:
        return "allow_condition_removal"

    return "unclassified"


def main():
    rows = read_csv(INPUT)

    if len(rows) != 82:
        raise RuntimeError(
            f"Expected 82 AWS new-access survivors, "
            f"found {len(rows)}"
        )

    output = []

    for row in rows:
        if row["status"] != "new_access_flagged":
            raise RuntimeError(
                f"{row['model']}/{row['case_id']}: "
                f"unexpected status {row['status']}"
            )

        if row["check_result"] != "FAIL":
            raise RuntimeError(
                f"{row['model']}/{row['case_id']}: "
                f"expected FAIL, got {row['check_result']}"
            )

        if row["api_error"]:
            raise RuntimeError(
                f"{row['model']}/{row['case_id']}: "
                "AWS error remains"
            )

        family = classify(
            row["case_id"]
        )

        output.append({
            **row,
            "validation_family": family,
        })

    unclassified = [
        row
        for row in output
        if row["validation_family"]
        == "unclassified"
    ]

    if unclassified:
        for row in unclassified:
            print(
                "UNCLASSIFIED:",
                row["model"],
                row["case_id"],
                row["semantic_failure"],
            )

        raise RuntimeError(
            f"{len(unclassified)} survivors "
            "were not assigned to a family"
        )

    family_counts = Counter(
        row["validation_family"]
        for row in output
    )

    if dict(family_counts) != EXPECTED_FAMILY_COUNTS:
        raise RuntimeError(
            "Unexpected family distribution.\n"
            f"Observed: {dict(family_counts)}\n"
            f"Expected: {EXPECTED_FAMILY_COUNTS}"
        )

    model_counts = Counter(
        row["model"]
        for row in output
    )

    if dict(model_counts) != EXPECTED_MODEL_COUNTS:
        raise RuntimeError(
            "Unexpected model distribution.\n"
            f"Observed: {dict(model_counts)}\n"
            f"Expected: {EXPECTED_MODEL_COUNTS}"
        )

    output.sort(
        key=lambda row: (
            row["validation_family"],
            row["model"],
            row["case_id"],
        )
    )

    OUT_CSV.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUT_CSV.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(
                output[0].keys()
            ),
        )
        writer.writeheader()
        writer.writerows(output)

    by_model = defaultdict(Counter)

    for row in output:
        by_model[
            row["model"]
        ][
            row["validation_family"]
        ] += 1

    family_order = list(
        EXPECTED_FAMILY_COUNTS
    )

    lines = [
        "# Adaptive compliance-exception v6 survivor families",
        "",
        "- AWS new-access survivors: **82**",
        "- Nova Pro survivors: **46**",
        "- Llama 3 8B survivors: **36**",
        "- Unclassified survivors: **0**",
        "",
        "## Family counts",
        "",
        "| Validation family | Candidates |",
        "|---|---:|",
    ]

    for family in family_order:
        lines.append(
            f"| {family} | "
            f"{family_counts[family]} |"
        )

    lines.extend([
        "",
        "## By model",
        "",
        (
            "| Model | Action | Resource | Public | "
            "LeadingKeys | Deny | Condition | KMS | "
            "PassRole | Trust/OIDC | SQS SourceArn |"
        ),
        (
            "|---|---:|---:|---:|---:|---:|---:|"
            "---:|---:|---:|---:|"
        ),
    ])

    labels = {
        "nova_pro": "Nova Pro",
        "llama3_8b": "Llama 3 8B",
    }

    compact_families = [
        "action_scope_widening",
        "resource_scope_widening",
        "public_or_principal_scope",
        "dynamodb_leadingkeys",
        "explicit_deny_guardrail",
        "allow_condition_removal",
        "kms_multi_condition",
        "passrole_scope",
        "oidc_or_role_trust",
        "sqs_sourcearn_resource",
    ]

    for model in [
        "nova_pro",
        "llama3_8b",
    ]:
        counts = by_model[model]

        values = [
            counts[family]
            for family in compact_families
        ]

        lines.append(
            f"| {labels[model]} | "
            + " | ".join(
                str(value)
                for value in values
            )
            + " |"
        )

    lines.extend([
        "",
        "## Candidate details",
        "",
    ])

    for family in family_order:
        lines.append(
            f"### {family}"
        )
        lines.append("")

        for row in output:
            if (
                row["validation_family"]
                != family
            ):
                continue

            lines.append(
                f"- `{row['model']}` / "
                f"`{row['case_id']}`: "
                f"{row['semantic_failure']}"
            )

        lines.append("")

    lines.extend([
        f"CSV: `{OUT_CSV}`",
        "",
        (
            "PASS: all 82 adaptive AWS new-access "
            "survivors were assigned to exact-witness "
            "validation families."
        ),
    ])

    OUT_MD.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUT_MD.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(
        OUT_MD.read_text(
            encoding="utf-8"
        )
    )


if __name__ == "__main__":
    main()
