#!/usr/bin/env python3
import csv
import json
from collections import Counter
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

OUT_CSV = Path("tables/table_gate_false_positive_provider_validation_v1.csv")
OUT_MD = Path("summaries/gate_false_positive_provider_validation_v1_summary.md")

TARGETS = [
    {
        "model": "Claude Sonnet 4.5",
        "run": "runs/20260605_023333_us_anthropic_claude_sonnet_4_5_20250929_v1_0",
        "case_id": "sts_trust_001",
        "policy_type": "RESOURCE_POLICY",
        "resource_type": "AWS::IAM::AssumeRolePolicyDocument",
    },
    {
        "model": "Mistral Small",
        "run": "runs/20260605_095315_mistral_mistral_small_2402_v1_0",
        "case_id": "sts_trust_001",
        "policy_type": "RESOURCE_POLICY",
        "resource_type": "AWS::IAM::AssumeRolePolicyDocument",
    },
    {
        "model": "Nova Lite",
        "run": "runs/20260605_021337_amazon_nova_lite_v1_0",
        "case_id": "sts_trust_001",
        "policy_type": "RESOURCE_POLICY",
        "resource_type": "AWS::IAM::AssumeRolePolicyDocument",
    },
    {
        "model": "Nova Pro",
        "run": "runs/20260605_022706_amazon_nova_pro_v1_0",
        "case_id": "sts_trust_001",
        "policy_type": "RESOURCE_POLICY",
        "resource_type": "AWS::IAM::AssumeRolePolicyDocument",
    },
    {
        "model": "Llama 3 8B",
        "run": "runs/20260605_024307_meta_llama3_8b_instruct_v1_0",
        "case_id": "sts_trust_001",
        "policy_type": "RESOURCE_POLICY",
        "resource_type": "AWS::IAM::AssumeRolePolicyDocument",
    },
    {
        "model": "Llama 3 8B",
        "run": "runs/20260605_024307_meta_llama3_8b_instruct_v1_0",
        "case_id": "ec2_mfa_deny_002",
        "policy_type": "IDENTITY_POLICY",
        "resource_type": "",
    },
    {
        "model": "Llama 3 8B",
        "run": "runs/20260605_024307_meta_llama3_8b_instruct_v1_0",
        "case_id": "sqs_tls_deny_002",
        "policy_type": "IDENTITY_POLICY",
        "resource_type": "",
    },
]


def load_policy(path: Path):
    obj = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(obj, list):
        obj = {
            "Version": "2012-10-17",
            "Statement": obj,
        }

    if not isinstance(obj, dict) or "Statement" not in obj:
        raise ValueError(f"Not a policy-shaped JSON object: {path}")

    return obj


def validate(client, target):
    path = (
        Path(target["run"])
        / "raw"
        / f"req_{target['case_id']}_ctrl__REPAIRED.json"
    )

    try:
        policy = load_policy(path)
    except Exception as exc:
        return {
            **target,
            "file": str(path),
            "status": "local_load_error",
            "error_count": "",
            "security_warning_count": "",
            "warning_count": "",
            "suggestion_count": "",
            "issue_codes": "",
            "finding_details": "",
            "api_error": str(exc),
        }

    params = {
        "policyDocument": json.dumps(
            policy,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
        "policyType": target["policy_type"],
        "locale": "EN",
    }

    if target["resource_type"]:
        params["validatePolicyResourceType"] = target["resource_type"]

    findings = []

    try:
        paginator = client.get_paginator("validate_policy")
        for page in paginator.paginate(**params):
            findings.extend(page.get("findings", []))
    except ClientError as exc:
        return {
            **target,
            "file": str(path),
            "status": "aws_error",
            "error_count": "",
            "security_warning_count": "",
            "warning_count": "",
            "suggestion_count": "",
            "issue_codes": "",
            "finding_details": "",
            "api_error": str(exc),
        }

    counts = Counter(f.get("findingType", "UNKNOWN") for f in findings)
    error_count = counts.get("ERROR", 0)

    return {
        **target,
        "file": str(path),
        "status": "provider_valid" if error_count == 0 else "provider_invalid",
        "error_count": error_count,
        "security_warning_count": counts.get("SECURITY_WARNING", 0),
        "warning_count": (
            counts.get("WARNING", 0)
            + counts.get("GENERAL_WARNING", 0)
        ),
        "suggestion_count": counts.get("SUGGESTION", 0),
        "issue_codes": ";".join(
            sorted(
                {
                    f.get("issueCode", "")
                    for f in findings
                    if f.get("issueCode")
                }
            )
        ),
        "finding_details": " || ".join(
            f"{f.get('findingType', '')}:{f.get('issueCode', '')}:"
            f"{f.get('findingDetails', '')}"
            for f in findings
        ),
        "api_error": "",
    }


def main():
    client = boto3.client("accessanalyzer")
    rows = [validate(client, target) for target in TARGETS]

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "model",
        "run",
        "case_id",
        "policy_type",
        "resource_type",
        "file",
        "status",
        "error_count",
        "security_warning_count",
        "warning_count",
        "suggestion_count",
        "issue_codes",
        "finding_details",
        "api_error",
    ]

    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    counts = Counter(row["status"] for row in rows)

    lines = [
        "# Provider validation of semantic-gate false positives v1",
        "",
        f"- Policies tested: **{len(rows)}**",
        f"- Provider-valid: **{counts['provider_valid']}**",
        f"- Provider-invalid: **{counts['provider_invalid']}**",
        f"- AWS/API errors: **{counts['aws_error']}**",
        f"- Local load errors: **{counts['local_load_error']}**",
        "",
        "| Model | Case | Policy type | Status | Errors | Issue codes |",
        "|---|---|---|---|---:|---|",
    ]

    for row in rows:
        lines.append(
            f"| {row['model']} | {row['case_id']} | "
            f"{row['policy_type']} | {row['status']} | "
            f"{row['error_count']} | {row['issue_codes']} |"
        )

    lines.extend(
        [
            "",
            f"CSV: `{OUT_CSV}`",
        ]
    )

    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

    for row in rows:
        print(
            f"{row['model']:<20} "
            f"{row['case_id']:<20} "
            f"status={row['status']:<18} "
            f"errors={row['error_count']} "
            f"issues={row['issue_codes']}"
        )

    print("")
    print(OUT_MD.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
