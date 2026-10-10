#!/usr/bin/env python3
import csv
import json
import time
from collections import Counter
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

INPUT = Path(
    "tables/table_provider_validity_all_e2e_clean_controls_v1.csv"
)

OUT_CSV = Path(
    "tables/table_sqs_sourcearn_resource_policy_validation_v1.csv"
)
OUT_MD = Path(
    "summaries/sqs_sourcearn_resource_policy_validation_v1_summary.md"
)

CASE_ID = "sqs_sourcearn_001"


def load_policy(path: Path):
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"json_parse_error:{exc}"

    if isinstance(obj, dict) and obj.get("ok") is False:
        return None, (
            "repair_wrapper:"
            + str(obj.get("repair", obj.get("error", "unknown")))
        )

    if isinstance(obj, list):
        obj = {
            "Version": "2012-10-17",
            "Statement": obj,
        }

    if not isinstance(obj, dict) or "Statement" not in obj:
        return None, "not_policy_object"

    return obj, ""


def statements(policy):
    value = policy.get("Statement", [])
    return value if isinstance(value, list) else [value]


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def summarize(policy):
    actions = []
    resources = []
    principals = []
    condition_keys = []

    for statement in statements(policy):
        actions.extend(as_list(statement.get("Action")))
        resources.extend(as_list(statement.get("Resource")))

        principal = statement.get("Principal")
        if isinstance(principal, dict):
            for kind, value in principal.items():
                for item in as_list(value):
                    principals.append(f"{kind}:{item}")
        elif principal is not None:
            principals.extend(as_list(principal))

        condition = statement.get("Condition", {})
        if isinstance(condition, dict):
            for operator, key_values in condition.items():
                if not isinstance(key_values, dict):
                    continue

                for key in key_values:
                    condition_keys.append(
                        f"{operator}:{key}"
                    )

    return {
        "actions": actions,
        "resources": resources,
        "principals": principals,
        "condition_keys": condition_keys,
        "has_principal": bool(principals),
        "has_sourcearn": any(
            key.lower().endswith(":aws:sourcearn")
            or key.lower() == "aws:sourcearn"
            or key.lower().endswith("aws:sourcearn")
            for key in condition_keys
        ),
    }


def validate_once(client, policy):
    findings = []
    next_token = None

    while True:
        params = {
            "policyDocument": json.dumps(
                policy,
                separators=(",", ":"),
                ensure_ascii=False,
            ),
            "policyType": "RESOURCE_POLICY",
            "locale": "EN",
        }

        # SQS is not currently a resource-specific
        # validatePolicyResourceType value, so we intentionally
        # request generic resource-policy validation.
        if next_token:
            params["nextToken"] = next_token

        response = client.validate_policy(**params)
        findings.extend(response.get("findings", []))

        next_token = response.get("nextToken")
        if not next_token:
            break

    return findings


def validate_with_retry(client, policy, attempts=6):
    delay = 1.0

    for attempt in range(attempts):
        try:
            return validate_once(client, policy), ""
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")

            if (
                code
                in {
                    "ThrottlingException",
                    "TooManyRequestsException",
                    "RequestLimitExceeded",
                }
                and attempt < attempts - 1
            ):
                time.sleep(delay)
                delay *= 2
                continue

            return [], str(exc)

    return [], "retry_exhausted"


def main():
    if not INPUT.exists():
        raise SystemExit(f"Missing input: {INPUT}")

    with INPUT.open(newline="", encoding="utf-8") as f:
        source_rows = [
            row
            for row in csv.DictReader(f)
            if row["case_id"] == CASE_ID
        ]

    if not source_rows:
        raise SystemExit(
            f"No clean-control rows found for {CASE_ID}"
        )

    client = boto3.client("accessanalyzer")
    rows = []

    for source in source_rows:
        policy_path = Path(source["policy_file"])
        policy, load_error = load_policy(policy_path)

        if policy is None:
            rows.append({
                "model": source["model"],
                "case_id": CASE_ID,
                "previous_policy_type": source["policy_type"],
                "previous_status": source["status"],
                "previous_issue_codes": source["issue_codes"],
                "resource_policy_status": "local_invalid",
                "error_count": "",
                "security_warning_count": "",
                "warning_count": "",
                "suggestion_count": "",
                "issue_codes": "",
                "has_principal": "",
                "has_sourcearn": "",
                "actions": "",
                "resources": "",
                "principals": "",
                "condition_keys": "",
                "finding_details": "",
                "local_error": load_error,
                "api_error": "",
                "policy_file": str(policy_path),
            })
            continue

        summary = summarize(policy)
        findings, api_error = validate_with_retry(
            client,
            policy,
        )

        counts = Counter(
            finding.get("findingType", "UNKNOWN")
            for finding in findings
        )

        if api_error:
            status = "aws_error"
        elif counts.get("ERROR", 0):
            status = "provider_invalid"
        else:
            status = "provider_valid"

        issue_codes = sorted({
            finding.get("issueCode", "")
            for finding in findings
            if finding.get("issueCode")
        })

        finding_details = " || ".join(
            (
                f"{finding.get('findingType', '')}:"
                f"{finding.get('issueCode', '')}:"
                f"{finding.get('findingDetails', '')}"
            )
            for finding in findings
        )

        rows.append({
            "model": source["model"],
            "case_id": CASE_ID,
            "previous_policy_type": source["policy_type"],
            "previous_status": source["status"],
            "previous_issue_codes": source["issue_codes"],
            "resource_policy_status": status,
            "error_count": counts.get("ERROR", ""),
            "security_warning_count": counts.get(
                "SECURITY_WARNING", ""
            ),
            "warning_count": (
                counts.get("WARNING", 0)
                + counts.get("GENERAL_WARNING", 0)
            ),
            "suggestion_count": counts.get("SUGGESTION", ""),
            "issue_codes": ";".join(issue_codes),
            "has_principal": summary["has_principal"],
            "has_sourcearn": summary["has_sourcearn"],
            "actions": ";".join(map(str, summary["actions"])),
            "resources": ";".join(map(str, summary["resources"])),
            "principals": ";".join(
                map(str, summary["principals"])
            ),
            "condition_keys": ";".join(
                summary["condition_keys"]
            ),
            "finding_details": finding_details,
            "local_error": "",
            "api_error": api_error,
            "policy_file": str(policy_path),
        })

        print(
            f"{source['model']:<20} "
            f"old={source['status']:<18} "
            f"resource_policy={status:<18} "
            f"principal={summary['has_principal']!s:<5} "
            f"sourcearn={summary['has_sourcearn']!s:<5} "
            f"issues={';'.join(issue_codes)}"
        )

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "model",
        "case_id",
        "previous_policy_type",
        "previous_status",
        "previous_issue_codes",
        "resource_policy_status",
        "error_count",
        "security_warning_count",
        "warning_count",
        "suggestion_count",
        "issue_codes",
        "has_principal",
        "has_sourcearn",
        "actions",
        "resources",
        "principals",
        "condition_keys",
        "finding_details",
        "local_error",
        "api_error",
        "policy_file",
    ]

    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    totals = Counter(
        row["resource_policy_status"]
        for row in rows
    )

    lines = [
        "# SQS SourceArn clean controls revalidated as resource policies",
        "",
        f"- Case: `{CASE_ID}`",
        f"- Controls audited: **{len(rows)}**",
        f"- Provider-valid as resource policies: **{totals['provider_valid']}**",
        f"- Provider-invalid: **{totals['provider_invalid']}**",
        f"- Local invalid: **{totals['local_invalid']}**",
        f"- AWS errors: **{totals['aws_error']}**",
        "",
        "| Model | Previous status | Resource-policy status | Principal | SourceArn | Issue codes |",
        "|---|---|---|---|---|---|",
    ]

    for row in rows:
        lines.append(
            f"| {row['model']} | "
            f"{row['previous_status']} | "
            f"{row['resource_policy_status']} | "
            f"{row['has_principal']} | "
            f"{row['has_sourcearn']} | "
            f"{row['issue_codes']} |"
        )

    lines.extend([
        "",
        f"CSV: `{OUT_CSV}`",
    ])

    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print("")
    print(OUT_MD.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
