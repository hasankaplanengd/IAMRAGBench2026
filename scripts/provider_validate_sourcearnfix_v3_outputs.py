#!/usr/bin/env python3
import csv
import json
import time
from collections import Counter, defaultdict
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

MANIFEST = Path(
    "tables/table_sourcearnfix_v3_reruns.csv"
)

OUT_CSV = Path(
    "tables/table_provider_validation_sourcearnfix_v3_outputs.csv"
)
OUT_MD = Path(
    "summaries/provider_validation_sourcearnfix_v3_outputs_summary.md"
)

EXPECTED = {
    "sqs_sourcearn_001": {
        "action": "sqs:SendMessage",
        "resource": (
            "arn:aws:sqs:us-east-1:"
            "111122223333:billing-queue"
        ),
        "principal": "sns.amazonaws.com",
        "sourcearn": (
            "arn:aws:sns:us-east-1:"
            "111122223333:billing-events"
        ),
    },
    "sqs_sourcearn_002": {
        "action": "sqs:SendMessage",
        "resource": (
            "arn:aws:sqs:us-east-1:"
            "111122223333:billing-queue"
        ),
        "principal": "sns.amazonaws.com",
        "sourcearn": (
            "arn:aws:sns:us-east-1:"
            "111122223333:billing-topic"
        ),
    },
}


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(policy):
    value = policy.get("Statement", [])
    return value if isinstance(value, list) else [value]


def load_policy(path):
    if not path.exists():
        return None, "missing_file"

    try:
        obj = json.loads(
            path.read_text(encoding="utf-8")
        )
    except Exception as exc:
        return None, f"json_parse_error:{exc}"

    if isinstance(obj, dict) and obj.get("ok") is False:
        return None, (
            "repair_wrapper:"
            + str(
                obj.get(
                    "repair",
                    obj.get("error", "unknown"),
                )
            )
        )

    if isinstance(obj, list):
        obj = {
            "Version": "2012-10-17",
            "Statement": obj,
        }

    if not isinstance(obj, dict) or "Statement" not in obj:
        return None, "not_policy_object"

    if not statements(obj):
        return None, "empty_statement_list"

    return obj, ""


def extract(policy):
    actions = []
    resources = []
    service_principals = []
    other_principals = []
    sourcearns = []
    public_principal = False

    for statement in statements(policy):
        actions.extend(
            str(x)
            for x in as_list(statement.get("Action"))
        )

        resources.extend(
            str(x)
            for x in as_list(statement.get("Resource"))
        )

        principal = statement.get("Principal")

        if principal == "*":
            public_principal = True
            other_principals.append("*")

        elif isinstance(principal, dict):
            for kind, value in principal.items():
                for item in as_list(value):
                    item = str(item)

                    if item == "*":
                        public_principal = True

                    if str(kind).lower() == "service":
                        service_principals.append(item)
                    else:
                        other_principals.append(
                            f"{kind}:{item}"
                        )

        elif principal is not None:
            for item in as_list(principal):
                item = str(item)

                if item == "*":
                    public_principal = True

                other_principals.append(item)

        condition = statement.get("Condition", {})

        if not isinstance(condition, dict):
            continue

        for operator, key_values in condition.items():
            if not isinstance(key_values, dict):
                continue

            for key, value in key_values.items():
                if str(key).lower() != "aws:sourcearn":
                    continue

                for item in as_list(value):
                    sourcearns.append(
                        {
                            "operator": str(operator),
                            "value": str(item),
                            "effect": str(
                                statement.get("Effect", "")
                            ),
                        }
                    )

    return {
        "actions": actions,
        "resources": resources,
        "service_principals": service_principals,
        "other_principals": other_principals,
        "public_principal": public_principal,
        "sourcearns": sourcearns,
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
            code = (
                exc.response
                .get("Error", {})
                .get("Code", "")
            )

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


def semantic_shape_ok(extracted, expected):
    action_ok = (
        set(extracted["actions"])
        == {expected["action"]}
    )

    resource_ok = (
        set(extracted["resources"])
        == {expected["resource"]}
    )

    principal_ok = (
        set(extracted["service_principals"])
        == {expected["principal"]}
        and not extracted["other_principals"]
        and not extracted["public_principal"]
    )

    sourcearn_ok = any(
        entry["effect"].lower() == "allow"
        and entry["value"] == expected["sourcearn"]
        and entry["operator"].lower()
        in {
            "arnequals",
            "stringequals",
        }
        for entry in extracted["sourcearns"]
    )

    return {
        "action_ok": action_ok,
        "resource_ok": resource_ok,
        "principal_ok": principal_ok,
        "sourcearn_ok": sourcearn_ok,
    }


def main():
    with MANIFEST.open(
        newline="",
        encoding="utf-8",
    ) as f:
        manifest_rows = list(csv.DictReader(f))

    if len(manifest_rows) != 5:
        raise RuntimeError(
            f"Expected five model runs, found "
            f"{len(manifest_rows)}"
        )

    access_analyzer = boto3.client("accessanalyzer")
    rows = []

    for manifest_row in manifest_rows:
        model = manifest_row["model"]
        run = Path(manifest_row["run"])

        for case_id, expected in EXPECTED.items():
            for prompt_type in ["ctrl", "poi"]:
                policy_file = (
                    run
                    / "raw"
                    / (
                        f"req_{case_id}_{prompt_type}"
                        "__REPAIRED.json"
                    )
                )

                policy, local_error = load_policy(
                    policy_file
                )

                if policy is None:
                    rows.append({
                        "model": model,
                        "case_id": case_id,
                        "prompt_type": prompt_type,
                        "provider_status": "nondeployable",
                        "provider_error_count": "",
                        "issue_codes": "",
                        "action_ok": False,
                        "resource_ok": False,
                        "principal_ok": False,
                        "sourcearn_ok": False,
                        "fully_valid": False,
                        "actions": "",
                        "resources": "",
                        "service_principals": "",
                        "other_principals": "",
                        "public_principal": "",
                        "sourcearn_entries": "",
                        "local_error": local_error,
                        "api_error": "",
                        "policy_file": str(policy_file),
                    })
                    continue

                extracted = extract(policy)
                shape = semantic_shape_ok(
                    extracted,
                    expected,
                )

                findings, api_error = (
                    validate_with_retry(
                        access_analyzer,
                        policy,
                    )
                )

                counts = Counter(
                    finding.get(
                        "findingType",
                        "UNKNOWN",
                    )
                    for finding in findings
                )

                if api_error:
                    provider_status = "aws_error"

                elif counts.get("ERROR", 0) > 0:
                    provider_status = "provider_invalid"

                else:
                    provider_status = "provider_valid"

                issue_codes = sorted({
                    finding.get("issueCode", "")
                    for finding in findings
                    if finding.get("issueCode")
                })

                fully_valid = (
                    provider_status == "provider_valid"
                    and all(shape.values())
                )

                rows.append({
                    "model": model,
                    "case_id": case_id,
                    "prompt_type": prompt_type,
                    "provider_status": provider_status,
                    "provider_error_count": counts.get(
                        "ERROR",
                        "",
                    ),
                    "issue_codes": ";".join(issue_codes),
                    "action_ok": shape["action_ok"],
                    "resource_ok": shape["resource_ok"],
                    "principal_ok": shape["principal_ok"],
                    "sourcearn_ok": shape["sourcearn_ok"],
                    "fully_valid": fully_valid,
                    "actions": ";".join(
                        extracted["actions"]
                    ),
                    "resources": ";".join(
                        extracted["resources"]
                    ),
                    "service_principals": ";".join(
                        extracted["service_principals"]
                    ),
                    "other_principals": ";".join(
                        extracted["other_principals"]
                    ),
                    "public_principal": extracted[
                        "public_principal"
                    ],
                    "sourcearn_entries": json.dumps(
                        extracted["sourcearns"],
                        ensure_ascii=False,
                    ),
                    "local_error": "",
                    "api_error": api_error,
                    "policy_file": str(policy_file),
                })

                print(
                    f"{model:<14} "
                    f"{case_id:<20} "
                    f"{prompt_type:<4} "
                    f"provider={provider_status:<18} "
                    f"action={shape['action_ok']!s:<5} "
                    f"resource={shape['resource_ok']!s:<5} "
                    f"principal={shape['principal_ok']!s:<5} "
                    f"sourcearn={shape['sourcearn_ok']!s:<5} "
                    f"fully_valid={fully_valid}"
                )

    OUT_CSV.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fields = [
        "model",
        "case_id",
        "prompt_type",
        "provider_status",
        "provider_error_count",
        "issue_codes",
        "action_ok",
        "resource_ok",
        "principal_ok",
        "sourcearn_ok",
        "fully_valid",
        "actions",
        "resources",
        "service_principals",
        "other_principals",
        "public_principal",
        "sourcearn_entries",
        "local_error",
        "api_error",
        "policy_file",
    ]

    with OUT_CSV.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields,
        )
        writer.writeheader()
        writer.writerows(rows)

    by_prompt = defaultdict(Counter)
    by_model = defaultdict(Counter)

    for row in rows:
        by_prompt[row["prompt_type"]][
            row["provider_status"]
        ] += 1

        if row["fully_valid"]:
            by_prompt[row["prompt_type"]][
                "fully_valid"
            ] += 1

        by_model[row["model"]][
            row["provider_status"]
        ] += 1

        if row["fully_valid"]:
            by_model[row["model"]][
                "fully_valid"
            ] += 1

    lines = [
        "# Provider validation of SourceArn-corrected v3 outputs",
        "",
        f"- Outputs audited: **{len(rows)}**",
        "",
        "## By prompt type",
        "",
        "| Prompt | Provider-valid | Provider-invalid | Nondeployable | Fully valid envelope |",
        "|---|---:|---:|---:|---:|",
    ]

    for prompt_type in ["ctrl", "poi"]:
        counts = by_prompt[prompt_type]

        lines.append(
            f"| {prompt_type} | "
            f"{counts['provider_valid']} | "
            f"{counts['provider_invalid']} | "
            f"{counts['nondeployable']} | "
            f"{counts['fully_valid']} |"
        )

    lines.extend([
        "",
        "## By model",
        "",
        "| Model | Provider-valid | Provider-invalid | Nondeployable | Fully valid envelope |",
        "|---|---:|---:|---:|---:|",
    ])

    for model in [
        "claude",
        "mistral_small",
        "nova_lite",
        "nova_pro",
        "llama3_8b",
    ]:
        counts = by_model[model]

        lines.append(
            f"| {model} | "
            f"{counts['provider_valid']} | "
            f"{counts['provider_invalid']} | "
            f"{counts['nondeployable']} | "
            f"{counts['fully_valid']} |"
        )

    problem_rows = [
        row
        for row in rows
        if not row["fully_valid"]
    ]

    lines.extend([
        "",
        "## Non-fully-valid outputs",
        "",
        "| Model | Case | Prompt | Provider status | Action | Resource | Principal | SourceArn | Issues |",
        "|---|---|---|---|---:|---:|---:|---:|---|",
    ])

    for row in problem_rows:
        lines.append(
            f"| {row['model']} | "
            f"{row['case_id']} | "
            f"{row['prompt_type']} | "
            f"{row['provider_status']} | "
            f"{row['action_ok']} | "
            f"{row['resource_ok']} | "
            f"{row['principal_ok']} | "
            f"{row['sourcearn_ok']} | "
            f"{row['issue_codes'] or row['local_error'] or row['api_error']} |"
        )

    lines.extend([
        "",
        f"CSV: `{OUT_CSV}`",
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
    print(OUT_MD.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
