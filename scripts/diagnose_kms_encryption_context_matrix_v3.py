#!/usr/bin/env python3
import csv
import json
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

OUT_CSV = Path(
    "tables/table_kms_encryption_context_matrix_v3.csv"
)
OUT_MD = Path(
    "summaries/kms_encryption_context_matrix_v3.md"
)

ACTION = "kms:Decrypt"
RESOURCE = (
    "arn:aws:kms:us-east-1:111122223333:key/"
    "1234abcd-12ab-34cd-56ef-1234567890ab"
)

VARIANTS = [
    {
        "variant": "app_equals_exact",
        "operator": "StringEquals",
        "key": "kms:EncryptionContext:AppName",
        "policy_value": "ExampleApp",
        "intended": "ExampleApp",
        "forbidden": "OtherApp",
    },
    {
        "variant": "app_like_exact",
        "operator": "StringLike",
        "key": "kms:EncryptionContext:AppName",
        "policy_value": "ExampleApp",
        "intended": "ExampleApp",
        "forbidden": "OtherApp",
    },
    {
        "variant": "app_like_wildcard",
        "operator": "StringLike",
        "key": "kms:EncryptionContext:AppName",
        "policy_value": "Example*",
        "intended": "ExampleApp",
        "forbidden": "OtherApp",
    },
    {
        "variant": "s3_equals_exact",
        "operator": "StringEquals",
        "key": "kms:EncryptionContext:aws:s3:arn",
        "policy_value": (
            "arn:aws:s3:::company-backups/"
            "validation-object"
        ),
        "intended": (
            "arn:aws:s3:::company-backups/"
            "validation-object"
        ),
        "forbidden": (
            "arn:aws:s3:::unrelated-bucket/"
            "forbidden-object"
        ),
    },
    {
        "variant": "s3_like_exact",
        "operator": "StringLike",
        "key": "kms:EncryptionContext:aws:s3:arn",
        "policy_value": (
            "arn:aws:s3:::company-backups/"
            "validation-object"
        ),
        "intended": (
            "arn:aws:s3:::company-backups/"
            "validation-object"
        ),
        "forbidden": (
            "arn:aws:s3:::unrelated-bucket/"
            "forbidden-object"
        ),
    },
    {
        "variant": "s3_like_wildcard",
        "operator": "StringLike",
        "key": "kms:EncryptionContext:aws:s3:arn",
        "policy_value": (
            "arn:aws:s3:::company-backups/*"
        ),
        "intended": (
            "arn:aws:s3:::company-backups/"
            "validation-object"
        ),
        "forbidden": (
            "arn:aws:s3:::unrelated-bucket/"
            "forbidden-object"
        ),
    },
]


def make_policy(spec):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ACTION,
                "Resource": RESOURCE,
                "Condition": {
                    spec["operator"]: {
                        spec["key"]:
                            spec["policy_value"]
                    }
                },
            }
        ],
    }


def compact(obj):
    return json.dumps(
        obj,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def context_entry(key, value):
    return {
        "ContextKeyName": key,
        "ContextKeyValues": [value],
        "ContextKeyType": "string",
    }


def simulate(client, policy, key, value):
    try:
        response = client.simulate_custom_policy(
            PolicyInputList=[compact(policy)],
            ActionNames=[ACTION],
            ResourceArns=[RESOURCE],
            ContextEntries=[
                context_entry(key, value)
            ],
        )

        result = response["EvaluationResults"][0]

        return {
            "decision": result.get(
                "EvalDecision",
                "",
            ),
            "missing_context": ";".join(
                result.get(
                    "MissingContextValues",
                    [],
                )
            ),
            "api_error": "",
        }

    except ClientError as exc:
        return {
            "decision": "",
            "missing_context": "",
            "api_error": str(exc),
        }


def required_keys(client, policy):
    try:
        response = (
            client
            .get_context_keys_for_custom_policy(
                PolicyInputList=[compact(policy)]
            )
        )

        return (
            ";".join(
                response.get(
                    "ContextKeyNames",
                    [],
                )
            ),
            "",
        )

    except ClientError as exc:
        return "", str(exc)


def denied(decision):
    return decision in {
        "implicitDeny",
        "explicitDeny",
    }


def main():
    iam = boto3.client(
        "iam",
        region_name="us-east-1",
    )

    rows = []
    outcomes = {}

    for spec in VARIANTS:
        policy = make_policy(spec)

        keys, key_error = required_keys(
            iam,
            policy,
        )

        intended = simulate(
            iam,
            policy,
            spec["key"],
            spec["intended"],
        )

        forbidden = simulate(
            iam,
            policy,
            spec["key"],
            spec["forbidden"],
        )

        works = (
            intended["decision"] == "allowed"
            and denied(forbidden["decision"])
            and not intended["api_error"]
            and not forbidden["api_error"]
            and not key_error
        )

        outcomes[spec["variant"]] = works

        row = {
            **spec,
            "required_context_keys": keys,
            "intended_decision":
                intended["decision"],
            "forbidden_decision":
                forbidden["decision"],
            "works_as_expected": works,
            "intended_missing_context":
                intended["missing_context"],
            "forbidden_missing_context":
                forbidden["missing_context"],
            "context_key_api_error":
                key_error,
            "intended_api_error":
                intended["api_error"],
            "forbidden_api_error":
                forbidden["api_error"],
        }

        rows.append(row)

        print("")
        print(spec["variant"])
        print("  operator:", spec["operator"])
        print("  key:", spec["key"])
        print("  policy value:", spec["policy_value"])
        print("  required keys:", keys)
        print(
            "  intended:",
            intended["decision"],
        )
        print(
            "  forbidden:",
            forbidden["decision"],
        )
        print(
            "  works:",
            works,
        )

    if not outcomes["app_equals_exact"]:
        diagnosis = (
            "generic_kms_encryption_context_"
            "simulation_mismatch"
        )

    elif (
        outcomes["app_equals_exact"]
        and outcomes["app_like_exact"]
        and outcomes["app_like_wildcard"]
        and not outcomes["s3_equals_exact"]
        and not outcomes["s3_like_exact"]
        and not outcomes["s3_like_wildcard"]
    ):
        diagnosis = (
            "nested_aws_s3_arn_context_key_"
            "simulation_mismatch"
        )

    elif (
        outcomes["app_equals_exact"]
        and outcomes["s3_equals_exact"]
        and not outcomes["app_like_exact"]
        and not outcomes["s3_like_exact"]
    ):
        diagnosis = (
            "stringlike_operator_simulation_mismatch"
        )

    elif (
        outcomes["app_equals_exact"]
        and outcomes["app_like_exact"]
        and outcomes["s3_equals_exact"]
        and outcomes["s3_like_exact"]
        and not outcomes["app_like_wildcard"]
        and not outcomes["s3_like_wildcard"]
    ):
        diagnosis = (
            "stringlike_wildcard_simulation_mismatch"
        )

    elif (
        outcomes["s3_equals_exact"]
        and outcomes["s3_like_exact"]
        and not outcomes["s3_like_wildcard"]
    ):
        diagnosis = (
            "aws_s3_arn_wildcard_simulation_mismatch"
        )

    elif all(outcomes.values()):
        diagnosis = (
            "all_minimal_encryption_context_"
            "variants_work"
        )

    else:
        diagnosis = (
            "mixed_encryption_context_"
            "simulation_behavior"
        )

    fields = list(rows[0].keys())

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
            fieldnames=fields,
        )
        writer.writeheader()
        writer.writerows(rows)

    api_errors = sum(
        bool(row["context_key_api_error"])
        or bool(row["intended_api_error"])
        or bool(row["forbidden_api_error"])
        for row in rows
    )

    lines = [
        "# KMS encryption-context simulator matrix v3",
        "",
        f"- Variants tested: **{len(rows)}**",
        f"- AWS/API errors: **{api_errors}**",
        f"- Diagnosis: **`{diagnosis}`**",
        "",
        "| Variant | Operator | Context key | Intended | Forbidden | Works |",
        "|---|---|---|---|---|---:|",
    ]

    for row in rows:
        lines.append(
            f"| {row['variant']} | "
            f"{row['operator']} | "
            f"`{row['key']}` | "
            f"{row['intended_decision']} | "
            f"{row['forbidden_decision']} | "
            f"{row['works_as_expected']} |"
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

    if api_errors:
        raise SystemExit(
            "FAIL: AWS/API errors occurred."
        )

    print(
        "PASS: encryption-context operator/key "
        "matrix completed."
    )


if __name__ == "__main__":
    main()
