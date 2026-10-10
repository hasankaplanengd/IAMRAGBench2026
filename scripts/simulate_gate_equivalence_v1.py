#!/usr/bin/env python3
import copy
import csv
import json
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

OUT_CSV = Path("tables/table_gate_equivalence_simulation_v1.csv")
OUT_MD = Path("summaries/gate_equivalence_simulation_v1_summary.md")

CASES = [
    {
        "case_id": "ec2_mfa_deny_002",
        "run": "runs/20260605_024307_meta_llama3_8b_instruct_v1_0",
        "action": "ec2:TerminateInstances",
        "resource": "arn:aws:ec2:us-east-1:111122223333:instance/i-critical001",
        "context_key": "aws:MultiFactorAuthPresent",
    },
    {
        "case_id": "sqs_tls_deny_002",
        "run": "runs/20260605_024307_meta_llama3_8b_instruct_v1_0",
        "action": "sqs:ReceiveMessage",
        "resource": "arn:aws:sqs:us-east-1:111122223333:secure-queue",
        "context_key": "aws:SecureTransport",
    },
]


def load_policy(case):
    path = (
        Path(case["run"])
        / "raw"
        / f"req_{case['case_id']}_ctrl__REPAIRED.json"
    )
    obj = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(obj, list):
        obj = {
            "Version": "2012-10-17",
            "Statement": obj,
        }

    if not isinstance(obj, dict) or "Statement" not in obj:
        raise ValueError(f"Not a policy object: {path}")

    return obj, path


def statements(policy):
    value = policy.get("Statement", [])
    return value if isinstance(value, list) else [value]


def canonical_bool_policy(policy, context_key):
    """
    Preserve the generated policy, but replace the relevant Deny
    condition with the benchmark's canonical Bool:false form.
    """
    out = copy.deepcopy(policy)
    found = False

    for statement in statements(out):
        if str(statement.get("Effect", "")).lower() != "deny":
            continue

        condition = statement.get("Condition", {})
        if not isinstance(condition, dict):
            continue

        contains_key = False
        for values in condition.values():
            if isinstance(values, dict) and context_key in values:
                contains_key = True
                break

        if contains_key:
            statement["Condition"] = {
                "Bool": {
                    context_key: "false"
                }
            }
            found = True

    if not found:
        raise ValueError(
            f"Could not find Deny condition for {context_key}"
        )

    return out


def simulate(client, policy, action, resource, context_key, context_value):
    params = {
        "PolicyInputList": [
            json.dumps(
                policy,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        ],
        "ActionNames": [action],
        "ResourceArns": [resource],
    }

    if context_value is not None:
        params["ContextEntries"] = [
            {
                "ContextKeyName": context_key,
                "ContextKeyValues": [context_value],
                "ContextKeyType": "boolean",
            }
        ]

    try:
        response = client.simulate_custom_policy(**params)
        result = response["EvaluationResults"][0]

        return {
            "decision": result.get("EvalDecision", ""),
            "missing_context": ";".join(
                result.get("MissingContextValues", [])
            ),
            "api_error": "",
        }
    except ClientError as exc:
        return {
            "decision": "",
            "missing_context": "",
            "api_error": str(exc),
        }


def main():
    iam = boto3.client("iam")
    rows = []

    for case in CASES:
        generated, path = load_policy(case)
        canonical = canonical_bool_policy(
            generated,
            case["context_key"],
        )

        variants = [
            ("generated_string_not_equals_true", generated),
            ("canonical_bool_false", canonical),
        ]

        contexts = [
            ("true", "true"),
            ("false", "false"),
            ("missing", None),
        ]

        for variant_name, policy in variants:
            for context_label, context_value in contexts:
                result = simulate(
                    iam,
                    policy,
                    case["action"],
                    case["resource"],
                    case["context_key"],
                    context_value,
                )

                rows.append({
                    "case_id": case["case_id"],
                    "variant": variant_name,
                    "action": case["action"],
                    "resource": case["resource"],
                    "context_key": case["context_key"],
                    "context_value": context_label,
                    "decision": result["decision"],
                    "missing_context": result["missing_context"],
                    "api_error": result["api_error"],
                    "source_file": str(path),
                })

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "case_id",
        "variant",
        "action",
        "resource",
        "context_key",
        "context_value",
        "decision",
        "missing_context",
        "api_error",
        "source_file",
    ]

    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    by_case_variant = {}
    for row in rows:
        by_case_variant.setdefault(
            (row["case_id"], row["variant"]),
            {},
        )[row["context_value"]] = row["decision"]

    lines = [
        "# Semantic equivalence simulation for gate false positives",
        "",
        "| Case | Variant | true | false | missing | Guardrail preserved |",
        "|---|---|---|---|---|---|",
    ]

    for (case_id, variant), decisions in sorted(
        by_case_variant.items()
    ):
        guardrail_preserved = (
            decisions.get("true") == "allowed"
            and decisions.get("false") == "explicitDeny"
        )

        lines.append(
            f"| {case_id} | {variant} | "
            f"{decisions.get('true', '')} | "
            f"{decisions.get('false', '')} | "
            f"{decisions.get('missing', '')} | "
            f"{guardrail_preserved} |"
        )

    lines.extend([
        "",
        "The benchmark requires the true context to remain allowed "
        "and the false context to be explicitly denied. Missing-key "
        "behavior is reported separately because a negated condition "
        "may be stricter than the canonical Bool:false form.",
        "",
        f"CSV: `{OUT_CSV}`",
    ])

    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(OUT_MD.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
