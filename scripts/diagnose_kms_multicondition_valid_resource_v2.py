#!/usr/bin/env python3
import csv
import json
import time
from collections import Counter
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


INPUT = Path(
    "tables/"
    "table_included_context_v6_unguarded_strong_"
    "kms_multi_condition_request_candidates.csv"
)

OUT_DETAIL = Path(
    "tables/"
    "table_kms_multicondition_valid_resource_v2.csv"
)

OUT_SUMMARY = Path(
    "tables/"
    "table_kms_multicondition_valid_resource_summary_v2.csv"
)

OUT_MD = Path(
    "summaries/"
    "kms_multicondition_valid_resource_v2.md"
)

ACTION = "kms:Decrypt"
VIA_KEY = "kms:ViaService"
ENC_KEY = "kms:EncryptionContext:aws:s3:arn"


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(policy):
    value = policy.get("Statement", [])
    return value if isinstance(value, list) else [value]


def load_policy(path_value):
    path = Path(path_value)

    if not path.exists():
        raise FileNotFoundError(path)

    obj = json.loads(
        path.read_text(encoding="utf-8")
    )

    if isinstance(obj, dict) and obj.get("ok") is False:
        raise ValueError(
            f"Nondeployable wrapper: {path}"
        )

    if isinstance(obj, list):
        obj = {
            "Version": "2012-10-17",
            "Statement": obj,
        }

    if not isinstance(obj, dict) or "Statement" not in obj:
        raise ValueError(
            f"Not an IAM policy: {path}"
        )

    return obj


def find_decrypt_allow(policy):
    for statement in statements(policy):
        if statement.get("Effect") != "Allow":
            continue

        actions = {
            str(item)
            for item in as_list(
                statement.get("Action")
            )
        }

        if ACTION in actions:
            return statement

    raise RuntimeError(
        "No Allow kms:Decrypt statement found."
    )


def find_condition(statement, expected_key):
    condition = statement.get("Condition", {})

    if not isinstance(condition, dict):
        return None

    for operator, values in condition.items():
        if not isinstance(values, dict):
            continue

        if expected_key in values:
            raw_value = values[expected_key]

            return {
                "operator": str(operator),
                "value": str(
                    as_list(raw_value)[0]
                ),
            }

    return None


def add_condition(condition, operator, key, value):
    condition.setdefault(
        operator,
        {},
    )[key] = value


def make_policy(resource, condition_items):
    condition = {}

    for operator, key, value in condition_items:
        add_condition(
            condition,
            operator,
            key,
            value,
        )

    statement = {
        "Effect": "Allow",
        "Action": ACTION,
        "Resource": resource,
    }

    if condition:
        statement["Condition"] = condition

    return {
        "Version": "2012-10-17",
        "Statement": [statement],
    }


def compact(policy):
    return json.dumps(
        policy,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def context_entries(service, encryption_context):
    return [
        {
            "ContextKeyName": VIA_KEY,
            "ContextKeyValues": [service],
            "ContextKeyType": "string",
        },
        {
            "ContextKeyName": ENC_KEY,
            "ContextKeyValues": [
                encryption_context
            ],
            "ContextKeyType": "string",
        },
    ]


def denied(decision):
    return decision in {
        "implicitDeny",
        "explicitDeny",
    }


def simulate_once(
    client,
    policy,
    resource,
    service,
    encryption_context,
):
    response = client.simulate_custom_policy(
        PolicyInputList=[
            compact(policy)
        ],
        ActionNames=[
            ACTION
        ],
        ResourceArns=[
            resource
        ],
        ContextEntries=context_entries(
            service,
            encryption_context,
        ),
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
    }


def simulate_with_retry(
    client,
    policy,
    resource,
    service,
    encryption_context,
    attempts=6,
):
    delay = 1.0

    for attempt in range(attempts):
        try:
            result = simulate_once(
                client,
                policy,
                resource,
                service,
                encryption_context,
            )

            return {
                **result,
                "api_error": "",
            }

        except ClientError as exc:
            code = (
                exc.response
                .get("Error", {})
                .get("Code", "")
            )

            retryable = code in {
                "Throttling",
                "ThrottlingException",
                "TooManyRequestsException",
                "RequestLimitExceeded",
                "ServiceUnavailableException",
            }

            if (
                retryable
                and attempt < attempts - 1
            ):
                time.sleep(delay)
                delay *= 2
                continue

            return {
                "decision": "",
                "missing_context": "",
                "api_error": str(exc),
            }

    return {
        "decision": "",
        "missing_context": "",
        "api_error": "retry_exhausted",
    }


def get_context_keys(client, policy):
    try:
        response = (
            client
            .get_context_keys_for_custom_policy(
                PolicyInputList=[
                    compact(policy)
                ]
            )
        )

        return sorted(
            response.get(
                "ContextKeyNames",
                [],
            )
        ), ""

    except ClientError as exc:
        return [], str(exc)


def classify(
    no_condition,
    via_only,
    encryption_only,
    both,
):
    no_condition_ok = all(
        decision == "allowed"
        for decision in no_condition.values()
    )

    via_ok = (
        via_only[
            "intended_service_intended_context"
        ] == "allowed"
        and denied(
            via_only[
                "wrong_service_intended_context"
            ]
        )
    )

    encryption_ok = (
        encryption_only[
            "intended_service_intended_context"
        ] == "allowed"
        and denied(
            encryption_only[
                "intended_service_wrong_context"
            ]
        )
    )

    both_ok = (
        both[
            "intended_service_intended_context"
        ] == "allowed"
        and denied(
            both[
                "wrong_service_intended_context"
            ]
        )
        and denied(
            both[
                "intended_service_wrong_context"
            ]
        )
        and denied(
            both[
                "wrong_service_wrong_context"
            ]
        )
    )

    if not no_condition_ok:
        diagnosis = (
            "base_action_or_resource_simulation_failure"
        )

    elif encryption_ok and not via_ok:
        diagnosis = (
            "via_service_forward_access_session_"
            "not_established_by_direct_simulation"
        )

    elif via_ok and encryption_ok and not both_ok:
        diagnosis = (
            "combined_condition_simulator_mismatch"
        )

    elif both_ok:
        diagnosis = (
            "canonical_clean_baseline_valid"
        )

    else:
        diagnosis = (
            "other_context_simulation_mismatch"
        )

    return {
        "no_condition_ok": no_condition_ok,
        "via_only_ok": via_ok,
        "encryption_only_ok": encryption_ok,
        "both_conditions_ok": both_ok,
        "diagnosis": diagnosis,
    }


def main():
    if not INPUT.exists():
        raise FileNotFoundError(INPUT)

    with INPUT.open(
        newline="",
        encoding="utf-8",
    ) as f:
        source_rows = list(csv.DictReader(f))

    if len(source_rows) != 3:
        raise RuntimeError(
            f"Expected three KMS rows, "
            f"found {len(source_rows)}"
        )

    iam = boto3.client(
        "iam",
        region_name="us-east-1",
    )

    detail_rows = []
    summary_rows = []

    for candidate in source_rows:
        model = candidate["model"]
        model_label = candidate["model_label"]

        clean = load_policy(
            candidate["control_policy_file"]
        )

        statement = find_decrypt_allow(clean)

        resources = [
            str(item)
            for item in as_list(
                statement.get("Resource")
            )
        ]

        if len(resources) != 1:
            raise RuntimeError(
                f"{model}: expected one KMS resource"
            )

        original_resource = resources[0]

        # Use a provider-shaped synthetic KMS key ARN.
        # SimulateCustomPolicy permits nonexistent resources.
        resource = (
            "arn:aws:kms:us-east-1:"
            "111122223333:key/"
            "1234abcd-12ab-34cd-56ef-1234567890ab"
        )

        via = find_condition(
            statement,
            VIA_KEY,
        )

        encryption = find_condition(
            statement,
            ENC_KEY,
        )

        if via is None or encryption is None:
            raise RuntimeError(
                f"{model}: required clean conditions missing"
            )

        intended_service = via["value"]
        wrong_service = (
            "ec2.us-east-1.amazonaws.com"
            if intended_service
            != "ec2.us-east-1.amazonaws.com"
            else "lambda.us-east-1.amazonaws.com"
        )

        encryption_pattern = encryption["value"]

        intended_context = (
            encryption_pattern
            .replace(
                "*",
                "validation-object",
            )
            .replace(
                "?",
                "a",
            )
        )

        wrong_context = (
            "arn:aws:s3:::"
            "unrelated-validation-bucket/"
            "forbidden-object"
        )

        variants = {
            "no_condition": make_policy(
                resource,
                [],
            ),
            "via_only": make_policy(
                resource,
                [
                    (
                        via["operator"],
                        VIA_KEY,
                        intended_service,
                    )
                ],
            ),
            "encryption_only": make_policy(
                resource,
                [
                    (
                        encryption["operator"],
                        ENC_KEY,
                        encryption_pattern,
                    )
                ],
            ),
            "both_conditions": make_policy(
                resource,
                [
                    (
                        via["operator"],
                        VIA_KEY,
                        intended_service,
                    ),
                    (
                        encryption["operator"],
                        ENC_KEY,
                        encryption_pattern,
                    ),
                ],
            ),
        }

        requests = {
            "intended_service_intended_context": (
                intended_service,
                intended_context,
            ),
            "wrong_service_intended_context": (
                wrong_service,
                intended_context,
            ),
            "intended_service_wrong_context": (
                intended_service,
                wrong_context,
            ),
            "wrong_service_wrong_context": (
                wrong_service,
                wrong_context,
            ),
        }

        print("")
        print("=" * 100)
        print(
            f"{model_label} / kms_condition_001"
        )
        print("=" * 100)

        decisions_by_variant = {}
        candidate_errors = 0

        for variant, policy in variants.items():
            required_keys, key_error = (
                get_context_keys(
                    iam,
                    policy,
                )
            )

            if key_error:
                candidate_errors += 1

            decisions_by_variant[
                variant
            ] = {}

            print("")
            print(
                f"VARIANT: {variant}"
            )
            print(
                "Required context keys:",
                required_keys,
            )

            for (
                request_class,
                (
                    service,
                    encryption_context,
                ),
            ) in requests.items():
                result = simulate_with_retry(
                    iam,
                    policy,
                    resource,
                    service,
                    encryption_context,
                )

                if result["api_error"]:
                    candidate_errors += 1

                decisions_by_variant[
                    variant
                ][request_class] = (
                    result["decision"]
                )

                detail_rows.append({
                    "model": model,
                    "model_label":
                        model_label,
                    "case_id":
                        "kms_condition_001",
                    "variant": variant,
                    "request_class":
                        request_class,
                    "resource": resource,
                    "via_service":
                        service,
                    "encryption_context":
                        encryption_context,
                    "required_context_keys":
                        ";".join(
                            required_keys
                        ),
                    "decision":
                        result["decision"],
                    "missing_context":
                        result[
                            "missing_context"
                        ],
                    "context_key_api_error":
                        key_error,
                    "simulation_api_error":
                        result[
                            "api_error"
                        ],
                })

                print(
                    f"{request_class:<40} "
                    f"decision="
                    f"{result['decision']:<14} "
                    f"service={service}"
                )

        diagnosis = classify(
            decisions_by_variant[
                "no_condition"
            ],
            decisions_by_variant[
                "via_only"
            ],
            decisions_by_variant[
                "encryption_only"
            ],
            decisions_by_variant[
                "both_conditions"
            ],
        )

        summary_rows.append({
            "model": model,
            "model_label": model_label,
            "case_id":
                "kms_condition_001",
            **diagnosis,
            "api_errors":
                candidate_errors,
            "resource": resource,
            "via_operator":
                via["operator"],
            "encryption_operator":
                encryption["operator"],
            "intended_service":
                intended_service,
            "encryption_pattern":
                encryption_pattern,
        })

        print("")
        print(
            "DIAGNOSIS:",
            diagnosis["diagnosis"],
        )

    OUT_DETAIL.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    detail_fields = [
        "model",
        "model_label",
        "case_id",
        "variant",
        "request_class",
        "resource",
        "via_service",
        "encryption_context",
        "required_context_keys",
        "decision",
        "missing_context",
        "context_key_api_error",
        "simulation_api_error",
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
        writer.writerows(detail_rows)

    summary_fields = [
        "model",
        "model_label",
        "case_id",
        "no_condition_ok",
        "via_only_ok",
        "encryption_only_ok",
        "both_conditions_ok",
        "diagnosis",
        "api_errors",
        "resource",
        "via_operator",
        "encryption_operator",
        "intended_service",
        "encryption_pattern",
    ]

    with OUT_SUMMARY.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=summary_fields,
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    diagnosis_counts = Counter(
        row["diagnosis"]
        for row in summary_rows
    )

    total_errors = sum(
        row["api_errors"]
        for row in summary_rows
    )

    lines = [
        "# KMS multi-condition valid-resource diagnosis v2",
        "",
        "- Models diagnosed: **3**",
        f"- AWS/API errors: **{total_errors}**",
        "",
        (
            "| Model | No condition | ViaService only | "
            "Encryption context only | Both | Diagnosis |"
        ),
        "|---|---:|---:|---:|---:|---|",
    ]

    for row in summary_rows:
        lines.append(
            f"| {row['model_label']} | "
            f"{row['no_condition_ok']} | "
            f"{row['via_only_ok']} | "
            f"{row['encryption_only_ok']} | "
            f"{row['both_conditions_ok']} | "
            f"{row['diagnosis']} |"
        )

    lines.extend([
        "",
        "## Diagnosis counts",
        "",
    ])

    for diagnosis, count in diagnosis_counts.items():
        lines.append(
            f"- `{diagnosis}`: **{count}**"
        )

    lines.extend([
        "",
        f"Detail CSV: `{OUT_DETAIL}`",
        f"Summary CSV: `{OUT_SUMMARY}`",
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
            "FAIL: AWS/API errors occurred."
        )

    print(
        "PASS: the two KMS condition keys "
        "were isolated and diagnosed."
    )


if __name__ == "__main__":
    main()
