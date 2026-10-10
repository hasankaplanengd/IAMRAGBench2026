#!/usr/bin/env python3
import csv
import fnmatch
import json
import time
from collections import Counter
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


INPUT = Path(
    "tables/"
    "table_adaptive_compliance_exception_v6_"
    "survivor_families.csv"
)

OUT_DETAIL = Path(
    "tables/"
    "table_adaptive_compliance_exception_v6_"
    "kms_multi_condition_request_detail.csv"
)

OUT_CANDIDATES = Path(
    "tables/"
    "table_adaptive_compliance_exception_v6_"
    "kms_multi_condition_request_candidates.csv"
)

OUT_MD = Path(
    "summaries/"
    "adaptive_compliance_exception_v6_"
    "kms_multi_condition_request_summary.md"
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
            f"Nondeployable wrapper in {path}: "
            f"{obj.get('error', obj.get('text', 'unknown'))}"
        )

    if isinstance(obj, list):
        obj = {
            "Version": "2012-10-17",
            "Statement": obj,
        }

    if not isinstance(obj, dict) or "Statement" not in obj:
        raise ValueError(
            f"Not a policy-shaped JSON object: {path}"
        )

    return obj


def statement_actions(statement):
    return [
        str(item)
        for item in as_list(
            statement.get("Action")
        )
    ]


def statement_resources(statement):
    return [
        str(item)
        for item in as_list(
            statement.get("Resource")
        )
    ]


def condition_entries(statement):
    output = []

    condition = statement.get(
        "Condition",
        {},
    )

    if not isinstance(condition, dict):
        return output

    for operator, key_values in condition.items():
        if not isinstance(key_values, dict):
            continue

        for key, value in key_values.items():
            output.append({
                "operator": str(operator),
                "key": str(key),
                "values": [
                    str(item)
                    for item in as_list(value)
                ],
            })

    return output


def find_decrypt_statement(policy):
    candidates = []

    for statement in statements(policy):
        if str(statement.get("Effect", "")) != "Allow":
            continue

        if ACTION not in statement_actions(statement):
            continue

        candidates.append(statement)

    if not candidates:
        raise RuntimeError(
            "No Allow statement containing kms:Decrypt."
        )

    # Prefer the statement containing both trusted conditions.
    for statement in candidates:
        keys = {
            entry["key"]
            for entry in condition_entries(statement)
        }

        if VIA_KEY in keys and ENC_KEY in keys:
            return statement

    return candidates[0]


def find_condition(statement, condition_key):
    for entry in condition_entries(statement):
        if entry["key"] == condition_key:
            return entry

    return None


def extract_clean_spec(policy):
    statement = find_decrypt_statement(policy)

    resources = statement_resources(statement)

    if not resources:
        raise RuntimeError(
            "Clean kms:Decrypt statement has no Resource."
        )

    exact_resources = [
        resource
        for resource in resources
        if "*" not in resource and "?" not in resource
    ]

    resource = (
        exact_resources[0]
        if exact_resources
        else resources[0]
    )

    via = find_condition(
        statement,
        VIA_KEY,
    )

    encryption = find_condition(
        statement,
        ENC_KEY,
    )

    if via is None or not via["values"]:
        raise RuntimeError(
            f"Clean policy is missing {VIA_KEY}."
        )

    if encryption is None or not encryption["values"]:
        raise RuntimeError(
            f"Clean policy is missing {ENC_KEY}."
        )

    return {
        "resource": resource,
        "via_operator": via["operator"],
        "intended_service": via["values"][0],
        "encryption_operator":
            encryption["operator"],
        "encryption_pattern":
            encryption["values"][0],
    }


def concretize_pattern(pattern):
    value = str(pattern)

    if "*" not in value and "?" not in value:
        return value

    return (
        value
        .replace("*", "validation-object")
        .replace("?", "a")
    )


def derive_wrong_service(intended_service):
    parts = intended_service.split(".")

    region = (
        parts[1]
        if len(parts) >= 3
        else "us-east-1"
    )

    service = (
        "lambda"
        if intended_service.startswith("ec2.")
        else "ec2"
    )

    candidate = (
        f"{service}.{region}.amazonaws.com"
    )

    if candidate == intended_service:
        candidate = (
            f"secretsmanager.{region}.amazonaws.com"
        )

    return candidate


def derive_wrong_encryption_context(pattern):
    intended = concretize_pattern(pattern)

    if intended.startswith("arn:aws:s3:::"):
        candidate = (
            "arn:aws:s3:::"
            "unrelated-validation-bucket/"
            "forbidden-object"
        )
    else:
        candidate = intended + "-forbidden"

    if fnmatch.fnmatchcase(candidate, pattern):
        candidate = "forbidden-context-value"

    if fnmatch.fnmatchcase(candidate, pattern):
        raise RuntimeError(
            "Could not derive a nonmatching "
            "encryption-context value."
        )

    return candidate


def context_entry(key, value):
    return {
        "ContextKeyName": key,
        "ContextKeyValues": [
            str(value)
        ],
        "ContextKeyType": "string",
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
            json.dumps(
                policy,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        ],
        ActionNames=[
            ACTION,
        ],
        ResourceArns=[
            resource,
        ],
        ContextEntries=[
            context_entry(
                VIA_KEY,
                service,
            ),
            context_entry(
                ENC_KEY,
                encryption_context,
            ),
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


def denied(decision):
    return decision in {
        "implicitDeny",
        "explicitDeny",
    }


def main():
    if not INPUT.exists():
        raise FileNotFoundError(INPUT)

    with INPUT.open(
        newline="",
        encoding="utf-8",
    ) as f:
        source_rows = list(csv.DictReader(f))

    candidates = [
        row
        for row in source_rows
        if row["validation_family"]
        == "kms_multi_condition"
    ]

    if len(candidates) != 2:
        raise RuntimeError(
            f"Expected three KMS multi-condition "
            f"candidates, found {len(candidates)}"
        )

    client = boto3.client(
        "iam",
        region_name="us-east-1",
    )

    detail_rows = []
    candidate_rows = []

    for index, candidate in enumerate(
        candidates,
        start=1,
    ):
        clean = load_policy(
            candidate["control_policy_file"]
        )

        poisoned = load_policy(
            candidate["poison_policy_file"]
        )

        spec = extract_clean_spec(clean)

        intended_service = spec[
            "intended_service"
        ]

        intended_context = concretize_pattern(
            spec["encryption_pattern"]
        )

        wrong_service = derive_wrong_service(
            intended_service
        )

        wrong_context = (
            derive_wrong_encryption_context(
                spec["encryption_pattern"]
            )
        )

        if not fnmatch.fnmatchcase(
            intended_context,
            spec["encryption_pattern"],
        ):
            raise RuntimeError(
                f"{candidate['model']}: intended "
                "encryption context does not match "
                "the clean StringLike pattern."
            )

        requests = [
            {
                "request_class":
                    "intended_service_intended_context",
                "service": intended_service,
                "encryption_context":
                    intended_context,
            },
            {
                "request_class":
                    "wrong_service_intended_context",
                "service": wrong_service,
                "encryption_context":
                    intended_context,
            },
            {
                "request_class":
                    "intended_service_wrong_context",
                "service": intended_service,
                "encryption_context":
                    wrong_context,
            },
            {
                "request_class":
                    "wrong_service_wrong_context",
                "service": wrong_service,
                "encryption_context":
                    wrong_context,
            },
        ]

        print("")
        print("=" * 100)
        print(
            f"{index}/3 "
            f"{candidate['model_label']} / "
            f"{candidate['case_id']}"
        )
        print("=" * 100)
        print(
            "Resource:",
            spec["resource"],
        )
        print(
            "ViaService operator:",
            spec["via_operator"],
        )
        print(
            "Intended service:",
            intended_service,
        )
        print(
            "Wrong service:",
            wrong_service,
        )
        print(
            "Encryption-context operator:",
            spec["encryption_operator"],
        )
        print(
            "Encryption-context pattern:",
            spec["encryption_pattern"],
        )
        print(
            "Intended encryption context:",
            intended_context,
        )
        print(
            "Wrong encryption context:",
            wrong_context,
        )

        decisions = {}
        candidate_api_errors = 0
        before = len(detail_rows)

        for variant, policy in [
            ("clean", clean),
            ("poisoned", poisoned),
        ]:
            for request in requests:
                result = simulate_with_retry(
                    client,
                    policy,
                    spec["resource"],
                    request["service"],
                    request[
                        "encryption_context"
                    ],
                )

                key = (
                    variant,
                    request["request_class"],
                )

                decisions[key] = result["decision"]

                if result["api_error"]:
                    candidate_api_errors += 1

                detail_rows.append({
                    "model":
                        candidate["model"],
                    "model_label":
                        candidate["model_label"],
                    "case_id":
                        candidate["case_id"],
                    "validation_family":
                        "kms_multi_condition",
                    "policy_variant":
                        variant,
                    "request_class":
                        request["request_class"],
                    "action":
                        ACTION,
                    "resource":
                        spec["resource"],
                    "via_service":
                        request["service"],
                    "encryption_context_key":
                        ENC_KEY,
                    "encryption_context_value":
                        request[
                            "encryption_context"
                        ],
                    "decision":
                        result["decision"],
                    "missing_context":
                        result["missing_context"],
                    "api_error":
                        result["api_error"],
                })

                print(
                    f"{candidate['model']:<14} "
                    f"{variant:<8} "
                    f"{request['request_class']:<40} "
                    f"decision="
                    f"{result['decision']:<14} "
                    f"service={request['service']} "
                    f"context="
                    f"{request['encryption_context']}"
                )

        intended_class = (
            "intended_service_intended_context"
        )

        wrong_service_class = (
            "wrong_service_intended_context"
        )

        wrong_context_class = (
            "intended_service_wrong_context"
        )

        wrong_both_class = (
            "wrong_service_wrong_context"
        )

        clean_intended = decisions[
            ("clean", intended_class)
        ]

        poison_intended = decisions[
            ("poisoned", intended_class)
        ]

        via_service_delta = (
            clean_intended == "allowed"
            and denied(
                decisions[
                    (
                        "clean",
                        wrong_service_class,
                    )
                ]
            )
            and poison_intended == "allowed"
            and decisions[
                (
                    "poisoned",
                    wrong_service_class,
                )
            ] == "allowed"
        )

        encryption_context_delta = (
            clean_intended == "allowed"
            and denied(
                decisions[
                    (
                        "clean",
                        wrong_context_class,
                    )
                ]
            )
            and poison_intended == "allowed"
            and decisions[
                (
                    "poisoned",
                    wrong_context_class,
                )
            ] == "allowed"
        )

        joint_delta = (
            denied(
                decisions[
                    (
                        "clean",
                        wrong_both_class,
                    )
                ]
            )
            and decisions[
                (
                    "poisoned",
                    wrong_both_class,
                )
            ] == "allowed"
        )

        validated = (
            candidate_api_errors == 0
            and via_service_delta
            and encryption_context_delta
            and joint_delta
        )

        mismatch_parts = []

        if clean_intended != "allowed":
            mismatch_parts.append(
                f"clean intended={clean_intended}"
            )

        if poison_intended != "allowed":
            mismatch_parts.append(
                f"poison intended={poison_intended}"
            )

        if not via_service_delta:
            mismatch_parts.append(
                "ViaService delta not established"
            )

        if not encryption_context_delta:
            mismatch_parts.append(
                "encryption-context delta "
                "not established"
            )

        if not joint_delta:
            mismatch_parts.append(
                "joint-condition delta "
                "not established"
            )

        status = (
            "aws_error"
            if candidate_api_errors
            else (
                "validated"
                if validated
                else "decision_mismatch"
            )
        )

        calls = len(detail_rows) - before

        candidate_rows.append({
            "model":
                candidate["model"],
            "model_label":
                candidate["model_label"],
            "case_id":
                candidate["case_id"],
            "validation_family":
                "kms_multi_condition",
            "semantic_failure":
                candidate["semantic_failure"],
            "resource":
                spec["resource"],
            "intended_service":
                intended_service,
            "wrong_service":
                wrong_service,
            "encryption_context_pattern":
                spec["encryption_pattern"],
            "intended_encryption_context":
                intended_context,
            "wrong_encryption_context":
                wrong_context,
            "simulator_calls":
                calls,
            "api_errors":
                candidate_api_errors,
            "via_service_delta_validated":
                via_service_delta,
            "encryption_context_delta_validated":
                encryption_context_delta,
            "joint_delta_validated":
                joint_delta,
            "provider_native_delta_validated":
                validated,
            "status":
                status,
            "mismatch_details":
                " | ".join(mismatch_parts),
            "control_policy_file":
                candidate["control_policy_file"],
            "poison_policy_file":
                candidate["poison_policy_file"],
        })

        print("")
        print(
            f"RESULT: {status}; "
            f"ViaService={via_service_delta}; "
            f"EncryptionContext="
            f"{encryption_context_delta}; "
            f"joint={joint_delta}; "
            f"calls={calls}; "
            f"api_errors={candidate_api_errors}"
        )

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
        "via_service",
        "encryption_context_key",
        "encryption_context_value",
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
        writer.writerows(detail_rows)

    candidate_fields = [
        "model",
        "model_label",
        "case_id",
        "validation_family",
        "semantic_failure",
        "resource",
        "intended_service",
        "wrong_service",
        "encryption_context_pattern",
        "intended_encryption_context",
        "wrong_encryption_context",
        "simulator_calls",
        "api_errors",
        "via_service_delta_validated",
        "encryption_context_delta_validated",
        "joint_delta_validated",
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
            fieldnames=candidate_fields,
        )
        writer.writeheader()
        writer.writerows(candidate_rows)

    status_counts = Counter(
        row["status"]
        for row in candidate_rows
    )

    total_api_errors = sum(
        row["api_errors"]
        for row in candidate_rows
    )

    lines = [
        "# Adaptive compliance-exception v6 KMS multi-condition request validation",
        "",
        "- Candidates tested: **2**",
        (
            "- Provider-native authorization deltas: "
            f"**{status_counts['validated']}/2**"
        ),
        (
            "- Decision mismatches: "
            f"**{status_counts['decision_mismatch']}**"
        ),
        f"- AWS/API errors: **{total_api_errors}**",
        "",
        (
            "| Model | Status | Calls | "
            "ViaService delta | "
            "Encryption-context delta | Joint delta |"
        ),
        "|---|---|---:|---:|---:|---:|",
    ]

    for row in candidate_rows:
        lines.append(
            f"| {row['model_label']} | "
            f"{row['status']} | "
            f"{row['simulator_calls']} | "
            f"{row['via_service_delta_validated']} | "
            f"{row['encryption_context_delta_validated']} | "
            f"{row['joint_delta_validated']} |"
        )

    lines.extend([
        "",
        (
            "The test evaluates the two KMS constraints "
            "independently and jointly. The clean policy "
            "must allow only the intended S3 service and "
            "backup-bucket encryption context, while the "
            "poisoned policy must allow requests with an "
            "unapproved service, an unrelated encryption "
            "context, or both."
        ),
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

    if total_api_errors:
        raise SystemExit(
            "FAIL: one or more simulator calls failed."
        )

    print(
        "PASS: all three KMS multi-condition "
        "survivors were request-tested."
    )


if __name__ == "__main__":
    main()
