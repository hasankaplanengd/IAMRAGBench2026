#!/usr/bin/env python3
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import csv
import hashlib
import json
import time

import boto3
from botocore.exceptions import ClientError


ROOT = Path.cwd()

POLICY_AUDIT = Path(
    "tables/repeatability_v1_provider_reuse_audit_v2.csv"
)

PAIR_AUDIT = Path(
    "tables/repeatability_v1_exact_reuse_audit_v2.csv"
)

PROVIDER_OUT = Path(
    "tables/table_repeatability_v1_pending_provider_validation_v2.csv"
)

EXACT_OUT = Path(
    "tables/table_repeatability_v1_pending_exact_validation_v2.csv"
)

DETAIL_OUT = Path(
    "tables/table_repeatability_v1_pending_leadingkeys_detail_v2.csv"
)

SUMMARY_OUT = Path(
    "summaries/repeatability_v1_pending_validation_v2_summary.md"
)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise RuntimeError(f"No rows for {path}")

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(rows[0].keys()),
        )
        writer.writeheader()
        writer.writerows(rows)


def resolve(path_value: str) -> Path:
    path = Path(path_value)
    return path if path.is_absolute() else ROOT / path


def load_policy(path_value: str):
    return json.loads(resolve(path_value).read_text(encoding="utf-8"))


def compact(policy) -> str:
    return json.dumps(
        policy,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_sha(path_value: str) -> str:
    return hashlib.sha256(
        compact(load_policy(path_value)).encode("utf-8")
    ).hexdigest()


def as_bool(value: object) -> bool:
    return str(value).strip().lower() in {
        "true",
        "1",
        "yes",
        "y",
    }


def validate_policy_with_retry(
    client,
    *,
    policy,
    policy_type: str,
    resource_type: str,
):
    kwargs = {
        "policyDocument": compact(policy),
        "policyType": policy_type,
    }

    if resource_type:
        kwargs["validatePolicyResourceType"] = resource_type

    delay = 1.0
    last_error = ""

    for attempt in range(1, 6):
        try:
            return client.validate_policy(**kwargs), ""
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            msg = exc.response.get("Error", {}).get("Message", "")
            last_error = f"{code}: {msg}"

            if code in {
                "ThrottlingException",
                "TooManyRequestsException",
                "InternalServerException",
                "ServiceUnavailableException",
            }:
                time.sleep(delay)
                delay *= 2
                continue

            return None, last_error

    return None, last_error or "retry_exhausted"


def finding_text(findings):
    parts = []

    for finding in findings or []:
        issue = finding.get("issueCode", "")
        ftype = finding.get("findingType", "")
        detail = finding.get("findingDetails", "")
        parts.append(f"{ftype}:{issue}:{detail}")

    return " | ".join(parts)


def context_entry(values: list[str]):
    return {
        "ContextKeyName": "dynamodb:LeadingKeys",
        "ContextKeyValues": values,
        "ContextKeyType": "stringList",
    }


def simulate_once(
    client,
    *,
    policy,
    action: str,
    resource: str,
    context_values: list[str],
):
    response = client.simulate_custom_policy(
        PolicyInputList=[compact(policy)],
        ActionNames=[action],
        ResourceArns=[resource],
        ContextEntries=[context_entry(context_values)],
    )

    results = response.get("EvaluationResults", [])

    if len(results) != 1:
        raise RuntimeError(
            f"Expected one simulator result, got {len(results)}"
        )

    return results[0].get("EvalDecision", "")


def simulate_with_retry(
    client,
    *,
    policy,
    action: str,
    resource: str,
    context_values: list[str],
):
    delay = 1.0
    last_error = ""

    for attempt in range(1, 6):
        try:
            return simulate_once(
                client,
                policy=policy,
                action=action,
                resource=resource,
                context_values=context_values,
            ), ""
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            msg = exc.response.get("Error", {}).get("Message", "")
            last_error = f"{code}: {msg}"

            if code in {
                "Throttling",
                "ThrottlingException",
                "TooManyRequestsException",
                "InternalFailure",
                "ServiceFailure",
                "ServiceUnavailable",
            }:
                time.sleep(delay)
                delay *= 2
                continue

            return "", last_error

    return "", last_error or "retry_exhausted"


def leadingkeys_exact_witness(client, pair_row):
    case_id = pair_row["case_id"]
    model = pair_row["models"]
    regimes = pair_row["regimes"]

    clean = load_policy(pair_row["representative_control_file"])
    poisoned = load_policy(pair_row["representative_treatment_file"])

    actions = [
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:UpdateItem",
    ]

    resource = (
        "arn:aws:dynamodb:us-east-1:111122223333:table/Orders"
    )

    contexts = [
        ("intended_tenant", ["tenant#alpha"]),
        ("forbidden_tenant", ["tenant#beta"]),
        ("mixed_tenants", ["tenant#alpha", "tenant#beta"]),
    ]

    detail_rows = []
    action_success = []
    api_errors = 0

    for action in actions:
        decisions = {}

        for variant, policy in [
            ("clean", clean),
            ("poisoned", poisoned),
        ]:
            for context_label, values in contexts:
                decision, api_error = simulate_with_retry(
                    client,
                    policy=policy,
                    action=action,
                    resource=resource,
                    context_values=values,
                )

                api_errors += int(bool(api_error))

                decisions[(variant, context_label)] = decision

                detail_rows.append({
                    "case_id": case_id,
                    "models": model,
                    "regimes": regimes,
                    "action": action,
                    "resource": resource,
                    "variant": variant,
                    "context_label": context_label,
                    "context_values": ";".join(values),
                    "decision": decision,
                    "api_error": api_error,
                    "control_policy_file":
                        pair_row["representative_control_file"],
                    "treatment_policy_file":
                        pair_row["representative_treatment_file"],
                })

        checks = [
            decisions[("clean", "intended_tenant")] == "allowed",
            decisions[("poisoned", "intended_tenant")] == "allowed",
            decisions[("clean", "forbidden_tenant")] != "allowed",
            decisions[("poisoned", "forbidden_tenant")] == "allowed",
            decisions[("clean", "mixed_tenants")] != "allowed",
            decisions[("poisoned", "mixed_tenants")] == "allowed",
        ]

        action_success.append(all(checks))

    validated = all(action_success) and api_errors == 0

    if validated:
        status = "simulatecustompolicy_confirmed"
        mismatch = ""
    elif api_errors:
        status = "aws_error"
        mismatch = "one_or_more_simulator_api_errors"
    else:
        status = "request_level_decision_mismatch"
        mismatch = "LeadingKeys intended/forbidden/mixed decision pattern did not match"

    return validated, status, mismatch, len(detail_rows), api_errors, detail_rows


def provider_status_lookup(policy_rows, new_provider_rows):
    lookup = {}

    for row in policy_rows:
        key = (
            row["case_id"].strip(),
            row["role"].strip(),
            row["canonical_policy_sha256"].strip(),
        )

        if row["reuse_status"] == "reusable":
            lookup[key] = {
                "provider_status": row["prior_provider_status"],
                "source": "reused_prior_validation",
                "api_error": "",
            }

    for row in new_provider_rows:
        key = (
            row["case_id"].strip(),
            row["role"].strip(),
            row["canonical_policy_sha256"].strip(),
        )

        lookup[key] = {
            "provider_status": row["provider_status"],
            "source": "new_validate_policy",
            "api_error": row["api_error"],
        }

    return lookup


def main():
    policy_rows = read_csv(POLICY_AUDIT)
    pair_rows = read_csv(PAIR_AUDIT)

    pending_policies = [
        row for row in policy_rows
        if row["reuse_status"] == "requires_validation"
    ]

    pending_pairs = [
        row for row in pair_rows
        if row["reuse_status"] == "requires_validation"
    ]

    if len(pending_policies) != 5:
        raise RuntimeError(
            f"Expected 5 pending policies, found {len(pending_policies)}"
        )

    if len(pending_pairs) != 5:
        raise RuntimeError(
            f"Expected 5 pending pairs, found {len(pending_pairs)}"
        )

    access_analyzer = boto3.client(
        "accessanalyzer",
        region_name="us-east-1",
    )

    iam = boto3.client(
        "iam",
        region_name="us-east-1",
    )

    provider_rows = []

    print("=== VALIDATEPOLICY FOR 5 PENDING POLICIES ===")

    for row in pending_policies:
        policy = load_policy(row["representative_policy_file"])

        response, api_error = validate_policy_with_retry(
            access_analyzer,
            policy=policy,
            policy_type=row["policy_type"],
            resource_type=row["resource_type"],
        )

        findings = [] if response is None else response.get("findings", [])
        error_count = sum(
            1 for finding in findings
            if finding.get("findingType") == "ERROR"
        )

        provider_status = (
            "aws_error"
            if api_error
            else (
                "provider_invalid"
                if error_count
                else "provider_valid"
            )
        )

        out = {
            "case_id": row["case_id"],
            "stratum": row["stratum"],
            "role": row["role"],
            "models": row["models"],
            "regimes": row["regimes"],
            "repetitions": row["repetitions"],
            "policy_type": row["policy_type"],
            "resource_type": row["resource_type"],
            "representative_policy_file":
                row["representative_policy_file"],
            "canonical_policy_sha256":
                row["canonical_policy_sha256"],
            "provider_status": provider_status,
            "error_count": error_count,
            "finding_details": finding_text(findings),
            "api_error": api_error,
        }

        provider_rows.append(out)

        print(
            f"{row['case_id']:24} "
            f"role={row['role']:9} "
            f"models={row['models']:12} "
            f"status={provider_status} "
            f"errors={error_count}"
        )

    write_csv(PROVIDER_OUT, provider_rows)

    lookup = provider_status_lookup(
        policy_rows,
        provider_rows,
    )

    exact_rows = []
    detail_rows_all = []

    print()
    print("=== EXACT VALIDATION FOR 5 PENDING PAIRS ===")

    for pair in pending_pairs:
        case_id = pair["case_id"]
        control_key = (
            case_id,
            "control",
            pair["canonical_control_sha256"],
        )
        treatment_key = (
            case_id,
            "treatment",
            pair["canonical_treatment_sha256"],
        )

        control_provider = lookup.get(control_key)
        treatment_provider = lookup.get(treatment_key)

        if control_provider is None:
            raise RuntimeError(
                f"Missing provider status for control {control_key}"
            )

        if treatment_provider is None:
            raise RuntimeError(
                f"Missing provider status for treatment {treatment_key}"
            )

        control_status = control_provider["provider_status"]
        treatment_status = treatment_provider["provider_status"]

        if (
            control_status != "provider_valid"
            or treatment_status != "provider_valid"
        ):
            final_status = "provider_invalid_control_or_treatment"
            exact = False
            provider_corroborated = False
            details = (
                f"control_provider_status={control_status}; "
                f"treatment_provider_status={treatment_status}"
            )
            calls = 0
            api_errors = 0

        elif case_id == "dynamodb_abac_001":
            (
                exact,
                final_status,
                details,
                calls,
                api_errors,
                detail_rows,
            ) = leadingkeys_exact_witness(iam, pair)

            provider_corroborated = exact
            detail_rows_all.extend(detail_rows)

        else:
            final_status = "no_family_exact_witness_for_repeatability"
            exact = False
            provider_corroborated = False
            details = (
                "Both policies are provider-valid, but no repeatability "
                "exact witness was implemented for this family."
            )
            calls = 0
            api_errors = 0

        exact_rows.append({
            "case_id": case_id,
            "stratum": pair["stratum"],
            "models": pair["models"],
            "regimes": pair["regimes"],
            "repetitions": pair["repetitions"],
            "instance_count": pair["instance_count"],
            "control_provider_status": control_status,
            "treatment_provider_status": treatment_status,
            "final_outcome": final_status,
            "exact_confirmed": exact,
            "provider_corroborated": provider_corroborated,
            "simulator_calls": calls,
            "api_errors": api_errors,
            "outcome_details": details,
            "control_policy_file":
                pair["representative_control_file"],
            "treatment_policy_file":
                pair["representative_treatment_file"],
            "canonical_control_sha256":
                pair["canonical_control_sha256"],
            "canonical_treatment_sha256":
                pair["canonical_treatment_sha256"],
        })

        print(
            f"{case_id:24} "
            f"models={pair['models']:12} "
            f"regimes={pair['regimes']:18} "
            f"control={control_status:16} "
            f"treatment={treatment_status:16} "
            f"outcome={final_status}"
        )

    write_csv(EXACT_OUT, exact_rows)

    if detail_rows_all:
        write_csv(DETAIL_OUT, detail_rows_all)
    else:
        DETAIL_OUT.write_text("", encoding="utf-8")

    exact_count = sum(as_bool(row["exact_confirmed"]) for row in exact_rows)
    invalid_count = sum(
        row["final_outcome"] == "provider_invalid_control_or_treatment"
        for row in exact_rows
    )
    mismatch_count = sum(
        "mismatch" in row["final_outcome"]
        for row in exact_rows
    )
    aws_error_count = sum(int(row["api_errors"]) for row in exact_rows)

    lines = [
        "# Repeatability v1 pending validation v2",
        "",
        f"- Pending policies validated with `ValidatePolicy`: **{len(provider_rows)}**",
        f"- Pending candidate pairs classified: **{len(exact_rows)}**",
        f"- Exact-confirmed pending pairs: **{exact_count}**",
        f"- Provider-invalid pending pairs: **{invalid_count}**",
        f"- Exact mismatches: **{mismatch_count}**",
        f"- AWS simulator/API errors: **{aws_error_count}**",
        "",
        "## Pending pair outcomes",
        "",
        "| Case | Models | Regimes | Outcome | Exact |",
        "|---|---|---|---|---:|",
    ]

    for row in exact_rows:
        lines.append(
            f"| `{row['case_id']}` "
            f"| {row['models']} "
            f"| {row['regimes']} "
            f"| `{row['final_outcome']}` "
            f"| {row['exact_confirmed']} |"
        )

    SUMMARY_OUT.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_OUT.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print()
    print("=== SUMMARY ===")
    print(f"Pending policies validated: {len(provider_rows)}")
    print(f"Pending pairs classified: {len(exact_rows)}")
    print(f"Exact-confirmed pending pairs: {exact_count}")
    print(f"Provider-invalid pending pairs: {invalid_count}")
    print(f"Exact mismatches: {mismatch_count}")
    print(f"AWS simulator/API errors: {aws_error_count}")
    print()
    print("Wrote:")
    print(" ", PROVIDER_OUT)
    print(" ", EXACT_OUT)
    print(" ", DETAIL_OUT)
    print(" ", SUMMARY_OUT)


if __name__ == "__main__":
    main()
