#!/usr/bin/env python3
import csv
import importlib.util
import json
import time
from collections import Counter, defaultdict
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

GATE_MODULE = Path("scripts/semantic_gate_baseline_v1.py")

OUT_CSV = Path(
    "tables/table_provider_validity_all_e2e_clean_controls_v1.csv"
)
OUT_SUMMARY_CSV = Path(
    "tables/table_provider_validity_all_e2e_clean_controls_summary_v1.csv"
)
OUT_MD = Path(
    "summaries/provider_validity_all_e2e_clean_controls_v1_summary.md"
)

spec = importlib.util.spec_from_file_location("gate_v1", GATE_MODULE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def load_policy(path: Path):
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"json_parse_error:{exc}"

    if isinstance(obj, dict) and obj.get("ok") is False:
        return None, f"repair_wrapper:{obj.get('repair')}"

    if isinstance(obj, list):
        obj = {
            "Version": "2012-10-17",
            "Statement": obj,
        }

    if not isinstance(obj, dict) or "Statement" not in obj:
        return None, "not_policy_object"

    return obj, ""


def expected_policy_type(case_id, mapping_row):
    """
    Classify using the benchmark's intended policy family, not the
    generated policy shape. This ensures an invalid Principal added
    to an identity policy is not silently reclassified as a resource
    policy.
    """
    case_l = case_id.lower()
    category = mapping_row.get("iam_category", "").lower()
    families = mapping_row.get("oracle_families", "").lower()
    oracle = mapping_row.get("oracle_check", "").lower()

    if (
        case_l.startswith("sts_trust")
        or "trust_policy" in category
        or "assume_role_web_identity" in oracle
        or "assumerolewithwebidentity" in oracle
    ):
        return (
            "RESOURCE_POLICY",
            "AWS::IAM::AssumeRolePolicyDocument",
        )

    if (
        "principal_or_trust_constraints" in families
        or "public" in category
        or "resource_policy" in category
        or "public_principal" in oracle
        or "principal_exact" in oracle
    ):
        return "RESOURCE_POLICY", ""

    return "IDENTITY_POLICY", ""


def validate_once(client, policy, policy_type, resource_type):
    params = {
        "policyDocument": json.dumps(
            policy,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
        "policyType": policy_type,
        "locale": "EN",
    }

    if resource_type:
        params["validatePolicyResourceType"] = resource_type

    findings = []
    next_token = None

    while True:
        call = dict(params)
        if next_token:
            call["nextToken"] = next_token

        response = client.validate_policy(**call)
        findings.extend(response.get("findings", []))
        next_token = response.get("nextToken")

        if not next_token:
            break

    return findings


def validate_with_retry(
    client,
    policy,
    policy_type,
    resource_type,
    attempts=6,
):
    delay = 1.0

    for attempt in range(attempts):
        try:
            findings = validate_once(
                client,
                policy,
                policy_type,
                resource_type,
            )
            return findings, ""
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")

            if code in {
                "ThrottlingException",
                "TooManyRequestsException",
                "RequestLimitExceeded",
            } and attempt < attempts - 1:
                time.sleep(delay)
                delay *= 2
                continue

            return [], str(exc)

    return [], "retry_exhausted"


def finding_counts(findings):
    counts = Counter(
        finding.get("findingType", "UNKNOWN")
        for finding in findings
    )

    return {
        "errors": counts.get("ERROR", 0),
        "security_warnings": counts.get("SECURITY_WARNING", 0),
        "warnings": (
            counts.get("WARNING", 0)
            + counts.get("GENERAL_WARNING", 0)
        ),
        "suggestions": counts.get("SUGGESTION", 0),
    }


def main():
    mapping = gate.load_mapping()
    client = boto3.client("accessanalyzer")

    rows = []

    for run_spec in gate.RUNS:
        run = Path(run_spec["run"])
        score_path = run / run_spec["score"]

        if not score_path.exists():
            print(f"WARNING missing score: {score_path}")
            continue

        scores = gate.load_score(score_path)
        cases = sorted(
            {
                case_id
                for case_id, prompt_type in scores
                if prompt_type == "ctrl"
                and case_id in mapping
            }
        )

        for case_id in cases:
            ctrl_score = scores.get(
                (case_id, "ctrl"),
                {"ok": False, "reason": ""},
            )

            # Audit only controls currently counted in the paper's
            # semantic clean-pass denominator.
            if not ctrl_score["ok"]:
                continue

            policy_path = (
                run
                / "raw"
                / f"req_{case_id}_ctrl__REPAIRED.json"
            )

            policy, load_error = load_policy(policy_path)
            policy_type, resource_type = expected_policy_type(
                case_id,
                mapping[case_id],
            )

            if policy is None:
                rows.append({
                    "setting": run_spec["setting"],
                    "model": run_spec["model"],
                    "run": str(run),
                    "case_id": case_id,
                    "iam_category": mapping[case_id].get(
                        "iam_category", ""
                    ),
                    "policy_type": policy_type,
                    "resource_type": resource_type,
                    "status": "local_invalid",
                    "error_count": "",
                    "security_warning_count": "",
                    "warning_count": "",
                    "suggestion_count": "",
                    "issue_codes": "",
                    "finding_details": "",
                    "api_error": load_error,
                    "policy_file": str(policy_path),
                })
                continue

            findings, api_error = validate_with_retry(
                client,
                policy,
                policy_type,
                resource_type,
            )

            if api_error:
                status = "aws_error"
                counts = {
                    "errors": "",
                    "security_warnings": "",
                    "warnings": "",
                    "suggestions": "",
                }
            else:
                counts = finding_counts(findings)
                status = (
                    "provider_invalid"
                    if counts["errors"] > 0
                    else "provider_valid"
                )

            issue_codes = sorted(
                {
                    finding.get("issueCode", "")
                    for finding in findings
                    if finding.get("issueCode")
                }
            )

            details = " || ".join(
                (
                    f"{finding.get('findingType', '')}:"
                    f"{finding.get('issueCode', '')}:"
                    f"{finding.get('findingDetails', '')}"
                )
                for finding in findings
            )

            rows.append({
                "setting": run_spec["setting"],
                "model": run_spec["model"],
                "run": str(run),
                "case_id": case_id,
                "iam_category": mapping[case_id].get(
                    "iam_category", ""
                ),
                "policy_type": policy_type,
                "resource_type": resource_type,
                "status": status,
                "error_count": counts["errors"],
                "security_warning_count": counts[
                    "security_warnings"
                ],
                "warning_count": counts["warnings"],
                "suggestion_count": counts["suggestions"],
                "issue_codes": ";".join(issue_codes),
                "finding_details": details,
                "api_error": api_error,
                "policy_file": str(policy_path),
            })

            print(
                f"{run_spec['model']:<20} "
                f"{case_id:<30} "
                f"{policy_type:<16} "
                f"status={status:<18} "
                f"errors={counts['errors']}"
            )

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "setting",
        "model",
        "run",
        "case_id",
        "iam_category",
        "policy_type",
        "resource_type",
        "status",
        "error_count",
        "security_warning_count",
        "warning_count",
        "suggestion_count",
        "issue_codes",
        "finding_details",
        "api_error",
        "policy_file",
    ]

    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    by_model = defaultdict(Counter)

    for row in rows:
        by_model[row["model"]]["semantic_clean_pass"] += 1
        by_model[row["model"]][row["status"]] += 1

    summary_rows = []

    for model in [
        "Claude Sonnet 4.5",
        "Mistral Small",
        "Nova Lite",
        "Nova Pro",
        "Llama 3 8B",
    ]:
        counts = by_model[model]

        summary_rows.append({
            "model": model,
            "semantic_clean_pass": counts[
                "semantic_clean_pass"
            ],
            "provider_valid_clean_pass": counts[
                "provider_valid"
            ],
            "provider_invalid": counts[
                "provider_invalid"
            ],
            "local_invalid": counts["local_invalid"],
            "aws_errors": counts["aws_error"],
        })

    with OUT_SUMMARY_CSV.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "model",
                "semantic_clean_pass",
                "provider_valid_clean_pass",
                "provider_invalid",
                "local_invalid",
                "aws_errors",
            ],
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    total = Counter(row["status"] for row in rows)

    invalid_rows = [
        row
        for row in rows
        if row["status"] != "provider_valid"
    ]

    lines = [
        "# Provider-validity audit of all E2E clean controls v1",
        "",
        f"- Semantic clean-pass outputs audited: **{len(rows)}**",
        f"- Provider-valid: **{total['provider_valid']}**",
        f"- Provider-invalid: **{total['provider_invalid']}**",
        f"- Locally invalid: **{total['local_invalid']}**",
        f"- AWS/API errors: **{total['aws_error']}**",
        "",
        "## Per-model denominator audit",
        "",
        "| Model | Semantic clean pass | Provider-valid clean pass | Provider-invalid | Local invalid | AWS errors |",
        "|---|---:|---:|---:|---:|---:|",
    ]

    for row in summary_rows:
        lines.append(
            f"| {row['model']} | "
            f"{row['semantic_clean_pass']} | "
            f"{row['provider_valid_clean_pass']} | "
            f"{row['provider_invalid']} | "
            f"{row['local_invalid']} | "
            f"{row['aws_errors']} |"
        )

    lines.extend([
        "",
        "## Non-provider-valid controls",
        "",
        "| Model | Case | Expected policy type | Status | Issue codes / error |",
        "|---|---|---|---|---|",
    ])

    for row in invalid_rows:
        problem = row["issue_codes"] or row["api_error"]

        lines.append(
            f"| {row['model']} | {row['case_id']} | "
            f"{row['policy_type']} | {row['status']} | "
            f"{problem} |"
        )

    lines.extend([
        "",
        f"Detail CSV: `{OUT_CSV}`",
        f"Summary CSV: `{OUT_SUMMARY_CSV}`",
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
