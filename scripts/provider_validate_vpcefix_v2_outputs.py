#!/usr/bin/env python3
import csv
import json
import time
from collections import Counter, defaultdict
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

MANIFEST = Path("tables/table_vpcefix_v2_reruns.csv")

OUT_CSV = Path(
    "tables/table_provider_validation_vpcefix_v2_outputs.csv"
)
OUT_MD = Path(
    "summaries/provider_validation_vpcefix_v2_outputs_summary.md"
)

EXPECTED_CASES = {
    "logs_vpce_002",
    "s3_vpce_002",
    "secrets_vpce_002",
}


def load_score(path):
    rows = {}

    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows[(row["pair_id"], row["prompt_type"])] = {
                "semantic_ok": row["semantic_ok"],
                "failures": row.get("failures", ""),
            }

    return rows


def load_policy(path):
    if not path.exists():
        return None, "missing_file"

    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"json_parse_error:{exc}"

    if isinstance(obj, dict) and obj.get("ok") is False:
        return None, (
            f"repair_wrapper:"
            f"{obj.get('repair', obj.get('error', 'unknown'))}"
        )

    if isinstance(obj, list):
        obj = {
            "Version": "2012-10-17",
            "Statement": obj,
        }

    if not isinstance(obj, dict) or "Statement" not in obj:
        return None, "not_policy_object"

    statements = obj.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list) or not statements:
        return None, "empty_statement_list"

    return obj, ""


def validate_once(client, policy):
    params = {
        "policyDocument": json.dumps(
            policy,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
        "policyType": "IDENTITY_POLICY",
        "locale": "EN",
    }

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
    client = boto3.client("accessanalyzer")

    with MANIFEST.open(newline="", encoding="utf-8") as f:
        manifest_rows = list(csv.DictReader(f))

    output_rows = []

    for item in manifest_rows:
        model = item["model"]
        run = Path(item["run"])
        score_file = Path(item["score_file"])

        scores = load_score(score_file)

        found_cases = {
            case_id
            for case_id, _ in scores
        }

        if found_cases != EXPECTED_CASES:
            raise RuntimeError(
                f"{model}: unexpected cases {found_cases}"
            )

        for case_id in sorted(EXPECTED_CASES):
            for prompt_type in ["ctrl", "poi"]:
                score = scores[(case_id, prompt_type)]

                policy_file = (
                    run
                    / "raw"
                    / f"req_{case_id}_{prompt_type}__REPAIRED.json"
                )

                policy, load_error = load_policy(policy_file)

                if policy is None:
                    output_rows.append({
                        "model": model,
                        "run": str(run),
                        "case_id": case_id,
                        "prompt_type": prompt_type,
                        "semantic_ok": score["semantic_ok"],
                        "semantic_failures": score["failures"],
                        "provider_status": "nondeployable",
                        "error_count": "",
                        "security_warning_count": "",
                        "warning_count": "",
                        "suggestion_count": "",
                        "issue_codes": "",
                        "finding_details": "",
                        "local_error": load_error,
                        "api_error": "",
                        "policy_file": str(policy_file),
                    })
                    continue

                findings, api_error = validate_with_retry(
                    client,
                    policy,
                )

                if api_error:
                    provider_status = "aws_error"
                    counts = Counter()
                else:
                    counts = Counter(
                        finding.get("findingType", "UNKNOWN")
                        for finding in findings
                    )

                    provider_status = (
                        "provider_invalid"
                        if counts.get("ERROR", 0) > 0
                        else "provider_valid"
                    )

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

                output_rows.append({
                    "model": model,
                    "run": str(run),
                    "case_id": case_id,
                    "prompt_type": prompt_type,
                    "semantic_ok": score["semantic_ok"],
                    "semantic_failures": score["failures"],
                    "provider_status": provider_status,
                    "error_count": counts.get("ERROR", ""),
                    "security_warning_count": counts.get(
                        "SECURITY_WARNING", ""
                    ),
                    "warning_count": (
                        counts.get("WARNING", 0)
                        + counts.get("GENERAL_WARNING", 0)
                    ),
                    "suggestion_count": counts.get(
                        "SUGGESTION", ""
                    ),
                    "issue_codes": ";".join(issue_codes),
                    "finding_details": finding_details,
                    "local_error": "",
                    "api_error": api_error,
                    "policy_file": str(policy_file),
                })

                print(
                    f"{model:<14} "
                    f"{case_id:<20} "
                    f"{prompt_type:<4} "
                    f"semantic={score['semantic_ok']:<5} "
                    f"provider={provider_status:<18} "
                    f"issues={';'.join(issue_codes)}"
                )

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "model",
        "run",
        "case_id",
        "prompt_type",
        "semantic_ok",
        "semantic_failures",
        "provider_status",
        "error_count",
        "security_warning_count",
        "warning_count",
        "suggestion_count",
        "issue_codes",
        "finding_details",
        "local_error",
        "api_error",
        "policy_file",
    ]

    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(output_rows)

    by_prompt = defaultdict(Counter)
    by_model = defaultdict(Counter)

    for row in output_rows:
        by_prompt[row["prompt_type"]][
            row["provider_status"]
        ] += 1

        by_model[row["model"]][
            row["provider_status"]
        ] += 1

    lines = [
        "# Provider validation of corrected VPCE outputs",
        "",
        f"- Outputs audited: **{len(output_rows)}**",
        "",
        "## By prompt type",
        "",
        "| Prompt | Provider-valid | Provider-invalid | Nondeployable | AWS errors |",
        "|---|---:|---:|---:|---:|",
    ]

    for prompt_type in ["ctrl", "poi"]:
        counts = by_prompt[prompt_type]

        lines.append(
            f"| {prompt_type} | "
            f"{counts['provider_valid']} | "
            f"{counts['provider_invalid']} | "
            f"{counts['nondeployable']} | "
            f"{counts['aws_error']} |"
        )

    lines.extend([
        "",
        "## By model",
        "",
        "| Model | Provider-valid | Provider-invalid | Nondeployable | AWS errors |",
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
            f"{counts['aws_error']} |"
        )

    lines.extend([
        "",
        "## Semantic failures after fixture correction",
        "",
        "| Model | Case | Prompt | Provider status | Semantic failure |",
        "|---|---|---|---|---|",
    ])

    for row in output_rows:
        if row["semantic_ok"].lower() != "true":
            lines.append(
                f"| {row['model']} | "
                f"{row['case_id']} | "
                f"{row['prompt_type']} | "
                f"{row['provider_status']} | "
                f"{row['semantic_failures']} |"
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
