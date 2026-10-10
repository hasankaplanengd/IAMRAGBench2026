#!/usr/bin/env python3
import csv
import json
import time
from collections import Counter
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

CASE_ID = "secrets_resource_001"

MASTER = Path(
    "data/generated_from_master_v5_leadingkeysfix/"
    "rag_pairs_from_master.jsonl"
)

CORPUS = Path(
    "data/master_e2e_rag_v5_leadingkeysfix/corpus.jsonl"
)

RUNS = [
    (
        "Claude Sonnet 4.5",
        Path(
            "runs/20260605_023333_"
            "us_anthropic_claude_sonnet_4_5_20250929_v1_0"
        ),
    ),
    (
        "Mistral Small",
        Path(
            "runs/20260605_095315_"
            "mistral_mistral_small_2402_v1_0"
        ),
    ),
    (
        "Nova Lite",
        Path(
            "runs/20260605_021337_amazon_nova_lite_v1_0"
        ),
    ),
    (
        "Nova Pro",
        Path(
            "runs/20260605_022706_amazon_nova_pro_v1_0"
        ),
    ),
    (
        "Llama 3 8B",
        Path(
            "runs/20260605_024307_meta_llama3_8b_instruct_v1_0"
        ),
    ),
]

SCORE_NAME = (
    "master_e2e_rag_v2_k5_standard_full60_"
    "semantic_score.csv"
)

OUT_CSV = Path(
    "tables/table_secrets_resource_audit_v1.csv"
)

OUT_MD = Path(
    "summaries/secrets_resource_audit_v1_summary.md"
)


def load_jsonl(path):
    return [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]


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
            + str(obj.get("repair", obj.get("error", "")))
        )

    if isinstance(obj, list):
        obj = {
            "Version": "2012-10-17",
            "Statement": obj,
        }

    if not isinstance(obj, dict) or "Statement" not in obj:
        return None, "not_policy_object"

    return obj, ""


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(policy):
    value = policy.get("Statement", [])
    return value if isinstance(value, list) else [value]


def extract(policy):
    actions = []
    resources = []
    conditions = []

    for statement in statements(policy):
        actions.extend(
            str(item)
            for item in as_list(statement.get("Action"))
        )

        resources.extend(
            str(item)
            for item in as_list(statement.get("Resource"))
        )

        condition = statement.get("Condition", {})

        if not isinstance(condition, dict):
            continue

        for operator, key_values in condition.items():
            if not isinstance(key_values, dict):
                continue

            for key, value in key_values.items():
                conditions.append({
                    "effect": str(
                        statement.get("Effect", "")
                    ),
                    "operator": str(operator),
                    "key": str(key),
                    "values": [
                        str(item)
                        for item in as_list(value)
                    ],
                })

    return actions, resources, conditions


def load_score(run):
    path = run / SCORE_NAME

    if not path.exists():
        return {}

    with path.open(newline="", encoding="utf-8") as f:
        return {
            (row["pair_id"], row["prompt_type"]): row
            for row in csv.DictReader(f)
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
            "policyType": "IDENTITY_POLICY",
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
                code in {
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
    master_rows = {
        row["case_id"]: row
        for row in load_jsonl(MASTER)
    }

    benchmark = master_rows[CASE_ID]

    print("---- benchmark definition ----")
    print("Case:", CASE_ID)
    print("Service:", benchmark.get("aws_service"))
    print("Category:", benchmark.get("iam_category"))
    print("Oracle:", benchmark.get("oracle_check"))
    print("Goal:", benchmark.get("attacker_goal"))
    print("")
    print("Control prompt:")
    print(benchmark.get("control_prompt", ""))
    print("")

    print("---- relevant corpus documents ----")

    for doc in load_jsonl(CORPUS):
        if doc.get("case_id") != CASE_ID:
            continue

        print("")
        print(
            doc.get("doc_id"),
            "kind=",
            doc.get("kind"),
        )
        print(doc.get("text", "")[:1800])

    client = boto3.client("accessanalyzer")
    rows = []

    print("")
    print("---- generated-policy audit ----")

    for model, run in RUNS:
        scores = load_score(run)

        for prompt_type in ["ctrl", "poi"]:
            policy_file = (
                run
                / "raw"
                / (
                    f"req_{CASE_ID}_{prompt_type}"
                    "__REPAIRED.json"
                )
            )

            policy, local_error = load_policy(policy_file)

            old_score = scores.get(
                (CASE_ID, prompt_type),
                {},
            )

            if policy is None:
                actions = []
                resources = []
                conditions = []
                findings = []
                api_error = ""
                status = "nondeployable"

            else:
                actions, resources, conditions = extract(policy)

                findings, api_error = validate_with_retry(
                    client,
                    policy,
                )

                counts = Counter(
                    finding.get(
                        "findingType",
                        "UNKNOWN",
                    )
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

            details = " || ".join(
                (
                    f"{finding.get('findingType', '')}:"
                    f"{finding.get('issueCode', '')}:"
                    f"{finding.get('findingDetails', '')}"
                )
                for finding in findings
            )

            row = {
                "model": model,
                "prompt_type": prompt_type,
                "old_semantic_ok":
                    old_score.get("semantic_ok", ""),
                "old_semantic_failures":
                    old_score.get("failures", ""),
                "provider_status": status,
                "issue_codes": ";".join(issue_codes),
                "actions": ";".join(actions),
                "resources": ";".join(resources),
                "condition_entries": json.dumps(
                    conditions,
                    ensure_ascii=False,
                ),
                "finding_details": details,
                "local_error": local_error,
                "api_error": api_error,
                "policy_file": str(policy_file),
            }

            rows.append(row)

            print("")
            print(
                f"{model} / {prompt_type}: "
                f"semantic={row['old_semantic_ok']} "
                f"provider={status}"
            )
            print("Actions:", actions)
            print("Resources:", resources)
            print("Conditions:")
            print(
                json.dumps(
                    conditions,
                    indent=2,
                    ensure_ascii=False,
                )
            )
            print("Issues:", ";".join(issue_codes))
            print("Findings:", details)

    OUT_CSV.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fields = [
        "model",
        "prompt_type",
        "old_semantic_ok",
        "old_semantic_failures",
        "provider_status",
        "issue_codes",
        "actions",
        "resources",
        "condition_entries",
        "finding_details",
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

    ctrl_rows = [
        row
        for row in rows
        if row["prompt_type"] == "ctrl"
    ]

    invalid_controls = [
        row
        for row in ctrl_rows
        if row["provider_status"] != "provider_valid"
    ]

    lines = [
        "# Secrets Manager resource case audit v1",
        "",
        f"- Outputs audited: **{len(rows)}**",
        f"- Clean controls provider-valid: **{len(ctrl_rows) - len(invalid_controls)}/{len(ctrl_rows)}**",
        f"- Clean controls non-provider-valid: **{len(invalid_controls)}**",
        "",
        "| Model | Prompt | Old semantic pass | Provider | Conditions | Issues |",
        "|---|---|---:|---|---|---|",
    ]

    for row in rows:
        lines.append(
            f"| {row['model']} | "
            f"{row['prompt_type']} | "
            f"{row['old_semantic_ok']} | "
            f"{row['provider_status']} | "
            f"`{row['condition_entries']}` | "
            f"{row['issue_codes']} |"
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
