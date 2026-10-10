#!/usr/bin/env python3
import csv
import json
import re
import time
from collections import Counter
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

MASTER = Path(
    "data/generated_from_master_v5_leadingkeysfix/"
    "rag_pairs_from_master.jsonl"
)

CORPUS = Path(
    "data/master_e2e_rag_v5_leadingkeysfix/"
    "corpus.jsonl"
)

PROVIDER_AUDIT = Path(
    "tables/"
    "table_provider_validity_all_e2e_clean_controls_v1.csv"
)

RUN = Path(
    "runs/20260605_024307_"
    "meta_llama3_8b_instruct_v1_0"
)

TARGETS = {
    "iam_boundary_001": {
        "policy_type": "IDENTITY_POLICY",
        "resource_type": "",
    },
    "logs_action_002": {
        "policy_type": "IDENTITY_POLICY",
        "resource_type": "",
    },
    "sts_trust_001": {
        "policy_type": "RESOURCE_POLICY",
        "resource_type":
            "AWS::IAM::AssumeRolePolicyDocument",
    },
}

OUT_CSV = Path(
    "tables/"
    "table_remaining_llama_controls_audit_v1.csv"
)

OUT_MD = Path(
    "summaries/"
    "remaining_llama_controls_audit_v1_summary.md"
)


def load_jsonl(path):
    return [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(policy):
    if not isinstance(policy, dict):
        return []

    value = policy.get("Statement", [])
    return value if isinstance(value, list) else [value]


def task_from_prompt(prompt):
    start = "Trusted user task:"
    end = "Trusted least-privilege specification:"

    if start not in prompt:
        return ""

    value = prompt.split(start, 1)[1]

    if end in value:
        value = value.split(end, 1)[0]

    return " ".join(value.split())


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

    return obj, ""


def summarize_policy(policy):
    effects = []
    sids = []
    actions = []
    resources = []
    not_resources = []
    principals = []
    conditions = []

    for statement in statements(policy):
        if "Effect" in statement:
            effects.append(
                str(statement.get("Effect"))
            )

        if "Sid" in statement:
            sids.append(
                str(statement.get("Sid"))
            )

        actions.extend(
            str(item)
            for item in as_list(
                statement.get("Action")
            )
        )

        resources.extend(
            str(item)
            for item in as_list(
                statement.get("Resource")
            )
        )

        not_resources.extend(
            str(item)
            for item in as_list(
                statement.get("NotResource")
            )
        )

        principal = statement.get("Principal")

        if isinstance(principal, dict):
            for kind, value in principal.items():
                for item in as_list(value):
                    principals.append(
                        f"{kind}:{item}"
                    )

        elif principal is not None:
            principals.extend(
                str(item)
                for item in as_list(principal)
            )

        condition = statement.get("Condition", {})

        if isinstance(condition, dict):
            for operator, key_values in condition.items():
                if not isinstance(key_values, dict):
                    continue

                for key, value in key_values.items():
                    conditions.append({
                        "operator": str(operator),
                        "key": str(key),
                        "values": [
                            str(item)
                            for item in as_list(value)
                        ],
                    })

    local_flags = []

    invalid_effects = [
        effect
        for effect in effects
        if effect not in {"Allow", "Deny"}
    ]

    if invalid_effects:
        local_flags.append(
            "invalid_effect:"
            + ";".join(invalid_effects)
        )

    suspicious_sids = [
        sid
        for sid in sids
        if not re.fullmatch(
            r"[A-Za-z0-9]+",
            sid,
        )
    ]

    if suspicious_sids:
        local_flags.append(
            "nonalphanumeric_sid:"
            + ";".join(suspicious_sids)
        )

    return {
        "effects": effects,
        "sids": sids,
        "actions": actions,
        "resources": resources,
        "not_resources": not_resources,
        "principals": principals,
        "conditions": conditions,
        "local_flags": local_flags,
    }


def validate_once(
    client,
    policy,
    policy_type,
    resource_type,
):
    findings = []
    next_token = None

    while True:
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
            params["validatePolicyResourceType"] = (
                resource_type
            )

        if next_token:
            params["nextToken"] = next_token

        response = client.validate_policy(**params)
        findings.extend(
            response.get("findings", [])
        )

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
            return validate_once(
                client,
                policy,
                policy_type,
                resource_type,
            ), ""

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
    master = {
        row["case_id"]: row
        for row in load_jsonl(MASTER)
        if row.get("case_id") in TARGETS
    }

    corpus = [
        row
        for row in load_jsonl(CORPUS)
        if row.get("case_id") in TARGETS
    ]

    previous = {}

    with PROVIDER_AUDIT.open(
        newline="",
        encoding="utf-8",
    ) as f:
        for row in csv.DictReader(f):
            if (
                row["model"] == "Llama 3 8B"
                and row["case_id"] in TARGETS
            ):
                previous[row["case_id"]] = row

    access_analyzer = boto3.client(
        "accessanalyzer"
    )

    rows = []

    for case_id, target in TARGETS.items():
        benchmark = master[case_id]

        print("")
        print("=" * 100)
        print(f"CASE: {case_id}")
        print("=" * 100)
        print(
            "Task:",
            task_from_prompt(
                benchmark.get(
                    "control_prompt",
                    "",
                )
            ),
        )
        print(
            "Oracle:",
            benchmark.get("oracle_check", ""),
        )
        print(
            "Goal:",
            benchmark.get("attacker_goal", ""),
        )

        print("\nRelevant documents:")

        for doc in corpus:
            if doc.get("case_id") != case_id:
                continue

            print(
                f"- {doc.get('doc_id')} "
                f"[{doc.get('kind')}]"
            )
            print(
                "  "
                + " ".join(
                    str(doc.get("text", "")).split()
                )[:650]
            )

        for prompt_type in ["ctrl", "poi"]:
            policy_file = (
                RUN
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
                summary = {
                    "effects": [],
                    "sids": [],
                    "actions": [],
                    "resources": [],
                    "not_resources": [],
                    "principals": [],
                    "conditions": [],
                    "local_flags": [],
                }

                provider_status = "nondeployable"
                findings = []
                api_error = ""

            else:
                summary = summarize_policy(policy)

                findings, api_error = (
                    validate_with_retry(
                        access_analyzer,
                        policy,
                        target["policy_type"],
                        target["resource_type"],
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
                elif counts.get("ERROR", 0):
                    provider_status = (
                        "provider_invalid"
                    )
                else:
                    provider_status = (
                        "provider_valid"
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

            row = {
                "case_id": case_id,
                "prompt_type": prompt_type,
                "policy_type":
                    target["policy_type"],
                "provider_status":
                    provider_status,
                "issue_codes":
                    ";".join(issue_codes),
                "effects":
                    json.dumps(
                        summary["effects"],
                        ensure_ascii=False,
                    ),
                "sids":
                    json.dumps(
                        summary["sids"],
                        ensure_ascii=False,
                    ),
                "actions":
                    json.dumps(
                        summary["actions"],
                        ensure_ascii=False,
                    ),
                "resources":
                    json.dumps(
                        summary["resources"],
                        ensure_ascii=False,
                    ),
                "not_resources":
                    json.dumps(
                        summary["not_resources"],
                        ensure_ascii=False,
                    ),
                "principals":
                    json.dumps(
                        summary["principals"],
                        ensure_ascii=False,
                    ),
                "conditions":
                    json.dumps(
                        summary["conditions"],
                        ensure_ascii=False,
                    ),
                "local_flags":
                    ";".join(
                        summary["local_flags"]
                    ),
                "finding_details":
                    finding_details,
                "local_error":
                    local_error,
                "api_error":
                    api_error,
                "policy_file":
                    str(policy_file),
            }

            rows.append(row)

            print("")
            print(
                f"{prompt_type.upper()}: "
                f"provider={provider_status}"
            )
            print("Effects:", summary["effects"])
            print("Sids:", summary["sids"])
            print("Actions:", summary["actions"])
            print("Resources:", summary["resources"])
            print(
                "NotResource:",
                summary["not_resources"],
            )
            print(
                "Principals:",
                summary["principals"],
            )
            print(
                "Conditions:",
                json.dumps(
                    summary["conditions"],
                    indent=2,
                    ensure_ascii=False,
                ),
            )
            print(
                "Local flags:",
                summary["local_flags"],
            )
            print(
                "AWS issues:",
                ";".join(issue_codes),
            )
            print(
                "AWS findings:",
                finding_details,
            )

            if policy is not None:
                print("Full policy:")
                print(
                    json.dumps(
                        policy,
                        indent=2,
                        ensure_ascii=False,
                    )
                )

    OUT_CSV.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fields = [
        "case_id",
        "prompt_type",
        "policy_type",
        "provider_status",
        "issue_codes",
        "effects",
        "sids",
        "actions",
        "resources",
        "not_resources",
        "principals",
        "conditions",
        "local_flags",
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

    lines = [
        "# Audit of the three remaining Llama clean-control failures",
        "",
        "| Case | Control provider status | Control issues | Poison provider status | Poison issues |",
        "|---|---|---|---|---|",
    ]

    by_case = {}

    for row in rows:
        by_case.setdefault(
            row["case_id"],
            {},
        )[row["prompt_type"]] = row

    for case_id in TARGETS:
        ctrl = by_case[case_id]["ctrl"]
        poi = by_case[case_id]["poi"]

        lines.append(
            f"| {case_id} | "
            f"{ctrl['provider_status']} | "
            f"{ctrl['issue_codes']} | "
            f"{poi['provider_status']} | "
            f"{poi['issue_codes']} |"
        )

    lines.extend([
        "",
        "These cases must be classified from the exact "
        "task, oracle, generated shape, and AWS findings. "
        "No selective model rerun should be performed merely "
        "to replace a genuine clean-control failure.",
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
