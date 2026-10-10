#!/usr/bin/env python3
import csv
import json
import time
from collections import Counter
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from leadingkeys_oracle_v5 import (
    extract_policy_from_text,
    score_policy,
)

CORPUS = Path(
    "data/master_e2e_rag_v5_leadingkeysfix/"
    "corpus.jsonl"
)

QUERIES = Path(
    "data/master_e2e_rag_v5_leadingkeysfix/"
    "queries.jsonl"
)

OUT_CSV = Path(
    "tables/"
    "table_leadingkeysfix_v5_tenant_template_validation.csv"
)

OUT_MD = Path(
    "summaries/"
    "leadingkeysfix_v5_tenant_template_validation_summary.md"
)

CASES = {
    "dynamodb_tenant_002",
}


def load_jsonl(path):
    return [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]


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
    attempts=6,
):
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


def main():
    queries = {
        row["case_id"]: row
        for row in load_jsonl(QUERIES)
        if row.get("case_id") in CASES
    }

    if set(queries) != CASES:
        raise RuntimeError(
            "Missing query metadata: "
            + ", ".join(
                sorted(CASES - set(queries))
            )
        )

    docs = [
        row
        for row in load_jsonl(CORPUS)
        if row.get("case_id") in CASES
    ]

    access_analyzer = boto3.client(
        "accessanalyzer"
    )

    rows = []

    for case_id in sorted(CASES):
        case_docs = [
            row
            for row in docs
            if row.get("case_id") == case_id
        ]

        clean_docs = [
            row
            for row in case_docs
            if row.get("kind") == "clean_relevant"
        ]

        poison_docs = [
            row
            for row in case_docs
            if (
                "poison"
                in str(
                    row.get("kind", "")
                ).lower()
                or "retrieval_competitive"
                in str(
                    row.get("doc_id", "")
                ).lower()
            )
        ]

        if len(clean_docs) != 1:
            raise RuntimeError(
                f"{case_id}: expected one clean doc, "
                f"found {len(clean_docs)}"
            )

        if len(poison_docs) != 1:
            raise RuntimeError(
                f"{case_id}: expected one poison doc, "
                f"found {len(poison_docs)}"
            )

        oracle = queries[case_id][
            "oracle_check"
        ]

        for variant, doc in [
            ("clean", clean_docs[0]),
            ("poison", poison_docs[0]),
        ]:
            policy = extract_policy_from_text(
                doc.get("text", "")
            )

            if policy is None:
                provider_status = "nondeployable"
                failures = [
                    "template_policy_not_found"
                ]
                findings = []
                api_error = ""

            else:
                failures = score_policy(
                    policy,
                    oracle,
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

                elif counts.get("ERROR", 0):
                    provider_status = (
                        "provider_invalid"
                    )

                else:
                    provider_status = (
                        "provider_valid"
                    )

            semantic_ok = len(failures) == 0
            expected_semantic_ok = (
                variant == "clean"
            )

            issue_codes = sorted({
                finding.get("issueCode", "")
                for finding in findings
                if finding.get("issueCode")
            })

            expected_outcome = (
                provider_status == "provider_valid"
                and semantic_ok
                == expected_semantic_ok
            )

            rows.append({
                "case_id": case_id,
                "variant": variant,
                "doc_id": doc.get("doc_id", ""),
                "provider_status": provider_status,
                "semantic_ok": semantic_ok,
                "expected_semantic_ok":
                    expected_semantic_ok,
                "expected_outcome":
                    expected_outcome,
                "failures":
                    " | ".join(failures),
                "issue_codes":
                    ";".join(issue_codes),
                "api_error": api_error,
                "policy_json": (
                    json.dumps(
                        policy,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    )
                    if policy
                    else ""
                ),
            })

            print(
                f"{case_id:<24} "
                f"{variant:<6} "
                f"provider={provider_status:<18} "
                f"semantic={str(semantic_ok):<5} "
                f"expected={str(expected_outcome):<5} "
                f"failures={' | '.join(failures)}"
            )

    OUT_CSV.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fields = [
        "case_id",
        "variant",
        "doc_id",
        "provider_status",
        "semantic_ok",
        "expected_semantic_ok",
        "expected_outcome",
        "failures",
        "issue_codes",
        "api_error",
        "policy_json",
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

    clean_rows = [
        row
        for row in rows
        if row["variant"] == "clean"
    ]

    poison_rows = [
        row
        for row in rows
        if row["variant"] == "poison"
    ]

    clean_provider_valid = sum(
        row["provider_status"] == "provider_valid"
        for row in clean_rows
    )

    clean_semantic_pass = sum(
        row["semantic_ok"]
        for row in clean_rows
    )

    poison_provider_valid = sum(
        row["provider_status"] == "provider_valid"
        for row in poison_rows
    )

    poison_semantic_reject = sum(
        not row["semantic_ok"]
        for row in poison_rows
    )

    expected_pass = sum(
        row["expected_outcome"]
        for row in rows
    )

    lines = [
        "# LeadingKeys v5 regenerated-template validation",
        "",
        f"- Templates audited: **{len(rows)}**",
        (
            "- Clean templates provider-valid: "
            f"**{clean_provider_valid}/{len(clean_rows)}**"
        ),
        (
            "- Clean templates semantic pass: "
            f"**{clean_semantic_pass}/{len(clean_rows)}**"
        ),
        (
            "- Poison templates provider-valid: "
            f"**{poison_provider_valid}/{len(poison_rows)}**"
        ),
        (
            "- Poison templates rejected by oracle: "
            f"**{poison_semantic_reject}/{len(poison_rows)}**"
        ),
        (
            "- Expected outcomes satisfied: "
            f"**{expected_pass}/{len(rows)}**"
        ),
        "",
        "| Case | Variant | Provider | Semantic | Failures |",
        "|---|---|---|---:|---|",
    ]

    for row in rows:
        lines.append(
            f"| {row['case_id']} | "
            f"{row['variant']} | "
            f"{row['provider_status']} | "
            f"{row['semantic_ok']} | "
            f"{row['failures']} |"
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

    if expected_pass != len(rows):
        raise SystemExit(
            "FAIL: one or more canonical LeadingKeys "
            "templates did not satisfy the expected outcome."
        )

    print(
        "PASS: both regenerated LeadingKeys templates are "
        "provider-valid and produce the intended oracle decisions."
    )


if __name__ == "__main__":
    main()
