#!/usr/bin/env python3
import csv
import json
import time
from collections import Counter
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from oidc_oracle_v4 import (
    extract_policy_from_text,
    score_policy,
)

CORPUS = Path(
    "data/master_e2e_rag_v4_oidcfix/corpus.jsonl"
)
QUERIES = Path(
    "data/master_e2e_rag_v4_oidcfix/queries.jsonl"
)

OUT_CSV = Path(
    "tables/table_oidcfix_v4_template_validation.csv"
)
OUT_MD = Path(
    "summaries/oidcfix_v4_template_validation_summary.md"
)

CASES = {
    f"sts_oidc_trust_{index:03d}"
    for index in range(1, 7)
}


def load_jsonl(path):
    rows = []

    for line in path.read_text(
        encoding="utf-8"
    ).splitlines():
        if line.strip():
            rows.append(json.loads(line))

    return rows


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
            "policyType": "RESOURCE_POLICY",
            "validatePolicyResourceType":
                "AWS::IAM::AssumeRolePolicyDocument",
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
    query_rows = {
        row["case_id"]: row
        for row in load_jsonl(QUERIES)
        if row.get("case_id") in CASES
    }

    corpus_rows = [
        row
        for row in load_jsonl(CORPUS)
        if row.get("case_id") in CASES
    ]

    if set(query_rows) != CASES:
        raise RuntimeError(
            f"Missing query cases: "
            f"{sorted(CASES - set(query_rows))}"
        )

    access_analyzer = boto3.client(
        "accessanalyzer"
    )

    output_rows = []

    for case_id in sorted(CASES):
        docs = [
            row
            for row in corpus_rows
            if row.get("case_id") == case_id
        ]

        clean_docs = [
            row
            for row in docs
            if row.get("kind") == "clean_relevant"
        ]

        poison_docs = [
            row
            for row in docs
            if (
                "poison" in str(
                    row.get("kind", "")
                ).lower()
                or "retrieval_competitive"
                in str(row.get("doc_id", "")).lower()
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

        oracle = query_rows[case_id][
            "oracle_check"
        ]

        variants = [
            ("clean", clean_docs[0]),
            ("poison", poison_docs[0]),
        ]

        for variant, doc in variants:
            policy = extract_policy_from_text(
                doc.get("text", "")
            )

            if policy is None:
                provider_status = "nondeployable"
                findings = []
                api_error = ""
                failures = [
                    "template_policy_not_found"
                ]

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
                    provider_status = "provider_valid"

            issue_codes = sorted({
                finding.get("issueCode", "")
                for finding in findings
                if finding.get("issueCode")
            })

            semantic_ok = not failures

            expected_semantic_ok = (
                variant == "clean"
            )

            expected_outcome = (
                provider_status == "provider_valid"
                and semantic_ok
                == expected_semantic_ok
            )

            output_rows.append({
                "case_id": case_id,
                "variant": variant,
                "doc_id": doc.get("doc_id", ""),
                "provider_status": provider_status,
                "semantic_ok": semantic_ok,
                "expected_semantic_ok":
                    expected_semantic_ok,
                "expected_outcome":
                    expected_outcome,
                "failures": " | ".join(failures),
                "issue_codes": ";".join(issue_codes),
                "api_error": api_error,
                "policy_json": json.dumps(
                    policy,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ) if policy else "",
            })

            print(
                f"{case_id:<22} "
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
        writer.writerows(output_rows)

    clean_rows = [
        row
        for row in output_rows
        if row["variant"] == "clean"
    ]

    poison_rows = [
        row
        for row in output_rows
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
        for row in output_rows
    )

    lines = [
        "# OIDC v4 canonical-template validation",
        "",
        f"- Templates audited: **{len(output_rows)}**",
        (
            "- Clean templates provider-valid: "
            f"**{clean_provider_valid}/6**"
        ),
        (
            "- Clean templates semantic pass: "
            f"**{clean_semantic_pass}/6**"
        ),
        (
            "- Poison templates provider-valid: "
            f"**{poison_provider_valid}/6**"
        ),
        (
            "- Poison templates rejected by oracle: "
            f"**{poison_semantic_reject}/6**"
        ),
        (
            "- Expected outcomes satisfied: "
            f"**{expected_pass}/12**"
        ),
        "",
        "| Case | Variant | Provider | Semantic | Failures |",
        "|---|---|---|---:|---|",
    ]

    for row in output_rows:
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

    if expected_pass != 12:
        raise SystemExit(
            "FAIL: one or more canonical OIDC "
            "templates did not satisfy the expected outcome."
        )

    print(
        "PASS: all 12 OIDC templates are provider-valid "
        "and produce the intended oracle decisions."
    )


if __name__ == "__main__":
    main()
