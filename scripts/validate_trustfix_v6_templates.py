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

CASE_ID = "sts_trust_001"

CORPUS = Path(
    "data/master_e2e_rag_v6_trustfix/corpus.jsonl"
)
QUERIES = Path(
    "data/master_e2e_rag_v6_trustfix/queries.jsonl"
)

OUT_CSV = Path(
    "tables/table_trustfix_v6_template_validation.csv"
)
OUT_MD = Path(
    "summaries/trustfix_v6_template_validation_summary.md"
)


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
            "policyType": "RESOURCE_POLICY",
            "validatePolicyResourceType":
                "AWS::IAM::AssumeRolePolicyDocument",
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
    query = next(
        row
        for row in load_jsonl(QUERIES)
        if row.get("case_id") == CASE_ID
    )

    docs = [
        row
        for row in load_jsonl(CORPUS)
        if row.get("case_id") == CASE_ID
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
            f"Expected one clean document, "
            f"found {len(clean_docs)}"
        )

    if len(poison_docs) != 1:
        raise RuntimeError(
            f"Expected one poison document, "
            f"found {len(poison_docs)}"
        )

    oracle = query["oracle_check"]
    access_analyzer = boto3.client("accessanalyzer")

    rows = []

    for variant, doc in [
        ("clean", clean_docs[0]),
        ("poison", poison_docs[0]),
    ]:
        policy = extract_policy_from_text(
            doc.get("text", "")
        )

        if policy is None:
            provider_status = "nondeployable"
            failures = ["template_policy_not_found"]
            findings = []
            api_error = ""

        else:
            failures = score_policy(
                policy,
                oracle,
            )

            findings, api_error = validate_with_retry(
                access_analyzer,
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
                provider_status = "aws_error"
            elif counts.get("ERROR", 0):
                provider_status = "provider_invalid"
            else:
                provider_status = "provider_valid"

        semantic_ok = not failures
        expected_semantic_ok = variant == "clean"

        issue_codes = sorted({
            finding.get("issueCode", "")
            for finding in findings
            if finding.get("issueCode")
        })

        expected_outcome = (
            provider_status == "provider_valid"
            and semantic_ok == expected_semantic_ok
        )

        rows.append({
            "case_id": CASE_ID,
            "variant": variant,
            "doc_id": doc.get("doc_id", ""),
            "provider_status": provider_status,
            "semantic_ok": semantic_ok,
            "expected_semantic_ok":
                expected_semantic_ok,
            "expected_outcome": expected_outcome,
            "failures": " | ".join(failures),
            "issue_codes": ";".join(issue_codes),
            "api_error": api_error,
            "policy_json": (
                json.dumps(
                    policy,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                if policy
                else ""
            ),
        })

        print("")
        print(
            f"{variant:<6} "
            f"provider={provider_status:<18} "
            f"semantic={str(semantic_ok):<5} "
            f"expected_outcome="
            f"{str(expected_outcome):<5}"
        )
        print(
            "failures=",
            " | ".join(failures),
        )
        print(
            "issues=",
            ";".join(issue_codes),
        )
        print("policy=")
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

    expected_pass = sum(
        row["expected_outcome"]
        for row in rows
    )

    lines = [
        "# Trust-policy v6 canonical-template validation",
        "",
        f"- Templates audited: **{len(rows)}**",
        (
            "- Provider-valid templates: "
            f"**{sum(row['provider_status'] == 'provider_valid' for row in rows)}/2**"
        ),
        (
            "- Clean template semantic pass: "
            f"**{sum(row['variant'] == 'clean' and row['semantic_ok'] for row in rows)}/1**"
        ),
        (
            "- Poison template rejected by oracle: "
            f"**{sum(row['variant'] == 'poison' and not row['semantic_ok'] for row in rows)}/1**"
        ),
        (
            "- Expected outcomes satisfied: "
            f"**{expected_pass}/2**"
        ),
        "",
        "| Variant | Provider | Semantic | Failures | Issues |",
        "|---|---|---:|---|---|",
    ]

    for row in rows:
        lines.append(
            f"| {row['variant']} | "
            f"{row['provider_status']} | "
            f"{row['semantic_ok']} | "
            f"{row['failures']} | "
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

    if expected_pass != 2:
        raise SystemExit(
            "FAIL: trust-policy templates did not "
            "produce the intended provider/oracle outcomes."
        )

    print(
        "PASS: both v6 trust-policy templates are "
        "provider-valid and produce the intended oracle decisions."
    )


if __name__ == "__main__":
    main()
