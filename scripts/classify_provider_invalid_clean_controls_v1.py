#!/usr/bin/env python3
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

INPUT = Path(
    "tables/table_provider_validity_all_e2e_clean_controls_v1.csv"
)
MAPPING = Path(
    "data/oracle_documentation_v1/oracle_case_mapping_v1.csv"
)

OUT_PATTERN_CSV = Path(
    "tables/table_provider_invalid_issue_patterns_v1.csv"
)
OUT_CASE_CSV = Path(
    "tables/table_provider_invalid_case_triage_v1.csv"
)
OUT_DETAIL_JSONL = Path(
    "data/provider_validity_audit_v1/"
    "provider_invalid_clean_controls_detail_v1.jsonl"
)
OUT_MD = Path(
    "summaries/provider_invalid_clean_controls_triage_v1.md"
)


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_mapping():
    if not MAPPING.exists():
        return {}

    rows = read_csv(MAPPING)
    return {
        row.get("case_id", ""): row
        for row in rows
        if row.get("case_id")
    }


def split_codes(value):
    return tuple(
        sorted(
            {
                code.strip()
                for code in (value or "").split(";")
                if code.strip()
            }
        )
    )


def initial_triage(case_id, codes):
    """
    This is triage only, not a final scientific classification.
    Every non-obvious class still requires policy inspection.
    """
    code_set = set(codes)

    if code_set == {"INVALID_VPCE_FORMAT"}:
        return "likely_synthetic_literal_artifact"

    if (
        code_set == {"UNSUPPORTED_PRINCIPAL"}
        and case_id.startswith("sqs_sourcearn")
    ):
        return "possible_policy_type_misclassification"

    if code_set == {"INVALID_ARN_ACCOUNT"}:
        return "inspect_oidc_arn_literal"

    if "MISSING_QUALIFIER" in code_set:
        return "provider_semantic_operator_invalid"

    if "INVALID_SERVICE_CONDITION_KEY" in code_set:
        return "inspect_benchmark_condition_key"

    structural_codes = {
        "INVALID_EFFECT",
        "INVALID_PRINCIPAL_KEY",
        "INVALID_SERVICE",
        "MISSING_PRINCIPAL",
        "MISSING_CONDITION_KEY_FOR_OIDC_PRINCIPAL",
        "ROLE_TRUST_POLICY_SYNTAX_ERROR_RESOURCE",
        "UNSUPPORTED_ACTION_FOR_CONDITION_KEY",
        "UNSUPPORTED_SID",
        "UNSUPPORTED_PRINCIPAL",
    }

    if code_set & structural_codes:
        return "likely_model_structural_invalid"

    return "manual_review_required"


def load_policy(path_string):
    path = Path(path_string)

    if not path.exists():
        return None, f"missing_file:{path}"

    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"json_error:{exc}"

    return obj, ""


def main():
    if not INPUT.exists():
        raise SystemExit(f"Missing input CSV: {INPUT}")

    mapping = load_mapping()
    all_rows = read_csv(INPUT)
    rows = [
        row
        for row in all_rows
        if row.get("status") != "provider_valid"
    ]

    case_ids = sorted({row["case_id"] for row in rows})
    model_names = sorted({row["model"] for row in rows})

    pattern_groups = defaultdict(list)
    code_counter = Counter()
    detail_rows = []

    for row in rows:
        codes = split_codes(row.get("issue_codes", ""))
        triage = initial_triage(row["case_id"], codes)

        pattern_groups[
            (";".join(codes), triage)
        ].append(row)

        for code in codes:
            code_counter[code] += 1

        policy, load_error = load_policy(
            row.get("policy_file", "")
        )
        case_meta = mapping.get(row["case_id"], {})

        detail_rows.append({
            "model": row.get("model", ""),
            "case_id": row.get("case_id", ""),
            "policy_type": row.get("policy_type", ""),
            "resource_type": row.get("resource_type", ""),
            "issue_codes": list(codes),
            "initial_triage": triage,
            "trusted_task": case_meta.get("trusted_task", ""),
            "oracle_check": case_meta.get("oracle_check", ""),
            "iam_category": case_meta.get("iam_category", ""),
            "finding_details": row.get(
                "finding_details", ""
            ),
            "policy_file": row.get("policy_file", ""),
            "load_error": load_error,
            "policy": policy,
        })

    # Exact issue-pattern summary.
    pattern_rows = []

    for (pattern, triage), grouped in sorted(
        pattern_groups.items(),
        key=lambda item: (-len(item[1]), item[0]),
    ):
        pattern_rows.append({
            "issue_pattern": pattern,
            "row_count": len(grouped),
            "unique_case_count": len({
                row["case_id"] for row in grouped
            }),
            "cases": ";".join(sorted({
                row["case_id"] for row in grouped
            })),
            "models": ";".join(sorted({
                row["model"] for row in grouped
            })),
            "initial_triage": triage,
        })

    OUT_PATTERN_CSV.parent.mkdir(
        parents=True, exist_ok=True
    )
    with OUT_PATTERN_CSV.open(
        "w", newline="", encoding="utf-8"
    ) as f:
        fields = [
            "issue_pattern",
            "row_count",
            "unique_case_count",
            "cases",
            "models",
            "initial_triage",
        ]
        writer = csv.DictWriter(
            f, fieldnames=fields
        )
        writer.writeheader()
        writer.writerows(pattern_rows)

    # One row per invalid model/case.
    case_rows = []

    for detail in detail_rows:
        case_rows.append({
            "model": detail["model"],
            "case_id": detail["case_id"],
            "iam_category": detail["iam_category"],
            "policy_type": detail["policy_type"],
            "issue_codes": ";".join(
                detail["issue_codes"]
            ),
            "initial_triage": detail[
                "initial_triage"
            ],
            "policy_file": detail["policy_file"],
        })

    with OUT_CASE_CSV.open(
        "w", newline="", encoding="utf-8"
    ) as f:
        fields = [
            "model",
            "case_id",
            "iam_category",
            "policy_type",
            "issue_codes",
            "initial_triage",
            "policy_file",
        ]
        writer = csv.DictWriter(
            f, fieldnames=fields
        )
        writer.writeheader()
        writer.writerows(case_rows)

    OUT_DETAIL_JSONL.parent.mkdir(
        parents=True, exist_ok=True
    )
    with OUT_DETAIL_JSONL.open(
        "w", encoding="utf-8"
    ) as f:
        for row in detail_rows:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )

    triage_counter = Counter(
        row["initial_triage"]
        for row in detail_rows
    )

    lines = [
        "# Provider-invalid clean-control triage v1",
        "",
        f"- Provider-invalid rows: **{len(rows)}**",
        f"- Unique affected cases: **{len(case_ids)}**",
        f"- Models affected: **{len(model_names)}**",
        "",
        "## Initial triage",
        "",
        "| Triage class | Rows |",
        "|---|---:|",
    ]

    for triage, count in sorted(
        triage_counter.items(),
        key=lambda item: (-item[1], item[0]),
    ):
        lines.append(f"| {triage} | {count} |")

    lines.extend([
        "",
        "## Individual issue-code frequency",
        "",
        "| Issue code | Rows containing code |",
        "|---|---:|",
    ])

    for code, count in code_counter.most_common():
        lines.append(f"| {code} | {count} |")

    lines.extend([
        "",
        "## Exact issue patterns",
        "",
        "| Pattern | Rows | Cases | Initial triage |",
        "|---|---:|---|---|",
    ])

    for row in pattern_rows:
        lines.append(
            f"| {row['issue_pattern']} | "
            f"{row['row_count']} | "
            f"{row['cases']} | "
            f"{row['initial_triage']} |"
        )

    lines.extend([
        "",
        "## Files",
        "",
        f"- Pattern CSV: `{OUT_PATTERN_CSV}`",
        f"- Case CSV: `{OUT_CASE_CSV}`",
        f"- Full policy detail: `{OUT_DETAIL_JSONL}`",
        "",
        "The classifications above are only triage labels. "
        "No denominator or attack count should be changed "
        "until fixture artifacts, validation-policy types, "
        "benchmark specifications, and genuine generated-policy "
        "errors are separated.",
    ])

    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(OUT_MD.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
