#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path.cwd()

TARGET = ROOT / "accept_upgrade_audit/regression_original_authority_v1/original_authority_regression_target_v1.csv"
EXPECTED = ROOT / "accept_upgrade_audit/regression_original_authority_v1/original_authority_regression_expected_v1.json"
TARGET_SCRIPT = ROOT / "accept_upgrade_audit/regression_original_authority_v1/build_original_authority_regression_target_v1.py"

REQUIRED_COLUMNS = {
    "model",
    "model_label",
    "case_id",
    "policy_type",
    "semantic_failure",
    "check_no_new_access",
    "check_status",
    "validation_family",
    "final_outcome",
    "exact_confirmed",
    "provider_corroborated",
    "control_policy_file",
    "poison_policy_file",
    "expected_exact_confirmed",
    "expected_provider_corroborated",
    "api_error",
    "validation_family_original_input",
    "family_mapping_source",
}

EXPECTED_FAMILIES = {
    "action_scope_widening": 8,
    "allow_condition_removal": 19,
    "dynamodb_leadingkeys": 4,
    "explicit_deny_guardrail": 9,
    "kms_multi_condition": 2,
    "oidc_or_role_trust": 13,
    "passrole_scope": 14,
    "public_or_principal_scope": 4,
    "resource_scope_widening": 9,
    "sqs_sourcearn_resource": 2,
}

EXPECTED_OUTCOMES = {
    "simulatecustompolicy_confirmed": 61,
    "exact_claim_differential_confirmed": 7,
    "exact_claim_differential_mismatch": 6,
    "exact_public_scope_differential_confirmed": 4,
    "access_analyzer_corroborated_simulatecustompolicy_unresolved": 2,
    "request_level_decision_mismatch": 2,
    "exact_sourcearn_differential_confirmed": 2,
}


def boolish(value: str) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def main() -> None:
    if not TARGET.exists():
        raise SystemExit(f"MISSING TARGET: {TARGET}")
    if not EXPECTED.exists():
        raise SystemExit(f"MISSING EXPECTED JSON: {EXPECTED}")
    if not TARGET_SCRIPT.exists():
        raise SystemExit(f"MISSING BUILD SCRIPT: {TARGET_SCRIPT}")

    with TARGET.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    with EXPECTED.open(encoding="utf-8") as f:
        expected = json.load(f)

    fields = set(rows[0].keys()) if rows else set()
    missing_cols = sorted(REQUIRED_COLUMNS - fields)
    suspicious_cols = sorted(c for c in fields if c in {"atus", "rget_v1.csv", "git status --short"})

    missing_policy_files = []
    for r in rows:
        for key in ["control_policy_file", "poison_policy_file"]:
            p = Path(r[key])
            if not p.is_absolute():
                p = ROOT / p
            if not p.exists():
                missing_policy_files.append((r["model"], r["case_id"], key, r[key]))

    family_counts = Counter(r["validation_family"] for r in rows)
    outcome_counts = Counter(r["final_outcome"] for r in rows)
    model_counts = Counter(r["model_label"] for r in rows)
    check_status_counts = Counter(r["check_status"] for r in rows)

    exact = sum(boolish(r["expected_exact_confirmed"]) for r in rows)
    corr = sum(boolish(r["expected_provider_corroborated"]) for r in rows)

    problems = []

    if len(rows) != 84:
        problems.append(f"Expected 84 rows, found {len(rows)}")
    if missing_cols:
        problems.append(f"Missing required columns: {missing_cols}")
    if suspicious_cols:
        problems.append(f"Suspicious corrupted columns present: {suspicious_cols}")
    if missing_policy_files:
        problems.append(f"Missing policy files: {len(missing_policy_files)}")
    if dict(family_counts) != EXPECTED_FAMILIES:
        problems.append(f"Family counts mismatch: {dict(family_counts)}")
    if dict(outcome_counts) != EXPECTED_OUTCOMES:
        problems.append(f"Outcome counts mismatch: {dict(outcome_counts)}")
    if dict(model_counts) != {"Nova Pro": 47, "Llama 3 8B": 37}:
        problems.append(f"Model counts mismatch: {dict(model_counts)}")
    if exact != 74:
        problems.append(f"Expected 74 exact, found {exact}")
    if corr != 76:
        problems.append(f"Expected 76 corroborated, found {corr}")
    if expected.get("total_candidates") != 84:
        problems.append("Expected JSON total_candidates mismatch")
    if expected.get("exact_confirmed") != 74:
        problems.append("Expected JSON exact_confirmed mismatch")
    if expected.get("provider_corroborated") != 76:
        problems.append("Expected JSON provider_corroborated mismatch")

    print("=== TARGET VERIFY SUMMARY ===")
    print("rows:", len(rows))
    print("columns:", len(fields))
    print("models:", dict(model_counts))
    print("families:", dict(family_counts))
    print("final_outcomes:", dict(outcome_counts))
    print("check_status:", dict(check_status_counts))
    print("expected exact:", exact)
    print("expected provider-corroborated:", corr)
    print("missing policy files:", len(missing_policy_files))
    print("missing required columns:", missing_cols)
    print("suspicious columns:", suspicious_cols)

    print()
    print("=== BUILD SCRIPT COMPILE CHECK ===")
    import py_compile
    py_compile.compile(str(TARGET_SCRIPT), doraise=True)
    print("build script compiles:", TARGET_SCRIPT)

    if problems:
        print()
        print("FAILURES:")
        for p in problems:
            print("-", p)
        raise SystemExit(1)

    print()
    print("PASS: original authority regression target is clean and usable")


if __name__ == "__main__":
    main()
