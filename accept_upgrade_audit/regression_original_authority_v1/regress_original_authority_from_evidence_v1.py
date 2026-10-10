#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import hashlib
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path.cwd()

TARGET = ROOT / "accept_upgrade_audit/regression_original_authority_v1/original_authority_regression_target_v1.csv"
EXPECTED = ROOT / "accept_upgrade_audit/regression_original_authority_v1/original_authority_regression_expected_v1.json"

OUT_LEDGER = ROOT / "accept_upgrade_audit/regression_original_authority_v1/original_authority_evidence_regression_ledger_v1.csv"
OUT_SUMMARY = ROOT / "accept_upgrade_audit/regression_original_authority_v1/original_authority_evidence_regression_summary_v1.md"
OUT_HASH = ROOT / "accept_upgrade_audit/regression_original_authority_v1/original_authority_evidence_regression_v1_sha256.txt"


EXACT_BOOL_COLUMNS = [
    "exact_delta_validated",
    "provider_native_delta_validated",
    "exact_claim_delta_validated",
    "exact_sourcearn_delta_validated",
]

UNRESOLVED_OUTCOME = "access_analyzer_corroborated_simulatecustompolicy_unresolved"


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def boolish(value) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "validated"}


def rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_evidence_tables(target_rows: list[dict]) -> dict[str, list[dict]]:
    tables = {}

    for r in target_rows:
        ev = r.get("evidence", "").strip()
        if not ev:
            continue

        p = Path(ev)
        if not p.is_absolute():
            p = ROOT / p

        if not p.exists():
            raise FileNotFoundError(f"Missing evidence table: {ev}")

        key = p.as_posix()
        if key not in tables:
            tables[key] = read_csv(p)

    return tables


def row_matches(evidence_row: dict, target_row: dict) -> bool:
    if evidence_row.get("case_id", "") != target_row.get("case_id", ""):
        return False

    # Prefer model_label because some tables use model slugs inconsistently.
    if evidence_row.get("model_label", "") and target_row.get("model_label", ""):
        return evidence_row.get("model_label", "") == target_row.get("model_label", "")

    if evidence_row.get("model", "") and target_row.get("model", ""):
        return evidence_row.get("model", "") == target_row.get("model", "")

    return False


def find_evidence_row(evidence_rows: list[dict], target_row: dict) -> dict:
    matches = [r for r in evidence_rows if row_matches(r, target_row)]

    if len(matches) != 1:
        raise RuntimeError(
            "Expected exactly one evidence row for "
            f"{target_row.get('model_label')}/{target_row.get('case_id')} "
            f"in {target_row.get('evidence')}; found {len(matches)}"
        )

    return matches[0]


def exact_from_evidence(evidence_row: dict, target_row: dict) -> bool:
    final_outcome = target_row.get("final_outcome", "")

    if final_outcome == UNRESOLVED_OUTCOME:
        return False

    for col in EXACT_BOOL_COLUMNS:
        if col in evidence_row and str(evidence_row.get(col, "")).strip() != "":
            return boolish(evidence_row[col])

    status = evidence_row.get("status", "")
    if status:
        return status == "validated"

    raise RuntimeError(
        "Could not infer exact result from evidence row for "
        f"{target_row.get('model_label')}/{target_row.get('case_id')} "
        f"columns={list(evidence_row.keys())}"
    )


def provider_corroborated_from_evidence(evidence_row: dict, target_row: dict, actual_exact: bool) -> bool:
    final_outcome = target_row.get("final_outcome", "")

    if actual_exact:
        return True

    if final_outcome == UNRESOLVED_OUTCOME:
        return True

    return False


def main() -> None:
    target_rows = read_csv(TARGET)

    with EXPECTED.open(encoding="utf-8") as f:
        expected = json.load(f)

    if len(target_rows) != expected["total_candidates"]:
        raise RuntimeError(
            f"Target row count mismatch: {len(target_rows)} vs {expected['total_candidates']}"
        )

    evidence_tables = load_evidence_tables(target_rows)

    ledger = []
    problems = []

    for r in target_rows:
        ev_path = Path(r["evidence"])
        if not ev_path.is_absolute():
            ev_path = ROOT / ev_path

        evidence_row = find_evidence_row(evidence_tables[ev_path.as_posix()], r)

        expected_exact = boolish(r["expected_exact_confirmed"])
        expected_provider = boolish(r["expected_provider_corroborated"])

        actual_exact = exact_from_evidence(evidence_row, r)
        actual_provider = provider_corroborated_from_evidence(evidence_row, r, actual_exact)

        exact_match = actual_exact == expected_exact
        provider_match = actual_provider == expected_provider

        if not exact_match or not provider_match:
            problems.append({
                "model": r["model_label"],
                "case_id": r["case_id"],
                "validation_family": r["validation_family"],
                "expected_exact": expected_exact,
                "actual_exact": actual_exact,
                "expected_provider": expected_provider,
                "actual_provider": actual_provider,
                "final_outcome": r["final_outcome"],
                "evidence": r["evidence"],
            })

        ledger.append({
            "model": r["model_label"],
            "model_slug": r["model"],
            "case_id": r["case_id"],
            "validation_family": r["validation_family"],
            "semantic_failure": r["semantic_failure"],
            "final_outcome": r["final_outcome"],
            "expected_exact": str(expected_exact),
            "actual_exact_from_evidence": str(actual_exact),
            "exact_match": str(exact_match),
            "expected_provider_corroborated": str(expected_provider),
            "actual_provider_corroborated_from_evidence": str(actual_provider),
            "provider_match": str(provider_match),
            "evidence": r["evidence"],
            "evidence_status": evidence_row.get("status", ""),
            "evidence_columns_used": "|".join(
                c for c in EXACT_BOOL_COLUMNS if c in evidence_row
            ),
        })

    fields = [
        "model",
        "model_slug",
        "case_id",
        "validation_family",
        "semantic_failure",
        "final_outcome",
        "expected_exact",
        "actual_exact_from_evidence",
        "exact_match",
        "expected_provider_corroborated",
        "actual_provider_corroborated_from_evidence",
        "provider_match",
        "evidence",
        "evidence_status",
        "evidence_columns_used",
    ]

    write_csv(OUT_LEDGER, ledger, fields)

    exact = sum(boolish(r["actual_exact_from_evidence"]) for r in ledger)
    provider = sum(boolish(r["actual_provider_corroborated_from_evidence"]) for r in ledger)

    by_family = Counter(r["validation_family"] for r in ledger)
    exact_by_family = Counter(
        r["validation_family"]
        for r in ledger
        if boolish(r["actual_exact_from_evidence"])
    )
    by_outcome = Counter(r["final_outcome"] for r in ledger)
    by_model = Counter(r["model"] for r in ledger)
    exact_by_model = Counter(
        r["model"]
        for r in ledger
        if boolish(r["actual_exact_from_evidence"])
    )

    md = []
    md.append("# Original authority evidence regression v1")
    md.append("")
    md.append("This regression reconstructs the corrected original two-model authority-spoofing")
    md.append("accounting from the exact-witness evidence tables referenced by the final")
    md.append("candidate ledger.")
    md.append("")
    md.append("## Result")
    md.append("")
    md.append(f"- Candidates checked: **{len(ledger)}**")
    md.append(f"- Exact-confirmed from evidence: **{exact}**")
    md.append(f"- Provider-corroborated from evidence: **{provider}**")
    md.append(f"- Exact expected: **{expected['exact_confirmed']}**")
    md.append(f"- Provider-corroborated expected: **{expected['provider_corroborated']}**")
    md.append(f"- Mismatching rows: **{len(problems)}**")
    md.append("")
    md.append("## By model")
    md.append("")
    md.append("| Model | Candidates | Exact from evidence |")
    md.append("|---|---:|---:|")
    for model in sorted(by_model):
        md.append(f"| {model} | {by_model[model]} | {exact_by_model[model]} |")
    md.append("")
    md.append("## By family")
    md.append("")
    md.append("| Family | Candidates | Exact from evidence |")
    md.append("|---|---:|---:|")
    for fam in sorted(by_family):
        md.append(f"| {fam} | {by_family[fam]} | {exact_by_family[fam]} |")
    md.append("")
    md.append("## Final outcome counts")
    md.append("")
    for outcome, count in sorted(by_outcome.items()):
        md.append(f"- `{outcome}`: **{count}**")
    md.append("")
    md.append(f"Ledger: `{rel(OUT_LEDGER)}`")

    OUT_SUMMARY.write_text("\n".join(md) + "\n", encoding="utf-8")

    hash_inputs = [
        TARGET,
        EXPECTED,
        OUT_LEDGER,
        OUT_SUMMARY,
    ]

    with OUT_HASH.open("w", encoding="utf-8") as f:
        for path in hash_inputs:
            f.write(f"{sha256_file(path)}  {rel(path)}\n")

    print("\n".join(md))
    print()
    print("WROTE", rel(OUT_LEDGER))
    print("WROTE", rel(OUT_SUMMARY))
    print("WROTE", rel(OUT_HASH))

    if exact != expected["exact_confirmed"]:
        raise RuntimeError(f"Exact count mismatch: {exact} vs {expected['exact_confirmed']}")

    if provider != expected["provider_corroborated"]:
        raise RuntimeError(
            f"Provider-corroborated mismatch: {provider} vs {expected['provider_corroborated']}"
        )

    if problems:
        print()
        print("MISMATCHING ROWS:")
        for p in problems:
            print(p)
        raise RuntimeError(f"Evidence regression has {len(problems)} mismatching rows")

    print()
    print("PASS: original authority evidence regression reproduces 74 exact and 76 provider-corroborated cases")


if __name__ == "__main__":
    main()
