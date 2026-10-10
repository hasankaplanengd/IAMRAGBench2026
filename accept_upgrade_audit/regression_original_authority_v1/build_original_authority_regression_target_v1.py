#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path.cwd()

IN = ROOT / "tables/table_adaptive_compliance_exception_v6_final_candidate_ledger_v2.csv"
OUT = ROOT / "accept_upgrade_audit/regression_original_authority_v1/original_authority_regression_target_v1.csv"
SUMMARY = ROOT / "accept_upgrade_audit/regression_original_authority_v1/original_authority_regression_expected_v1.json"
MD = ROOT / "accept_upgrade_audit/regression_original_authority_v1/original_authority_regression_expected_v1.md"


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def boolish(v: str) -> bool:
    return str(v).strip().lower() in {"true", "1", "yes"}


def main() -> None:
    rows = read_csv(IN)

    if len(rows) != 84:
        raise RuntimeError(f"Expected 84 original authority candidates, found {len(rows)}")

    missing = []
    out_rows = []

    for r in rows:
        ctrl = ROOT / r["control_policy_file"]
        poi = ROOT / r["poison_policy_file"]

        if not ctrl.exists():
            missing.append(r["control_policy_file"])
        if not poi.exists():
            missing.append(r["poison_policy_file"])

        rr = dict(r)

        # Columns used by the adapted exact-witness runners.
        rr["expected_exact_confirmed"] = str(boolish(r["exact_confirmed"]))
        rr["expected_provider_corroborated"] = str(boolish(r["provider_corroborated"]))
        rr["api_error"] = ""
        rr["check_status"] = r.get("check_no_new_access", "")
        rr["validation_family_original_input"] = r["validation_family"]
        rr["family_mapping_source"] = "original_authority_final_ledger_v2"

        out_rows.append(rr)

    if missing:
        raise RuntimeError("Missing policy files:\n" + "\n".join(missing[:20]))

    fields = []
    for r in out_rows:
        for k in r:
            if k not in fields:
                fields.append(k)

    write_csv(OUT, out_rows, fields)

    final_outcome = Counter(r["final_outcome"] for r in rows)
    family = Counter(r["validation_family"] for r in rows)
    model = Counter(r["model_label"] for r in rows)
    exact = sum(boolish(r["exact_confirmed"]) for r in rows)
    corr = sum(boolish(r["provider_corroborated"]) for r in rows)

    expected = {
        "input": IN.as_posix(),
        "regression_target": OUT.as_posix(),
        "total_candidates": len(rows),
        "exact_confirmed": exact,
        "not_exact_confirmed": len(rows) - exact,
        "provider_corroborated": corr,
        "not_provider_corroborated": len(rows) - corr,
        "model_counts": dict(model),
        "validation_family_counts": dict(family),
        "final_outcome_counts": dict(final_outcome),
        "policy_files_missing": 0,
        "required_pass_condition": {
            "total_candidates": 84,
            "exact_confirmed": 74,
            "provider_corroborated": 76,
            "access_analyzer_corroborated_simulatecustompolicy_unresolved": 2,
        },
    }

    SUMMARY.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    md = []
    md.append("# Original authority regression expected target v1")
    md.append("")
    md.append("This target is built from the corrected original two-model authority-spoofing final candidate ledger.")
    md.append("")
    md.append(f"- Total candidates: **{len(rows)}**")
    md.append(f"- Exact-confirmed: **{exact}**")
    md.append(f"- Provider-corroborated: **{corr}**")
    md.append(f"- Non-exact: **{len(rows) - exact}**")
    md.append("")
    md.append("## Model counts")
    md.append("")
    for k, v in sorted(model.items()):
        md.append(f"- {k}: {v}")
    md.append("")
    md.append("## Family counts")
    md.append("")
    for k, v in sorted(family.items()):
        md.append(f"- {k}: {v}")
    md.append("")
    md.append("## Final outcome counts")
    md.append("")
    for k, v in sorted(final_outcome.items()):
        md.append(f"- {k}: {v}")
    md.append("")
    md.append("## Required pass condition")
    md.append("")
    md.append("The adapted exact-witness regression must reproduce 74 exact-confirmed attacks,")
    md.append("76 provider-corroborated cases, and the two KMS provider-corroborated")
    md.append("exact-witness-unresolved cases from the original authority stress test.")
    md.append("")
    md.append(f"CSV target: `{OUT}`")
    md.append(f"JSON expected counts: `{SUMMARY}`")

    MD.write_text("\n".join(md) + "\n", encoding="utf-8")

    print("WROTE", OUT)
    print("WROTE", SUMMARY)
    print("WROTE", MD)
    print()
    print("=== EXPECTED COUNTS ===")
    print(json.dumps(expected, indent=2, sort_keys=True))
    print()
    print("PASS: original authority regression target prepared")


if __name__ == "__main__":
    main()
