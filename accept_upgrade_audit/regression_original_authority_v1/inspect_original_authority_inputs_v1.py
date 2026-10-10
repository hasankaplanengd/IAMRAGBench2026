#!/usr/bin/env python3
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

ROOT = Path.cwd()

FILES = [
    ROOT / "tables/table_adaptive_compliance_exception_v6_final_candidate_ledger_v2.csv",
    ROOT / "tables/table_adaptive_compliance_exception_v6_survivor_families.csv",
    ROOT / "tables/table_adaptive_compliance_exception_v6_final_results_v2.csv",
    ROOT / "summaries/adaptive_compliance_exception_v6_final_results_v2.md",
]

OUT = ROOT / "accept_upgrade_audit/regression_original_authority_v1/original_authority_input_inspection_v1.txt"


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def boolish(value: str) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def summarize_csv(path: Path, lines: list[str]) -> None:
    lines.append("=" * 100)
    lines.append(str(path))
    lines.append("=" * 100)

    if not path.exists():
        lines.append("MISSING")
        lines.append("")
        return

    rows = read_csv(path)
    lines.append(f"rows: {len(rows)}")

    if not rows:
        lines.append("")
        return

    fields = list(rows[0].keys())
    lines.append("fields:")
    for f in fields:
        lines.append(f"  - {f}")

    for col in [
        "model",
        "model_label",
        "case_id",
        "validation_family",
        "semantic_failure",
        "check_status",
        "check_result",
        "final_outcome",
        "terminal_outcome",
        "exact_confirmed",
        "provider_corroborated",
        "counted_in_exact_asr",
        "counted_in_candidate",
        "provider_status",
    ]:
        if col in fields:
            c = Counter(str(r.get(col, "")).strip() for r in rows)
            lines.append("")
            lines.append(f"{col}:")
            for k, v in c.most_common():
                lines.append(f"  {k}: {v}")

    # If final ledger has exact/provider fields, compute headline.
    if "exact_confirmed" in fields:
        exact = sum(boolish(r.get("exact_confirmed", "")) for r in rows)
        lines.append("")
        lines.append(f"exact_confirmed_TRUE: {exact}")

    if "provider_corroborated" in fields:
        corr = sum(boolish(r.get("provider_corroborated", "")) for r in rows)
        lines.append(f"provider_corroborated_TRUE: {corr}")

    # File existence checks for policy paths.
    for key in ["control_policy_file", "poison_policy_file", "treatment_policy_file"]:
        if key in fields:
            missing = []
            for r in rows:
                value = r.get(key, "")
                if not value:
                    continue
                p = Path(value)
                if not p.is_absolute():
                    p = ROOT / p
                if not p.exists():
                    missing.append(value)
            lines.append("")
            lines.append(f"{key}_missing_count: {len(missing)}")
            for item in missing[:20]:
                lines.append(f"  MISSING {item}")

    lines.append("")
    lines.append("first 8 rows:")
    for r in rows[:8]:
        small_keys = [
            k for k in [
                "model",
                "model_label",
                "case_id",
                "validation_family",
                "semantic_failure",
                "check_status",
                "final_outcome",
                "exact_confirmed",
                "provider_corroborated",
                "control_policy_file",
                "poison_policy_file",
            ]
            if k in fields
        ]
        lines.append(str({k: r.get(k, "") for k in small_keys}))

    lines.append("")


def main() -> None:
    lines: list[str] = []

    lines.append("=== GIT STATE ===")
    lines.append("branch/status are printed by shell command below")
    lines.append("")

    for path in FILES:
        if path.suffix == ".csv":
            summarize_csv(path, lines)
        else:
            lines.append("=" * 100)
            lines.append(str(path))
            lines.append("=" * 100)
            if path.exists():
                text = path.read_text(encoding="utf-8")
                lines.extend(text.splitlines()[:80])
            else:
                lines.append("MISSING")
            lines.append("")

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"WROTE {OUT}")
    print()
    print("\n".join(lines[:260]))


if __name__ == "__main__":
    main()
