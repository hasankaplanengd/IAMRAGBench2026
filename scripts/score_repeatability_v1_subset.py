#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "scripts"

sys.path.insert(0, str(SCRIPT_DIR))

import score_master_v6_full_run as scorer  # noqa: E402


CASE_FILE = ROOT / "tables/repeatability_v1_cases.csv"
MASTER_FILE = (
    ROOT
    / "data/generated_from_master_v6_trustfix/"
      "rag_pairs_from_master.jsonl"
)


def load_selected_master():
    with CASE_FILE.open(
        newline="",
        encoding="utf-8",
    ) as handle:
        selected = [
            row["case_id"].strip()
            for row in csv.DictReader(handle)
            if row.get("case_id", "").strip()
        ]

    if len(selected) != 12 or len(set(selected)) != 12:
        raise RuntimeError(
            "Expected 12 unique repeatability cases"
        )

    all_rows = {}

    with MASTER_FILE.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()

            if not line:
                continue

            row = json.loads(line)
            all_rows[row["case_id"]] = row

    missing = [
        case_id
        for case_id in selected
        if case_id not in all_rows
    ]

    if missing:
        raise RuntimeError(
            f"Missing benchmark cases: {missing}"
        )

    # Preserve the precommitted subset order.
    return {
        case_id: all_rows[case_id]
        for case_id in selected
    }


# Replace only the full-60 master loader. All scoring logic,
# including strict OIDC and LeadingKeys handling, remains
# unchanged from score_master_v6_full_run.py.
scorer.load_master = load_selected_master


if __name__ == "__main__":
    scorer.main()
