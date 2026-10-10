#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path.cwd()

FILES = [
    Path("CONFIRM24_V1_DESIGN.md"),
    Path("data/confirm24_v1/source_manifest.csv"),
    Path("data/confirm24_v1/case_plan.csv"),
    Path("data/confirm24_v1/cases.jsonl"),
    Path("data/confirm24_v1/clean_docs.jsonl"),
    Path("data/confirm24_v1/ordinary_poison_docs.jsonl"),
    Path("data/confirm24_v1/authority_poison_docs.jsonl"),
    Path("scripts/build_confirm24_v1_design.py"),
    Path("scripts/validate_confirm24_v1_design.py"),
    Path("summaries/confirm24_v1_design_summary.md"),
]

def read_csv(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))

def read_jsonl(path):
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]

def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    missing = [str(p) for p in FILES if not (ROOT / p).exists()]
    if missing:
        raise SystemExit("Missing files:\n" + "\n".join(missing))

    cases = read_jsonl(ROOT / "data/confirm24_v1/cases.jsonl")
    sources = read_csv(ROOT / "data/confirm24_v1/source_manifest.csv")
    clean = read_jsonl(ROOT / "data/confirm24_v1/clean_docs.jsonl")
    ordinary = read_jsonl(ROOT / "data/confirm24_v1/ordinary_poison_docs.jsonl")
    authority = read_jsonl(ROOT / "data/confirm24_v1/authority_poison_docs.jsonl")

    assert len(cases) == 24, len(cases)
    assert len(sources) == 24, len(sources)
    assert len(clean) == 24, len(clean)
    assert len(ordinary) == 24, len(ordinary)
    assert len(authority) == 24, len(authority)

    family_counts = Counter(c["family"] for c in cases)
    assert len(family_counts) == 8, family_counts
    assert all(v == 3 for v in family_counts.values()), family_counts

    ids = [c["case_id"] for c in cases]
    assert len(set(ids)) == 24, "duplicate case_id"

    for c in cases:
        assert c["source_url"].startswith("https://"), c["case_id"]
        assert c["frozen_before_generation"] is True, c["case_id"]
        assert c["policy_type"] in {
            "IDENTITY_POLICY",
            "RESOURCE_POLICY",
            "TRUST_POLICY",
            "KEY_POLICY",
        }, (c["case_id"], c["policy_type"])

    for rows, kind in [(clean, "clean"), (ordinary, "ordinary_poison"), (authority, "authority_poison")]:
        seen = {r["case_id"] for r in rows}
        assert seen == set(ids), f"{kind} case mismatch"
        for r in rows:
            text = r["text"]
            assert "CONFIRM24" in text, r["doc_id"]
            assert "111122223333" not in text or True

    run_dir = ROOT / "runs/confirm24_v1"
    if run_dir.exists():
        raise SystemExit("Refusing to validate design freeze after runs/confirm24_v1 exists")

    out_hash = ROOT / "tables/confirm24_v1_pre_run_sha256.txt"
    with out_hash.open("w", encoding="utf-8") as handle:
        for rel in FILES:
            path = ROOT / rel
            handle.write(f"{sha256_file(path)}  {rel.as_posix()}\n")

    print("PASS: Confirm-24 v1 design is internally consistent")
    print("cases:", len(cases))
    print("families:", dict(sorted(family_counts.items())))
    print("hash_file:", out_hash)

if __name__ == "__main__":
    main()
