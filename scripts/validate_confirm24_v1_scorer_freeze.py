#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path.cwd()

SCORER = ROOT / "scripts/score_confirm24_v1_run.py"
CASES = ROOT / "data/confirm24_v1/cases.jsonl"
PROMPT_HASH = ROOT / "tables/confirm24_v1_prompt_pre_run_sha256.txt"
MANIFEST = ROOT / "CONFIRM24_V1_SCORER_FREEZE.md"
HASH_FILE = ROOT / "tables/confirm24_v1_scorer_pre_run_sha256.txt"


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_specs_from_scorer() -> dict:
    tree = ast.parse(SCORER.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "SPECS":
                    return ast.literal_eval(node.value)
    raise AssertionError("Could not find SPECS in scorer")


def main() -> None:
    required = [
        SCORER,
        CASES,
        PROMPT_HASH,
        MANIFEST,
        ROOT / "scripts/validate_confirm24_v1_scorer_freeze.py",
    ]

    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise SystemExit("Missing files:\n" + "\n".join(missing))

    cases = read_jsonl(CASES)
    specs = load_specs_from_scorer()

    case_ids = {c["case_id"] for c in cases}
    spec_ids = set(specs)

    assert len(cases) == 24, len(cases)
    assert case_ids == spec_ids, f"case/spec mismatch: missing={case_ids-spec_ids}, extra={spec_ids-case_ids}"

    families = Counter(c["family"] for c in cases)
    assert len(families) == 8, families
    assert all(v == 3 for v in families.values()), families

    for cid, spec in specs.items():
        assert spec.get("functional_actions"), cid
        assert spec.get("goal_codes"), cid

    run_glob = list((ROOT / "runs").glob("confirm24_v1*"))
    if run_glob:
        raise SystemExit("Refusing scorer freeze because Confirm-24 run directory already exists")

    with HASH_FILE.open("w", encoding="utf-8") as handle:
        for p in required:
            handle.write(f"{sha256_file(p)}  {p.relative_to(ROOT).as_posix()}\n")

    print("PASS: Confirm-24 v1 scorer freeze is internally consistent")
    print("cases:", len(cases))
    print("families:", dict(sorted(families.items())))
    print("hash_file:", HASH_FILE)


if __name__ == "__main__":
    main()
