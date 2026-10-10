#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path.cwd()

ORDINARY_JSONL = ROOT / "data/confirm24_v1/rag_pairs_confirm24_v1_ordinary_run_eval.jsonl"
AUTHORITY_JSONL = ROOT / "data/confirm24_v1/rag_pairs_confirm24_v1_authority_run_eval.jsonl"
HASH_FILE = ROOT / "tables/confirm24_v1_prompt_pre_run_sha256.txt"

CONFIGS = sorted(ROOT.glob("configs/confirm24_v1_*.yaml"))

EXPECTED_CONFIGS = {
    f"configs/confirm24_v1_{regime}_{model}.yaml"
    for regime in ["ordinary", "authority"]
    for model in ["claude", "mistral_small", "nova_lite", "nova_pro", "llama3_8b"]
}


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def assert_no_oracle_leak(prompt: str, pair_id: str) -> None:
    forbidden_fragments = [
        "Required authorization obligation",
        "Forbidden expansion",
        "required_obligation",
        "forbidden_expansion",
        "source_url",
    ]

    for fragment in forbidden_fragments:
        if fragment in prompt:
            raise AssertionError(f"{pair_id}: prompt leaks oracle/source field: {fragment}")


def validate_pairs(path: Path, regime: str) -> list[dict]:
    rows = read_jsonl(path)

    if len(rows) != 24:
        raise AssertionError(f"{path}: expected 24 rows, found {len(rows)}")

    ids = [r["pair_id"] for r in rows]
    if len(set(ids)) != 24:
        raise AssertionError(f"{path}: duplicate pair_id")

    families = Counter(r["family"] for r in rows)
    if len(families) != 8 or any(v != 3 for v in families.values()):
        raise AssertionError(f"{path}: expected 8 families x 3, got {dict(families)}")

    for r in rows:
        if r["confirm24_regime"] != regime:
            raise AssertionError((r["pair_id"], r["confirm24_regime"], regime))

        for field in ["ctrl_prompt", "poi_prompt"]:
            prompt = r[field]
            if "Trusted policy-generation task:" not in prompt:
                raise AssertionError(f"{r['pair_id']}: missing trusted task in {field}")
            if "Required IAM policy type:" not in prompt:
                raise AssertionError(f"{r['pair_id']}: missing policy type in {field}")
            if "Retrieved context:" not in prompt:
                raise AssertionError(f"{r['pair_id']}: missing retrieved context in {field}")
            if "Return exactly one valid AWS IAM policy JSON object" not in prompt:
                raise AssertionError(f"{r['pair_id']}: missing JSON-only instruction in {field}")
            assert_no_oracle_leak(prompt, r["pair_id"])

        if "operational_template" not in r["poi_prompt"] and regime == "ordinary":
            raise AssertionError(f"{r['pair_id']}: ordinary poison marker missing")
        if "security_exception" not in r["poi_prompt"] and regime == "authority":
            raise AssertionError(f"{r['pair_id']}: authority poison marker missing")

    return rows


def main() -> None:
    ordinary = validate_pairs(ORDINARY_JSONL, "ordinary")
    authority = validate_pairs(AUTHORITY_JSONL, "authority")

    config_names = {p.relative_to(ROOT).as_posix() for p in CONFIGS}
    if config_names != EXPECTED_CONFIGS:
        missing = EXPECTED_CONFIGS - config_names
        extra = config_names - EXPECTED_CONFIGS
        raise AssertionError(f"config mismatch; missing={missing}; extra={extra}")

    for cfg in CONFIGS:
        text = cfg.read_text(encoding="utf-8")
        if "sample_size_pairs: 24" not in text:
            raise AssertionError(f"{cfg}: missing sample_size_pairs 24")
        if "temperature: 0.0" not in text:
            raise AssertionError(f"{cfg}: missing temperature 0.0")
        if "ctrl_key: ctrl_prompt" not in text or "poi_key: poi_prompt" not in text:
            raise AssertionError(f"{cfg}: missing prompt keys")
        if cfg.name.startswith("confirm24_v1_ordinary") and ORDINARY_JSONL.relative_to(ROOT).as_posix() not in text:
            raise AssertionError(f"{cfg}: wrong ordinary dataset")
        if cfg.name.startswith("confirm24_v1_authority") and AUTHORITY_JSONL.relative_to(ROOT).as_posix() not in text:
            raise AssertionError(f"{cfg}: wrong authority dataset")

    if not HASH_FILE.exists():
        raise AssertionError("missing prompt hash file")

    print("PASS: Confirm-24 v1 prompt/config freeze is internally consistent")
    print("ordinary pairs:", len(ordinary))
    print("authority pairs:", len(authority))
    print("configs:", len(CONFIGS))
    print("families:", dict(sorted(Counter(r["family"] for r in ordinary).items())))


if __name__ == "__main__":
    main()
