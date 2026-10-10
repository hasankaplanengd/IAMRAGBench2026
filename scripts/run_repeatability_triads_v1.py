#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import run_eval as base  # noqa: E402


VERSION = "repeatability.v1"
VARIANTS = (
    ("control", "ctrl_prompt"),
    ("ordinary", "ordinary_poi_prompt"),
    ("authority", "adaptive_poi_prompt"),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()

            if not line:
                continue

            row = json.loads(line)

            if not isinstance(row, dict):
                raise RuntimeError(
                    f"{path}:{line_number}: expected object"
                )

            rows.append(row)

    return rows


def status_of(raw: str, repaired: Any) -> str:
    if raw.startswith("[ERROR]") or bool(
        base.safe_json_get(
            repaired,
            "error_stub",
            False,
        )
    ):
        return "error_stub"

    if base.safe_json_get(
        repaired,
        "repair",
        None,
    ) == "wrapped_plain":
        return "wrapped_plain"

    return "ok_json"


def load_or_call(
    *,
    raw_path: Path,
    repaired_path: Path,
    prompt: str,
    model_cfg: dict[str, Any],
) -> tuple[str, Any, str, bool]:
    raw_exists = raw_path.exists()
    repaired_exists = repaired_path.exists()

    if raw_exists != repaired_exists:
        raise RuntimeError(
            "Partial output exists; refusing ambiguous resume: "
            f"{raw_path} / {repaired_path}"
        )

    if raw_exists and repaired_exists:
        raw = raw_path.read_text(encoding="utf-8")
        repaired = json.loads(
            repaired_path.read_text(encoding="utf-8")
        )

        return (
            raw,
            repaired,
            status_of(raw, repaired),
            False,
        )

    result = base.call_bedrock(
        model_id=model_cfg["model_id"],
        region=model_cfg.get("region", "us-east-1"),
        user_text=prompt,
        provider_hint=model_cfg.get(
            "provider",
            "bedrock",
        ),
        system_text=model_cfg.get("system_text"),
        max_tokens=model_cfg.get("max_tokens", 1200),
        temperature=model_cfg.get(
            "temperature",
            0.0,
        ),
        top_p=model_cfg.get("top_p"),
        use_converse=bool(
            model_cfg.get("use_converse", True)
        ),
    )

    raw = (result.get("raw_text") or "").strip()
    base.write_text(str(raw_path), raw)

    if raw.startswith("[ERROR]"):
        repaired = {
            "ok": False,
            "error_stub": True,
            "text": raw,
        }
    else:
        repaired, _ = base.try_parse_json(raw)

    base.write_json(
        str(repaired_path),
        repaired,
    )

    return (
        raw,
        repaired,
        status_of(raw, repaired),
        True,
    )


def mirror_control(
    *,
    raw: str,
    repaired: Any,
    raw_path: Path,
    repaired_path: Path,
) -> None:
    if raw_path.exists():
        existing = raw_path.read_text(encoding="utf-8")

        if existing != raw:
            raise RuntimeError(
                f"Control raw-output mismatch: {raw_path}"
            )
    else:
        base.write_text(str(raw_path), raw)

    if repaired_path.exists():
        existing = json.loads(
            repaired_path.read_text(encoding="utf-8")
        )

        if existing != repaired:
            raise RuntimeError(
                "Control repaired-output mismatch: "
                f"{repaired_path}"
            )
    else:
        base.write_json(
            str(repaired_path),
            repaired,
        )


def sample_row(
    *,
    case_id: str,
    prompt_type: str,
    repaired: Any,
    model_cfg: dict[str, Any],
) -> dict[str, Any]:
    return {
        "pair_id": case_id,
        "prompt_type": prompt_type,
        "ok": bool(
            base.safe_json_get(
                repaired,
                "ok",
                False,
            )
        ),
        "repair": base.safe_json_get(
            repaired,
            "repair",
        ),
        "error_stub": bool(
            base.safe_json_get(
                repaired,
                "error_stub",
                False,
            )
        ),
        "model_id": model_cfg["model_id"],
        "provider": model_cfg.get(
            "provider",
            "bedrock",
        ),
    }


def write_per_sample(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:
    fields = [
        "pair_id",
        "prompt_type",
        "ok",
        "repair",
        "error_stub",
        "model_id",
        "provider",
    ]

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
        )
        writer.writeheader()
        writer.writerows(rows)


def write_summary(
    *,
    path: Path,
    model_cfg: dict[str, Any],
    rows: list[dict[str, Any]],
    counters: Counter,
    regime: str,
    repetition: int,
) -> None:
    base.write_json(
        str(path),
        {
            "version": VERSION,
            "regime": regime,
            "repetition": repetition,
            "model_id": model_cfg["model_id"],
            "provider": model_cfg.get(
                "provider",
                "bedrock",
            ),
            "pairs_total": len(rows) // 2,
            "pairs_evaluated": len(rows) // 2,
            "responses_total": len(rows),
            "counts": {
                "ok_json": counters.get(
                    "ok_json",
                    0,
                ),
                "wrapped_plain": counters.get(
                    "wrapped_plain",
                    0,
                ),
                "error_stub": counters.get(
                    "error_stub",
                    0,
                ),
            },
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--config",
        required=True,
    )
    parser.add_argument(
        "--dataset",
        required=True,
    )
    parser.add_argument(
        "--repetition",
        required=True,
        type=int,
        choices=(1, 2),
    )
    parser.add_argument(
        "--run-root",
        required=True,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
    )

    args = parser.parse_args()

    config_path = Path(args.config)
    dataset_path = Path(args.dataset)
    run_root = Path(args.run_root)

    cfg = yaml.safe_load(
        config_path.read_text(encoding="utf-8")
    )

    model_cfg = cfg.get("model", {})
    repeatability_cfg = cfg.get(
        "repeatability",
        {},
    )

    required_model_fields = (
        "provider",
        "model_id",
        "region",
    )

    for field in required_model_fields:
        if not model_cfg.get(field):
            raise RuntimeError(
                f"Missing model field: {field}"
            )

    rows = read_jsonl(dataset_path)

    expected_cases = int(
        repeatability_cfg.get(
            "expected_cases",
            12,
        )
    )

    if len(rows) != expected_cases:
        raise RuntimeError(
            f"Expected {expected_cases} cases, "
            f"found {len(rows)}"
        )

    case_ids: list[str] = []

    for row in rows:
        case_id = str(
            row.get("case_id", "")
        ).strip()

        if not case_id:
            raise RuntimeError(
                "Dataset row missing case_id"
            )

        case_ids.append(case_id)

        for _, field in VARIANTS:
            value = row.get(field)

            if not isinstance(value, str) or not value:
                raise RuntimeError(
                    f"{case_id}: missing {field}"
                )

    if len(set(case_ids)) != len(case_ids):
        raise RuntimeError(
            "Duplicate case identifiers"
        )

    expected_calls = len(rows) * 3

    print("=== REPEATABILITY V1 PLAN ===")
    print(
        "Model:",
        model_cfg["model_id"],
    )
    print(
        "Repetition:",
        args.repetition,
    )
    print(
        "Cases:",
        len(rows),
    )
    print(
        "Prompt variants:",
        "control, ordinary, authority",
    )
    print(
        "Expected model calls:",
        expected_calls,
    )
    print(
        "Run root:",
        run_root,
    )
    print(
        "Ordinary pair view:",
        run_root / "ordinary",
    )
    print(
        "Authority pair view:",
        run_root / "authority",
    )
    print(
        "First three cases:",
        case_ids[:3],
    )

    if args.dry_run:
        print(
            "DRY RUN PASS: no Bedrock calls made."
        )
        return

    ordinary_dir = run_root / "ordinary"
    authority_dir = run_root / "authority"

    ordinary_raw = ordinary_dir / "raw"
    authority_raw = authority_dir / "raw"

    ordinary_raw.mkdir(
        parents=True,
        exist_ok=True,
    )
    authority_raw.mkdir(
        parents=True,
        exist_ok=True,
    )

    binding = {
        "version": VERSION,
        "repetition": args.repetition,
        "model_id": model_cfg["model_id"],
        "provider": model_cfg.get(
            "provider",
            "bedrock",
        ),
        "dataset": str(dataset_path),
        "dataset_sha256": sha256_file(
            dataset_path
        ),
        "config": str(config_path),
        "config_sha256": sha256_file(
            config_path
        ),
        "run_eval_sha256": sha256_file(
            ROOT / "run_eval.py"
        ),
        "case_ids": case_ids,
        "expected_model_calls": expected_calls,
    }

    binding_path = run_root / "input_binding.json"

    if binding_path.exists():
        existing = json.loads(
            binding_path.read_text(
                encoding="utf-8"
            )
        )

        if existing != binding:
            raise RuntimeError(
                "Existing run-root binding does not "
                "match the requested execution"
            )
    else:
        base.write_json(
            str(binding_path),
            binding,
        )

    ordinary_rows: list[dict[str, Any]] = []
    authority_rows: list[dict[str, Any]] = []

    ordinary_counts: Counter = Counter()
    authority_counts: Counter = Counter()

    execution_rows: list[dict[str, Any]] = []
    new_calls = 0

    for index, row in enumerate(rows, start=1):
        case_id = row["case_id"]

        print(
            f"[{index:02d}/{len(rows)}] "
            f"{case_id}"
        )

        control_prompt = row["ctrl_prompt"]
        ordinary_prompt = row[
            "ordinary_poi_prompt"
        ]
        authority_prompt = row[
            "adaptive_poi_prompt"
        ]

        control_raw_path = (
            ordinary_raw
            / f"req_{case_id}_ctrl.txt"
        )
        control_repaired_path = (
            ordinary_raw
            / (
                f"req_{case_id}_ctrl"
                "__REPAIRED.json"
            )
        )

        (
            control_raw,
            control_repaired,
            control_status,
            control_called,
        ) = load_or_call(
            raw_path=control_raw_path,
            repaired_path=control_repaired_path,
            prompt=control_prompt,
            model_cfg=model_cfg,
        )

        new_calls += int(control_called)
        ordinary_counts[control_status] += 1
        authority_counts[control_status] += 1

        mirror_control(
            raw=control_raw,
            repaired=control_repaired,
            raw_path=(
                authority_raw
                / f"req_{case_id}_ctrl.txt"
            ),
            repaired_path=(
                authority_raw
                / (
                    f"req_{case_id}_ctrl"
                    "__REPAIRED.json"
                )
            ),
        )

        ordinary_rows.append(
            sample_row(
                case_id=case_id,
                prompt_type="ctrl",
                repaired=control_repaired,
                model_cfg=model_cfg,
            )
        )

        authority_rows.append(
            sample_row(
                case_id=case_id,
                prompt_type="ctrl",
                repaired=control_repaired,
                model_cfg=model_cfg,
            )
        )

        ordinary_raw_path = (
            ordinary_raw
            / f"req_{case_id}_poi.txt"
        )
        ordinary_repaired_path = (
            ordinary_raw
            / (
                f"req_{case_id}_poi"
                "__REPAIRED.json"
            )
        )

        (
            ordinary_output,
            ordinary_repaired,
            ordinary_status,
            ordinary_called,
        ) = load_or_call(
            raw_path=ordinary_raw_path,
            repaired_path=ordinary_repaired_path,
            prompt=ordinary_prompt,
            model_cfg=model_cfg,
        )

        new_calls += int(ordinary_called)
        ordinary_counts[ordinary_status] += 1

        ordinary_rows.append(
            sample_row(
                case_id=case_id,
                prompt_type="poi",
                repaired=ordinary_repaired,
                model_cfg=model_cfg,
            )
        )

        authority_raw_path = (
            authority_raw
            / f"req_{case_id}_poi.txt"
        )
        authority_repaired_path = (
            authority_raw
            / (
                f"req_{case_id}_poi"
                "__REPAIRED.json"
            )
        )

        (
            authority_output,
            authority_repaired,
            authority_status,
            authority_called,
        ) = load_or_call(
            raw_path=authority_raw_path,
            repaired_path=authority_repaired_path,
            prompt=authority_prompt,
            model_cfg=model_cfg,
        )

        new_calls += int(authority_called)
        authority_counts[authority_status] += 1

        authority_rows.append(
            sample_row(
                case_id=case_id,
                prompt_type="poi",
                repaired=authority_repaired,
                model_cfg=model_cfg,
            )
        )

        execution_rows.append({
            "order": index,
            "case_id": case_id,
            "repetition": args.repetition,
            "model_id": model_cfg["model_id"],
            "control_prompt_sha256":
                sha256_text(control_prompt),
            "ordinary_prompt_sha256":
                sha256_text(ordinary_prompt),
            "authority_prompt_sha256":
                sha256_text(authority_prompt),
            "control_called": control_called,
            "ordinary_called": ordinary_called,
            "authority_called": authority_called,
            "control_status": control_status,
            "ordinary_status": ordinary_status,
            "authority_status": authority_status,
            "control_output_sha256":
                sha256_text(control_raw),
            "ordinary_output_sha256":
                sha256_text(ordinary_output),
            "authority_output_sha256":
                sha256_text(authority_output),
        })

    if len(ordinary_rows) != len(rows) * 2:
        raise RuntimeError(
            "Unexpected ordinary row count"
        )

    if len(authority_rows) != len(rows) * 2:
        raise RuntimeError(
            "Unexpected authority row count"
        )

    write_per_sample(
        ordinary_dir / "per_sample.csv",
        ordinary_rows,
    )
    write_per_sample(
        authority_dir / "per_sample.csv",
        authority_rows,
    )

    write_summary(
        path=ordinary_dir / "summary_overall.json",
        model_cfg=model_cfg,
        rows=ordinary_rows,
        counters=ordinary_counts,
        regime="ordinary",
        repetition=args.repetition,
    )

    write_summary(
        path=authority_dir / "summary_overall.json",
        model_cfg=model_cfg,
        rows=authority_rows,
        counters=authority_counts,
        regime="authority_spoofing",
        repetition=args.repetition,
    )

    execution_path = (
        run_root / "triad_execution.csv"
    )

    with execution_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(
                execution_rows[0].keys()
            ),
        )
        writer.writeheader()
        writer.writerows(execution_rows)

    total_status = Counter()

    for row in execution_rows:
        total_status[row["control_status"]] += 1
        total_status[row["ordinary_status"]] += 1
        total_status[row["authority_status"]] += 1

    base.write_json(
        str(run_root / "triad_summary.json"),
        {
            "version": VERSION,
            "model_id": model_cfg["model_id"],
            "repetition": args.repetition,
            "cases": len(rows),
            "expected_model_calls": expected_calls,
            "new_model_calls_this_execution":
                new_calls,
            "responses_total": len(rows) * 3,
            "counts": dict(total_status),
            "ordinary_run_dir":
                str(ordinary_dir),
            "authority_run_dir":
                str(authority_dir),
        },
    )

    print()
    print("=== EXECUTION COMPLETE ===")
    print(
        "Model:",
        model_cfg["model_id"],
    )
    print(
        "Repetition:",
        args.repetition,
    )
    print(
        "New model calls:",
        new_calls,
    )
    print(
        "Expected fresh-run calls:",
        expected_calls,
    )
    print(
        "Response status:",
        dict(total_status),
    )
    print(
        "Ordinary view:",
        ordinary_dir,
    )
    print(
        "Authority view:",
        authority_dir,
    )
    print(
        "Execution ledger:",
        execution_path,
    )


if __name__ == "__main__":
    main()
