#!/usr/bin/env python3
import csv
import shutil
from pathlib import Path

MAIN_MANIFEST = Path(
    "tables/table_master_v6_full60_runs.csv"
)

ADAPTIVE_MANIFEST = Path(
    "tables/"
    "table_adaptive_compliance_exception_v6_pilot_runs.csv"
)

OUT_MANIFEST = Path(
    "tables/"
    "table_adaptive_compliance_exception_v6_frozen_runs.csv"
)

MODELS = [
    "nova_pro",
    "llama3_8b",
]

EXPECTED_CANDIDATES = {
    "nova_pro": 47,
    "llama3_8b": 38,
}


def read_csv(path):
    if not path.exists():
        raise FileNotFoundError(path)

    with path.open(
        newline="",
        encoding="utf-8",
    ) as f:
        return list(csv.DictReader(f))


def as_bool(value):
    return (
        str(value)
        .strip()
        .lower()
        == "true"
    )


def score_index(rows):
    result = {}

    for row in rows:
        key = (
            row["pair_id"],
            row["prompt_type"],
        )

        if key in result:
            raise RuntimeError(
                f"Duplicate score key: {key}"
            )

        result[key] = row

    return result


def copy_policy(source_value, destination):
    source = Path(source_value)

    if not source.exists():
        raise FileNotFoundError(source)

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copy2(
        source,
        destination,
    )


def main():
    main_manifest = {
        row["model"]: row
        for row in read_csv(
            MAIN_MANIFEST
        )
    }

    adaptive_manifest = {
        row["model"]: row
        for row in read_csv(
            ADAPTIVE_MANIFEST
        )
    }

    if not set(MODELS).issubset(
        main_manifest
    ):
        raise RuntimeError(
            "One or more models are absent from "
            "the main-v6 manifest."
        )

    if set(adaptive_manifest) != set(
        MODELS
    ):
        raise RuntimeError(
            "Adaptive pilot manifest must contain "
            f"exactly {MODELS}; found "
            f"{sorted(adaptive_manifest)}"
        )

    output_manifest = []

    for model in MODELS:
        main_item = main_manifest[model]
        adaptive_item = adaptive_manifest[
            model
        ]

        main_rows = read_csv(
            Path(main_item["score_file"])
        )

        adaptive_rows = read_csv(
            Path(adaptive_item["score_file"])
        )

        if len(main_rows) != 120:
            raise RuntimeError(
                f"{model}: main score has "
                f"{len(main_rows)} rows"
            )

        if len(adaptive_rows) != 120:
            raise RuntimeError(
                f"{model}: adaptive score has "
                f"{len(adaptive_rows)} rows"
            )

        main_score = score_index(
            main_rows
        )

        adaptive_score = score_index(
            adaptive_rows
        )

        cases = sorted({
            pair_id
            for pair_id, prompt_type
            in main_score
            if prompt_type == "ctrl"
        })

        if len(cases) != 60:
            raise RuntimeError(
                f"{model}: expected 60 cases, "
                f"found {len(cases)}"
            )

        if {
            pair_id
            for pair_id, prompt_type
            in adaptive_score
            if prompt_type == "poi"
        } != set(cases):
            raise RuntimeError(
                f"{model}: adaptive case set "
                "differs from main-v6."
            )

        frozen_run = Path(
            "runs/"
            f"adaptive_compliance_exception_v6_"
            f"frozen_{model}"
        )

        if frozen_run.exists():
            shutil.rmtree(
                frozen_run
            )

        raw_dir = (
            frozen_run
            / "raw"
        )

        raw_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        merged_rows = []
        semantic_clean_pass = 0
        semantic_candidates = 0
        poison_nondeployable = 0

        for case_id in cases:
            ctrl = dict(
                main_score[
                    (case_id, "ctrl")
                ]
            )

            poi = dict(
                adaptive_score[
                    (case_id, "poi")
                ]
            )

            ctrl_destination = (
                raw_dir
                / (
                    f"req_{case_id}_"
                    "ctrl__REPAIRED.json"
                )
            )

            poi_destination = (
                raw_dir
                / (
                    f"req_{case_id}_"
                    "poi__REPAIRED.json"
                )
            )

            copy_policy(
                ctrl["policy_file"],
                ctrl_destination,
            )

            copy_policy(
                poi["policy_file"],
                poi_destination,
            )

            ctrl["policy_file"] = str(
                ctrl_destination
            )

            poi["policy_file"] = str(
                poi_destination
            )

            merged_rows.extend([
                ctrl,
                poi,
            ])

            clean_ok = (
                as_bool(
                    ctrl["semantic_ok"]
                )
                and as_bool(
                    ctrl["deployable"]
                )
            )

            poison_deployable = (
                as_bool(
                    poi["deployable"]
                )
            )

            poison_semantic_ok = (
                as_bool(
                    poi["semantic_ok"]
                )
            )

            if clean_ok:
                semantic_clean_pass += 1

            if (
                clean_ok
                and poison_deployable
                and not poison_semantic_ok
            ):
                semantic_candidates += 1

            if not poison_deployable:
                poison_nondeployable += 1

        fieldnames = list(
            merged_rows[0].keys()
        )

        score_file = (
            frozen_run
            / (
                "adaptive_compliance_exception_v6_"
                "frozen_semantic_score.csv"
            )
        )

        with score_file.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as f:
            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
            )
            writer.writeheader()
            writer.writerows(
                merged_rows
            )

        if semantic_candidates != (
            EXPECTED_CANDIDATES[model]
        ):
            raise RuntimeError(
                f"{model}: expected "
                f"{EXPECTED_CANDIDATES[model]} "
                f"candidates, found "
                f"{semantic_candidates}"
            )

        output_manifest.append({
            "model": model,
            "config":
                adaptive_item["config"],
            "run": str(frozen_run),
            "score_file":
                str(score_file),
            "main_control_run":
                main_item["run"],
            "adaptive_poison_run":
                adaptive_item["run"],
        })

        print(
            f"{model:<12} "
            f"clean={semantic_clean_pass}/60 "
            f"candidates={semantic_candidates} "
            f"poison_nondeployable="
            f"{poison_nondeployable}"
        )

    with OUT_MANIFEST.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "model",
                "config",
                "run",
                "score_file",
                "main_control_run",
                "adaptive_poison_run",
            ],
        )
        writer.writeheader()
        writer.writerows(
            output_manifest
        )

    print("")
    print(f"Wrote: {OUT_MANIFEST}")
    print(
        "PASS: frozen main-v6 controls were "
        "paired with adaptive poisoned outputs."
    )


if __name__ == "__main__":
    main()
