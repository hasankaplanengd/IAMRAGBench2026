#!/usr/bin/env python3
import csv
from collections import Counter
from pathlib import Path

INPUT = Path(
    "tables/table_retrieval_sensitivity_v6_new_access_survivors.csv"
)

OUT = Path(
    "tables/table_retrieval_sensitivity_v6_survivor_families.csv"
)

LABELS = {
    "nova_lite": "Nova Lite",
    "nova_pro": "Nova Pro",
    "llama3_8b": "Llama 3 8B",
}


def read_csv(path):
    if not path.exists():
        raise FileNotFoundError(path)

    with path.open(
        newline="",
        encoding="utf-8",
    ) as f:
        return list(csv.DictReader(f))


def family(case_id):
    if case_id == "dynamodb_abac_001":
        return "dynamodb_leadingkeys"

    if case_id in {
        "ec2_region_002",
        "kms_tag_002",
        "s3_vpce_002",
    }:
        return "allow_condition_removal"

    if case_id == "secrets_tls_deny_002":
        return "explicit_deny_guardrail"

    if case_id == "kms_condition_001":
        return "kms_multi_condition"

    raise RuntimeError(
        f"Unclassified survivor: {case_id}"
    )


rows = read_csv(INPUT)

if len(rows) != 9:
    raise RuntimeError(
        f"Expected nine survivors, found {len(rows)}"
    )

output = []

for row in rows:
    if row["check_status"] != "new_access_flagged":
        raise RuntimeError(
            f"{row['model']}/{row['retriever']}/"
            f"{row['case_id']}: unexpected status"
        )

    if row["check_result"] != "FAIL":
        raise RuntimeError(
            f"{row['model']}/{row['retriever']}/"
            f"{row['case_id']}: expected FAIL"
        )

    if row.get("check_api_error"):
        raise RuntimeError(
            f"{row['model']}/{row['retriever']}/"
            f"{row['case_id']}: AWS error remains"
        )

    model = row["model"]
    retriever = row["retriever"]

    output.append({
        **row,
        "base_model": model,
        "base_model_label": LABELS[model],
        # Existing validators use model+case as an identity.
        # Add the retriever to avoid collisions between the
        # dense and hybrid versions of the same model/case.
        "model": f"{model}__{retriever}",
        "model_label": (
            f"{LABELS[model]} / {retriever}"
        ),
        "validation_family": family(
            row["case_id"]
        ),
    })

counts = Counter(
    row["validation_family"]
    for row in output
)

expected = {
    "allow_condition_removal": 3,
    "dynamodb_leadingkeys": 2,
    "explicit_deny_guardrail": 2,
    "kms_multi_condition": 2,
}

if dict(counts) != expected:
    raise RuntimeError(
        f"Unexpected family counts: {dict(counts)}"
    )

with OUT.open(
    "w",
    newline="",
    encoding="utf-8",
) as f:
    writer = csv.DictWriter(
        f,
        fieldnames=list(output[0].keys()),
    )
    writer.writeheader()
    writer.writerows(output)

print("---- retrieval-sensitivity survivor families ----")

for name, count in counts.items():
    print(f"{name}: {count}")

print(f"\nWrote: {OUT}")
print("PASS: all nine survivors were classified.")
