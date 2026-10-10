#!/usr/bin/env python3
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import csv
import hashlib
import json


ROOT = Path.cwd()

UNIQUE_POLICIES = Path(
    "tables/repeatability_v1_unique_provider_policies.csv"
)
UNIQUE_PAIRS = Path(
    "tables/repeatability_v1_unique_candidate_pairs.csv"
)

PROVIDER_SOURCES = [
    (
        "ordinary",
        Path("tables/table_master_v6_provider_validation_detail.csv"),
    ),
    (
        "authority",
        Path(
            "tables/"
            "table_adaptive_compliance_exception_v6_"
            "provider_validation_detail.csv"
        ),
    ),
]

EXACT_SOURCES = [
    (
        "ordinary",
        Path(
            "tables/"
            "table_master_v6_request_validation_candidates.csv"
        ),
    ),
    (
        "authority",
        Path(
            "tables/"
            "table_adaptive_compliance_exception_v6_"
            "final_candidate_ledger_v2.csv"
        ),
    ),
]

POLICY_OUT = Path(
    "tables/repeatability_v1_provider_reuse_audit_v2.csv"
)
PAIR_OUT = Path(
    "tables/repeatability_v1_exact_reuse_audit_v2.csv"
)
SUMMARY_OUT = Path(
    "summaries/repeatability_v1_validation_reuse_audit_v2.md"
)


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(path)

    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def resolve(path_value: str) -> Path:
    path = Path(path_value)

    if not path.is_absolute():
        path = ROOT / path

    return path


def canonical_json_sha256(path_value: str) -> str:
    path = resolve(path_value)

    if not path.exists():
        raise FileNotFoundError(path)

    obj = json.loads(path.read_text(encoding="utf-8"))

    canonical = json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


def as_bool(value: object) -> bool:
    return str(value).strip().lower() in {
        "true",
        "1",
        "yes",
        "y",
    }


def write_csv(
    path: Path,
    rows: list[dict[str, object]],
) -> None:
    if not rows:
        raise RuntimeError(f"No rows for {path}")

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(rows[0].keys()),
        )
        writer.writeheader()
        writer.writerows(rows)


# ------------------------------------------------------------------
# Index prior provider-validation records by exact canonical policy.
# ------------------------------------------------------------------

provider_index = defaultdict(list)
case_metadata = defaultdict(set)

for source_name, source_path in PROVIDER_SOURCES:
    for row in read_csv(source_path):
        case_id = row.get("case_id", "").strip()
        prompt_type = row.get("prompt_type", "").strip().lower()
        policy_file = row.get("policy_file", "").strip()

        if not case_id or not policy_file:
            continue

        if prompt_type in {"ctrl", "control", "clean"}:
            role = "control"
        elif prompt_type in {"poi", "poison", "treatment"}:
            role = "treatment"
        else:
            continue

        try:
            canonical_sha = canonical_json_sha256(policy_file)
        except Exception:
            continue

        policy_type = row.get("policy_type", "").strip()
        resource_type = row.get("resource_type", "").strip()

        provider_index[
            (case_id, role, canonical_sha)
        ].append({
            "source": source_name,
            "provider_status":
                row.get("provider_status", "").strip(),
            "policy_type": policy_type,
            "resource_type": resource_type,
            "policy_file": policy_file,
        })

        if policy_type:
            case_metadata[case_id].add(
                (policy_type, resource_type)
            )


policy_audit = []

for row in read_csv(UNIQUE_POLICIES):
    case_id = row["case_id"].strip()
    role = row["role"].strip()
    policy_file = row[
        "representative_policy_file"
    ].strip()

    canonical_sha = canonical_json_sha256(
        policy_file
    )

    matches = provider_index.get(
        (case_id, role, canonical_sha),
        [],
    )

    statuses = sorted({
        match["provider_status"]
        for match in matches
        if match["provider_status"]
    })

    policy_types = sorted({
        match["policy_type"]
        for match in matches
        if match["policy_type"]
    })

    resource_types = sorted({
        match["resource_type"]
        for match in matches
        if match["resource_type"]
    })

    if not policy_types:
        policy_types = sorted({
            policy_type
            for policy_type, _ in case_metadata.get(
                case_id,
                set(),
            )
            if policy_type
        })

    if not resource_types:
        resource_types = sorted({
            resource_type
            for _, resource_type in case_metadata.get(
                case_id,
                set(),
            )
            if resource_type
        })

    if len(statuses) > 1:
        reuse_status = "conflicting_prior_status"
    elif matches:
        reuse_status = "reusable"
    else:
        reuse_status = "requires_validation"

    policy_audit.append({
        "case_id": case_id,
        "stratum": row["stratum"],
        "role": role,
        "instance_count": row["instance_count"],
        "models": row["models"],
        "regimes": row["regimes"],
        "repetitions": row["repetitions"],
        "representative_policy_file": policy_file,
        "canonical_policy_sha256": canonical_sha,
        "reuse_status": reuse_status,
        "prior_provider_status":
            "|".join(statuses),
        "policy_type":
            "|".join(policy_types),
        "resource_type":
            "|".join(resource_types),
        "reuse_sources":
            "|".join(sorted({
                match["source"]
                for match in matches
            })),
        "matched_prior_records": len(matches),
    })


# ------------------------------------------------------------------
# Index prior exact-witness results by exact canonical policy pair.
# ------------------------------------------------------------------

exact_index = defaultdict(list)

for source_name, source_path in EXACT_SOURCES:
    for row in read_csv(source_path):
        case_id = row.get("case_id", "").strip()
        control_file = row.get(
            "control_policy_file",
            "",
        ).strip()
        treatment_file = (
            row.get("poison_policy_file", "").strip()
            or row.get("treatment_policy_file", "").strip()
        )

        if not (
            case_id
            and control_file
            and treatment_file
        ):
            continue

        try:
            control_sha = canonical_json_sha256(
                control_file
            )
            treatment_sha = canonical_json_sha256(
                treatment_file
            )
        except Exception:
            continue

        if source_name == "ordinary":
            exact_confirmed = (
                as_bool(
                    row.get(
                        "provider_native_delta_validated",
                        False,
                    )
                )
                or row.get("status", "").strip()
                == "validated"
            )
            provider_corroborated = exact_confirmed
            final_outcome = row.get(
                "status",
                "",
            ).strip()
        else:
            exact_confirmed = as_bool(
                row.get("exact_confirmed", False)
            )
            provider_corroborated = as_bool(
                row.get(
                    "provider_corroborated",
                    False,
                )
            )
            final_outcome = row.get(
                "final_outcome",
                "",
            ).strip()

        exact_index[
            (
                case_id,
                control_sha,
                treatment_sha,
            )
        ].append({
            "source": source_name,
            "exact_confirmed": exact_confirmed,
            "provider_corroborated":
                provider_corroborated,
            "final_outcome": final_outcome,
            "validation_family":
                row.get(
                    "validation_family",
                    "",
                ).strip(),
        })


pair_audit = []

for row in read_csv(UNIQUE_PAIRS):
    case_id = row["case_id"].strip()

    control_file = row[
        "representative_control_file"
    ].strip()
    treatment_file = row[
        "representative_treatment_file"
    ].strip()

    control_sha = canonical_json_sha256(
        control_file
    )
    treatment_sha = canonical_json_sha256(
        treatment_file
    )

    matches = exact_index.get(
        (
            case_id,
            control_sha,
            treatment_sha,
        ),
        [],
    )

    exact_values = {
        match["exact_confirmed"]
        for match in matches
    }
    corroborated_values = {
        match["provider_corroborated"]
        for match in matches
    }

    if (
        len(exact_values) > 1
        or len(corroborated_values) > 1
    ):
        reuse_status = "conflicting_prior_outcome"
    elif matches:
        reuse_status = "reusable"
    else:
        reuse_status = "requires_validation"

    pair_audit.append({
        "case_id": case_id,
        "stratum": row["stratum"],
        "models": row["models"],
        "regimes": row["regimes"],
        "repetitions": row["repetitions"],
        "instance_count": row["instance_count"],
        "representative_control_file":
            control_file,
        "representative_treatment_file":
            treatment_file,
        "canonical_control_sha256":
            control_sha,
        "canonical_treatment_sha256":
            treatment_sha,
        "reuse_status": reuse_status,
        "prior_exact_confirmed":
            (
                str(next(iter(exact_values)))
                if len(exact_values) == 1
                else ""
            ),
        "prior_provider_corroborated":
            (
                str(
                    next(
                        iter(corroborated_values)
                    )
                )
                if len(corroborated_values) == 1
                else ""
            ),
        "prior_final_outcome":
            "|".join(sorted({
                match["final_outcome"]
                for match in matches
                if match["final_outcome"]
            })),
        "validation_family":
            "|".join(sorted({
                match["validation_family"]
                for match in matches
                if match["validation_family"]
            })),
        "reuse_sources":
            "|".join(sorted({
                match["source"]
                for match in matches
            })),
        "matched_prior_records": len(matches),
    })


write_csv(POLICY_OUT, policy_audit)
write_csv(PAIR_OUT, pair_audit)

reused_policies = sum(
    row["reuse_status"] == "reusable"
    for row in policy_audit
)
pending_policies = sum(
    row["reuse_status"] == "requires_validation"
    for row in policy_audit
)

reused_pairs = sum(
    row["reuse_status"] == "reusable"
    for row in pair_audit
)
pending_pairs = sum(
    row["reuse_status"] == "requires_validation"
    for row in pair_audit
)

lines = [
    "# Repeatability v1 validation-reuse audit",
    "",
    f"- Unique policies: **{len(policy_audit)}**",
    (
        "- Provider-validity records reusable by canonical "
        f"equality: **{reused_policies}**"
    ),
    (
        "- Policies requiring new provider validation: "
        f"**{pending_policies}**"
    ),
    f"- Unique candidate pairs: **{len(pair_audit)}**",
    (
        "- Exact outcomes reusable by canonical pair equality: "
        f"**{reused_pairs}**"
    ),
    (
        "- Candidate pairs requiring new differential or "
        f"exact validation: **{pending_pairs}**"
    ),
    "",
    "Reuse is allowed only for exact case-scoped canonical "
    "policy equality.",
]

SUMMARY_OUT.parent.mkdir(
    parents=True,
    exist_ok=True,
)
SUMMARY_OUT.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)

print("PASS: canonical validation-reuse audit complete")
print(
    "Provider records reusable:",
    f"{reused_policies}/{len(policy_audit)}",
)
print(
    "Policies requiring validation:",
    pending_policies,
)
print(
    "Exact pair outcomes reusable:",
    f"{reused_pairs}/{len(pair_audit)}",
)
print(
    "Pairs requiring validation:",
    pending_pairs,
)

print()
print("PENDING POLICIES")
print("----------------")

for row in policy_audit:
    if row["reuse_status"] == "requires_validation":
        print(
            f"{row['case_id']:26} "
            f"role={row['role']:9} "
            f"type={row['policy_type'] or '?':18} "
            f"models={row['models']:18} "
            f"regimes={row['regimes']}"
        )

print()
print("PENDING CANDIDATE PAIRS")
print("-----------------------")

for row in pair_audit:
    if row["reuse_status"] == "requires_validation":
        print(
            f"{row['case_id']:26} "
            f"models={row['models']:18} "
            f"regimes={row['regimes']:18} "
            f"instances={row['instance_count']}"
        )

print()
print("Wrote:")
print(" ", POLICY_OUT)
print(" ", PAIR_OUT)
print(" ", SUMMARY_OUT)
