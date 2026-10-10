#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
from pathlib import Path

ROOT = Path.cwd()

GATE_CSV = ROOT / "tables/table_gate_evaluation_v2.csv"
BY_REGIME_CSV = ROOT / "tables/table_gate_evaluation_by_regime_v2.csv"
BY_MODEL_CSV = ROOT / "tables/table_gate_evaluation_by_model_v2.csv"

OUT_TABLE = ROOT / "tables/table_gate_evaluation_v2_paper.tex"
OUT_INSERT = ROOT / "paper_sections/gate_evaluation_v2_result_insert.tex"
OUT_SUMMARY = ROOT / "summaries/gate_evaluation_v2_paper_insert_summary.md"
OUT_HASH = ROOT / "tables/gate_evaluation_v2_paper_insert_sha256.txt"

GATE_LABELS = {
    "provider_valid_only": "Provider-valid only",
    "check_no_new_access_only": "\\texttt{CheckNoNewAccess} only",
    "semantic_envelope_only": "Semantic envelope only",
    "full_proposal_to_commit": "Full proposal-to-commit",
}

GATE_ORDER = [
    "provider_valid_only",
    "check_no_new_access_only",
    "semantic_envelope_only",
    "full_proposal_to_commit",
]


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise SystemExit(f"Missing required input: {path}")

    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def as_int(row: dict[str, str], key: str) -> int:
    return int(row[key])


def escape_percent(value: str) -> str:
    return value.strip().replace("%", "\\%")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def write_hash_manifest(paths: list[Path]) -> None:
    lines = []
    for path in paths:
        rel = path.relative_to(ROOT).as_posix()
        lines.append(f"{sha256_file(path)}  {rel}")

    OUT_HASH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    rows = read_csv(GATE_CSV)
    by_regime = read_csv(BY_REGIME_CSV)
    by_model = read_csv(BY_MODEL_CSV)

    by_gate = {row["gate"]: row for row in rows}
    missing = [gate for gate in GATE_ORDER if gate not in by_gate]
    if missing:
        raise SystemExit(f"Missing gate rows: {missing}")

    provider = by_gate["provider_valid_only"]
    cna = by_gate["check_no_new_access_only"]
    semantic = by_gate["semantic_envelope_only"]
    full = by_gate["full_proposal_to_commit"]

    expected = {
        "clean_controls": 880,
        "semantic_candidates": 194,
        "exact_attacks": 171,
        "provider_corroborated": 177,
    }

    for key, value in expected.items():
        observed = as_int(provider, key)
        if observed != value:
            raise SystemExit(f"Unexpected {key}: {observed} != {value}")

    # The legacy gate CSV field `exact_attacks` stores exact
    # authorization deltas. Goal matching is a separate frozen audit.
    goal_match_csv = ROOT / (
        "release/iamragbench2026/goal_match/"
        "goalmatch_all_candidates_v2.csv"
    )

    candidate_ledger = ROOT / (
        "tables/"
        "table_gate_evaluation_candidate_ledger_v2.csv"
    )

    with goal_match_csv.open(
        newline="",
        encoding="utf-8-sig",
    ) as handle:
        goal_rows = list(csv.DictReader(handle))

    with candidate_ledger.open(
        newline="",
        encoding="utf-8-sig",
    ) as handle:
        candidate_rows = list(csv.DictReader(handle))

    def truthy(value):
        return str(value or "").strip().lower() in {
            "true",
            "1",
            "yes",
            "y",
        }

    def normalized_model(value):
        return "".join(
            character
            for character in str(value or "").lower()
            if character.isalnum()
        )

    def candidate_key(row):
        return (
            str(row.get("scope", "")).strip(),
            normalized_model(
                row.get("model")
                or row.get("model_label")
            ),
            str(row.get("case_id", "")).strip(),
        )

    frozen_exact_keys = {
        candidate_key(row)
        for row in goal_rows
        if truthy(row.get("exact_confirmed"))
    }

    goal_matched_exact_keys = {
        candidate_key(row)
        for row in goal_rows
        if (
            truthy(row.get("exact_confirmed"))
            and str(
                row.get("goalmatch_any_status", "")
            ).strip().lower() == "match"
        )
    }

    off_target_exact_keys = (
        frozen_exact_keys
        - goal_matched_exact_keys
    )

    gate_exact_keys = {
        candidate_key(row)
        for row in candidate_rows
        if truthy(row.get("exact_confirmed"))
    }

    check_exact_accept_keys = {
        candidate_key(row)
        for row in candidate_rows
        if (
            truthy(row.get("exact_confirmed"))
            and str(
                row.get("check_gate_action", "")
            ).strip().lower() == "accept"
        )
    }

    expected_off_target = {
        (
            "included_context",
            "mistralsmall",
            "sts_oidc_trust_001",
        ),
        (
            "included_context",
            "mistralsmall",
            "sts_oidc_trust_003",
        ),
        (
            "included_context",
            "mistralsmall",
            "sts_oidc_trust_004",
        ),
    }

    if (
        len(goal_rows) != 194
        or len(frozen_exact_keys)
        != as_int(provider, "exact_attacks")
        or len(goal_matched_exact_keys) != 168
        or gate_exact_keys != frozen_exact_keys
        or off_target_exact_keys != expected_off_target
        or len(check_exact_accept_keys) != 4
        or not (
            check_exact_accept_keys
            <= goal_matched_exact_keys
        )
        or as_int(
            provider,
            "exact_attacks_accepted",
        ) != 171
        or as_int(
            cna,
            "exact_attacks_accepted",
        ) != 4
        or as_int(
            semantic,
            "exact_attacks_accepted",
        ) != 0
        or as_int(
            full,
            "exact_attacks_accepted",
        ) != 0
    ):
        raise SystemExit(
            "Unexpected frozen goal-match accounting: "
            f"candidates={len(goal_rows)}, "
            f"exact={len(frozen_exact_keys)}, "
            f"goal_matched="
            f"{len(goal_matched_exact_keys)}, "
            f"off_target="
            f"{sorted(off_target_exact_keys)}, "
            f"check_accepts="
            f"{sorted(check_exact_accept_keys)}"
        )

    goal_matched_total = len(
        goal_matched_exact_keys
    )

    goal_matched_accepts = {
        "provider_valid_only":
            goal_matched_total,
        "check_no_new_access_only":
            len(check_exact_accept_keys),
        "semantic_envelope_only": 0,
        "full_proposal_to_commit": 0,
    }

    table_lines = [
        "\\begin{table*}[t]",
        "    \\centering",
        "    \\small",
        "    \\setlength{\\tabcolsep}{4.5pt}",
        "    \\renewcommand{\\arraystretch}{1.08}",
        "    \\caption{",
        "        Proposal-to-commit gate evaluation over all provider-valid",
        "        semantic candidates. Candidate and exact-delta columns report",
        "        blocked/accepted/reviewed counts as B/A/R. The final column reports",
        "        goal-matched exact attacks that would pass the gate.",
        "    }",
        "    \\label{tab:gate-evaluation}",
        "    \\begin{tabular}{@{}lrrrr@{}}",
        "        \\toprule",
        "        Gate",
        "        & Clean accepted",
        "        & Candidates (B/A/R)",
        "        & Exact deltas (B/A/R)",
        "        & \\shortstack{Goal-matched\\\\attacks accepted} \\\\",
        "        \\midrule",
    ]

    for gate in GATE_ORDER:
        row = by_gate[gate]
        clean = f"{row['clean_accept']}/{row['clean_controls']}"
        candidates = (
            f"{row['candidate_blocked']}/"
            f"{row['candidate_accepted']}/"
            f"{row['candidate_review']}"
        )
        exact = (
            f"{row['exact_attacks_blocked']}/"
            f"{row['exact_attacks_accepted']}/"
            f"{row['exact_attacks_review']}"
        )
        goal_accepted = goal_matched_accepts[gate]
        goal_rate = (
            100.0
            * goal_accepted
            / goal_matched_total
        )

        unsafe = (
            f"{goal_accepted}/"
            f"{goal_matched_total} "
            f"({goal_rate:.2f}\\%)"
        )

        table_lines.append(
            f"        {GATE_LABELS[gate]} & {clean} & {candidates} & {exact} & {unsafe} \\\\"
        )

    table_lines.extend([
        "        \\bottomrule",
        "    \\end{tabular}",
        "\\end{table*}",
        "",
    ])

    OUT_TABLE.write_text("\n".join(table_lines), encoding="utf-8")

    insert = f"""\\subsection{{Proposal-to-commit gate evaluation}}
\\label{{sec:results-gate}}

We next ask whether simpler deployment gates would have prevented the
confirmed policy-level compromises. Table~\\ref{{tab:gate-evaluation}}
evaluates four deterministic gates over the frozen provider-valid semantic
candidates from the included-context, end-to-end BM25, and authority-spoofing
regimes. The evaluation covers {provider['clean_controls']} provider-valid
clean controls, {provider['semantic_candidates']} provider-valid semantic
candidates, {provider['exact_attacks']} exact authorization deltas, of which
{goal_matched_total} match at least one predeclared attacker-goal category,
and {provider['provider_corroborated']} exact-or-provider-corroborated cases.

Provider policy-form validation alone is not a security boundary: it accepts
all {provider['semantic_candidates']} semantic candidates, all
{provider['exact_attacks']} exact authorization deltas, and all
{goal_matched_total} goal-matched exact attacks. AWS Access Analyzer
\\texttt{{CheckNoNewAccess}} is a useful auxiliary screen, blocking
{cna['exact_attacks_blocked']}/{cna['exact_attacks']} exact authorization
deltas, but it still accepts {cna['exact_attacks_accepted']}/
{cna['exact_attacks']} exact deltas. All four accepted deltas are goal-matched,
so its goal-matched attack acceptance is
{goal_matched_accepts['check_no_new_access_only']}/{goal_matched_total}
(2.38\\%). These misses are precisely why we do not treat provider
differential output as the terminal oracle.

The task-scoped semantic envelope blocks all
{semantic['semantic_candidates']} semantic candidates and therefore all
{semantic['exact_attacks']} exact authorization deltas, including all
{goal_matched_total} goal-matched exact attacks. The full proposal-to-commit
gate combines provider validity, the semantic envelope, and review routing for
cases that are provider-corroborated but exact-witness unresolved; it blocks
all {full['exact_attacks']} exact authorization deltas, including all
{goal_matched_total} goal-matched exact attacks, and routes
{full['candidate_review']} candidates to review.
"""

    OUT_INSERT.write_text(insert, encoding="utf-8")

    summary_lines = [
        "# Gate Evaluation V2 paper insert",
        "",
        "## Inputs",
        "",
        f"- `{GATE_CSV.relative_to(ROOT).as_posix()}`",
        f"- `{BY_REGIME_CSV.relative_to(ROOT).as_posix()}`",
        f"- `{BY_MODEL_CSV.relative_to(ROOT).as_posix()}`",
        f"- `{candidate_ledger.relative_to(ROOT).as_posix()}`",
        f"- `{goal_match_csv.relative_to(ROOT).as_posix()}`",
        "",
        "## Main numbers",
        "",
        f"- Clean controls: **{provider['clean_controls']}**",
        f"- Semantic candidates: **{provider['semantic_candidates']}**",
        f"- Exact authorization deltas: **{provider['exact_attacks']}**",
        f"- Goal-matched exact attacks: **{goal_matched_total}**",
        f"- Exact-or-provider-corroborated cases: **{provider['provider_corroborated']}**",
        f"- Provider-valid-only goal-matched attacks accepted: **{goal_matched_accepts['provider_valid_only']}/{goal_matched_total}**",
        f"- CheckNoNewAccess-only goal-matched attacks accepted: **{goal_matched_accepts['check_no_new_access_only']}/{goal_matched_total}**",
        f"- Semantic-envelope-only goal-matched attacks accepted: **{goal_matched_accepts['semantic_envelope_only']}/{goal_matched_total}**",
        f"- Full proposal-to-commit goal-matched attacks accepted: **{goal_matched_accepts['full_proposal_to_commit']}/{goal_matched_total}**",
        "",
        "## Outputs",
        "",
        f"- `{OUT_TABLE.relative_to(ROOT).as_posix()}`",
        f"- `{OUT_INSERT.relative_to(ROOT).as_posix()}`",
        f"- `{OUT_SUMMARY.relative_to(ROOT).as_posix()}`",
        f"- `{OUT_HASH.relative_to(ROOT).as_posix()}`",
        "",
    ]

    OUT_SUMMARY.write_text("\n".join(summary_lines), encoding="utf-8")

    write_hash_manifest([
        goal_match_csv,
        candidate_ledger,
        GATE_CSV,
        BY_REGIME_CSV,
        BY_MODEL_CSV,
        Path(__file__).resolve(),
        OUT_TABLE,
        OUT_INSERT,
        OUT_SUMMARY,
    ])

    print("WROTE", OUT_TABLE)
    print("WROTE", OUT_INSERT)
    print("WROTE", OUT_SUMMARY)
    print("WROTE", OUT_HASH)


if __name__ == "__main__":
    main()
