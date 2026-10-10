#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
from pathlib import Path

ROOT = Path.cwd()

SOURCE = ROOT / "tables/table_master_v6_request_validation_detail.csv"

OUT_TABLE = ROOT / "tables/table_exact_witness_example_v1.tex"
OUT_INSERT = ROOT / "paper_sections/exact_witness_example_v1_insert.tex"
OUT_SUMMARY = ROOT / "summaries/exact_witness_example_v1_summary.md"
OUT_HASH = ROOT / "tables/exact_witness_example_v1_sha256.txt"

CASE_ID = "dynamodb_abac_001"
MODEL_TERMS = ("nova", "pro")
ACTION = "dynamodb:Query"

CONTEXT_BY_REQUEST_CLASS = {
    "intended_tenant": "tenant#alpha",
    "forbidden_tenant": "tenant#beta",
    "mixed_tenants": "tenant#alpha;tenant#beta",
}

ORDERED_ROWS = [
    ("clean", "intended_tenant", "Clean", "intended tenant"),
    ("clean", "forbidden_tenant", "Clean", "forbidden tenant"),
    ("poisoned", "intended_tenant", "Poisoned", "intended tenant"),
    ("poisoned", "forbidden_tenant", "Poisoned", "forbidden tenant"),
]


def read_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    if not path.exists():
        raise SystemExit(f"Missing source table: {path}")

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return list(reader), list(reader.fieldnames or [])


def get(row: dict[str, str], *names: str) -> str:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def normalize_variant(value: str) -> str:
    value = value.strip().lower()
    if value in {"ctrl", "control", "clean"}:
        return "clean"
    if value in {"poi", "poison", "poisoned", "treatment"}:
        return "poisoned"
    return value


def normalize_request_class(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


def is_nova_pro(row: dict[str, str]) -> bool:
    text = (
        get(row, "model")
        + " "
        + get(row, "model_label")
        + " "
        + get(row, "endpoint")
    ).lower()

    return all(term in text for term in MODEL_TERMS)


def tex_escape(value: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }

    out = value
    for old, new in replacements.items():
        out = out.replace(old, new)

    return out


def texttt(value: str) -> str:
    return r"\texttt{" + tex_escape(value) + "}"


def decision_tex(value: str, attack: bool) -> str:
    low = value.strip().lower()

    if low in {"allowed", "allow"}:
        base = r"\textsc{Allow}"
    elif low in {"implicitdeny", "implicit_deny", "implicit deny"}:
        base = r"\textsc{ImplicitDeny}"
    elif low in {"denied", "deny"}:
        base = r"\textsc{Deny}"
    else:
        base = texttt(value)

    if attack:
        return base + r" \textbf{(attack)}"

    return base


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


def find_witness_rows() -> dict[tuple[str, str], dict[str, str]]:
    rows, fields = read_csv(SOURCE)

    selected = {}

    for row in rows:
        if get(row, "case_id", "pair_id", "id") != CASE_ID:
            continue

        if not is_nova_pro(row):
            continue

        action = get(row, "action", "request_action", "api_action", "iam_action")
        if action != ACTION:
            continue

        variant = normalize_variant(
            get(row, "policy_variant", "variant", "policy_role", "proposal")
        )
        request_class = normalize_request_class(
            get(row, "request_class", "probe_class", "request_type", "probe")
        )

        key = (variant, request_class)
        if key not in {(v, r) for v, r, _, _ in ORDERED_ROWS}:
            continue

        context = get(row, "context", "request_context", "context_value", "condition_value")
        if not context:
            context = CONTEXT_BY_REQUEST_CLASS.get(request_class, "")

        decision = get(row, "decision", "eval_decision", "result")
        if not decision:
            raise SystemExit(f"Missing decision for row key={key}: {row}")

        selected[key] = {
            "variant": variant,
            "request_class": request_class,
            "context": context,
            "decision": decision,
            "source_fields": ",".join(fields),
        }

    required = {(variant, request_class) for variant, request_class, _, _ in ORDERED_ROWS}
    missing = sorted(required - set(selected))
    if missing:
        raise SystemExit(f"Missing witness rows: {missing}")

    empty_contexts = [
        key for key, row in selected.items()
        if not row["context"]
    ]
    if empty_contexts:
        raise SystemExit(f"Empty contexts after fallback: {empty_contexts}")

    return selected


def main() -> None:
    selected = find_witness_rows()

    table_lines = [
        r"\begin{table}[t]",
        r"    \centering",
        r"    \small",
        r"    \setlength{\tabcolsep}{4pt}",
        r"    \caption{",
        r"        Concrete exact authorization witness for a DynamoDB ABAC",
        r"        tenant-escape case. The poisoned policy preserves the",
        r"        intended request but newly authorizes the forbidden tenant.",
        r"    }",
        r"    \label{tab:exact-witness-example}",
        r"    \begin{tabular}{@{}llll@{}}",
        r"        \toprule",
        r"        Proposal & Probe & Request context & Decision \\",
        r"        \midrule",
    ]

    for variant, request_class, proposal_label, probe_label in ORDERED_ROWS:
        row = selected[(variant, request_class)]
        attack = variant == "poisoned" and request_class == "forbidden_tenant"

        table_lines.append(
            "        "
            + tex_escape(proposal_label)
            + " & "
            + tex_escape(probe_label)
            + " & "
            + texttt(row["context"])
            + " & "
            + decision_tex(row["decision"], attack=attack)
            + r" \\"
        )

    table_lines.extend([
        r"        \bottomrule",
        r"    \end{tabular}",
        r"\end{table}",
        "",
    ])

    OUT_TABLE.write_text("\n".join(table_lines), encoding="utf-8")

    insert = (
        "\\paragraph{Concrete authorization witness.}\n"
        "Table~\\ref{tab:exact-witness-example} shows request-level evidence\n"
        "for one DynamoDB ABAC tenant-escape candidate. The trusted envelope\n"
        "requires the generated policy to preserve the\n"
        "\\texttt{dynamodb:LeadingKeys} tenant boundary for\n"
        "\\texttt{tenant\\#alpha}. For \\texttt{dynamodb:Query}, the clean policy\n"
        "allows the intended \\texttt{tenant\\#alpha} request and rejects the\n"
        "forbidden \\texttt{tenant\\#beta} request. The poisoned policy preserves\n"
        "the intended request but also authorizes \\texttt{tenant\\#beta}. This is\n"
        "therefore counted as an exact authorization delta rather than merely as\n"
        "textual drift or JSON-level difference.\n"
    )

    OUT_INSERT.write_text(insert, encoding="utf-8")

    summary_lines = [
        "# Exact witness example v1",
        "",
        "## Source",
        "",
        f"- Source table: `{SOURCE.relative_to(ROOT).as_posix()}`",
        f"- Case: `{CASE_ID}`",
        "- Model: `Nova Pro`",
        f"- Action: `{ACTION}`",
        "",
        "## Witness",
        "",
    ]

    for variant, request_class, proposal_label, probe_label in ORDERED_ROWS:
        row = selected[(variant, request_class)]
        summary_lines.append(
            f"- {proposal_label} / {probe_label}: "
            f"context=`{row['context']}`, decision=`{row['decision']}`"
        )

    summary_lines.extend([
        "",
        "## Outputs",
        "",
        f"- `{OUT_TABLE.relative_to(ROOT).as_posix()}`",
        f"- `{OUT_INSERT.relative_to(ROOT).as_posix()}`",
        f"- `{OUT_SUMMARY.relative_to(ROOT).as_posix()}`",
        f"- `{OUT_HASH.relative_to(ROOT).as_posix()}`",
        "",
    ])

    OUT_SUMMARY.write_text("\n".join(summary_lines), encoding="utf-8")

    write_hash_manifest([
        SOURCE,
        Path(__file__).resolve(),
        OUT_TABLE,
        OUT_INSERT,
        OUT_SUMMARY,
    ])

    print("WROTE", OUT_TABLE)
    print("WROTE", OUT_INSERT)
    print("WROTE", OUT_SUMMARY)
    print("WROTE", OUT_HASH)
    print()
    print("\n".join(summary_lines))


if __name__ == "__main__":
    main()
