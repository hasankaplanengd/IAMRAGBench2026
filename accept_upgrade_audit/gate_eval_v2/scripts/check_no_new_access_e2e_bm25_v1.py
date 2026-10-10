#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import time
from collections import Counter, defaultdict
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT = Path.cwd()

INPUT = ROOT / "tables/table_master_v6_provider_valid_candidates.csv"
EXACT = ROOT / "tables/table_master_v6_request_validation_candidates.csv"

OUT_DIR = ROOT / "accept_upgrade_audit/gate_eval_v2/e2e_checknonewaccess"
OUT_DETAIL = OUT_DIR / "e2e_bm25_check_no_new_access_detail_v1.csv"
OUT_SUMMARY = OUT_DIR / "e2e_bm25_check_no_new_access_summary_v1.csv"
OUT_MD = OUT_DIR / "e2e_bm25_check_no_new_access_summary_v1.md"
OUT_HASH = OUT_DIR / "e2e_bm25_check_no_new_access_v1_sha256.txt"


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def compact_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def load_policy(path_value: str):
    path = Path(path_value)
    if not path.is_absolute():
        path = ROOT / path

    obj = json.loads(path.read_text(encoding="utf-8"))

    # Conservative unwrap for common repaired-output wrappers.
    # Does not alter statements, effects, actions, resources, principals, or conditions.
    if isinstance(obj, dict):
        if isinstance(obj.get("policy"), dict):
            return obj["policy"]
        if isinstance(obj.get("PolicyDocument"), dict):
            return obj["PolicyDocument"]
        if isinstance(obj.get("policy_document"), dict):
            return obj["policy_document"]

    return obj


def model_slug(row: dict) -> str:
    v = (row.get("model") or row.get("model_label") or "").strip()
    return {
        "Claude Sonnet 4.5": "claude",
        "Mistral Small": "mistral_small",
        "Nova Lite": "nova_lite",
        "Nova Pro": "nova_pro",
        "Llama 3 8B": "llama3_8b",
        "claude": "claude",
        "mistral_small": "mistral_small",
        "nova_lite": "nova_lite",
        "nova_pro": "nova_pro",
        "llama3_8b": "llama3_8b",
    }.get(v, v.lower().replace(" ", "_").replace(".", "").replace("~", ""))


def key(row: dict) -> tuple[str, str]:
    return (model_slug(row), row["case_id"].strip())


def boolish(value) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "validated"}


def check_no_new_access(client, control_policy, poison_policy, policy_type: str) -> dict:
    last_error = None

    for attempt in range(5):
        try:
            resp = client.check_no_new_access(
                existingPolicyDocument=compact_json(control_policy),
                newPolicyDocument=compact_json(poison_policy),
                policyType=policy_type,
            )
            result = resp.get("result", "")
            reasons = resp.get("reasons", [])
            message = resp.get("message", "")

            return {
                "check_result": result,
                "message": message,
                "reasons": json.dumps(reasons, sort_keys=True),
                "reason_count": str(len(reasons)),
                "api_error": "",
            }

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            msg = e.response.get("Error", {}).get("Message", str(e))
            last_error = f"{code}: {msg}"

            if code in {"ThrottlingException", "TooManyRequestsException", "InternalServerException"}:
                time.sleep(1.5 * (attempt + 1))
                continue

            return {
                "check_result": "",
                "message": "",
                "reasons": "[]",
                "reason_count": "0",
                "api_error": last_error,
            }

    return {
        "check_result": "",
        "message": "",
        "reasons": "[]",
        "reason_count": "0",
        "api_error": last_error or "unknown_error",
    }


def classify(result: dict) -> str:
    if result.get("api_error"):
        return "api_error"
    if result.get("check_result") == "FAIL":
        return "new_access_flagged"
    if result.get("check_result") == "PASS":
        return "no_new_access"
    return "unknown_result"


def main() -> None:
    if not INPUT.exists():
        raise SystemExit(f"Missing input: {INPUT}")
    if not EXACT.exists():
        raise SystemExit(f"Missing exact table: {EXACT}")

    candidates = read_csv(INPUT)
    exact_rows = read_csv(EXACT)

    if len(candidates) != 8:
        raise SystemExit(f"Expected 8 E2E BM25 provider-valid candidates, found {len(candidates)}")

    exact_by_key = {key(r): r for r in exact_rows}

    client = boto3.client("accessanalyzer", region_name="us-east-1")

    rows = []

    for i, row in enumerate(candidates, start=1):
        k = key(row)
        exact = exact_by_key.get(k, {})

        control_policy = load_policy(row["control_policy_file"])
        poison_policy = load_policy(row["poison_policy_file"])

        result = check_no_new_access(
            client=client,
            control_policy=control_policy,
            poison_policy=poison_policy,
            policy_type=row["policy_type"],
        )
        status = classify(result)

        out = {
            "model": row.get("model", ""),
            "model_label": row.get("model_label", ""),
            "case_id": row.get("case_id", ""),
            "semantic_failure": row.get("semantic_failure", ""),
            "policy_type": row.get("policy_type", ""),
            "control_provider_status": row.get("control_provider_status", ""),
            "poison_provider_status": row.get("poison_provider_status", ""),
            "exact_status": exact.get("status", ""),
            "exact_confirmed": str(boolish(exact.get("provider_native_delta_validated", ""))),
            "check_result": result["check_result"],
            "check_status": status,
            "provider_new_access_flagged": str(status == "new_access_flagged"),
            "message": result["message"],
            "reason_count": result["reason_count"],
            "reasons": result["reasons"],
            "check_api_error": result["api_error"],
            "control_policy_file": row.get("control_policy_file", ""),
            "poison_policy_file": row.get("poison_policy_file", ""),
            "run": row.get("run", ""),
        }
        rows.append(out)

        print(
            f"{i:02d}/08 "
            f"{out['model_label']:<12} "
            f"{out['case_id']:<28} "
            f"exact={out['exact_confirmed']:<5} "
            f"check={out['check_result'] or '-':<5} "
            f"status={out['check_status']}"
        )

    fields = [
        "model",
        "model_label",
        "case_id",
        "semantic_failure",
        "policy_type",
        "control_provider_status",
        "poison_provider_status",
        "exact_status",
        "exact_confirmed",
        "check_result",
        "check_status",
        "provider_new_access_flagged",
        "message",
        "reason_count",
        "reasons",
        "check_api_error",
        "control_policy_file",
        "poison_policy_file",
        "run",
    ]
    write_csv(OUT_DETAIL, rows, fields)

    summary_rows = []
    for group_name, group_rows in [
        ("all", rows),
        *[(f"model={m}", [r for r in rows if r["model_label"] == m]) for m in sorted({r["model_label"] for r in rows})],
    ]:
        c_status = Counter(r["check_status"] for r in group_rows)
        c_result = Counter(r["check_result"] or "EMPTY" for r in group_rows)
        exact_total = sum(boolish(r["exact_confirmed"]) for r in group_rows)
        exact_fail = sum(boolish(r["exact_confirmed"]) and r["check_status"] == "new_access_flagged" for r in group_rows)
        exact_pass = sum(boolish(r["exact_confirmed"]) and r["check_status"] == "no_new_access" for r in group_rows)
        exact_api = sum(boolish(r["exact_confirmed"]) and r["check_status"] in {"api_error", "unknown_result"} for r in group_rows)

        summary_rows.append({
            "group": group_name,
            "rows": str(len(group_rows)),
            "check_FAIL_new_access_flagged": str(c_status["new_access_flagged"]),
            "check_PASS_no_new_access": str(c_status["no_new_access"]),
            "check_review_or_error": str(c_status["api_error"] + c_status["unknown_result"]),
            "exact_attacks": str(exact_total),
            "exact_attacks_flagged": str(exact_fail),
            "exact_attacks_passed": str(exact_pass),
            "exact_attacks_review_or_error": str(exact_api),
            "check_result_counts": json.dumps(dict(c_result), sort_keys=True),
        })

    write_csv(OUT_SUMMARY, summary_rows, [
        "group",
        "rows",
        "check_FAIL_new_access_flagged",
        "check_PASS_no_new_access",
        "check_review_or_error",
        "exact_attacks",
        "exact_attacks_flagged",
        "exact_attacks_passed",
        "exact_attacks_review_or_error",
        "check_result_counts",
    ])

    md = []
    md.append("# E2E BM25 CheckNoNewAccess v1")
    md.append("")
    md.append("This evaluates Access Analyzer CheckNoNewAccess for the eight provider-valid semantic candidates in the end-to-end BM25 regime.")
    md.append("")
    md.append("## Summary")
    md.append("")
    md.append("| Group | Rows | New access flagged | No new access | Review/error | Exact attacks | Exact flagged | Exact passed | Exact review/error |")
    md.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in summary_rows:
        md.append(
            f"| {r['group']} | {r['rows']} | {r['check_FAIL_new_access_flagged']} | "
            f"{r['check_PASS_no_new_access']} | {r['check_review_or_error']} | "
            f"{r['exact_attacks']} | {r['exact_attacks_flagged']} | "
            f"{r['exact_attacks_passed']} | {r['exact_attacks_review_or_error']} |"
        )
    md.append("")
    md.append("## Files")
    md.append("")
    md.append(f"- `{OUT_DETAIL.relative_to(ROOT).as_posix()}`")
    md.append(f"- `{OUT_SUMMARY.relative_to(ROOT).as_posix()}`")

    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")

    with OUT_HASH.open("w", encoding="utf-8") as f:
        for p in [INPUT, EXACT, OUT_DETAIL, OUT_SUMMARY, OUT_MD]:
            f.write(f"{sha256_file(p)}  {p.relative_to(ROOT).as_posix()}\n")

    print()
    print("WROTE", OUT_DETAIL)
    print("WROTE", OUT_SUMMARY)
    print("WROTE", OUT_MD)
    print("WROTE", OUT_HASH)


if __name__ == "__main__":
    main()
