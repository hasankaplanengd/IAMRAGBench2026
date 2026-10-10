#!/usr/bin/env bash
set -euo pipefail

echo "=== BRANCH / STATUS ==="
git branch --show-current
git status --short

echo
echo "=== TARGET EXPECTED COUNTS ==="
cat accept_upgrade_audit/regression_original_authority_v1/original_authority_regression_expected_v1.json

echo
echo "=== GENERIC EXACT WITNESS ENGINE ==="
if [ -f scripts/simulate_master_v6_candidates.py ]; then
  echo "FOUND scripts/simulate_master_v6_candidates.py"
  wc -l scripts/simulate_master_v6_candidates.py
  grep -nE '^(INPUT|OUT_|DETAIL|SUMMARY|CANDIDATE|MASTER|CASES|RUNS)|argparse|sys\.argv|def main|if __name__|read_csv|DictReader|writer|fieldnames|case_id|semantic_failure|control_policy_file|poison_policy_file|validation_family|final_outcome|exact|simulate_custom_policy|boto3\.client' \
    scripts/simulate_master_v6_candidates.py \
    | sed -n '1,260p'
else
  echo "MISSING scripts/simulate_master_v6_candidates.py"
fi

echo
echo "=== ADAPTIVE EXACT SOURCE SCRIPTS ==="
for f in \
  scripts/simulate_adaptive_compliance_exception_v6_condition_cases.py \
  scripts/simulate_adaptive_compliance_exception_v6_kms_multi_condition.py \
  scripts/simulate_adaptive_compliance_exception_v6_passrole.py \
  scripts/simulate_adaptive_compliance_exception_v6_explicit_deny.py \
  scripts/validate_adaptive_compliance_exception_v6_oidc_claim_deltas.py \
  scripts/validate_adaptive_compliance_exception_v6_sqs_sourcearn_deltas.py \
  scripts/validate_adaptive_compliance_exception_v6_public_scope.py
do
  echo
  echo "######## $f ########"
  if [ -f "$f" ]; then
    wc -l "$f"
    grep -nE '^(INPUT|OUT_|DETAIL|SUMMARY|CANDIDATE|EXPECTED)|argparse|sys\.argv|def main|if __name__|read_csv|DictReader|writer|fieldnames|case_id|semantic_failure|control_policy_file|poison_policy_file|validation_family|final_outcome|exact|validated|simulate_custom_policy|boto3\.client' \
      "$f" \
      | sed -n '1,220p'
  else
    echo "MISSING"
  fi
done

echo
echo "=== EVIDENCE TABLE HEADERS FROM ORIGINAL TARGET ==="
python3 - <<'PY'
from pathlib import Path
import csv
from collections import Counter

ROOT = Path.cwd()
target = ROOT / "accept_upgrade_audit/regression_original_authority_v1/original_authority_regression_target_v1.csv"

with target.open(newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

evidence_paths = sorted({r["evidence"] for r in rows if r.get("evidence")})

print("evidence files:", len(evidence_paths))
for ep in evidence_paths:
    p = ROOT / ep
    print()
    print("=" * 100)
    print(ep)
    print("exists:", p.exists())
    if not p.exists():
        continue
    with p.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        print("fields:", reader.fieldnames)
        sample = []
        for i, r in enumerate(reader):
            if i < 3:
                sample.append(r)
            else:
                break
    print("first rows:")
    for r in sample:
        print({k: r.get(k, "") for k in (reader.fieldnames or [])[:18]})

print()
print("families:", dict(Counter(r["validation_family"] for r in rows)))
print("final_outcomes:", dict(Counter(r["final_outcome"] for r in rows)))
PY
