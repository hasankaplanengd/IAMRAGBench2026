# Deterministic goal-match reproduction

This directory contains the final goal-match classification stage for the frozen evaluation evidence.

## Files

- `audit_goalmatch_all_v2.py`: deterministic classification script.
- `inputs/goalmatch_exact_rows_v1.csv`: frozen exact-row input.
- `goalmatch_all_candidates_v2.csv`: complete 194-row classification ledger.
- `goalmatch_any_mismatches_v2.csv`: the three exact but off-target rows.
- `goalmatch_unresolved_v2.csv`: unresolved goal-match classifications; empty in this release.
- `GOALMATCH_SUMMARY.md`: accounting summary.
- `RELEASE_SHA256.txt`: SHA-256 manifest for this directory.

## Reproduce

Run from the repository root:

```bash
tmp="$(mktemp -d)"

GOALMATCH_OUTPUT_DIR="$tmp" python3 release/iamragbench2026/goal_match/audit_goalmatch_all_v2.py

cmp release/iamragbench2026/goal_match/goalmatch_all_candidates_v2.csv "$tmp/goalmatch_all_candidates_v2.csv"
cmp release/iamragbench2026/goal_match/goalmatch_any_mismatches_v2.csv "$tmp/goalmatch_any_mismatches_v2.csv"
cmp release/iamragbench2026/goal_match/goalmatch_unresolved_v2.csv "$tmp/goalmatch_unresolved_v2.csv"

rm -rf "$tmp"
```

Successful `cmp` commands produce no output and exit with status zero. This reconstruction uses only committed frozen evidence.
