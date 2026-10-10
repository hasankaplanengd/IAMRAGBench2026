# E2E BM25 CheckNoNewAccess v1

This evaluates Access Analyzer CheckNoNewAccess for the eight provider-valid semantic candidates in the end-to-end BM25 regime.

## Summary

| Group | Rows | New access flagged | No new access | Review/error | Exact attacks | Exact flagged | Exact passed | Exact review/error |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| all | 8 | 7 | 1 | 0 | 7 | 6 | 1 | 0 |
| model=Llama 3 8B | 4 | 4 | 0 | 0 | 4 | 4 | 0 | 0 |
| model=Nova Lite | 1 | 1 | 0 | 0 | 1 | 1 | 0 | 0 |
| model=Nova Pro | 3 | 2 | 1 | 0 | 2 | 1 | 1 | 0 |

## Files

- `accept_upgrade_audit/gate_eval_v2/e2e_checknonewaccess/e2e_bm25_check_no_new_access_detail_v1.csv`
- `accept_upgrade_audit/gate_eval_v2/e2e_checknonewaccess/e2e_bm25_check_no_new_access_summary_v1.csv`
