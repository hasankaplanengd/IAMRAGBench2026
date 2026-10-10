# Authority exact-witness regression v1

## Purpose

This regression checks that the original two-model authority-spoofing accounting
is reproduced from the final exact-witness evidence tables. It is included because
the all-five extension required adapter plumbing for the missing-three candidate
set.

## Regression target

The target is the corrected original authority-spoofing candidate ledger:

- `tables/table_adaptive_compliance_exception_v6_final_candidate_ledger_v2.csv`

Expected original authority-spoofing accounting:

- Candidates: 84
- Exact-confirmed attacks: 74
- Provider-corroborated cases: 76
- Non-exact candidates: 10
- Provider-corroborated but exact-witness-unresolved KMS cases: 2

## Regression result

The evidence regression reconstructs the corrected original Nova Pro and Llama
3 8B accounting from the exact-witness evidence tables referenced by the final
candidate ledger:

- Candidates checked: 84
- Exact-confirmed from evidence: 74
- Provider-corroborated from evidence: 76
- Mismatching rows: 0

By model:

- Nova Pro: 45 exact-confirmed attacks over 47 semantic candidates
- Llama 3 8B: 29 exact-confirmed attacks over 37 semantic candidates

## What this regression does and does not claim

This is an evidence-table regression. It verifies that the final original
authority candidate ledger and its exact-witness evidence tables reproduce the
published 74 exact-confirmed and 76 provider-corroborated cases. It is not a
fresh AWS re-execution of every original exact-witness call.

## Adapter audit for the all-five extension

The missing-three extension required adapter changes only for:

- file paths;
- expected candidate counts;
- model-label plumbing;
- column plumbing, including an explicit `api_error` column;
- routing candidates to the same family-level witness categories used by the
  original authority accounting.

Existing family decision semantics were not changed for the original two-model
evidence regression. The only additional case-specific evaluator introduced for
the missing-three extension is the public/resource-policy witness for
`secrets_public_002`, because the older public-scope validator did not include
that Secrets Manager public-principal case.

## Output files

- `tables/table_authority_original_evidence_regression_ledger_v1.csv`
- `summaries/authority_original_evidence_regression_summary_v1.md`
