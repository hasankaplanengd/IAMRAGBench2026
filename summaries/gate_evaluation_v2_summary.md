# Gate evaluation v2

This gate evaluation uses existing frozen outputs and the completed E2E BM25 CheckNoNewAccess pass.

## Scope

- Provider-valid clean controls covered: **880**
- Provider-valid semantic candidates covered: **194**
- Exact-confirmed authorization deltas covered: **171**
- Goal-matched exact attacks covered: **168**
- Exact-or-provider-corroborated cases covered: **177**

Included scopes:
- `included_context`: clean controls=292, candidates=57, exact=49, provider-or-exact=52
- `e2e_bm25`: clean controls=294, candidates=8, exact=7, provider-or-exact=8
- `authority_original_two_model`: clean controls=116, candidates=84, exact=74, provider-or-exact=76
- `authority_missing_three_extension`: clean controls=178, candidates=45, exact=41, provider-or-exact=41

## Overall gate outcomes

| Gate | Clean accept | Candidates blocked | Candidates accepted | Review | Exact deltas blocked | Exact deltas accepted | Exact deltas review |
|---|---:|---:|---:|---:|---:|---:|---:|
| `provider_valid_only` | 880/880 | 0 | 194 | 0 | 0/171 | 171 | 0 |
| `check_no_new_access_only` | 880/880 | 186 | 8 | 0 | 167/171 | 4 | 0 |
| `semantic_envelope_only` | 880/880 | 194 | 0 | 0 | 171/171 | 0 | 0 |
| `full_proposal_to_commit` | 880/880 | 189 | 0 | 5 | 171/171 | 0 | 0 |

The four exact deltas accepted by `check_no_new_access_only` are all
goal-matched. Its exact-delta acceptance is therefore 4/171 (2.34%),
while its goal-matched attack acceptance is 4/168 (2.38%).

## Interpretation

- `provider_valid_only` models deployment after policy-form validation alone.
- `check_no_new_access_only` accepts candidates when Access Analyzer reports no new access and blocks candidates when it reports possible new access.
- `semantic_envelope_only` blocks every semantic violation of the trusted authorization envelope.
- `full_proposal_to_commit` blocks exact-confirmed authorization deltas and routes provider-corroborated exact-witness-unresolved cases to review.

## Output files

- `tables/table_gate_evaluation_candidate_ledger_v2.csv`
- `tables/table_gate_evaluation_v2.csv`
- `tables/table_gate_evaluation_by_regime_v2.csv`
- `tables/table_gate_evaluation_by_model_v2.csv`
- `tables/table_gate_evaluation_missed_cases_v2.csv`
