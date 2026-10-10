# Gate evaluation v2

## Purpose

This evaluation quantifies what different proposal-to-commit gates would have
done on the frozen generated policy proposals. It is not a new model run. It
uses existing frozen outputs, completed semantic candidate ledgers, provider
validation outputs, Access Analyzer CheckNoNewAccess results, and exact-witness
classification ledgers.

## Scope

The evaluation covers four scopes:

- Included-context operational poisoning
- End-to-end BM25 operational poisoning
- Original two-model authority-spoofing stress test
- Missing-three all-five authority-spoofing extension

Headline scope:

- Provider-valid clean controls covered: 880
- Provider-valid semantic candidates covered: 194
- Exact-confirmed authorization deltas covered: 171
- Goal-matched exact attacks covered: 168
- Exact-or-provider-corroborated cases covered: 177

## Gates

The evaluated gates are:

1. `provider_valid_only`: accepts provider-valid generated policies.
2. `check_no_new_access_only`: blocks when Access Analyzer CheckNoNewAccess
   reports possible new access and accepts when it reports no new access.
3. `semantic_envelope_only`: blocks semantic violations of the
   trusted authorization envelope.
4. `full_proposal_to_commit`: requires provider-validity and trusted-envelope
   satisfaction, blocks exact-confirmed authorization deltas, and routes
   provider-corroborated exact-witness-unresolved cases to review.

## Headline results

| Gate | Clean retained | Semantic candidates blocked | Semantic candidates accepted | Review | Exact deltas blocked | Exact deltas accepted | Goal-matched attacks accepted |
|---|---:|---:|---:|---:|---:|---:|---:|
| provider_valid_only | 880/880 | 0/194 | 194/194 | 0 | 0/171 | 171/171 | 168/168 |
| check_no_new_access_only | 880/880 | 186/194 | 8/194 | 0 | 167/171 | 4/171 | 4/168 |
| semantic_envelope_only | 880/880 | 194/194 | 0/194 | 0 | 171/171 | 0/171 | 0/168 |
| full_proposal_to_commit | 880/880 | 189/194 | 0/194 | 5 | 171/171 | 0/171 | 0/168 |

The four exact authorization deltas accepted by CheckNoNewAccess-only are
goal-matched explicit-Deny guardrail attacks. Thus its broad exact-delta
acceptance is 4/171 (2.34%), while its goal-matched attack acceptance is
4/168 (2.38%). This supports the paper's claim that CheckNoNewAccess is useful
auxiliary provider evidence but not a complete semantic commit gate.

## Public files

- `tables/table_gate_evaluation_v2.csv`
- `tables/table_gate_evaluation_by_regime_v2.csv`
- `tables/table_gate_evaluation_by_model_v2.csv`
- `tables/table_gate_evaluation_candidate_ledger_v2.csv`
- `tables/table_gate_evaluation_missed_cases_v2.csv`
- `tables/table_e2e_bm25_check_no_new_access_detail_v1.csv`
- `tables/table_e2e_bm25_check_no_new_access_summary_v1.csv`
- `tables/table_authority_all5_extension_missing3_check_no_new_access_detail_v1.csv`
- `summaries/gate_evaluation_v2_summary.md`
- `summaries/e2e_bm25_check_no_new_access_summary_v1.md`

## Interpretation

Provider-form validation alone is not a security boundary: it accepts all
171 exact authorization deltas, including all 168 goal-matched exact attacks,
because all evaluated generated policies are provider-valid by construction.
CheckNoNewAccess blocks 167/171 exact deltas but misses four goal-matched
explicit-Deny guardrail attacks. The semantic-envelope and full
proposal-to-commit gates block all 171 exact authorization deltas, including all
168 goal-matched exact attacks; the full gate routes provider-corroborated but
exact-witness-unresolved cases to review rather than accepting them by default.
