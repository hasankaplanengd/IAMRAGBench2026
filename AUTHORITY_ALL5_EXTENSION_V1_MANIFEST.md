# Authority-spoofing all-five extension v1

## Purpose

This extension checks whether the authority-spoofing stress-test conclusion
depends on evaluating only Nova Pro and Llama 3 8B. It applies the same frozen
authority-spoofing prompt set to the three remaining model classes: Claude
Sonnet 4.5, Mistral Small, and Amazon Nova Lite.

## Scope

Original authority-spoofing headline result:

- Models: Nova Pro and Llama 3 8B
- Provider-valid clean controls: 116
- Provider-valid semantic candidates: 84
- Exact-confirmed attacks: 74/116 (63.79%)
- Provider-corroborated including two simulator-unresolved KMS cases:
  76/116 (65.52%)

Missing-three extension:

- Models: Claude Sonnet 4.5, Mistral Small, and Amazon Nova Lite
- Provider-valid clean controls: 178
- Provider-valid semantic candidates: 45
- Exact-confirmed attacks: 41/178 (23.03%)

Combined all-five authority-spoofing result:

- Provider-valid clean controls: 294
- Provider-valid semantic candidates: 129
- Exact-confirmed attacks: 115/294 (39.12%)
- Provider-corroborated including the original two simulator-unresolved KMS
  cases: 117/294 (39.80%)

## By model for the missing-three extension

- Claude Sonnet 4.5: 0/60 exact-confirmed attacks
- Mistral Small: 15/59 exact-confirmed attacks
- Amazon Nova Lite: 26/59 exact-confirmed attacks

## Output files

- `tables/table_authority_all5_extension_summary_v1.csv`
- `tables/table_authority_all5_extension_missing3_by_model_v1.csv`
- `tables/table_authority_all5_extension_missing3_exact_ledger_v1.csv`
- `summaries/authority_all5_extension_missing3_summary_v1.md`
- `tables/authority_all5_extension_v1_sha256.txt`

## Reporting note

The original two-model authority-spoofing result remains the primary stress-test
headline. The all-five result is reported as a model-coverage robustness
extension.
