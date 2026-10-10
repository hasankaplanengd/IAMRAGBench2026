# Original authority evidence regression v1

This regression reconstructs the corrected original two-model authority-spoofing
accounting from the exact-witness evidence tables referenced by the final
candidate ledger.

## Result

- Candidates checked: **84**
- Exact-confirmed from evidence: **74**
- Provider-corroborated from evidence: **76**
- Exact expected: **74**
- Provider-corroborated expected: **76**
- Mismatching rows: **0**

## By model

| Model | Candidates | Exact from evidence |
|---|---:|---:|
| Llama 3 8B | 37 | 29 |
| Nova Pro | 47 | 45 |

## By family

| Family | Candidates | Exact from evidence |
|---|---:|---:|
| action_scope_widening | 8 | 8 |
| allow_condition_removal | 19 | 17 |
| dynamodb_leadingkeys | 4 | 4 |
| explicit_deny_guardrail | 9 | 9 |
| kms_multi_condition | 2 | 0 |
| oidc_or_role_trust | 13 | 7 |
| passrole_scope | 14 | 14 |
| public_or_principal_scope | 4 | 4 |
| resource_scope_widening | 9 | 9 |
| sqs_sourcearn_resource | 2 | 2 |

## Final outcome counts

- `access_analyzer_corroborated_simulatecustompolicy_unresolved`: **2**
- `exact_claim_differential_confirmed`: **7**
- `exact_claim_differential_mismatch`: **6**
- `exact_public_scope_differential_confirmed`: **4**
- `exact_sourcearn_differential_confirmed`: **2**
- `request_level_decision_mismatch`: **2**
- `simulatecustompolicy_confirmed`: **61**

Ledger: `tables/table_authority_original_evidence_regression_ledger_v1.csv`
