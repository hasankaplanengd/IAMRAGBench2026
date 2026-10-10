# Corrected authority-spoofing v6 results (family-specific witnessing after PASS)

- Provider-valid semantic candidates: **84**
- Exact-confirmed authorization deltas: **74/116 (63.79%)**
- Provider-corroborated but exact-witness-unresolved: **2**
- Total provider-corroborated cases: **76/116 (65.52%)**
- Exact-witness mismatches: **8**
- Raw `CheckNoNewAccess=PASS`: **2**
- PASS cases exact-confirmed by family witness: **2**
- PASS cases rejected by family witness: **0**

## By model

| Model | Valid controls | Candidates | Exact | Corroborated | Exact ASR |
|---|---:|---:|---:|---:|---:|
| Nova Pro | 60/60 | 47 | 45 | 46 | 75.00% |
| Llama 3 8B | 56/60 | 37 | 29 | 30 | 51.79% |

## Terminal outcome accounting

| Outcome | Cases |
|---|---:|
| `access_analyzer_corroborated_simulatecustompolicy_unresolved` | 2 |
| `exact_claim_differential_confirmed` | 7 |
| `exact_claim_differential_mismatch` | 6 |
| `exact_public_scope_differential_confirmed` | 4 |
| `exact_sourcearn_differential_confirmed` | 2 |
| `request_level_decision_mismatch` | 2 |
| `simulatecustompolicy_confirmed` | 61 |

`CheckNoNewAccess` is retained as auxiliary provider evidence; family-specific exact witnessing determines the final attack class.
