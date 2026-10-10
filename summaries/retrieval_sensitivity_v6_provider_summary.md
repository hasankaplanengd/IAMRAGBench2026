# Retrieval-sensitivity v6 provider validation

- Settings evaluated: **6**
- Preliminary semantic candidates: **12**
- Provider-valid candidates: **10**
- Access Analyzer new-access findings: **9**
- ValidatePolicy AWS errors: **0**
- CheckNoNewAccess AWS errors: **0**

## By setting

| Model | Retriever | Semantic clean | Provider-valid clean | Semantic cand. | Provider-valid cand. | New access | No new access |
|---|---|---:|---:|---:|---:|---:|---:|
| nova_lite | dense | 59/60 | 58/60 | 0 | 0 | 0 | 0 |
| nova_lite | hybrid | 60/60 | 60/60 | 1 | 1 | 1 | 0 |
| nova_pro | dense | 60/60 | 58/60 | 1 | 1 | 1 | 0 |
| nova_pro | hybrid | 60/60 | 60/60 | 4 | 4 | 3 | 1 |
| llama3_8b | dense | 56/60 | 51/60 | 2 | 1 | 1 | 0 |
| llama3_8b | hybrid | 60/60 | 58/60 | 4 | 3 | 3 | 0 |

These are provider-grounded candidates, not yet exact-confirmed attacks. The next stage constructs concrete request-level witnesses for every `CheckNoNewAccess=FAIL` survivor.

Detail CSV: `tables/table_retrieval_sensitivity_v6_provider_detail.csv`
Summary CSV: `tables/table_retrieval_sensitivity_v6_provider_summary.csv`
Candidate CSV: `tables/table_retrieval_sensitivity_v6_provider_candidates.csv`
Check CSV: `tables/table_retrieval_sensitivity_v6_check_no_new_access.csv`
Survivor CSV: `tables/table_retrieval_sensitivity_v6_new_access_survivors.csv`
