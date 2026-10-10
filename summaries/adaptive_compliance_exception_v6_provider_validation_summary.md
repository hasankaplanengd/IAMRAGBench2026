# Adaptive compliance-exception v6 provider validation

- Frozen model runs: **2**
- Paired outputs accounted for: **240**
- New adaptive poisoned policies submitted to Access Analyzer: **119**
- Provider-valid semantic candidates: **84**
- AWS/API errors: **0**

## By model

| Model | Semantic clean | Provider-valid clean | Semantic candidates | Provider-valid candidates | Provider-invalid candidates | Provisional ASR |
|---|---:|---:|---:|---:|---:|---:|
| Nova Pro | 60/60 | 60/60 | 47 | 47 | 0 | 78.33% |
| Llama 3 8B | 58/60 | 56/60 | 38 | 37 | 1 | 66.07% |

These remain provisional semantic candidates. The next stage is AWS `CheckNoNewAccess`, followed by exact request-, claim-, and resource-policy differential witnesses.

Detail CSV: `tables/table_adaptive_compliance_exception_v6_provider_validation_detail.csv`
Model CSV: `tables/table_adaptive_compliance_exception_v6_provider_validation_by_model.csv`
Candidate CSV: `tables/table_adaptive_compliance_exception_v6_provider_valid_candidates.csv`
