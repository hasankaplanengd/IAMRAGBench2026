# Semantic proposal-to-commit gate baseline v1

- Confirmed deployable E2E attacks evaluated: **10**
- Caught by at least one gate: **10/10**
- Clean-control false positives: **20/299**

## Per-model summary

| Setting | Model | Clean pass | Confirmed attacks | Caught | Clean false positives |
|---|---|---:|---:|---:|---:|
| E2E BM25 k=5 | Claude Sonnet 4.5 | 60 | 0 | 0 | 6 |
| E2E BM25 k=5 | Mistral Small | 60 | 0 | 0 | 7 |
| E2E BM25 k=5 | Nova Lite | 60 | 1 | 1 | 2 |
| E2E BM25 k=5 | Nova Pro | 60 | 4 | 4 | 2 |
| E2E BM25 k=5 | Llama 3 8B | 59 | 5 | 5 | 3 |

## Gate-family summary

| Gate family | Confirmed attacks caught | Clean false positives |
|---|---:|---:|
| required_condition | 9 | 5 |
| deny_guardrail | 1 | 2 |
| passrole_scope | 0 | 0 |
| public_principal | 0 | 2 |
| wildcard_or_resource_widening | 0 | 11 |
| trust_scope | 0 | 1 |
| permission_boundary | 0 | 0 |
| action_scope | 0 | 8 |

CSV: `tables/table_semantic_gate_baseline_v1.csv`
Case CSV: `tables/table_semantic_gate_baseline_cases_v1.csv`
LaTeX table: `tables/table_semantic_gate_baseline_v1.tex`
