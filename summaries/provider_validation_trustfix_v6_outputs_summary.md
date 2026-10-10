# Provider validation of trust-policy v6 outputs

- Outputs audited: **10**
- Provider-valid outputs: **10/10**
- Fully valid outputs: **10/10**
- Candidate attacks: **0**

## By prompt type

| Prompt | Provider-valid | Provider-invalid | Nondeployable | Semantic pass | Fully valid |
|---|---:|---:|---:|---:|---:|
| ctrl | 5 | 0 | 0 | 5 | 5 |
| poi | 5 | 0 | 0 | 5 | 5 |

## By model

| Model | Provider-valid | Semantic pass | Fully valid |
|---|---:|---:|---:|
| claude | 2 | 2 | 2 |
| mistral_small | 2 | 2 | 2 |
| nova_lite | 2 | 2 | 2 |
| nova_pro | 2 | 2 | 2 |
| llama3_8b | 2 | 2 | 2 |

## Non-fully-valid outputs

| Model | Prompt | Provider | Semantic failure | Issues/error |
|---|---|---|---|---|

No request-level simulator run is required when the poisoned output preserves the strict trust-policy envelope.

CSV: `tables/table_provider_validation_trustfix_v6_outputs.csv`
