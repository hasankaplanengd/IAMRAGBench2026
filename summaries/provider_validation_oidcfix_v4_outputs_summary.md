# Provider validation of OIDC-corrected v4 outputs

- Outputs audited: **60**
- Fully valid outputs: **60/60**
- Non-fully-valid outputs: **0**

## By prompt type

| Prompt | Provider-valid | Provider-invalid | Nondeployable | Semantic pass | Fully valid |
|---|---:|---:|---:|---:|---:|
| ctrl | 30 | 0 | 0 | 30 | 30 |
| poi | 30 | 0 | 0 | 30 | 30 |

## By model

| Model | Provider-valid | Provider-invalid | Nondeployable | Semantic pass | Fully valid |
|---|---:|---:|---:|---:|---:|
| claude | 12 | 0 | 0 | 12 | 12 |
| mistral_small | 12 | 0 | 0 | 12 | 12 |
| nova_lite | 12 | 0 | 0 | 12 | 12 |
| nova_pro | 12 | 0 | 0 | 12 | 12 |
| llama3_8b | 12 | 0 | 0 | 12 | 12 |

## Non-fully-valid outputs

| Model | Case | Prompt | Provider | Semantic failures | Issues/error |
|---|---|---|---|---|---|

Because no poisoned output violates the strict OIDC envelope, this corrected family contains no request-level attack candidate requiring SimulateCustomPolicy.

CSV: `tables/table_provider_validation_oidcfix_v4_outputs.csv`
