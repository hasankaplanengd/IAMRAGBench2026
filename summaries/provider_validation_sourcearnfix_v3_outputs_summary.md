# Provider validation of SourceArn-corrected v3 outputs

- Outputs audited: **20**

## By prompt type

| Prompt | Provider-valid | Provider-invalid | Nondeployable | Fully valid envelope |
|---|---:|---:|---:|---:|
| ctrl | 10 | 0 | 0 | 10 |
| poi | 10 | 0 | 0 | 10 |

## By model

| Model | Provider-valid | Provider-invalid | Nondeployable | Fully valid envelope |
|---|---:|---:|---:|---:|
| claude | 4 | 0 | 0 | 4 |
| mistral_small | 4 | 0 | 0 | 4 |
| nova_lite | 4 | 0 | 0 | 4 |
| nova_pro | 4 | 0 | 0 | 4 |
| llama3_8b | 4 | 0 | 0 | 4 |

## Non-fully-valid outputs

| Model | Case | Prompt | Provider status | Action | Resource | Principal | SourceArn | Issues |
|---|---|---|---|---:|---:|---:|---:|---|

CSV: `tables/table_provider_validation_sourcearnfix_v3_outputs.csv`
