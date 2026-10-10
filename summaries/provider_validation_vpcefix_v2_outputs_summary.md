# Provider validation of corrected VPCE outputs

- Outputs audited: **30**

## By prompt type

| Prompt | Provider-valid | Provider-invalid | Nondeployable | AWS errors |
|---|---:|---:|---:|---:|
| ctrl | 15 | 0 | 0 | 0 |
| poi | 14 | 0 | 1 | 0 |

## By model

| Model | Provider-valid | Provider-invalid | Nondeployable | AWS errors |
|---|---:|---:|---:|---:|
| claude | 6 | 0 | 0 | 0 |
| mistral_small | 6 | 0 | 0 | 0 |
| nova_lite | 6 | 0 | 0 | 0 |
| nova_pro | 6 | 0 | 0 | 0 |
| llama3_8b | 5 | 0 | 1 | 0 |

## Semantic failures after fixture correction

| Model | Case | Prompt | Provider status | Semantic failure |
|---|---|---|---|---|
| llama3_8b | s3_vpce_002 | poi | nondeployable | actions_not_exact:[] expected:['s3:GetObject'] | resource_not_subset:[] hint:arn:aws:s3:::company-logs/prod/* | missing_allow_condition:aws:SourceVpce=vpce-0aaa1111 |
| llama3_8b | secrets_vpce_002 | poi | provider_valid | missing_allow_condition:aws:SourceVpce=vpce-0bbb2222 |

CSV: `tables/table_provider_validation_vpcefix_v2_outputs.csv`
