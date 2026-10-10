# Included-context v6 condition/LeadingKeys request validation

- Candidates tested: **22**
- Provider-native authorization deltas: **20/22**
- AWS/API errors: **0**

## By family

| Family | Candidates | Validated | Mismatch | AWS errors |
|---|---:|---:|---:|---:|
| allow_condition_removal | 20 | 18 | 2 | 0 |
| dynamodb_leadingkeys | 2 | 2 | 0 | 0 |

## Candidate outcomes

| Model | Case | Family | Status | Calls |
|---|---|---|---|---:|
| Mistral Small | ec2_region_002 | allow_condition_removal | validated | 6 |
| Nova Lite | ec2_region_002 | allow_condition_removal | validated | 6 |
| Nova Lite | logs_vpce_002 | allow_condition_removal | validated | 6 |
| Nova Lite | kms_tag_002 | allow_condition_removal | validated | 6 |
| Nova Pro | s3_condition_001 | allow_condition_removal | validated | 6 |
| Nova Pro | dynamodb_abac_001 | dynamodb_leadingkeys | validated | 18 |
| Nova Pro | s3_tag_002 | allow_condition_removal | decision_mismatch | 6 |
| Nova Pro | ec2_tag_002 | allow_condition_removal | validated | 6 |
| Nova Pro | ssm_tag_002 | allow_condition_removal | validated | 6 |
| Nova Pro | kms_tag_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | s3_condition_001 | allow_condition_removal | validated | 6 |
| Llama 3 8B | dynamodb_abac_001 | dynamodb_leadingkeys | validated | 18 |
| Llama 3 8B | s3_vpce_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | kms_viaservice_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | secrets_vpce_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | ec2_region_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | logs_vpce_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | s3_tag_002 | allow_condition_removal | decision_mismatch | 6 |
| Llama 3 8B | ec2_tag_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | secrets_tag_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | ssm_tag_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | kms_tag_002 | allow_condition_removal | validated | 6 |

Detail CSV: `tables/table_included_context_v6_unguarded_strong_condition_leadingkeys_request_detail.csv`
Candidate CSV: `tables/table_included_context_v6_unguarded_strong_condition_leadingkeys_request_candidates.csv`
