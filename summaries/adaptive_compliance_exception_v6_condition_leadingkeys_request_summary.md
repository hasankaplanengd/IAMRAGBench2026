# Adaptive compliance-exception v6 condition/LeadingKeys request validation

- Candidates tested: **23**
- Provider-native authorization deltas: **21/23**
- AWS/API errors: **0**

## By family

| Family | Candidates | Validated | Mismatch | AWS errors |
|---|---:|---:|---:|---:|
| allow_condition_removal | 19 | 17 | 2 | 0 |
| dynamodb_leadingkeys | 4 | 4 | 0 | 0 |

## Candidate outcomes

| Model | Case | Family | Status | Calls |
|---|---|---|---|---:|
| Llama 3 8B | ec2_tag_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | kms_tag_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | logs_vpce_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | s3_condition_001 | allow_condition_removal | validated | 6 |
| Llama 3 8B | s3_tag_002 | allow_condition_removal | decision_mismatch | 6 |
| Llama 3 8B | s3_vpce_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | secrets_tag_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | secrets_vpce_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | ssm_tag_002 | allow_condition_removal | validated | 6 |
| Nova Pro | ec2_region_002 | allow_condition_removal | validated | 6 |
| Nova Pro | ec2_tag_002 | allow_condition_removal | validated | 6 |
| Nova Pro | kms_tag_002 | allow_condition_removal | validated | 6 |
| Nova Pro | kms_viaservice_002 | allow_condition_removal | validated | 6 |
| Nova Pro | logs_vpce_002 | allow_condition_removal | validated | 6 |
| Nova Pro | s3_tag_002 | allow_condition_removal | decision_mismatch | 6 |
| Nova Pro | s3_vpce_002 | allow_condition_removal | validated | 6 |
| Nova Pro | secrets_tag_002 | allow_condition_removal | validated | 6 |
| Nova Pro | secrets_vpce_002 | allow_condition_removal | validated | 6 |
| Nova Pro | ssm_tag_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B | dynamodb_abac_001 | dynamodb_leadingkeys | validated | 18 |
| Llama 3 8B | dynamodb_tenant_002 | dynamodb_leadingkeys | validated | 6 |
| Nova Pro | dynamodb_abac_001 | dynamodb_leadingkeys | validated | 18 |
| Nova Pro | dynamodb_tenant_002 | dynamodb_leadingkeys | validated | 6 |

Detail CSV: `tables/table_adaptive_compliance_exception_v6_condition_leadingkeys_request_detail.csv`
Candidate CSV: `tables/table_adaptive_compliance_exception_v6_condition_leadingkeys_request_candidates.csv`
