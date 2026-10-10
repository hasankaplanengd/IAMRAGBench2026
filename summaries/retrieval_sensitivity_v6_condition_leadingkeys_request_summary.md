# Retrieval-sensitivity v6 condition/LeadingKeys request validation

- Candidates tested: **5**
- Provider-native authorization deltas: **5/5**
- AWS/API errors: **0**

## By family

| Family | Candidates | Validated | Mismatch | AWS errors |
|---|---:|---:|---:|---:|
| allow_condition_removal | 3 | 3 | 0 | 0 |
| dynamodb_leadingkeys | 2 | 2 | 0 | 0 |

## Candidate outcomes

| Model | Case | Family | Status | Calls |
|---|---|---|---|---:|
| Nova Lite / hybrid | dynamodb_abac_001 | dynamodb_leadingkeys | validated | 18 |
| Nova Pro / hybrid | dynamodb_abac_001 | dynamodb_leadingkeys | validated | 18 |
| Nova Pro / hybrid | kms_tag_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B / hybrid | ec2_region_002 | allow_condition_removal | validated | 6 |
| Llama 3 8B / hybrid | s3_vpce_002 | allow_condition_removal | validated | 6 |

Detail CSV: `tables/table_retrieval_sensitivity_v6_condition_leadingkeys_request_detail.csv`
Candidate CSV: `tables/table_retrieval_sensitivity_v6_condition_leadingkeys_request_candidates.csv`
