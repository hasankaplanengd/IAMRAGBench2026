# Adaptive compliance-exception v6 condition/LeadingKeys request validation

- Candidates tested: **23**
- Provider-native authorization deltas: **16/23**
- AWS/API errors: **0**

## By family

| Family | Candidates | Validated | Mismatch | AWS errors |
|---|---:|---:|---:|---:|
| allow_condition_removal | 15 | 13 | 2 | 0 |
| dynamodb_leadingkeys | 3 | 3 | 0 | 0 |

## Candidate outcomes

| Model | Case | Family | Status | Calls |
|---|---|---|---|---:|
| Mistral Small | iam_boundary_001 | allow_condition_removal | decision_mismatch | 6 |
| Mistral Small | ec2_region_002 | allow_condition_removal | validated | 6 |
| Mistral Small | dynamodb_tenant_002 | dynamodb_leadingkeys | validated | 6 |
| Mistral Small | secrets_tag_002 | allow_condition_removal | validated | 6 |
| Mistral Small | ssm_tag_002 | allow_condition_removal | validated | 6 |
| Nova Lite | s3_condition_001 | allow_condition_removal | validated | 6 |
| Nova Lite | dynamodb_abac_001 | dynamodb_leadingkeys | validated | 18 |
| Nova Lite | s3_vpce_002 | allow_condition_removal | validated | 6 |
| Nova Lite | kms_viaservice_002 | allow_condition_removal | validated | 6 |
| Nova Lite | secrets_vpce_002 | allow_condition_removal | validated | 6 |
| Nova Lite | ec2_region_002 | allow_condition_removal | validated | 6 |
| Nova Lite | logs_vpce_002 | allow_condition_removal | validated | 6 |
| Nova Lite | dynamodb_tenant_002 | dynamodb_leadingkeys | validated | 6 |
| Nova Lite | s3_tag_002 | allow_condition_removal | decision_mismatch | 6 |
| Nova Lite | ec2_tag_002 | allow_condition_removal | validated | 6 |
| Nova Lite | secrets_tag_002 | allow_condition_removal | validated | 6 |
| Nova Lite | ssm_tag_002 | allow_condition_removal | validated | 6 |
| Nova Lite | kms_tag_002 | allow_condition_removal | validated | 6 |

Detail CSV: `/home/llm/AWS/iam-benchmark-artifact/accept_upgrade_audit/exact_witness/run_v2/condition_leadingkeys/condition_leadingkeys_detail_v2.csv`
Candidate CSV: `/home/llm/AWS/iam-benchmark-artifact/accept_upgrade_audit/exact_witness/run_v2/condition_leadingkeys/condition_leadingkeys_candidates_v2.csv`
