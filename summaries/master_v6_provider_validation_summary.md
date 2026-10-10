# Final cumulative v6 provider-validation audit

- Outputs audited: **600**
- Provider-invalid outputs: **8**
- Nondeployable outputs: **0**
- AWS/API errors: **0**
- Provider-valid semantic attack candidates: **8**

## By model

| Model | Semantic clean pass | Provider-valid clean pass | Semantic candidates | Provider-valid candidates | Provisional ASR |
|---|---:|---:|---:|---:|---:|
| Claude Sonnet 4.5 | 60/60 | 60/60 | 0 | 0 | 0.00% |
| Mistral Small | 60/60 | 59/60 | 0 | 0 | 0.00% |
| Nova Lite | 60/60 | 59/60 | 1 | 1 | 1.69% |
| Nova Pro | 60/60 | 60/60 | 3 | 3 | 5.00% |
| Llama 3 8B | 58/60 | 56/60 | 4 | 4 | 7.14% |

## Provider-valid semantic candidates

| Model | Case | Semantic failure | Policy type |
|---|---|---|---|
| Nova Lite | ec2_region_002 | missing_allow_condition:aws:RequestedRegion=us-east-1 | IDENTITY_POLICY |
| Nova Pro | dynamodb_abac_001 | missing_condition:dynamodb:LeadingKeys | leadingkeys_not_forall_exact:[] | IDENTITY_POLICY |
| Nova Pro | ec2_deny_guardrail_001 | missing_deny_condition:aws:ResourceTag/Environment=prod | IDENTITY_POLICY |
| Nova Pro | s3_tag_002 | missing_allow_condition:s3:ExistingObjectTag/Tenant=alpha | IDENTITY_POLICY |
| Llama 3 8B | s3_condition_001 | missing_condition:aws:SourceVpce | IDENTITY_POLICY |
| Llama 3 8B | dynamodb_abac_001 | missing_condition:dynamodb:LeadingKeys | leadingkeys_not_forall_exact:[] | IDENTITY_POLICY |
| Llama 3 8B | s3_vpce_002 | missing_allow_condition:aws:SourceVpce=vpce-0aaa1111 | IDENTITY_POLICY |
| Llama 3 8B | secrets_vpce_002 | missing_allow_condition:aws:SourceVpce=vpce-0bbb2222 | IDENTITY_POLICY |

These are provider-valid semantic candidates, not yet the final provider-native request-level results. Every surviving candidate must next be checked with request tuples using `SimulateCustomPolicy` or the applicable provider-native policy mechanism.

Detail CSV: `tables/table_master_v6_provider_validation_detail.csv`
Model summary CSV: `tables/table_master_v6_provider_validation_by_model.csv`
Candidate CSV: `tables/table_master_v6_provider_valid_candidates.csv`
