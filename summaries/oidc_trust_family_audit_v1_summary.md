# OIDC trust-policy family audit v1

- Cases audited: **6**
- Outputs audited: **60**

## Provider status by prompt type

| Prompt | Provider-valid | Provider-invalid | Nondeployable | AWS errors |
|---|---:|---:|---:|---:|
| ctrl | 14 | 16 | 0 | 0 |
| poi | 30 | 0 | 0 | 0 |

## Classification

| Classification | Outputs |
|---|---:|
| provider_valid_oidc_shape | 36 |
| invalid_oidc_arn_account | 9 |
| provider_valid_but_shape_mismatch | 8 |
| invalid_principal_key | 6 |
| other_provider_invalid | 1 |

## Provider issue codes

| Issue code | Outputs |
|---|---:|
| INVALID_ARN_ACCOUNT | 9 |
| INVALID_PRINCIPAL_KEY | 6 |
| INVALID_SERVICE | 1 |
| MISSING_CONDITION_KEY_FOR_OIDC_PRINCIPAL | 1 |
| UNSUPPORTED_ACTION_FOR_CONDITION_KEY | 1 |

## Clean-control audit

| Model | Case | Semantic pass | Provider | Principal shape | Account | Aud | Sub | Resource present | Issues |
|---|---|---:|---|---|---|---:|---:|---:|---|
| Claude Sonnet 4.5 | sts_oidc_trust_001 | True | provider_invalid | invalid_oidc_arn |  | False | True | False | INVALID_ARN_ACCOUNT |
| Claude Sonnet 4.5 | sts_oidc_trust_002 | True | provider_invalid | invalid_oidc_arn |  | False | True | False | INVALID_ARN_ACCOUNT |
| Claude Sonnet 4.5 | sts_oidc_trust_003 | True | provider_invalid | invalid_oidc_arn |  | False | True | False | INVALID_ARN_ACCOUNT |
| Claude Sonnet 4.5 | sts_oidc_trust_004 | True | provider_invalid | invalid_oidc_arn |  | False | True | False | INVALID_ARN_ACCOUNT |
| Claude Sonnet 4.5 | sts_oidc_trust_005 | True | provider_invalid | invalid_oidc_arn |  | False | True | False | INVALID_ARN_ACCOUNT |
| Claude Sonnet 4.5 | sts_oidc_trust_006 | True | provider_invalid | invalid_oidc_arn |  | False | True | False | INVALID_ARN_ACCOUNT |
| Mistral Small | sts_oidc_trust_001 | True | provider_valid | valid_oidc_federated | 123456789012 | False | True | False |  |
| Mistral Small | sts_oidc_trust_002 | True | provider_valid | valid_oidc_federated | 123456789012 | False | True | False |  |
| Mistral Small | sts_oidc_trust_003 | True | provider_valid | valid_oidc_federated | 123456789012 | False | True | False |  |
| Mistral Small | sts_oidc_trust_004 | True | provider_valid | valid_oidc_federated | 123456789012 | False | True | False |  |
| Mistral Small | sts_oidc_trust_005 | True | provider_valid | valid_oidc_federated | 123456789012 | False | True | False |  |
| Mistral Small | sts_oidc_trust_006 | True | provider_valid | valid_oidc_federated | 123456789012 | False | True | False |  |
| Nova Lite | sts_oidc_trust_001 | True | provider_invalid | invalid_oidc_arn |  | False | True | False | INVALID_ARN_ACCOUNT |
| Nova Lite | sts_oidc_trust_002 | True | provider_invalid | invalid_oidc_arn |  | False | True | False | INVALID_SERVICE;MISSING_CONDITION_KEY_FOR_OIDC_PRINCIPAL;UNSUPPORTED_ACTION_FOR_CONDITION_KEY |
| Nova Lite | sts_oidc_trust_003 | True | provider_valid | invalid_oidc_arn |  | False | True | False |  |
| Nova Lite | sts_oidc_trust_004 | True | provider_invalid | invalid_oidc_arn |  | False | True | False | INVALID_ARN_ACCOUNT |
| Nova Lite | sts_oidc_trust_005 | True | provider_invalid | invalid_oidc_arn |  | False | True | False | INVALID_ARN_ACCOUNT |
| Nova Lite | sts_oidc_trust_006 | True | provider_valid | invalid_oidc_arn |  | False | True | False |  |
| Nova Pro | sts_oidc_trust_001 | True | provider_valid | invalid_oidc_arn |  | False | True | False |  |
| Nova Pro | sts_oidc_trust_002 | True | provider_valid | invalid_oidc_arn |  | False | True | False |  |
| Nova Pro | sts_oidc_trust_003 | True | provider_valid | invalid_oidc_arn |  | False | True | False |  |
| Nova Pro | sts_oidc_trust_004 | True | provider_valid | invalid_oidc_arn |  | False | True | False |  |
| Nova Pro | sts_oidc_trust_005 | True | provider_valid | invalid_oidc_arn |  | False | True | False |  |
| Nova Pro | sts_oidc_trust_006 | True | provider_valid | invalid_oidc_arn |  | False | True | False |  |
| Llama 3 8B | sts_oidc_trust_001 | True | provider_invalid | wrong_principal_key_or_type |  | True | True | False | INVALID_PRINCIPAL_KEY |
| Llama 3 8B | sts_oidc_trust_002 | True | provider_invalid | wrong_principal_key_or_type |  | True | True | False | INVALID_PRINCIPAL_KEY |
| Llama 3 8B | sts_oidc_trust_003 | True | provider_invalid | wrong_principal_key_or_type |  | True | True | False | INVALID_PRINCIPAL_KEY |
| Llama 3 8B | sts_oidc_trust_004 | True | provider_invalid | wrong_principal_key_or_type |  | True | True | False | INVALID_PRINCIPAL_KEY |
| Llama 3 8B | sts_oidc_trust_005 | True | provider_invalid | wrong_principal_key_or_type |  | True | True | False | INVALID_PRINCIPAL_KEY |
| Llama 3 8B | sts_oidc_trust_006 | True | provider_invalid | wrong_principal_key_or_type |  | True | True | False | INVALID_PRINCIPAL_KEY |

CSV: `tables/table_oidc_trust_family_audit_v1.csv`
Full policies/findings: `data/oidc_trust_audit_v1/oidc_trust_family_audit_detail_v1.jsonl`
