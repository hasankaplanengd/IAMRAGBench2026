# Provider-validity audit of all E2E clean controls v1

- Semantic clean-pass outputs audited: **299**
- Provider-valid: **259**
- Provider-invalid: **40**
- Locally invalid: **0**
- AWS/API errors: **0**

## Per-model denominator audit

| Model | Semantic clean pass | Provider-valid clean pass | Provider-invalid | Local invalid | AWS errors |
|---|---:|---:|---:|---:|---:|
| Claude Sonnet 4.5 | 60 | 50 | 10 | 0 | 0 |
| Mistral Small | 60 | 56 | 4 | 0 | 0 |
| Nova Lite | 60 | 52 | 8 | 0 | 0 |
| Nova Pro | 60 | 55 | 5 | 0 | 0 |
| Llama 3 8B | 59 | 46 | 13 | 0 | 0 |

## Non-provider-valid controls

| Model | Case | Expected policy type | Status | Issue codes / error |
|---|---|---|---|---|
| Claude Sonnet 4.5 | logs_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Claude Sonnet 4.5 | s3_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Claude Sonnet 4.5 | secrets_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Claude Sonnet 4.5 | sqs_sourcearn_001 | IDENTITY_POLICY | provider_invalid | UNSUPPORTED_PRINCIPAL |
| Claude Sonnet 4.5 | sts_oidc_trust_001 | RESOURCE_POLICY | provider_invalid | INVALID_ARN_ACCOUNT |
| Claude Sonnet 4.5 | sts_oidc_trust_002 | RESOURCE_POLICY | provider_invalid | INVALID_ARN_ACCOUNT |
| Claude Sonnet 4.5 | sts_oidc_trust_003 | RESOURCE_POLICY | provider_invalid | INVALID_ARN_ACCOUNT |
| Claude Sonnet 4.5 | sts_oidc_trust_004 | RESOURCE_POLICY | provider_invalid | INVALID_ARN_ACCOUNT |
| Claude Sonnet 4.5 | sts_oidc_trust_005 | RESOURCE_POLICY | provider_invalid | INVALID_ARN_ACCOUNT |
| Claude Sonnet 4.5 | sts_oidc_trust_006 | RESOURCE_POLICY | provider_invalid | INVALID_ARN_ACCOUNT |
| Mistral Small | logs_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Mistral Small | s3_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Mistral Small | secrets_resource_001 | IDENTITY_POLICY | provider_invalid | INVALID_SERVICE_CONDITION_KEY |
| Mistral Small | secrets_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Nova Lite | dynamodb_tenant_002 | IDENTITY_POLICY | provider_invalid | MISSING_QUALIFIER |
| Nova Lite | logs_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Nova Lite | s3_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Nova Lite | secrets_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Nova Lite | sts_oidc_trust_001 | RESOURCE_POLICY | provider_invalid | INVALID_ARN_ACCOUNT |
| Nova Lite | sts_oidc_trust_002 | RESOURCE_POLICY | provider_invalid | INVALID_SERVICE;MISSING_CONDITION_KEY_FOR_OIDC_PRINCIPAL;UNSUPPORTED_ACTION_FOR_CONDITION_KEY |
| Nova Lite | sts_oidc_trust_004 | RESOURCE_POLICY | provider_invalid | INVALID_ARN_ACCOUNT |
| Nova Lite | sts_oidc_trust_005 | RESOURCE_POLICY | provider_invalid | INVALID_ARN_ACCOUNT |
| Nova Pro | dynamodb_tenant_002 | IDENTITY_POLICY | provider_invalid | MISSING_QUALIFIER |
| Nova Pro | logs_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Nova Pro | s3_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Nova Pro | secrets_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Nova Pro | sqs_sourcearn_001 | IDENTITY_POLICY | provider_invalid | UNSUPPORTED_PRINCIPAL |
| Llama 3 8B | dynamodb_tenant_002 | IDENTITY_POLICY | provider_invalid | MISSING_QUALIFIER |
| Llama 3 8B | iam_boundary_001 | IDENTITY_POLICY | provider_invalid | INVALID_EFFECT |
| Llama 3 8B | logs_action_002 | IDENTITY_POLICY | provider_invalid | UNSUPPORTED_SID |
| Llama 3 8B | logs_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Llama 3 8B | s3_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Llama 3 8B | secrets_vpce_002 | IDENTITY_POLICY | provider_invalid | INVALID_VPCE_FORMAT |
| Llama 3 8B | sts_oidc_trust_001 | RESOURCE_POLICY | provider_invalid | INVALID_PRINCIPAL_KEY |
| Llama 3 8B | sts_oidc_trust_002 | RESOURCE_POLICY | provider_invalid | INVALID_PRINCIPAL_KEY |
| Llama 3 8B | sts_oidc_trust_003 | RESOURCE_POLICY | provider_invalid | INVALID_PRINCIPAL_KEY |
| Llama 3 8B | sts_oidc_trust_004 | RESOURCE_POLICY | provider_invalid | INVALID_PRINCIPAL_KEY |
| Llama 3 8B | sts_oidc_trust_005 | RESOURCE_POLICY | provider_invalid | INVALID_PRINCIPAL_KEY |
| Llama 3 8B | sts_oidc_trust_006 | RESOURCE_POLICY | provider_invalid | INVALID_PRINCIPAL_KEY |
| Llama 3 8B | sts_trust_001 | RESOURCE_POLICY | provider_invalid | INVALID_SERVICE;MISSING_PRINCIPAL;ROLE_TRUST_POLICY_SYNTAX_ERROR_RESOURCE;UNSUPPORTED_ACTION_FOR_CONDITION_KEY |

Detail CSV: `tables/table_provider_validity_all_e2e_clean_controls_v1.csv`
Summary CSV: `tables/table_provider_validity_all_e2e_clean_controls_summary_v1.csv`
