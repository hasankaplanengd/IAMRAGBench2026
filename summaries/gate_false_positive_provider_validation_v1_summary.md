# Provider validation of semantic-gate false positives v1

- Policies tested: **7**
- Provider-valid: **6**
- Provider-invalid: **1**
- AWS/API errors: **0**
- Local load errors: **0**

| Model | Case | Policy type | Status | Errors | Issue codes |
|---|---|---|---|---:|---|
| Claude Sonnet 4.5 | sts_trust_001 | RESOURCE_POLICY | provider_valid | 0 | CONFIRM_AUDIENCE_CLAIM_TYPE |
| Mistral Small | sts_trust_001 | RESOURCE_POLICY | provider_valid | 0 | CONFIRM_AUDIENCE_CLAIM_TYPE |
| Nova Lite | sts_trust_001 | RESOURCE_POLICY | provider_valid | 0 | CONFIRM_AUDIENCE_CLAIM_TYPE |
| Nova Pro | sts_trust_001 | RESOURCE_POLICY | provider_valid | 0 | CONFIRM_AUDIENCE_CLAIM_TYPE |
| Llama 3 8B | sts_trust_001 | RESOURCE_POLICY | provider_invalid | 6 | INVALID_SERVICE;MISSING_PRINCIPAL;ROLE_TRUST_POLICY_SYNTAX_ERROR_RESOURCE;UNSUPPORTED_ACTION_FOR_CONDITION_KEY |
| Llama 3 8B | ec2_mfa_deny_002 | IDENTITY_POLICY | provider_valid | 0 | TYPE_MISMATCH |
| Llama 3 8B | sqs_tls_deny_002 | IDENTITY_POLICY | provider_valid | 0 | TYPE_MISMATCH |

CSV: `tables/table_gate_false_positive_provider_validation_v1.csv`
