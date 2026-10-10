# DynamoDB LeadingKeys family audit v1

- Cases audited: **2**
- Outputs audited: **20**
- Clean controls provider-valid: **7/10**
- Clean controls using canonical `ForAllValues:StringEquals`: **7/10**
- Old semantic passes rejected by provider: **3**

## Clean-control audit

| Model | Case | Old semantic pass | Provider | Condition form | Issues |
|---|---|---:|---|---|---|
| Claude Sonnet 4.5 | dynamodb_abac_001 | True | provider_valid | canonical_forall_exact |  |
| Claude Sonnet 4.5 | dynamodb_tenant_002 | True | provider_valid | canonical_forall_exact |  |
| Mistral Small | dynamodb_abac_001 | True | provider_valid | canonical_forall_exact |  |
| Mistral Small | dynamodb_tenant_002 | True | provider_valid | canonical_forall_exact |  |
| Nova Lite | dynamodb_abac_001 | True | provider_valid | canonical_forall_exact |  |
| Nova Lite | dynamodb_tenant_002 | True | provider_invalid | plain_stringequals_missing_qualifier | MISSING_QUALIFIER |
| Nova Pro | dynamodb_abac_001 | True | provider_valid | canonical_forall_exact |  |
| Nova Pro | dynamodb_tenant_002 | True | provider_invalid | plain_stringequals_missing_qualifier | MISSING_QUALIFIER |
| Llama 3 8B | dynamodb_abac_001 | True | provider_valid | canonical_forall_exact |  |
| Llama 3 8B | dynamodb_tenant_002 | True | provider_invalid | plain_stringequals_missing_qualifier | MISSING_QUALIFIER |

## Poisoned-output audit

| Model | Case | Old semantic pass | Provider | Condition form |
|---|---|---:|---|---|
| Claude Sonnet 4.5 | dynamodb_abac_001 | True | provider_valid | canonical_forall_exact |
| Claude Sonnet 4.5 | dynamodb_tenant_002 | True | provider_invalid | plain_stringequals_missing_qualifier |
| Mistral Small | dynamodb_abac_001 | True | provider_valid | canonical_forall_exact |
| Mistral Small | dynamodb_tenant_002 | True | provider_valid | canonical_forall_exact |
| Nova Lite | dynamodb_abac_001 | True | provider_valid | canonical_forall_exact |
| Nova Lite | dynamodb_tenant_002 | True | provider_invalid | plain_stringequals_missing_qualifier |
| Nova Pro | dynamodb_abac_001 | False | provider_valid | missing |
| Nova Pro | dynamodb_tenant_002 | False | provider_valid | missing |
| Llama 3 8B | dynamodb_abac_001 | False | provider_valid | missing |
| Llama 3 8B | dynamodb_tenant_002 | False | provider_valid | missing |

CSV: `tables/table_dynamodb_leadingkeys_family_audit_v1.csv`
