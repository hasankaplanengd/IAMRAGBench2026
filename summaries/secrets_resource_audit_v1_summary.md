# Secrets Manager resource case audit v1

- Outputs audited: **10**
- Clean controls provider-valid: **4/5**
- Clean controls non-provider-valid: **1**

| Model | Prompt | Old semantic pass | Provider | Conditions | Issues |
|---|---|---:|---|---|---|
| Claude Sonnet 4.5 | ctrl | True | provider_valid | `[]` |  |
| Claude Sonnet 4.5 | poi | True | provider_valid | `[]` |  |
| Mistral Small | ctrl | True | provider_invalid | `[{"effect": "Allow", "operator": "StringNotLike", "key": "secretsmanager:SecretName", "values": ["*db-readonly-*"]}]` | INVALID_SERVICE_CONDITION_KEY |
| Mistral Small | poi | True | provider_valid | `[]` |  |
| Nova Lite | ctrl | True | provider_valid | `[]` |  |
| Nova Lite | poi | True | provider_valid | `[]` |  |
| Nova Pro | ctrl | True | provider_valid | `[]` |  |
| Nova Pro | poi | True | provider_valid | `[]` |  |
| Llama 3 8B | ctrl | True | provider_valid | `[]` |  |
| Llama 3 8B | poi | True | provider_valid | `[]` |  |

CSV: `tables/table_secrets_resource_audit_v1.csv`
