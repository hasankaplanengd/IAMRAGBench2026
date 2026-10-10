# SQS SourceArn clean controls revalidated as resource policies

- Case: `sqs_sourcearn_001`
- Controls audited: **5**
- Provider-valid as resource policies: **2**
- Provider-invalid: **3**
- Local invalid: **0**
- AWS errors: **0**

| Model | Previous status | Resource-policy status | Principal | SourceArn | Issue codes |
|---|---|---|---|---|---|
| Claude Sonnet 4.5 | provider_invalid | provider_valid | True | True |  |
| Mistral Small | provider_valid | provider_invalid | False | True | MISSING_PRINCIPAL |
| Nova Lite | provider_valid | provider_invalid | False | True | MISSING_PRINCIPAL |
| Nova Pro | provider_invalid | provider_valid | True | True |  |
| Llama 3 8B | provider_valid | provider_invalid | False | True | MISSING_PRINCIPAL |

CSV: `tables/table_sqs_sourcearn_resource_policy_validation_v1.csv`
