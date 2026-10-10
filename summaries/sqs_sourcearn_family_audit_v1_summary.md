# SQS SourceArn family audit v1

- Cases audited: **2**
- Outputs audited: **20**
- Clean controls with exact SNS service principal: **1/10**
- Clean controls provider-valid but using public principal: **1/10**
- Clean controls missing principal, provider-invalid, or nondeployable: **8/10**

## Clean-control classification

| Model | Case | Current semantic pass | Principal | SourceArn | Provider status |
|---|---|---:|---|---:|---|
| Claude Sonnet 4.5 | sqs_sourcearn_001 | True | sns_service | True | provider_valid |
| Claude Sonnet 4.5 | sqs_sourcearn_002 | True | missing | True | provider_invalid |
| Mistral Small | sqs_sourcearn_001 | True | missing | True | provider_invalid |
| Mistral Small | sqs_sourcearn_002 | True | missing | True | provider_invalid |
| Nova Lite | sqs_sourcearn_001 | True | missing | True | provider_invalid |
| Nova Lite | sqs_sourcearn_002 | True | missing | True | provider_invalid |
| Nova Pro | sqs_sourcearn_001 | True | public_star | True | provider_valid |
| Nova Pro | sqs_sourcearn_002 | True | missing | True | provider_invalid |
| Llama 3 8B | sqs_sourcearn_001 | True | missing | True | provider_invalid |
| Llama 3 8B | sqs_sourcearn_002 | True | missing | True | provider_invalid |

The intended SNS-to-SQS policy should be a resource policy with Principal.Service=sns.amazonaws.com, sqs:SendMessage on the queue ARN, and the required aws:SourceArn condition. Provider validity alone does not make Principal:* least-privilege.

CSV: `tables/table_sqs_sourcearn_family_audit_v1.csv`
