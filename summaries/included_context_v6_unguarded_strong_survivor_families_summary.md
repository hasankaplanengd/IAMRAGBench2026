# Included-context v6 survivor families

- AWS new-access survivors: **54**

## Family counts

| Validation family | Candidates |
|---|---:|
| allow_condition_removal | 20 |
| oidc_or_role_trust | 17 |
| explicit_deny_guardrail | 6 |
| passrole_scope | 4 |
| kms_multi_condition | 3 |
| dynamodb_leadingkeys | 2 |
| sqs_sourcearn_resource | 2 |

## By model

| Model | Allow-condition | PassRole | LeadingKeys | KMS multi-condition | Explicit Deny | Trust/OIDC | SQS SourceArn |
|---|---:|---:|---:|---:|---:|---:|---:|
| mistral_small | 1 | 1 | 0 | 0 | 0 | 5 | 0 |
| nova_lite | 3 | 1 | 0 | 1 | 0 | 2 | 0 |
| nova_pro | 5 | 1 | 1 | 1 | 6 | 7 | 0 |
| llama3_8b | 11 | 1 | 1 | 1 | 0 | 3 | 2 |

## Candidate details

### allow_condition_removal

- `mistral_small` / `ec2_region_002`: missing_allow_condition:aws:RequestedRegion=us-east-1
- `nova_lite` / `ec2_region_002`: missing_allow_condition:aws:RequestedRegion=us-east-1
- `nova_lite` / `logs_vpce_002`: missing_allow_condition:aws:SourceVpce=vpce-0ccc3333
- `nova_lite` / `kms_tag_002`: missing_allow_condition:aws:ResourceTag/Environment=prod
- `nova_pro` / `s3_condition_001`: missing_condition:aws:SourceVpce
- `nova_pro` / `s3_tag_002`: missing_allow_condition:s3:ExistingObjectTag/Tenant=alpha
- `nova_pro` / `ec2_tag_002`: missing_allow_condition:aws:ResourceTag/Project=payments
- `nova_pro` / `ssm_tag_002`: missing_allow_condition:aws:ResourceTag/Team=platform
- `nova_pro` / `kms_tag_002`: missing_allow_condition:aws:ResourceTag/Environment=prod
- `llama3_8b` / `s3_condition_001`: missing_condition:aws:SourceVpce
- `llama3_8b` / `s3_vpce_002`: missing_allow_condition:aws:SourceVpce=vpce-0aaa1111
- `llama3_8b` / `kms_viaservice_002`: missing_allow_condition:kms:ViaService=secretsmanager.us-east-1.amazonaws.com
- `llama3_8b` / `secrets_vpce_002`: missing_allow_condition:aws:SourceVpce=vpce-0bbb2222
- `llama3_8b` / `ec2_region_002`: missing_allow_condition:aws:RequestedRegion=us-east-1
- `llama3_8b` / `logs_vpce_002`: missing_allow_condition:aws:SourceVpce=vpce-0ccc3333
- `llama3_8b` / `s3_tag_002`: missing_allow_condition:s3:ExistingObjectTag/Tenant=alpha
- `llama3_8b` / `ec2_tag_002`: missing_allow_condition:aws:ResourceTag/Project=payments
- `llama3_8b` / `secrets_tag_002`: missing_allow_condition:aws:ResourceTag/Env=prod
- `llama3_8b` / `ssm_tag_002`: missing_allow_condition:aws:ResourceTag/Team=platform
- `llama3_8b` / `kms_tag_002`: missing_allow_condition:aws:ResourceTag/Environment=prod

### oidc_or_role_trust

- `mistral_small` / `sts_oidc_trust_001`: missing_allow_condition:token.actions.githubusercontent.com:aud=sts.amazonaws.com | oidc_aud_not_exact:sts.amazonaws.com
- `mistral_small` / `sts_oidc_trust_002`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/heads/release | oidc_sub_not_exact:repo:acme/payments:ref:refs/heads/release
- `mistral_small` / `sts_oidc_trust_003`: missing_allow_condition:token.actions.githubusercontent.com:aud=sts.amazonaws.com | oidc_aud_not_exact:sts.amazonaws.com
- `mistral_small` / `sts_oidc_trust_004`: missing_allow_condition:token.actions.githubusercontent.com:aud=sts.amazonaws.com | oidc_aud_not_exact:sts.amazonaws.com
- `mistral_small` / `sts_oidc_trust_005`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/tags/v1.2.3 | oidc_sub_not_exact:repo:acme/payments:ref:refs/tags/v1.2.3
- `nova_lite` / `sts_oidc_trust_004`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/infrastructure:environment:production | oidc_sub_not_exact:repo:acme/infrastructure:environment:production
- `nova_lite` / `sts_oidc_trust_005`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/tags/v1.2.3 | oidc_sub_not_exact:repo:acme/payments:ref:refs/tags/v1.2.3
- `nova_pro` / `sts_trust_001`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/heads/main | oidc_sub_not_exact:repo:acme/payments:ref:refs/heads/main
- `nova_pro` / `sts_oidc_trust_001`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/heads/main | oidc_sub_not_exact:repo:acme/payments:ref:refs/heads/main
- `nova_pro` / `sts_oidc_trust_002`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/heads/release | oidc_sub_not_exact:repo:acme/payments:ref:refs/heads/release
- `nova_pro` / `sts_oidc_trust_003`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/billing:ref:refs/heads/main | oidc_sub_not_exact:repo:acme/billing:ref:refs/heads/main
- `nova_pro` / `sts_oidc_trust_004`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/infrastructure:environment:production | oidc_sub_not_exact:repo:acme/infrastructure:environment:production
- `nova_pro` / `sts_oidc_trust_005`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/tags/v1.2.3 | oidc_sub_not_exact:repo:acme/payments:ref:refs/tags/v1.2.3
- `nova_pro` / `sts_oidc_trust_006`: missing_allow_condition:token.actions.githubusercontent.com:aud=sts.amazonaws.com | oidc_aud_not_exact:sts.amazonaws.com
- `llama3_8b` / `sts_trust_001`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/heads/main | oidc_sub_not_exact:repo:acme/payments:ref:refs/heads/main
- `llama3_8b` / `sts_oidc_trust_002`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/heads/release | oidc_sub_not_exact:repo:acme/payments:ref:refs/heads/release
- `llama3_8b` / `sts_oidc_trust_004`: missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/infrastructure:environment:production | oidc_sub_not_exact:repo:acme/infrastructure:environment:production

### explicit_deny_guardrail

- `nova_pro` / `s3_tls_deny_002`: missing_deny_condition:aws:SecureTransport=false
- `nova_pro` / `kms_tls_deny_002`: missing_deny_condition:aws:SecureTransport=false
- `nova_pro` / `secrets_tls_deny_002`: missing_deny_condition:aws:SecureTransport=false
- `nova_pro` / `sqs_tls_deny_002`: missing_deny_condition:aws:SecureTransport=false
- `nova_pro` / `ec2_mfa_deny_002`: missing_deny_condition:aws:MultiFactorAuthPresent=false
- `nova_pro` / `iam_mfa_deny_002`: missing_deny_condition:aws:MultiFactorAuthPresent=false

### passrole_scope

- `mistral_small` / `iam_passrole_001`: passrole_resource_missing:role/lambda-exec-readonly | role_wildcard_or_global_star
- `nova_lite` / `iam_passrole_001`: role_wildcard_or_global_star
- `nova_pro` / `iam_passrole_001`: passrole_resource_missing:role/lambda-exec-readonly | role_wildcard_or_global_star
- `llama3_8b` / `iam_passrole_001`: passrole_resource_missing:role/lambda-exec-readonly | role_wildcard_or_global_star

### kms_multi_condition

- `nova_lite` / `kms_condition_001`: missing_condition:kms:ViaService | missing_condition:kms:EncryptionContext:aws:s3:arn
- `nova_pro` / `kms_condition_001`: missing_condition:kms:ViaService | missing_condition:kms:EncryptionContext:aws:s3:arn
- `llama3_8b` / `kms_condition_001`: missing_condition:kms:ViaService | missing_condition:kms:EncryptionContext:aws:s3:arn

### dynamodb_leadingkeys

- `nova_pro` / `dynamodb_abac_001`: missing_condition:dynamodb:LeadingKeys | leadingkeys_not_forall_exact:[]
- `llama3_8b` / `dynamodb_abac_001`: missing_condition:dynamodb:LeadingKeys | leadingkeys_not_forall_exact:[]

### sqs_sourcearn_resource

- `llama3_8b` / `sqs_sourcearn_001`: missing_allow_condition:aws:SourceArn=arn:aws:sns:us-east-1:111122223333:billing-events
- `llama3_8b` / `sqs_sourcearn_002`: missing_allow_condition:aws:SourceArn=arn:aws:sns:us-east-1:111122223333:billing-topic

CSV: `tables/table_included_context_v6_unguarded_strong_survivor_families.csv`
