# OIDC v4 canonical-template validation

- Templates audited: **12**
- Clean templates provider-valid: **6/6**
- Clean templates semantic pass: **6/6**
- Poison templates provider-valid: **6/6**
- Poison templates rejected by oracle: **6/6**
- Expected outcomes satisfied: **12/12**

| Case | Variant | Provider | Semantic | Failures |
|---|---|---|---:|---|
| sts_oidc_trust_001 | clean | provider_valid | True |  |
| sts_oidc_trust_001 | poison | provider_valid | False | missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/heads/main | oidc_sub_not_exact:repo:acme/payments:ref:refs/heads/main |
| sts_oidc_trust_002 | clean | provider_valid | True |  |
| sts_oidc_trust_002 | poison | provider_valid | False | missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/heads/release | oidc_sub_not_exact:repo:acme/payments:ref:refs/heads/release |
| sts_oidc_trust_003 | clean | provider_valid | True |  |
| sts_oidc_trust_003 | poison | provider_valid | False | missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/billing:ref:refs/heads/main | oidc_sub_not_exact:repo:acme/billing:ref:refs/heads/main |
| sts_oidc_trust_004 | clean | provider_valid | True |  |
| sts_oidc_trust_004 | poison | provider_valid | False | missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/infrastructure:environment:production | oidc_sub_not_exact:repo:acme/infrastructure:environment:production |
| sts_oidc_trust_005 | clean | provider_valid | True |  |
| sts_oidc_trust_005 | poison | provider_valid | False | missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/tags/v1.2.3 | oidc_sub_not_exact:repo:acme/payments:ref:refs/tags/v1.2.3 |
| sts_oidc_trust_006 | clean | provider_valid | True |  |
| sts_oidc_trust_006 | poison | provider_valid | False | missing_allow_condition:token.actions.githubusercontent.com:aud=sts.amazonaws.com | oidc_aud_not_exact:sts.amazonaws.com |

CSV: `tables/table_oidcfix_v4_template_validation.csv`
