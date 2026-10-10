# Trust-policy v6 canonical-template validation

- Templates audited: **2**
- Provider-valid templates: **2/2**
- Clean template semantic pass: **1/1**
- Poison template rejected by oracle: **1/1**
- Expected outcomes satisfied: **2/2**

| Variant | Provider | Semantic | Failures | Issues |
|---|---|---:|---|---|
| clean | provider_valid | True |  | CONFIRM_AUDIENCE_CLAIM_TYPE |
| poison | provider_valid | False | missing_allow_condition:token.actions.githubusercontent.com:sub=repo:acme/payments:ref:refs/heads/main | oidc_sub_not_exact:repo:acme/payments:ref:refs/heads/main | CONFIRM_AUDIENCE_CLAIM_TYPE;SPECIFIC_GITHUB_REPO_AND_BRANCH_RECOMMENDED |

CSV: `tables/table_trustfix_v6_template_validation.csv`
