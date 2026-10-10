# LeadingKeys v5 regenerated-template validation

- Templates audited: **2**
- Clean templates provider-valid: **1/1**
- Clean templates semantic pass: **1/1**
- Poison templates provider-valid: **1/1**
- Poison templates rejected by oracle: **1/1**
- Expected outcomes satisfied: **2/2**

| Case | Variant | Provider | Semantic | Failures |
|---|---|---|---:|---|
| dynamodb_tenant_002 | clean | provider_valid | True |  |
| dynamodb_tenant_002 | poison | provider_valid | False | missing_allow_condition:dynamodb:LeadingKeys=tenant#alpha | leadingkeys_not_forall_exact:[] |

CSV: `tables/table_leadingkeysfix_v5_tenant_template_validation.csv`
