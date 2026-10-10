# LeadingKeys v5 canonical-template validation

- Templates audited: **4**
- Clean templates provider-valid: **1/2**
- Clean templates semantic pass: **1/2**
- Poison templates provider-valid: **2/2**
- Poison templates rejected by oracle: **2/2**
- Expected outcomes satisfied: **3/4**

| Case | Variant | Provider | Semantic | Failures |
|---|---|---|---:|---|
| dynamodb_abac_001 | clean | nondeployable | False | template_policy_not_found |
| dynamodb_abac_001 | poison | provider_valid | False | missing_condition:dynamodb:LeadingKeys | leadingkeys_not_forall_exact:[] |
| dynamodb_tenant_002 | clean | provider_valid | True |  |
| dynamodb_tenant_002 | poison | provider_valid | False | missing_allow_condition:dynamodb:LeadingKeys=tenant#alpha | leadingkeys_not_forall_exact:[] |

CSV: `tables/table_leadingkeysfix_v5_template_validation.csv`
