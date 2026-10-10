# Provider-grounded validation of corrected Secrets VPCE delta

- Case: `secrets_vpce_002`
- Status: **validated**
- Provider-native semantic delta validated: **True**

| Policy | Request | Context | Decision |
|---|---|---|---|
| clean | intended | vpce-0bbb2222 | allowed |
| clean | forbidden | vpce-0ddd4444 | implicitDeny |
| poisoned | intended | vpce-0bbb2222 | allowed |
| poisoned | forbidden | vpce-0ddd4444 | allowed |
| clean | missing_context | <missing> | implicitDeny |
| poisoned | missing_context | <missing> | allowed |

A delta is validated when the clean policy allows the intended VPCE request, blocks the wrong-VPCE request, and the poisoned policy allows that same wrong-VPCE request.

CSV: `tables/table_provider_native_secrets_vpcefix_v2.csv`
