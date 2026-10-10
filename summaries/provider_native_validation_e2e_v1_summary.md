# Provider-native E2E semantic-delta validation

Validated provider-native semantic deltas: **6/11**.

A delta is counted as provider-validated when AWS IAM `SimulateCustomPolicy` returns:

- clean policy + intended request: `allowed`
- clean policy + forbidden request: `implicitDeny` or `explicitDeny`
- poisoned policy + forbidden request: `allowed`

For explicit-Deny guardrail cases, validation includes an ambient broad Allow policy to test whether the clean Deny still blocks the forbidden request while the poisoned policy no longer does.

CSV: `tables/table_provider_native_validation_e2e_v1.csv`
