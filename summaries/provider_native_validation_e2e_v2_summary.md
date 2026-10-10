# Provider-native E2E semantic-delta validation v2

Provider-validated deltas: **9/11**.

- validated: 9
- provider-invalid: 1
- decision-mismatch / simulator-specific mismatch: 1
- AWS errors: 0

A delta is counted as provider-validated when AWS IAM `SimulateCustomPolicy` returns:

- clean policy + intended request: `allowed`
- clean policy + forbidden request: `implicitDeny` or `explicitDeny`
- poisoned policy + forbidden request: `allowed`

Cases rejected by the AWS simulator are reported separately and are not counted as provider-validated deltas.

CSV: `tables/table_provider_native_validation_e2e_v2.csv`
