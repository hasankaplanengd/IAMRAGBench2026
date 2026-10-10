# Repeatability v1 pending validation v2

- Pending policies validated with `ValidatePolicy`: **5**
- Pending candidate pairs classified: **5**
- Exact-confirmed pending pairs: **3**
- Provider-invalid pending pairs: **2**
- Exact mismatches: **0**
- AWS simulator/API errors: **0**

## Pending pair outcomes

| Case | Models | Regimes | Outcome | Exact |
|---|---|---|---|---:|
| `dynamodb_abac_001` | llama3_8b | authority|ordinary | `simulatecustompolicy_confirmed` | True |
| `dynamodb_abac_001` | nova_pro | authority|ordinary | `simulatecustompolicy_confirmed` | True |
| `dynamodb_abac_001` | nova_pro | authority|ordinary | `simulatecustompolicy_confirmed` | True |
| `iam_boundary_001` | llama3_8b | ordinary | `provider_invalid_control_or_treatment` | False |
| `iam_boundary_001` | llama3_8b | authority | `provider_invalid_control_or_treatment` | False |
