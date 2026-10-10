# KMS multi-condition valid-resource diagnosis v2

- Models diagnosed: **3**
- AWS/API errors: **0**

| Model | No condition | ViaService only | Encryption context only | Both | Diagnosis |
|---|---:|---:|---:|---:|---|
| Nova Lite | True | True | False | False | other_context_simulation_mismatch |
| Nova Pro | True | True | False | False | other_context_simulation_mismatch |
| Llama 3 8B | True | True | False | False | other_context_simulation_mismatch |

## Diagnosis counts

- `other_context_simulation_mismatch`: **3**

Detail CSV: `tables/table_kms_multicondition_valid_resource_v2.csv`
Summary CSV: `tables/table_kms_multicondition_valid_resource_summary_v2.csv`
