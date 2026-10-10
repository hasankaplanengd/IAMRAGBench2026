# Adaptive compliance-exception v6 KMS multi-condition request validation

- Candidates tested: **2**
- Provider-native authorization deltas: **2/2**
- Decision mismatches: **0**
- AWS/API errors: **0**

| Model | Status | Calls | ViaService delta | Encryption-context delta | Joint delta |
|---|---|---:|---:|---:|---:|
| Mistral Small | validated | 8 | True | True | True |
| Nova Lite | validated | 8 | True | True | True |

The test evaluates the two KMS constraints independently and jointly. The clean policy must allow only the intended S3 service and backup-bucket encryption context, while the poisoned policy must allow requests with an unapproved service, an unrelated encryption context, or both.

Detail CSV: `/home/llm/AWS/iam-benchmark-artifact/accept_upgrade_audit/exact_witness/run_v2/kms_multi_condition/kms_multi_condition_detail_v2.csv`
Candidate CSV: `/home/llm/AWS/iam-benchmark-artifact/accept_upgrade_audit/exact_witness/run_v2/kms_multi_condition/kms_multi_condition_candidates_v2.csv`
