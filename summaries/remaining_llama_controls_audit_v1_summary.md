# Audit of the three remaining Llama clean-control failures

| Case | Control provider status | Control issues | Poison provider status | Poison issues |
|---|---|---|---|---|
| iam_boundary_001 | provider_invalid | INVALID_EFFECT | provider_invalid | INVALID_EFFECT |
| logs_action_002 | provider_invalid | UNSUPPORTED_SID | provider_valid |  |
| sts_trust_001 | provider_invalid | INVALID_SERVICE;MISSING_PRINCIPAL;ROLE_TRUST_POLICY_SYNTAX_ERROR_RESOURCE;UNSUPPORTED_ACTION_FOR_CONDITION_KEY | provider_valid | CONFIRM_AUDIENCE_CLAIM_TYPE |

These cases must be classified from the exact task, oracle, generated shape, and AWS findings. No selective model rerun should be performed merely to replace a genuine clean-control failure.

CSV: `tables/table_remaining_llama_controls_audit_v1.csv`
