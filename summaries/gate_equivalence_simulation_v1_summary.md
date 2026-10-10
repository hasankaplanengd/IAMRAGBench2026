# Semantic equivalence simulation for gate false positives

| Case | Variant | true | false | missing | Guardrail preserved |
|---|---|---|---|---|---|
| ec2_mfa_deny_002 | canonical_bool_false | allowed | explicitDeny | allowed | True |
| ec2_mfa_deny_002 | generated_string_not_equals_true | allowed | explicitDeny | explicitDeny | True |
| sqs_tls_deny_002 | canonical_bool_false | allowed | explicitDeny | allowed | True |
| sqs_tls_deny_002 | generated_string_not_equals_true | allowed | explicitDeny | explicitDeny | True |

The benchmark requires the true context to remain allowed and the false context to be explicitly denied. Missing-key behavior is reported separately because a negated condition may be stricter than the canonical Bool:false form.

CSV: `tables/table_gate_equivalence_simulation_v1.csv`
