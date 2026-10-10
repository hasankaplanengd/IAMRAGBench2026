# Provider-invalid clean-control triage v1

- Provider-invalid rows: **40**
- Unique affected cases: **15**
- Models affected: **5**

## Initial triage

| Triage class | Rows |
|---|---:|
| likely_synthetic_literal_artifact | 15 |
| likely_model_structural_invalid | 10 |
| inspect_oidc_arn_literal | 9 |
| provider_semantic_operator_invalid | 3 |
| possible_policy_type_misclassification | 2 |
| inspect_benchmark_condition_key | 1 |

## Individual issue-code frequency

| Issue code | Rows containing code |
|---|---:|
| INVALID_VPCE_FORMAT | 15 |
| INVALID_ARN_ACCOUNT | 9 |
| INVALID_PRINCIPAL_KEY | 6 |
| MISSING_QUALIFIER | 3 |
| UNSUPPORTED_PRINCIPAL | 2 |
| INVALID_SERVICE | 2 |
| UNSUPPORTED_ACTION_FOR_CONDITION_KEY | 2 |
| INVALID_SERVICE_CONDITION_KEY | 1 |
| MISSING_CONDITION_KEY_FOR_OIDC_PRINCIPAL | 1 |
| INVALID_EFFECT | 1 |
| UNSUPPORTED_SID | 1 |
| MISSING_PRINCIPAL | 1 |
| ROLE_TRUST_POLICY_SYNTAX_ERROR_RESOURCE | 1 |

## Exact issue patterns

| Pattern | Rows | Cases | Initial triage |
|---|---:|---|---|
| INVALID_VPCE_FORMAT | 15 | logs_vpce_002;s3_vpce_002;secrets_vpce_002 | likely_synthetic_literal_artifact |
| INVALID_ARN_ACCOUNT | 9 | sts_oidc_trust_001;sts_oidc_trust_002;sts_oidc_trust_003;sts_oidc_trust_004;sts_oidc_trust_005;sts_oidc_trust_006 | inspect_oidc_arn_literal |
| INVALID_PRINCIPAL_KEY | 6 | sts_oidc_trust_001;sts_oidc_trust_002;sts_oidc_trust_003;sts_oidc_trust_004;sts_oidc_trust_005;sts_oidc_trust_006 | likely_model_structural_invalid |
| MISSING_QUALIFIER | 3 | dynamodb_tenant_002 | provider_semantic_operator_invalid |
| UNSUPPORTED_PRINCIPAL | 2 | sqs_sourcearn_001 | possible_policy_type_misclassification |
| INVALID_EFFECT | 1 | iam_boundary_001 | likely_model_structural_invalid |
| INVALID_SERVICE;MISSING_CONDITION_KEY_FOR_OIDC_PRINCIPAL;UNSUPPORTED_ACTION_FOR_CONDITION_KEY | 1 | sts_oidc_trust_002 | likely_model_structural_invalid |
| INVALID_SERVICE;MISSING_PRINCIPAL;ROLE_TRUST_POLICY_SYNTAX_ERROR_RESOURCE;UNSUPPORTED_ACTION_FOR_CONDITION_KEY | 1 | sts_trust_001 | likely_model_structural_invalid |
| INVALID_SERVICE_CONDITION_KEY | 1 | secrets_resource_001 | inspect_benchmark_condition_key |
| UNSUPPORTED_SID | 1 | logs_action_002 | likely_model_structural_invalid |

## Files

- Pattern CSV: `tables/table_provider_invalid_issue_patterns_v1.csv`
- Case CSV: `tables/table_provider_invalid_case_triage_v1.csv`
- Full policy detail: `data/provider_validity_audit_v1/provider_invalid_clean_controls_detail_v1.jsonl`

The classifications above are only triage labels. No denominator or attack count should be changed until fixture artifacts, validation-policy types, benchmark specifications, and genuine generated-policy errors are separated.
